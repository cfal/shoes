# HTTPUpgrade Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Speak sing-box's `v2ray-http-upgrade` transport on both sides — a WebSocket-shaped HTTP handshake followed by unframed bytes.

**Architecture:** A new `src/httpupgrade/` module with a server handler and a client handler, each implementing the existing `TcpServerHandler` / `TcpClientHandler` traits and wrapping an inner protocol handler, exactly as `src/websocket/` does. No stream type: after the `101` the bytes are the connection's own. Two existing pieces are promoted out of the modules that own them — `ParsedHttpData` from the WebSocket handler and `PrependStream` from h2mux — because both are needed verbatim.

**Tech Stack:** Rust 2024, tokio, async-trait, serde/serde_yaml for config, chrono for the `Date` header.

Design: [../specs/2026-08-25-httpupgrade-transport-design.md](../specs/2026-08-25-httpupgrade-transport-design.md).

---

## Reference behaviour this plan encodes

From sing-box `transport/v2rayhttpupgrade` at `0f17638`. Every one of these is
pinned by a test below.

- The client sends **no** `Sec-WebSocket-Key`, and the server **refuses** any
  request that carries one.
- `Connection: Upgrade` and `Upgrade: websocket` are applied over the top of
  user-configured headers, not merged with them.
- The response is accepted only on `101` *and* both headers, compared without
  regard to case.
- Bytes read past the header block belong to the tunnel and must reach the
  inner handler.

---

## File structure

| File | Responsibility |
| --- | --- |
| `src/prepend_stream.rs` (moved from `src/h2mux/prepend_stream.rs`) | Put a byte prefix in front of a stream; now also an `AsyncStream` |
| `src/http_parse.rs` (moved from inside `src/websocket/websocket_handler.rs`) | Read an HTTP start line and header block off a stream, with limits |
| `src/httpupgrade/mod.rs` | Module wiring and re-exports |
| `src/httpupgrade/server.rs` | Request parsing, target matching, `101` or refusal |
| `src/httpupgrade/client.rs` | Request construction, response validation |
| `src/config/types/server.rs` | `HttpUpgradeServerConfig`, `ServerProxyConfig::HttpUpgrade` |
| `src/config/types/client.rs` | `HttpUpgradeClientConfig`, `ClientProxyConfig::HttpUpgrade` |
| `src/config/validate.rs`, `src/config/pem.rs` | Recurse into the new variant — these have `_ => {}` arms, so the compiler will **not** catch an omission |
| `src/tcp/tcp_server_handler_factory.rs`, `src/tcp/tcp_client_handler_factory.rs` | Build the handlers from config |
| `CONFIG.md`, `CHANGELOG.md`, `examples/httpupgrade.yaml` | Documentation |

---

### Task 1: `PrependStream` becomes a shared `AsyncStream`

`PrependStream` is private to h2mux and implements only `AsyncRead` + `AsyncWrite`.
`AsyncStream` also requires `AsyncPing`, so as it stands it cannot be boxed as
`Box<dyn AsyncStream>`, which is what both handlers need.

**Files:**
- Create: `src/prepend_stream.rs`
- Delete: `src/h2mux/prepend_stream.rs`
- Modify: `src/h2mux/mod.rs:35`, `src/h2mux/h2mux_server_session.rs:32`, `src/lib.rs`, `src/main.rs`

- [x] **Step 1: Move the file unchanged**

```bash
git mv src/h2mux/prepend_stream.rs src/prepend_stream.rs
```

Remove the line `mod prepend_stream;` from `src/h2mux/mod.rs`, and change the
import in `src/h2mux/h2mux_server_session.rs` from
`use super::prepend_stream::PrependStream;` to
`use crate::prepend_stream::PrependStream;`.

Add `mod prepend_stream;` to `src/lib.rs` (alphabetically, after
`mod port_forward_handler;`) and to `src/main.rs` (after `mod port_forward_handler;`).

- [x] **Step 2: Write the failing test**

Append to `src/prepend_stream.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    /// `AsyncStream` requires `AsyncPing`, which a bare duplex does not have.
    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    /// The prefix comes first, then whatever the stream itself carries.
    #[tokio::test]
    async fn the_prefix_is_read_before_the_stream() {
        let (near, mut far) = duplex(1024);
        far.write_all(b"world").await.unwrap();

        let mut stream = PrependStream::new(TestStream(near), Some(b"hello ".to_vec().into()));

        let mut got = vec![0u8; 11];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello world");
    }

    /// The point of the move: a handler can hand this to an inner handler.
    #[tokio::test]
    async fn a_prepend_stream_is_an_async_stream() {
        let (near, _far) = duplex(1024);
        let boxed: Box<dyn AsyncStream> =
            Box::new(PrependStream::new(TestStream(near), Some(b"x".to_vec().into())));
        assert!(!boxed.supports_ping());
    }
}
```

- [x] **Step 3: Run the tests and watch them fail**

Run: `cargo test --lib prepend_stream:: 2>&1 | tail -20`
Expected: compile error — `the trait bound PrependStream<TestStream>: AsyncStream is not satisfied`, and `AsyncPing` is not implemented.

- [x] **Step 4: Add the two impls**

Append to `src/prepend_stream.rs`, before the test module:

```rust
impl<S: crate::async_stream::AsyncPing + Unpin> crate::async_stream::AsyncPing
    for PrependStream<S>
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: crate::async_stream::AsyncStream> crate::async_stream::AsyncStream for PrependStream<S> {}
```

- [x] **Step 5: Run the tests and the rest of the suite**

Run: `cargo test --lib prepend_stream:: 2>&1 | tail -5`
Expected: `test result: ok. 2 passed`

Run: `cargo test 2>&1 | rg "^test result"`
Expected: every line `ok`, h2mux included — the move must not change its behaviour.

- [x] **Step 6: Commit**

```bash
git add -A src/prepend_stream.rs src/h2mux src/lib.rs src/main.rs
git commit -m "refactor: PrependStream leaves h2mux and becomes an AsyncStream"
```

---

### Task 2: `ParsedHttpData` moves to a shared module

**Files:**
- Create: `src/http_parse.rs`
- Modify: `src/websocket/websocket_handler.rs:1-17,263-315`, `src/lib.rs`, `src/main.rs`

- [x] **Step 1: Create the module with the code moved verbatim**

Create `src/http_parse.rs`:

```rust
use std::collections::HashMap;

use crate::async_stream::AsyncStream;
use crate::stream_reader::StreamReader;

/// An HTTP/1.x start line plus its header block, read off a stream.
///
/// Header names are lowercased; values are trimmed. The `StreamReader` is
/// handed back because whatever it buffered past the blank line belongs to
/// whoever asked for the parse -- for an upgrade transport those bytes are the
/// tunnel's first payload, and dropping them is silent corruption.
pub struct ParsedHttpData {
    pub first_line: String,
    pub headers: HashMap<String, String>,
    pub stream_reader: StreamReader,
}

impl ParsedHttpData {
    pub async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        // don't use FxHashMap for unvalidated user data
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::other("http request line is too long"));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::other(format!(
                        "invalid http request line: {line}"
                    )));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::other("http request is too long"));
            }
        }

        let first_line = first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
        })
    }
}
```

Add `mod http_parse;` to `src/lib.rs` (after `mod http_handler;`) and to
`src/main.rs` (after `mod http_handler;`).

- [x] **Step 2: Delete the original and import the new one**

In `src/websocket/websocket_handler.rs`, delete the `struct ParsedHttpData`
definition and its `impl` block (lines 263-315), and add to the imports:

```rust
use crate::http_parse::ParsedHttpData;
```

- [x] **Step 3: Write the failing test**

Append to `src/http_parse.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn parse_from(bytes: &[u8]) -> std::io::Result<ParsedHttpData> {
        let (near, mut far) = tokio::io::duplex(4096);
        far.write_all(bytes).await.unwrap();
        let mut stream: Box<dyn AsyncStream> = Box::new(crate::util::testing::TestStream(near));
        ParsedHttpData::parse(&mut stream).await
    }

    #[tokio::test]
    async fn header_names_are_lowercased_and_values_trimmed() {
        let parsed = parse_from(b"GET /p HTTP/1.1\r\nX-Secret:  value \r\n\r\n")
            .await
            .unwrap();
        assert_eq!(parsed.first_line, "GET /p HTTP/1.1");
        assert_eq!(parsed.headers.get("x-secret").map(String::as_str), Some("value"));
    }

    /// The bytes after the blank line are the caller's, not ours. An upgrade
    /// transport puts its first payload there.
    #[tokio::test]
    async fn bytes_after_the_blank_line_are_kept() {
        let parsed = parse_from(b"GET /p HTTP/1.1\r\n\r\nPAYLOAD").await.unwrap();
        assert_eq!(parsed.stream_reader.unparsed_data(), b"PAYLOAD");
    }
}
```

This needs a shared `TestStream`. Create `src/util/testing.rs`? No — `src/util.rs`
is a plain module. Instead, add the helper to `src/async_stream.rs` behind
`#[cfg(test)]` so every module's tests can use it:

```rust
#[cfg(test)]
pub mod testing {
    use super::*;
    use tokio::io::DuplexStream;

    /// A duplex half that satisfies `AsyncStream`, which a bare `DuplexStream`
    /// does not because of `AsyncPing`.
    pub struct TestStream(pub DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}
}
```

Then replace the local `TestStream` in `src/prepend_stream.rs`'s test module
with `use crate::async_stream::testing::TestStream;`.

- [x] **Step 4: Run the tests**

Run: `cargo test --lib http_parse:: 2>&1 | tail -5`
Expected: `test result: ok. 2 passed`

Run: `cargo test 2>&1 | rg "^test result"`
Expected: all `ok` — the WebSocket handler now uses the moved parser.

- [x] **Step 5: Commit**

```bash
git add -A src/http_parse.rs src/async_stream.rs src/prepend_stream.rs src/websocket src/lib.rs src/main.rs
git commit -m "refactor: the HTTP header parser moves out of the WebSocket handler"
```

---

### Task 3: Configuration types

**Files:**
- Modify: `src/config/types/server.rs:623-656,748-752,847`, `src/config/types/client.rs:676-679,752,799-807`

- [x] **Step 1: Write the failing tests**

Append to the `mod tests` in `src/config/types/server.rs`:

```rust
    #[test]
    fn test_httpupgrade_server_config() {
        let yaml = r#"
type: httpupgrade
targets:
  - matching_path: /download
    matching_headers:
      Host: cdn.example.com
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
"#;
        let config: ServerProxyConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            ServerProxyConfig::HttpUpgrade { targets } => {
                let targets = targets.into_vec();
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].matching_path.as_deref(), Some("/download"));
            }
            other => panic!("expected HttpUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn test_httpupgrade_server_config_alias() {
        let yaml = r#"
type: http-upgrade
target:
  protocol:
    type: direct
"#;
        let config: ServerProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(config, ServerProxyConfig::HttpUpgrade { .. }));
    }
```

Append to the `mod tests` in `src/config/types/client.rs`:

```rust
    #[test]
    fn test_httpupgrade_client_config() {
        let yaml = r#"
type: httpupgrade
host: cdn.example.com
matching_path: /download
protocol:
  type: direct
"#;
        let config: ClientProxyConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            ClientProxyConfig::HttpUpgrade(c) => {
                assert_eq!(c.host.as_deref(), Some("cdn.example.com"));
                assert_eq!(c.matching_path.as_deref(), Some("/download"));
            }
            other => panic!("expected HttpUpgrade, got {other:?}"),
        }
    }
```

- [x] **Step 2: Run them and watch them fail**

Run: `cargo test --lib httpupgrade 2>&1 | tail -10`
Expected: compile error — `no variant named HttpUpgrade`.

- [x] **Step 3: Add the server config**

In `src/config/types/server.rs`, after `WebsocketPingType`'s `impl` block
(line 656):

```rust
/// One matchable HTTPUpgrade target.
///
/// The same shape as `WebsocketServerConfig` without `ping_type`: HTTPUpgrade
/// has no frames, so there is nothing to ping with.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpUpgradeServerConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    pub protocol: ServerProxyConfig,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}
```

Add the variant to `ServerProxyConfig`, immediately after `Websocket`:

```rust
    #[serde(alias = "http-upgrade", alias = "http_upgrade")]
    HttpUpgrade {
        #[serde(alias = "target")]
        targets: Box<OneOrSome<HttpUpgradeServerConfig>>,
    },
```

Add the `Display` arm next to the `Websocket` one (line 847):

```rust
            Self::HttpUpgrade { .. } => write!(f, "HttpUpgrade"),
```

- [x] **Step 4: Add the client config**

In `src/config/types/client.rs`, after `WebsocketClientConfig` (line 807):

```rust
/// HTTPUpgrade client transport.
///
/// `host` exists here and not on the server because there is nowhere else to
/// get the value: `setup_client_tcp_stream` receives the user's destination,
/// not the proxy's address, and the TLS wrapper's SNI is not visible from this
/// layer. On the server, `Host` is one header among many and
/// `matching_headers` already matches it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpUpgradeClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_headers: Option<HashMap<String, String>>,
    pub protocol: Box<ClientProxyConfig>,
}
```

Add the variant after `Websocket(WebsocketClientConfig)` (line 677):

```rust
    #[serde(alias = "http-upgrade", alias = "http_upgrade")]
    HttpUpgrade(HttpUpgradeClientConfig),
```

And the `protocol_name` arm after the `Websocket` one (line 752):

```rust
            ClientProxyConfig::HttpUpgrade(..) => "HTTPUpgrade",
```

- [x] **Step 5: Run the tests**

Run: `cargo test --lib httpupgrade 2>&1 | tail -5`
Expected: `test result: ok. 3 passed`

- [x] **Step 6: Commit**

```bash
git add src/config/types/server.rs src/config/types/client.rs
git commit -m "config: HTTPUpgrade server and client types"
```

---

### Task 4: The server handler

**Files:**
- Create: `src/httpupgrade/mod.rs`, `src/httpupgrade/server.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [x] **Step 1: Create the module skeleton**

Create `src/httpupgrade/mod.rs`:

```rust
//! HTTPUpgrade: WebSocket's HTTP handshake without WebSocket's framing.
//!
//! Compatible with sing-box's `v2ray-http-upgrade` (`transport/v2rayhttpupgrade`
//! at `0f17638`). The client sends a `GET` carrying `Connection: Upgrade` and
//! `Upgrade: websocket`, the server answers `101`, and both sides then write
//! raw bytes -- no masking, no frame headers, no pings.
//!
//! The distinguishing rule, and the one an implementation gets wrong silently:
//! a real WebSocket handshake must be *refused*. sing-box answers `404` to any
//! request carrying `Sec-WebSocket-Key`, so this client never sends one and
//! this server rejects one.

mod client;
mod server;

pub use client::HttpUpgradeTcpClientHandler;
pub use server::{HttpUpgradeServerTarget, HttpUpgradeTcpServerHandler};
```

Add `mod httpupgrade;` to `src/lib.rs` (after `mod http_parse;`) and to
`src/main.rs` (after `mod http_parse;`).

- [x] **Step 2: Write the failing tests**

Create `src/httpupgrade/server.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::testing::TestStream;
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Records the stream it was handed so a test can read what survived the
    /// handshake.
    #[derive(Debug)]
    struct RecordingHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl TcpServerHandler for RecordingHandler {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut got = vec![0u8; 7];
            stream.read_exact(&mut got).await?;
            *self.received.lock().unwrap() = got;
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    fn handler_with(
        matching_path: Option<&str>,
        received: Arc<Mutex<Vec<u8>>>,
    ) -> HttpUpgradeTcpServerHandler {
        HttpUpgradeTcpServerHandler::new(vec![HttpUpgradeServerTarget {
            matching_path: matching_path.map(String::from),
            matching_headers: None,
            handler: Box::new(RecordingHandler { received }),
        }])
    }

    /// Drives the handler against `request` and returns what it wrote back.
    async fn respond_to(
        handler: &HttpUpgradeTcpServerHandler,
        request: &[u8],
    ) -> (std::io::Result<TcpServerSetupResult>, Vec<u8>) {
        let (near, mut far) = duplex(8192);
        far.write_all(request).await.unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(near)))
            .await;
        let mut response = vec![0u8; 512];
        let n = far.read(&mut response).await.unwrap();
        response.truncate(n);
        (result, response)
    }

    /// Byte for byte what sing-box writes. Asserted literally: a round trip
    /// through our own client would pass even if both were wrong.
    #[tokio::test]
    async fn a_matching_request_gets_the_reference_101() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received);
        let (result, response) = respond_to(
            &handler,
            b"GET /download HTTP/1.1\r\nHost: cdn.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            response,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
    }

    /// The bytes that arrived in the same packet as the header block are the
    /// tunnel's first payload. Without `PrependStream` they vanish.
    #[tokio::test]
    async fn the_payload_after_the_header_block_reaches_the_inner_handler() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received.clone());
        let (result, _) = respond_to(
            &handler,
            b"GET /download HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(&*received.lock().unwrap(), b"PAYLOAD");
    }

    /// sing-box logs this one as "real websocket request received". Accepting
    /// it would mean speaking framed bytes to a peer that expects raw ones.
    #[tokio::test]
    async fn a_real_websocket_handshake_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(
            response.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "got {}",
            String::from_utf8_lossy(&response)
        );
    }

    #[tokio::test]
    async fn a_path_mismatch_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received);
        let (result, response) = respond_to(
            &handler,
            b"GET /other HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    #[tokio::test]
    async fn a_non_get_method_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"POST / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    #[tokio::test]
    async fn a_request_without_the_upgrade_headers_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) =
            respond_to(&handler, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    /// A start line we cannot parse is a malformed request, not a wrong one.
    #[tokio::test]
    async fn a_bad_http_version_is_a_bad_request() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"GET / HTTP/0.9\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }

    /// A refusal has to look like a web server's, not like a closed socket.
    #[tokio::test]
    async fn a_refusal_carries_web_server_headers() {
        let response = refusal_response(NOT_FOUND, "Mon, 25 Aug 2026 12:00:00 GMT");
        assert_eq!(
            response,
            "HTTP/1.1 404 Not Found\r\nDate: Mon, 25 Aug 2026 12:00:00 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
```

- [x] **Step 3: Run them and watch them fail**

Run: `cargo test --lib httpupgrade::server 2>&1 | tail -10`
Expected: compile error — `HttpUpgradeTcpServerHandler` is not defined.

- [x] **Step 4: Write the implementation**

Prepend to `src/httpupgrade/server.rs`, above the test module:

```rust
use async_trait::async_trait;
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::http_parse::ParsedHttpData;
use crate::prepend_stream::PrependStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const NOT_FOUND: &str = "404 Not Found";
const BAD_REQUEST: &str = "400 Bad Request";

const UPGRADE_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Debug)]
pub struct HttpUpgradeServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub handler: Box<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    server_targets: Vec<HttpUpgradeServerTarget>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(server_targets: Vec<HttpUpgradeServerTarget>) -> Self {
        Self { server_targets }
    }
}

/// A refusal that reads as an ordinary web server's, because looking like one
/// is this transport's entire purpose.
fn refusal_response(status: &str, date: &str) -> String {
    format!("HTTP/1.1 {status}\r\nDate: {date}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Writes the refusal and returns the error the caller will log. Write failures
/// are ignored deliberately: the connection is being refused either way, and the
/// interesting error is the reason for the refusal.
async fn refuse(
    stream: &mut Box<dyn AsyncStream>,
    status: &'static str,
    reason: String,
) -> std::io::Error {
    let response = refusal_response(status, &http_date_now());
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    std::io::Error::other(reason)
}

fn header_is(headers: &std::collections::HashMap<String, String>, key: &str, value: &str) -> bool {
    headers
        .get(key)
        .is_some_and(|v| v.eq_ignore_ascii_case(value))
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let parsed = match ParsedHttpData::parse(&mut server_stream).await {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(refuse(&mut server_stream, BAD_REQUEST, format!("httpupgrade: unreadable request: {e}")).await);
            }
        };

        let ParsedHttpData {
            mut first_line,
            headers: request_headers,
            stream_reader,
        } = parsed;

        if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
            return Err(refuse(
                &mut server_stream,
                BAD_REQUEST,
                format!("httpupgrade: invalid http version: {first_line}"),
            )
            .await);
        }

        if !first_line.starts_with("GET ") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                format!("httpupgrade: bad method: {first_line}"),
            )
            .await);
        }

        // remove ' HTTP/1.x', then everything after 'GET ' is the path
        first_line.truncate(first_line.len() - 9);
        let request_path = first_line.split_off(4);

        if !header_is(&request_headers, "connection", "upgrade") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: not an upgrade request".to_string(),
            )
            .await);
        }

        if !header_is(&request_headers, "upgrade", "websocket") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: not a websocket upgrade".to_string(),
            )
            .await);
        }

        // A framed WebSocket peer would read our unframed bytes as garbage, so
        // this is refused rather than served. Same rule, same status code, as
        // the reference.
        if request_headers.contains_key("sec-websocket-key") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: real websocket request received".to_string(),
            )
            .await);
        }

        'outer: for server_target in self.server_targets.iter() {
            let HttpUpgradeServerTarget {
                matching_path,
                matching_headers,
                handler,
            } = server_target;

            if let Some(path) = matching_path
                && path != &request_path
            {
                continue;
            }

            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            server_stream.write_all(UPGRADE_RESPONSE).await?;

            let tunnel = PrependStream::new(server_stream, stream_reader.unparsed_data_owned());

            let mut target_setup_result = handler.setup_server_stream(Box::new(tunnel)).await;

            if let Ok(ref mut setup_result) = target_setup_result {
                if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                    return target_setup_result;
                }
                setup_result.set_need_initial_flush(true);
            }

            return target_setup_result;
        }

        Err(refuse(
            &mut server_stream,
            NOT_FOUND,
            format!("httpupgrade: no target matched path {request_path}"),
        )
        .await)
    }
}
```

- [x] **Step 5: Run the tests**

Run: `cargo test --lib httpupgrade::server 2>&1 | tail -5`
Expected: `test result: ok. 8 passed`

- [x] **Step 6: Mutation check the two rules that matter**

Temporarily delete the `sec-websocket-key` block and re-run:
Expected: `a_real_websocket_handshake_is_refused` FAILS. Restore it.

Temporarily replace `stream_reader.unparsed_data_owned()` with `None` and re-run:
Expected: `the_payload_after_the_header_block_reaches_the_inner_handler` FAILS
(hangs on `read_exact`, then times out — kill it and restore). If it passes,
the test is not testing what it claims.

- [x] **Step 7: Commit**

```bash
git add src/httpupgrade src/lib.rs src/main.rs
git commit -m "httpupgrade: the server side"
```

---

### Task 5: The client handler

**Files:**
- Create: `src/httpupgrade/client.rs`

- [x] **Step 1: Write the failing tests**

Create `src/httpupgrade/client.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{NetLocation, ResolvedLocation};
    use crate::async_stream::testing::TestStream;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Hands back whatever stream it is given, after recording its first bytes.
    #[derive(Debug)]
    struct RecordingHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl TcpClientHandler for RecordingHandler {
        async fn setup_client_tcp_stream(
            &self,
            mut client_stream: Box<dyn AsyncStream>,
            _remote_location: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            let mut got = vec![0u8; 7];
            client_stream.read_exact(&mut got).await?;
            *self.received.lock().unwrap() = got;
            Ok(TcpClientSetupResult {
                client_stream,
                early_data: None,
            })
        }
    }

    fn target() -> ResolvedLocation {
        ResolvedLocation::new(NetLocation::from_str("example.com:443", None).unwrap())
    }

    fn client(
        host: Option<&str>,
        headers: Option<Vec<(&str, &str)>>,
        received: Arc<Mutex<Vec<u8>>>,
    ) -> HttpUpgradeTcpClientHandler {
        HttpUpgradeTcpClientHandler::new(
            host.map(String::from),
            Some("/download".to_string()),
            headers.map(|hs| {
                hs.into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            }),
            Box::new(RecordingHandler { received }),
        )
    }

    /// Byte for byte, including order. sing-box applies Connection and Upgrade
    /// over the top of the configured headers, so they come last.
    #[tokio::test]
    async fn the_request_is_what_the_reference_sends() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(
            Some("cdn.example.com"),
            Some(vec![("X-Secret", "value")]),
            received,
        );
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        request.truncate(n);
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /download HTTP/1.1\r\nHost: cdn.example.com\r\nX-Secret: value\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );

        far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD")
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }

    /// The server refuses a request carrying one, so sending it would make
    /// every connection fail.
    #[tokio::test]
    async fn no_websocket_key_is_sent() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        let request = String::from_utf8(request[..n].to_vec()).unwrap();
        assert!(
            !request.to_lowercase().contains("sec-websocket"),
            "request carried a websocket header: {request}"
        );

        far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD")
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }

    /// Same defect as on the server side, seen from the other end.
    #[tokio::test]
    async fn the_payload_after_the_header_block_reaches_the_inner_handler() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received.clone());
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        far.read(&mut request).await.unwrap();
        far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD")
            .await
            .unwrap();

        task.await.unwrap().unwrap();
        assert_eq!(&*received.lock().unwrap(), b"PAYLOAD");
    }

    async fn response_is_rejected(response: &'static [u8]) -> String {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        far.read(&mut request).await.unwrap();
        far.write_all(response).await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        err.to_string()
    }

    #[tokio::test]
    async fn a_non_101_response_is_an_error_that_quotes_it() {
        let message = response_is_rejected(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(message.contains("404 Not Found"), "got {message}");
    }

    #[tokio::test]
    async fn a_response_without_the_upgrade_headers_is_an_error() {
        let message =
            response_is_rejected(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n")
                .await;
        assert!(message.to_lowercase().contains("upgrade"), "got {message}");
    }

    /// UDP-over-TCP is the inner protocol's business; this transport only says
    /// whether the thing it wraps can do it.
    #[tokio::test]
    async fn udp_support_is_the_inner_handler_s_answer() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        assert!(!handler.supports_udp_over_tcp());
    }

    /// Go writes Host from the request field, so a header of that name in the
    /// config is ignored; Connection and Upgrade are overwritten. Ours must not
    /// emit either of them twice.
    #[tokio::test]
    async fn configured_headers_cannot_forge_the_upgrade() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(
            Some("real.example.com"),
            Some(vec![
                ("Host", "forged.example.com"),
                ("Connection", "keep-alive"),
                ("Upgrade", "h2c"),
            ]),
            received,
        );
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        request.truncate(n);
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /download HTTP/1.1\r\nHost: real.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );

        far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD")
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }
}
```

- [x] **Step 2: Run them and watch them fail**

Run: `cargo test --lib httpupgrade::client 2>&1 | tail -10`
Expected: compile error — `HttpUpgradeTcpClientHandler` is not defined.

- [x] **Step 3: Write the implementation**

Prepend to `src/httpupgrade/client.rs`:

```rust
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::http_parse::ParsedHttpData;
use crate::prepend_stream::PrependStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct HttpUpgradeTcpClientHandler {
    host: Option<String>,
    request_path: String,
    /// Sorted, and with the three headers this transport owns removed, so the
    /// bytes on the wire are the same on every run and cannot be forged from
    /// config.
    headers: Vec<(String, String)>,
    handler: Box<dyn TcpClientHandler>,
}

impl HttpUpgradeTcpClientHandler {
    pub fn new(
        host: Option<String>,
        matching_path: Option<String>,
        matching_headers: Option<Vec<(String, String)>>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let mut headers: Vec<(String, String)> = matching_headers
            .unwrap_or_default()
            .into_iter()
            .filter(|(key, _)| {
                // Host is written from `host`; Connection and Upgrade are what
                // makes this an upgrade request. The reference overwrites all
                // three, so accepting them from config would only let a
                // configuration break itself.
                !key.eq_ignore_ascii_case("host")
                    && !key.eq_ignore_ascii_case("connection")
                    && !key.eq_ignore_ascii_case("upgrade")
            })
            .collect();
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            host,
            request_path: matching_path.unwrap_or_else(|| "/".to_string()),
            headers,
            handler,
        }
    }

    fn build_request(&self) -> String {
        let mut request = String::with_capacity(256);
        request.push_str("GET ");
        request.push_str(&self.request_path);
        request.push_str(" HTTP/1.1\r\n");

        if let Some(ref host) = self.host {
            request.push_str("Host: ");
            request.push_str(host);
            request.push_str("\r\n");
        }

        for (key, value) in self.headers.iter() {
            request.push_str(key);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }

        request.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        request
    }

    async fn setup_tunnel(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        client_stream
            .write_all(self.build_request().as_bytes())
            .await?;
        client_stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers: response_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::other(format!(
                "httpupgrade: server refused the upgrade: {first_line}"
            )));
        }

        for (key, expected) in [("connection", "upgrade"), ("upgrade", "websocket")] {
            let value = response_headers.get(key).map(String::as_str).unwrap_or("");
            if !value.eq_ignore_ascii_case(expected) {
                return Err(std::io::Error::other(format!(
                    "httpupgrade: response header {key} was {value:?}, expected {expected:?}"
                )));
            }
        }

        Ok(Box::new(PrependStream::new(
            client_stream,
            stream_reader.unparsed_data_owned(),
        )))
    }
}

#[async_trait]
impl TcpClientHandler for HttpUpgradeTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let tunnel = self.setup_tunnel(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(tunnel, remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let tunnel = self.setup_tunnel(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(tunnel, target)
            .await
    }
}
```

- [x] **Step 4: Run the tests**

Run: `cargo test --lib httpupgrade::client 2>&1 | tail -5`
Expected: `test result: ok. 7 passed`

- [x] **Step 5: Mutation check**

Temporarily add `("Sec-WebSocket-Key", "x")` to the always-sent headers in
`build_request` and re-run: `no_websocket_key_is_sent` must FAIL. Restore.

Temporarily replace `stream_reader.unparsed_data_owned()` with `None`:
`the_payload_after_the_header_block_reaches_the_inner_handler` must FAIL.
Restore.

- [x] **Step 6: Commit**

```bash
git add src/httpupgrade/client.rs
git commit -m "httpupgrade: the client side"
```

---

### Task 6: Wire the handlers to configuration

The two `match` statements in `src/config/validate.rs` and `src/config/pem.rs`
end in `_ => {}`, so **the compiler will not tell you** if the new variant is
missed. A missed arm means the inner protocol is never validated and its PEM
paths are never resolved — a config that looks fine and fails at runtime.

**Files:**
- Modify: `src/tcp/tcp_server_handler_factory.rs:225,587`, `src/tcp/tcp_client_handler_factory.rs:325`, `src/config/validate.rs:932,1250,1597`, `src/config/pem.rs:295,406`

- [x] **Step 1: Write the failing test**

Append to the `mod tests` in `src/config/validate.rs`:

```rust
    /// The `_ => {}` arms in this file mean a new transport is skipped
    /// silently. This pins that HTTPUpgrade recurses into what it wraps: the
    /// inner rule names a client group that does not exist, which only
    /// validation of the inner protocol can catch.
    #[tokio::test]
    async fn httpupgrade_validates_the_protocol_it_wraps() {
        let yaml = r#"
- address: 0.0.0.0:443
  protocol:
    type: httpupgrade
    targets:
      - matching_path: /download
        protocol:
          type: socks
        override_rules:
          - mask: 0.0.0.0/0
            action: allow
            client_chain: no-such-group
  rules:
    - mask: 0.0.0.0/0
      action: allow
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        let err = validate_configs_test(configs).await.unwrap_err().to_string();
        assert!(
            err.contains("no-such-group"),
            "the wrapped protocol's rules were not validated: {err}"
        );
    }
```

- [x] **Step 2: Run it and watch it fail**

Run: `cargo test --lib httpupgrade_validates 2>&1 | tail -10`
Expected: FAIL — the config loads without complaint, because nothing looks
inside the new variant. (If it fails to compile instead, adjust the call to
match how neighbouring tests in this file load a config, then re-run and
confirm it fails for the right reason before continuing.)

- [x] **Step 3: Add the server factory arm**

In `src/tcp/tcp_server_handler_factory.rs`, after the `Websocket` arm (line 233):

```rust
        ServerProxyConfig::HttpUpgrade { targets } => {
            let server_targets: Vec<HttpUpgradeServerTarget> = targets
                .into_vec()
                .into_iter()
                .map(|config| {
                    create_httpupgrade_server_target(config, client_proxy_selector, resolver, bind_ip)
                })
                .collect::<Vec<_>>();
            Box::new(HttpUpgradeTcpServerHandler::new(server_targets))
        }
```

And after `create_websocket_server_target` (line 628):

```rust
fn create_httpupgrade_server_target(
    httpupgrade_server_config: HttpUpgradeServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> HttpUpgradeServerTarget {
    let HttpUpgradeServerConfig {
        matching_path,
        matching_headers,
        protocol,
        override_rules,
    } = httpupgrade_server_config;

    let matching_headers = matching_headers.map(|h| {
        h.into_iter()
            .map(|(mut key, val)| {
                key.make_ascii_lowercase();
                (key, val)
            })
            .collect::<FxHashMap<_, _>>()
    });

    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()))
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_tcp_server_handler(protocol, &effective_selector, resolver, bind_ip);

    HttpUpgradeServerTarget {
        matching_path,
        matching_headers,
        handler,
    }
}
```

Add to the imports at the top of the file:

```rust
use crate::httpupgrade::{HttpUpgradeServerTarget, HttpUpgradeTcpServerHandler};
```

and add `HttpUpgradeServerConfig` to the existing `use crate::config::{...}` list.

- [x] **Step 4: Add the client factory arm**

In `src/tcp/tcp_client_handler_factory.rs`, after the `Websocket` arm (line 339):

```rust
        ClientProxyConfig::HttpUpgrade(httpupgrade_client_config) => {
            let HttpUpgradeClientConfig {
                host,
                matching_path,
                matching_headers,
                protocol,
            } = httpupgrade_client_config;

            let handler = create_tcp_client_handler(*protocol, None, resolver.clone());

            Box::new(HttpUpgradeTcpClientHandler::new(
                host,
                matching_path,
                matching_headers.map(|h| h.into_iter().collect()),
                handler,
            ))
        }
```

Add to the imports:

```rust
use crate::httpupgrade::HttpUpgradeTcpClientHandler;
```

and add `HttpUpgradeClientConfig` to the existing `use crate::config::{...}` list.

- [x] **Step 5: Add the validation and PEM arms**

In `src/config/validate.rs`, beside the `ServerProxyConfig::Websocket` arm
(line 1597):

```rust
        ServerProxyConfig::HttpUpgrade { targets } => {
            for httpupgrade_server_config in targets.iter_mut() {
                let HttpUpgradeServerConfig {
                    protocol,
                    override_rules,
                    ..
                } = httpupgrade_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    false,
                )?;
                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                    )?;
                }
            }
        }
```

Beside `ClientProxyConfig::Websocket` at line 932:

```rust
        ClientProxyConfig::HttpUpgrade(config) => {
            validate_client_proxy_structure(&config.protocol)?;
        }
```

Beside `ClientProxyConfig::Websocket` at line 1250:

```rust
        ClientProxyConfig::HttpUpgrade(config) => {
            validate_client_proxy_config(&mut config.protocol, named_pems)?;
        }
```

In `src/config/pem.rs`, beside `ServerProxyConfig::Websocket` at line 295:

```rust
        ServerProxyConfig::HttpUpgrade { targets } => {
            for httpupgrade_config in targets.iter_mut() {
                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut httpupgrade_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in httpupgrade_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }
        }
```

And beside `ClientProxyConfig::Websocket` at line 406:

```rust
        ClientProxyConfig::HttpUpgrade(config) => {
            gather_pem_file_paths_from_client_proxy(
                &mut config.protocol,
                known_pem_paths,
                unknown_pem_paths,
            );
        }
```

- [x] **Step 6: Run the test and the suite**

Run: `cargo test --lib httpupgrade 2>&1 | rg "^test result"`
Expected: `ok`, with the validation test now passing.

Run: `cargo test 2>&1 | rg "^test result"`
Expected: all `ok`.

- [x] **Step 7: Commit**

```bash
git add src/tcp src/config
git commit -m "httpupgrade: build the handlers from configuration"
```

---

### Task 7: End-to-end through the real handlers

**Files:**
- Create: `src/httpupgrade/tests.rs`
- Modify: `src/httpupgrade/mod.rs`

- [x] **Step 1: Write the failing test**

Create `src/httpupgrade/tests.rs`:

```rust
//! Client against server, both built the way the factories build them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::{HttpUpgradeServerTarget, HttpUpgradeTcpClientHandler, HttpUpgradeTcpServerHandler};
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::async_stream::testing::TestStream;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

/// Stands in for the wrapped proxy protocol: hands the tunnel straight back.
#[derive(Debug)]
struct PassthroughClient;

#[async_trait]
impl TcpClientHandler for PassthroughClient {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        _remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }
}

/// Echoes back everything it is sent, so the test can prove the tunnel carries
/// bytes in both directions after the handshake.
#[derive(Debug)]
struct EchoServer {
    done: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[async_trait]
impl TcpServerHandler for EchoServer {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok(n) = server_stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if server_stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        *self.done.lock().unwrap() = Some(handle);
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[tokio::test]
async fn a_tunnel_carries_bytes_in_both_directions() {
    let (client_side, server_side) = duplex(65536);

    let server = HttpUpgradeTcpServerHandler::new(vec![HttpUpgradeServerTarget {
        matching_path: Some("/download".to_string()),
        matching_headers: None,
        handler: Box::new(EchoServer {
            done: Arc::new(Mutex::new(None)),
        }),
    }]);

    let server_task = tokio::spawn(async move {
        server
            .setup_server_stream(Box::new(TestStream(server_side)))
            .await
    });

    let client = HttpUpgradeTcpClientHandler::new(
        Some("cdn.example.com".to_string()),
        Some("/download".to_string()),
        None,
        Box::new(PassthroughClient),
    );

    let mut result = client
        .setup_client_tcp_stream(
            Box::new(TestStream(client_side)),
            ResolvedLocation::new(NetLocation::from_str("example.com:443", None).unwrap()),
        )
        .await
        .unwrap();

    assert!(server_task.await.unwrap().is_ok());

    result.client_stream.write_all(b"ping").await.unwrap();
    result.client_stream.flush().await.unwrap();

    let mut got = [0u8; 4];
    result.client_stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}
```

Add to `src/httpupgrade/mod.rs`:

```rust
#[cfg(test)]
mod tests;
```

- [x] **Step 2: Run it**

Run: `cargo test --lib httpupgrade::tests 2>&1 | tail -5`
Expected: `test result: ok. 1 passed`

If it hangs, the handshake is deadlocking on a duplex with too small a buffer —
check that the server writes its `101` before the client reads.

- [x] **Step 3: Commit**

```bash
git add src/httpupgrade
git commit -m "httpupgrade: an end-to-end test through both handlers"
```

---

### Task 8: Documentation

**Files:**
- Modify: `CONFIG.md:237-248,590-598`, `CHANGELOG.md:3`
- Create: `examples/httpupgrade.yaml`

- [x] **Step 1: Document the server type**

In `CONFIG.md`, after the `### WebSocket` block (line 248):

````markdown
### HTTPUpgrade
```yaml
protocol:
  type: httpupgrade            # Aliases: http-upgrade, http_upgrade
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/download")
      matching_headers:        # Optional header filters, including Host
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]
```

WebSocket's handshake without its framing, compatible with sing-box's
`httpupgrade`. There is no `ping_type`: without frames there is nothing to ping
with. A request that carries `Sec-WebSocket-Key` is refused with `404`, as the
reference does — a real WebSocket client would misread the unframed bytes that
follow. Anything else that does not match is refused with `404` too.
````

- [x] **Step 2: Document the client type**

After the `### WebSocket Client` block (line 598):

````markdown
### HTTPUpgrade Client
```yaml
protocol:
  type: httpupgrade
  host: string?                # Sent as the Host header
  matching_path: string?
  matching_headers:
    header_name: string
  protocol: ClientProxyConfig
```

Set `host` whenever a CDN or a sing-box server with its own `host` configured
sits in front: left unset, the request goes out without a `Host` header, which
a bare sing-box server accepts and a CDN does not. `Host`, `Connection` and
`Upgrade` in `matching_headers` are ignored — the transport owns all three.
````

- [x] **Step 3: Write the example**

Create `examples/httpupgrade.yaml`:

```yaml
# HTTPUpgrade behind TLS, the shape a CDN-fronted deployment uses.
# Same handshake as WebSocket, without the framing on every write.
- address: 0.0.0.0:443
  transport: tcp
  protocol:
    type: tls
    default_target:
      cert: cert.pem
      key: key.pem
      protocol:
        type: httpupgrade
        targets:
          - matching_path: /download
            matching_headers:
              Host: cdn.example.com
            protocol:
              type: vmess
              cipher: aes-128-gcm
              user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
  rules:
    - mask: 0.0.0.0/0
      action: allow

# The matching client.
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_chain:
        address: cdn.example.com:443
        protocol:
          type: tls
          protocol:
            type: httpupgrade
            host: cdn.example.com
            matching_path: /download
            protocol:
              type: vmess
              cipher: aes-128-gcm
              user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
```

- [x] **Step 4: Add the changelog entry**

Under `## Unreleased` in `CHANGELOG.md`, after the existing sections:

```markdown
### HTTPUpgrade transport

WebSocket's HTTP handshake without WebSocket's framing, on the server and the
client, compatible with sing-box's `httpupgrade`. A `GET` carrying
`Connection: Upgrade`, a `101`, and raw bytes after that — no masking and no
frame header on every write, which is what a proxy pays WebSocket for and gets
nothing back.

Read from the reference implementation rather than from its documentation, which
is where the two rules that decide interoperability live. A real WebSocket
handshake is *refused* rather than served: our client never sends
`Sec-WebSocket-Key` and our server answers `404` to a request carrying one,
because a framed peer would read the unframed bytes that follow as garbage. And
bytes that arrive in the same packet as the header block are the tunnel's first
payload; both reference implementations carry dedicated code so as not to drop
them.

One deviation, deliberate: sing-box answers `400` for a Host mismatch and `404`
for everything else, while `Host` here is an ordinary entry in
`matching_headers` and indistinguishable at the point of refusal, so every
mismatch is `404`.

Not implemented: Xray's `ed` early data, which returns a stream before its
response has been read, and Xray's browser-shaped default headers.
```

- [x] **Step 5: Check the example parses**

Run: `cargo run -- --dry-run examples/httpupgrade.yaml 2>&1 | tail -5`

`--dry-run` (`-d`) parses the config and exits — see `src/main.rs:186`.
Expected: no error about the config's shape. A complaint about the missing
`cert.pem` is fine and expected; a complaint about an unknown protocol type or
an unknown field is not.

- [x] **Step 6: Commit**

```bash
git add CONFIG.md CHANGELOG.md examples/httpupgrade.yaml
git commit -m "docs: HTTPUpgrade configuration, example and changelog"
```

---

### Task 9: The full gate

- [x] **Step 1: Format, lint, test**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features ffi -- -D warnings
cargo test 2>&1 | rg "^test result"
```

Expected: `fmt` silent, both clippy runs clean, every test line `ok`.

- [x] **Step 2: Commit anything the gate changed**

```bash
git add -A
git commit -m "httpupgrade: satisfy fmt and clippy"
```

(Skip if there is nothing to commit.)

---

### Task 10: Live interoperability with sing-box

Tests here are written against our own reading of the reference. That reading is
what mieru and Hysteria2 both got wrong while every test was green. This task is
the check that no test can substitute for, and it is **manual**.

**Prerequisites:** a Go toolchain and a sing-box binary built from source. Do
not use a distribution package — the version matters.

```bash
git clone --depth 1 https://github.com/SagerNet/sing-box /tmp/sing-box
cd /tmp/sing-box && go build -o /tmp/sing-box-bin ./cmd/sing-box && /tmp/sing-box-bin version
```

Write both configs under `/tmp`, never inside the working tree.

- [x] **Step 1: Our client against their server**

Run sing-box as a VMess server behind `httpupgrade` on `127.0.0.1:18443` with
`path: /download`, no TLS. Point a shoes socks5 inbound at it through
`type: httpupgrade` with `matching_path: /download`. Then:

```bash
curl -sS --socks5-hostname 127.0.0.1:1080 https://example.com -o /tmp/a.html -w '%{http_code}\n'
```

Expected: `200`, and sing-box's log shows the connection. Record the byte count.

- [x] **Step 2: Their client against our server**

Swap the roles: shoes serves `httpupgrade` wrapping VMess, sing-box dials it as
a client with its own socks5 inbound. Run the same `curl` through sing-box's
socks5 port.

Expected: `200`.

- [x] **Step 3: Bulk transfer, both directions**

Through each of the two chains above, fetch a file of at least 10 MB and
compare its hash against the same file fetched directly:

```bash
curl -sS --socks5-hostname 127.0.0.1:1080 <url> | sha256sum
curl -sS <url> | sha256sum
```

Expected: identical hashes. A framing or a leftover-bytes defect shows up here
and nowhere else.

- [x] **Step 4: The refusals, against a real client**

Point sing-box's `httpupgrade` client at our server with the *wrong* path.
Expected: sing-box logs an unexpected status rather than hanging, and our log
names the path that did not match.

Then, against our server, run sing-box configured with `type: ws` (a real
WebSocket client) on the same port.
Expected: our server answers `404` and sing-box reports the failure. This is the
rule the whole design turns on, checked against a peer we do not control.

- [x] **Step 5: Record what the run proved**

Add the measured results to the `CHANGELOG.md` entry from Task 8 — what was
transferred, in which direction, and what the refusal cases did. State what was
*not* covered.

```bash
git add CHANGELOG.md
git commit -m "docs: record the sing-box interoperability run"
```

- [x] **Step 6: Clean up**

```bash
rm -rf /tmp/sing-box /tmp/sing-box-bin /tmp/*.json /tmp/a.html
git status --short
```

Expected: no stray files in the working tree.
