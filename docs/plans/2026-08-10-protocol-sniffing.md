# Protocol sniffing implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the destination hostname from the first bytes of a TCP
connection, so domain rules and rule-sets keep matching when the client only
gave us an IP address.

**Architecture:** Sniffers are pure functions over a byte slice returning
`Found` / `NeedMore` / `NotThisOne`. A peek loop reads into a buffer until one
of them succeeds or a deadline passes, and hands back every byte it read so the
caller can replay them upstream. The recovered name is judged as
`ResolvedLocation::with_resolved(name, original_addr)`, which makes domain
rules, CIDR masks and direct dialling all fall out of code that already exists.

**Tech Stack:** Rust, tokio, serde. No new dependencies.

**Spec:** [docs/specs/2026-08-10-protocol-sniffing.md](../specs/2026-08-10-protocol-sniffing.md)

---

## File structure

Created:

- `src/sniff/mod.rs` — `SniffedProtocol`, `Sniffed`, `SniffOutcome`,
  `SniffSettings`, `normalize_host`, `sniff_target`, `judged_location`.
- `src/sniff/tls.rs` — ClientHello SNI over a slice.
- `src/sniff/http.rs` — HTTP/1.x request line and `Host` header over a slice.
- `src/sniff/peek.rs` — the bounded read loop, `PeekResult`.
- `src/config/types/sniff.rs` — `SniffConfig` and its bool-or-map deserializer.
- `src/tcp/tcp_forward.rs` — the `TcpForward` handling shared by the TCP and
  QUIC servers, and the end-to-end tests that drive it over real sockets.
- `examples/sniff.yaml` — worked example.

Modified:

- `src/tun/mod.rs` — `early_data` fix, then the sniff hook.
- `src/tcp/tcp_server.rs` — `TcpForward` arm moved out; sniff settings threaded.
- `src/quic_server.rs` — same arm removed, calls the shared function.
- `src/config/types/server.rs`, `src/config/types/tun.rs` — the `sniff` field.
- `src/config/types/mod.rs` — module and re-export.
- `src/config/validate.rs` — `validate_sniff_config`.
- `src/lib.rs`, `src/main.rs` — `mod sniff;`.
- `CONFIG.md`, `README.md`, `ROADMAP.md`, `.github/workflows/build.yml`.

---

### Task 1: Fix the dropped `early_data` in the TUN path

`src/tun/mod.rs` takes `setup_result.client_stream` and discards
`setup_result.early_data`. The inbound path writes it to the client
(`src/tcp/tcp_server.rs:307`); the TUN path silently loses it. This is fixed
first, on its own, because the next task rewrites the same function.

**Files:**
- Modify: `src/tun/mod.rs:213-278`
- Test: `src/tun/mod.rs` (new `#[cfg(test)] mod tests`)

- [ ] **Step 1: Make `handle_tcp_connection` generic so it can be driven by a test**

In `src/tun/mod.rs`, change the signature and the call site. Replace:

```rust
async fn handle_tcp_connection(
    connection: tcp_conn::TcpConnection,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
```

with:

```rust
async fn handle_tcp_connection<S>(
    connection: S,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
```

The call site at `src/tun/mod.rs:136` passes `new_conn.connection`, which is a
`tcp_conn::TcpConnection` and satisfies the bound; it does not change.

- [ ] **Step 2: Write the failing test**

Add at the end of `src/tun/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;

    use crate::address::{Address, NetLocation, NetLocationMask};
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::config::{
        ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection,
    };
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::chain_builder::build_client_chain_group;

    use super::*;

    /// A local stream that reports EOF on read and records everything written.
    /// Stands in for the smoltcp-backed TUN connection.
    struct RecordingStream {
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(())) // EOF
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A SOCKS5 server that answers the handshake and then sends the success
    /// reply and some payload in a single write, which is what makes the
    /// client handler report early data.
    async fn spawn_socks_server_with_early_data(payload: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Greeting: version, one method count, methods.
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // Request: VER CMD RSV ATYP, then an IPv4 address and port.
            let mut req = [0u8; 4];
            stream.read_exact(&mut req).await.unwrap();
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.unwrap();

            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            reply.extend_from_slice(payload);
            stream.write_all(&reply).await.unwrap();
            stream.flush().await.unwrap();

            // Hold the connection open long enough for the copy to drain.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        addr
    }

    fn selector_through_socks(
        socks_addr: SocketAddr,
        resolver: Arc<dyn Resolver>,
    ) -> Arc<ClientProxySelector> {
        let client_config = ClientConfig {
            address: NetLocation::from_ip_addr(socks_addr.ip(), socks_addr.port()),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let chain = ClientChain {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                client_config,
            ))),
        };
        let group = build_client_chain_group(NoneOrSome::One(chain), resolver);
        let rule = ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_allow(None, group),
        );
        Arc::new(ClientProxySelector::new(vec![rule]))
    }

    #[tokio::test]
    async fn tun_forwards_early_data_to_the_local_connection() {
        let socks_addr = spawn_socks_server_with_early_data(b"EARLY").await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = selector_through_socks(socks_addr, resolver.clone());

        let written = Arc::new(Mutex::new(Vec::new()));
        let local = RecordingStream {
            written: written.clone(),
        };

        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        handle_tcp_connection(local, target, selector, resolver)
            .await
            .unwrap();

        assert_eq!(
            written.lock().unwrap().as_slice(),
            b"EARLY",
            "early data from the final hop must reach the local connection"
        );
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --locked --lib tun::tests::tun_forwards_early_data -- --nocapture`

Expected: FAIL — the assertion reports an empty buffer, because `early_data` is
discarded.

- [ ] **Step 4: Fix the call site**

In `src/tun/mod.rs`, inside the `ConnectDecision::Allow` arm, replace:

```rust
                Ok(setup_result) => {
                    debug!(
                        "TCP: connected to {}, starting bidirectional copy",
                        remote_location.location()
                    );

                    let mut remote = setup_result.client_stream;
                    // Wrap the local connection with traffic counting so bytes
                    // are reported in real time, not only after the stream closes.
                    let mut counting = traffic::TrafficCountingStream::new(connection);
```

with:

```rust
                Ok(setup_result) => {
                    debug!(
                        "TCP: connected to {}, starting bidirectional copy",
                        remote_location.location()
                    );

                    let crate::tcp::tcp_handler::TcpClientSetupResult {
                        client_stream: mut remote,
                        early_data,
                    } = setup_result;

                    // Wrap the local connection with traffic counting so bytes
                    // are reported in real time, not only after the stream closes.
                    let mut counting = traffic::TrafficCountingStream::new(connection);

                    // The final hop can hand back payload it read while still
                    // completing its own handshake. Dropping it loses the first
                    // bytes the server said, which the inbound path has always
                    // forwarded (src/tcp/tcp_server.rs).
                    if let Some(data) = early_data {
                        use tokio::io::AsyncWriteExt;
                        counting.write_all(&data).await?;
                    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --locked --lib tun::tests::tun_forwards_early_data -- --nocapture`

Expected: `test result: ok. 1 passed`

- [ ] **Step 6: Check nothing else broke**

Run: `cargo test --locked --lib`

Expected: the same pass/fail counts as before this task, plus one new pass. The
three pre-existing `dns::proxy_runtime` failures are unrelated and expected on
hosts that route `10.0.0.0/8`.

- [ ] **Step 7: Commit**

```bash
git add src/tun/mod.rs
git commit -m "tun: forward early data from the final hop to the local connection"
```

---

### Task 2: Extract the shared `TcpForward` handling

`src/tcp/tcp_server.rs:150-218` and `src/quic_server.rs:135-203` are the same
block written twice. Sniffing adds a hook inside it; two copies of the hook
would diverge. This task is a pure refactor — no behaviour change.

**Files:**
- Create: `src/tcp/tcp_forward.rs`
- Modify: `src/tcp/mod.rs`, `src/tcp/tcp_server.rs`, `src/quic_server.rs`

- [ ] **Step 1: Confirm `setup_client_tcp_stream` has only these two callers**

Run: `rg -n 'setup_client_tcp_stream' --type rust src`

Expected: definition in `src/tcp/tcp_server.rs`, one call in
`src/tcp/tcp_server.rs`, one call in `src/quic_server.rs`. If there are others,
they must be updated in Step 3 as well.

- [ ] **Step 2: Create the shared module**

Create `src/tcp/tcp_forward.rs`:

```rust
//! The `TcpForward` half of connection handling, shared by the TCP and QUIC
//! servers. Both transports reach the same place once the inbound protocol has
//! been parsed: a destination, a stream carrying application data, and a proxy
//! selector to route it with.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use tokio::io::AsyncWriteExt;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::util::write_all;

/// Everything `TcpServerSetupResult::TcpForward` carries, plus the resolver.
pub struct ForwardRequest {
    pub remote_location: NetLocation,
    pub server_stream: Box<dyn AsyncStream>,
    pub server_need_initial_flush: bool,
    pub connection_success_response: Option<Box<[u8]>>,
    pub initial_remote_data: Option<Box<[u8]>>,
    pub proxy_selector: Arc<ClientProxySelector>,
    pub resolver: Arc<dyn Resolver>,
}

pub async fn forward_tcp(request: ForwardRequest) -> std::io::Result<()> {
    let ForwardRequest {
        remote_location,
        mut server_stream,
        server_need_initial_flush,
        connection_success_response,
        initial_remote_data,
        proxy_selector,
        resolver,
    } = request;

    let judged: ResolvedLocation = remote_location.clone().into();

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(&mut server_stream, proxy_selector, resolver, judged),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    if let Some(data) = connection_success_response {
        write_all(&mut server_stream, &data).await?;
        // server_need_initial_flush should be set to true by the handler if
        // it's needed.
    }

    let client_need_initial_flush = match initial_remote_data {
        Some(data) => {
            write_all(&mut client_stream, &data).await?;
            true
        }
        None => false,
    };

    let copy_result = copy_bidirectional(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

/// Judge the destination and open the client side of the connection.
///
/// Takes a `ResolvedLocation` rather than a `NetLocation` so that a caller
/// which already knows the address — after sniffing, for instance — can keep
/// it attached to the name.
pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: ResolvedLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector.judge(remote_location, &resolver).await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                write_all(server_stream, &data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}
```

`shutdown()` on a `Box<dyn AsyncStream>` resolves through
`tokio::io::AsyncWriteExt`, not through `AsyncShutdownMessageExt` — that one is
for message streams and stays behind in `tcp_server.rs` for `run_udp_copy`.

- [ ] **Step 3: Register the module and delete the duplicated blocks**

In `src/tcp/mod.rs`, add:

```rust
pub mod tcp_forward;
```

In `src/tcp/tcp_server.rs`, replace the whole `TcpServerSetupResult::TcpForward`
arm (lines 151-218) with:

```rust
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            connection_success_response,
            initial_remote_data,
        } => {
            crate::tcp::tcp_forward::forward_tcp(crate::tcp::tcp_forward::ForwardRequest {
                remote_location,
                server_stream,
                server_need_initial_flush,
                connection_success_response,
                initial_remote_data,
                proxy_selector,
                resolver,
            })
            .await
        }
```

Delete `pub async fn setup_client_tcp_stream` from `src/tcp/tcp_server.rs`
(lines 287-316) — it now lives in `tcp_forward.rs`.

In `src/quic_server.rs`, replace its `TcpServerSetupResult::TcpForward` arm
(lines 136-203) with the same block, and remove the now-unused
`setup_client_tcp_stream` import.

- [ ] **Step 4: Fix imports**

Both files will now have unused imports (`copy_bidirectional`, `timeout`,
`write_all`, `TcpClientSetupResult`, `ConnectDecision` may or may not still be
used by the UDP arms). Remove exactly the ones the compiler names; do not
remove any that the remaining arms use.

- [ ] **Step 5: Build and test**

Run: `cargo clippy --locked --lib --bins -- -D warnings`

Expected: clean.

Run: `cargo test --locked --lib`

Expected: same results as at the end of Task 1. This task changes no behaviour,
so any new failure is a mistake in the extraction.

- [ ] **Step 6: Commit**

```bash
git add src/tcp/tcp_forward.rs src/tcp/mod.rs src/tcp/tcp_server.rs src/quic_server.rs
git commit -m "tcp: share the TcpForward path between the TCP and QUIC servers"
```

---

### Task 3: The sniff module skeleton

**Files:**
- Create: `src/sniff/mod.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Write the failing test**

Create `src/sniff/mod.rs`:

```rust
//! Recovering a destination hostname from the first bytes of a connection.
//!
//! Each sniffer is a pure function over a slice. It never reads, never
//! allocates beyond the name it returns, and answers one of three things:
//! it found the protocol, it needs more bytes, or this is definitely not its
//! protocol. The peek loop in [`peek`] is the only part that touches a stream.

pub mod peek;
pub mod http;
pub mod tls;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::address::{Address, NetLocation, ResolvedLocation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedProtocol {
    Tls,
    Http,
}

impl SniffedProtocol {
    pub(crate) fn sniff(self, buf: &[u8]) -> SniffOutcome {
        match self {
            SniffedProtocol::Tls => tls::sniff(buf),
            SniffedProtocol::Http => http::sniff(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    pub protocol: SniffedProtocol,
    /// `None` when the protocol was recognised but carries no name: a
    /// ClientHello without SNI, an HTTP/1.0 request without `Host`.
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcome {
    Found(Sniffed),
    /// The bytes so far are consistent with this protocol. Read more and ask
    /// again.
    NeedMore,
    /// Definitively not this protocol. Stop asking.
    NotThisOne,
}

/// Resolved sniffing settings for one listener.
#[derive(Debug, Clone)]
pub struct SniffSettings {
    pub protocols: Vec<SniffedProtocol>,
    pub timeout: Duration,
}

/// Ports where the server speaks first. Reading there learns nothing and
/// stalls the connection for the whole timeout. The list is sing-box's
/// `common/sniff/sniff.go` unchanged: SMTP, IMAP and POP3.
const SERVER_FIRST_PORTS: [u16; 7] = [25, 110, 143, 465, 587, 993, 995];

/// The address to fall back to if sniffing finds nothing, or `None` when this
/// connection should not be sniffed at all.
///
/// A destination that is already a hostname has nothing to recover.
pub fn sniff_target(location: &NetLocation) -> Option<SocketAddr> {
    if SERVER_FIRST_PORTS.contains(&location.port()) {
        return None;
    }
    match location.address() {
        Address::Ipv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), location.port())),
        Address::Ipv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), location.port())),
        Address::Hostname(_) => None,
    }
}

/// The location a sniffed connection is judged by: the recovered name, with
/// the original address kept alongside it.
///
/// Rules match the name; CIDR masks match `addr` without a DNS lookup; a
/// direct connection dials `addr`; a proxied connection sends the name upstream
/// for the exit to resolve.
pub fn judged_location(name: &str, addr: SocketAddr) -> ResolvedLocation {
    ResolvedLocation::with_resolved(
        NetLocation::new(Address::Hostname(name.to_string()), addr.port()),
        addr,
    )
}

/// A name that reaches routing and the log must be a plain hostname. Anything
/// else is discarded rather than cleaned up: a rule matching a half-sanitised
/// name is worse than no name at all.
pub(crate) fn normalize_host(raw: &[u8]) -> Option<String> {
    let raw = raw.trim_ascii();

    // A bracketed IPv6 literal is not a name and there is nothing to route on.
    if raw.first() == Some(&b'[') {
        return None;
    }

    // A hostname cannot contain a colon, so the first one starts the port.
    let host = match raw.iter().position(|&b| b == b':') {
        Some(i) => &raw[..i],
        None => raw,
    };

    let host = host.strip_suffix(b".").unwrap_or(host);

    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }

    String::from_utf8(host.to_ascii_lowercase()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn normalize_lowercases_and_strips_the_root_dot() {
        assert_eq!(normalize_host(b"Example.COM."), Some("example.com".into()));
    }

    #[test]
    fn normalize_strips_a_port() {
        assert_eq!(normalize_host(b"example.com:8443"), Some("example.com".into()));
    }

    #[test]
    fn normalize_trims_surrounding_space() {
        assert_eq!(normalize_host(b"  example.com \t"), Some("example.com".into()));
    }

    #[test]
    fn normalize_keeps_punycode() {
        assert_eq!(
            normalize_host(b"xn--80ak6aa92e.com"),
            Some("xn--80ak6aa92e.com".into())
        );
    }

    #[test]
    fn normalize_rejects_empty_and_bracketed_and_odd_bytes() {
        assert_eq!(normalize_host(b""), None);
        assert_eq!(normalize_host(b"."), None);
        assert_eq!(normalize_host(b"[::1]:443"), None);
        assert_eq!(normalize_host(b"exa mple.com"), None);
        assert_eq!(normalize_host(b"exa\nmple.com"), None);
        assert_eq!(normalize_host(&vec![b'a'; 254]), None);
    }

    #[test]
    fn sniff_target_skips_hostnames_and_server_first_ports() {
        let by_name = NetLocation::new(Address::Hostname("example.com".into()), 443);
        assert_eq!(sniff_target(&by_name), None);

        let smtp = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 25);
        assert_eq!(sniff_target(&smtp), None);

        let https = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        assert_eq!(
            sniff_target(&https),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443))
        );

        let v6 = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(
            sniff_target(&v6),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443))
        );
    }

    #[test]
    fn judged_location_keeps_the_original_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let location = judged_location("example.com", addr);
        assert_eq!(
            location.location(),
            &NetLocation::new(Address::Hostname("example.com".into()), 443)
        );
        assert_eq!(location.resolved_addr(), Some(addr));
    }
}
```

- [ ] **Step 2: Add the empty submodules so the crate compiles**

Create `src/sniff/tls.rs`:

```rust
use super::SniffOutcome;

pub fn sniff(_buf: &[u8]) -> SniffOutcome {
    SniffOutcome::NotThisOne
}
```

Create `src/sniff/http.rs`:

```rust
use super::SniffOutcome;

pub fn sniff(_buf: &[u8]) -> SniffOutcome {
    SniffOutcome::NotThisOne
}
```

Create `src/sniff/peek.rs`:

```rust
// Filled in by Task 6.
```

- [ ] **Step 3: Register the module in both crate roots**

`src/main.rs` declares its own module tree independently of `src/lib.rs`, so
both need the declaration. Add `mod sniff;` to `src/main.rs` and `pub mod
sniff;` to `src/lib.rs`, next to `rule_set`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --locked --lib sniff::tests`

Expected: `test result: ok. 6 passed`

- [ ] **Step 5: Commit**

```bash
git add src/sniff src/lib.rs src/main.rs
git commit -m "sniff: add the module skeleton and host normalisation"
```

---

### Task 4: The TLS sniffer

**Files:**
- Modify: `src/sniff/tls.rs`

- [ ] **Step 1: Write the failing tests**

Replace `src/sniff/tls.rs` with the tests only, keeping the stub `sniff`:

```rust
use super::{Sniffed, SniffOutcome, SniffedProtocol};

pub fn sniff(_buf: &[u8]) -> SniffOutcome {
    SniffOutcome::NotThisOne
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello record around an extensions block.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// A `server_name` extension carrying one host_name entry.
    fn sni_extension(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let mut entry = Vec::new();
        entry.push(0x00); // host_name
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);

        let mut data = Vec::new();
        data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry);

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&data);
        ext
    }

    fn found(name: Option<&str>) -> SniffOutcome {
        SniffOutcome::Found(Sniffed {
            protocol: SniffedProtocol::Tls,
            domain: name.map(str::to_string),
        })
    }

    #[test]
    fn finds_the_server_name() {
        let hello = client_hello(&sni_extension("Example.COM"));
        assert_eq!(sniff(&hello), found(Some("example.com")));
    }

    #[test]
    fn recognises_tls_without_sni() {
        let hello = client_hello(&[]);
        assert_eq!(sniff(&hello), found(None));
    }

    #[test]
    fn takes_the_first_host_name_entry() {
        let mut ext = sni_extension("first.example");
        ext.extend_from_slice(&sni_extension("second.example"));
        let hello = client_hello(&ext);
        assert_eq!(sniff(&hello), found(Some("first.example")));
    }

    #[test]
    fn skips_extensions_before_server_name() {
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x02, 0x04, 0x03]); // signature_algorithms
        ext.extend_from_slice(&sni_extension("example.com"));
        let hello = client_hello(&ext);
        assert_eq!(sniff(&hello), found(Some("example.com")));
    }

    #[test]
    fn needs_more_when_the_record_is_incomplete() {
        let hello = client_hello(&sni_extension("example.com"));
        for cut in [1, 3, 5, 10, hello.len() - 1] {
            assert_eq!(
                sniff(&hello[..cut]),
                SniffOutcome::NeedMore,
                "a {cut}-byte prefix should ask for more"
            );
        }
    }

    #[test]
    fn rejects_non_tls_bytes() {
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_a_handshake_that_is_not_a_client_hello() {
        let mut hello = client_hello(&[]);
        // Overwrite the handshake type: 0x02 is ServerHello.
        hello[5] = 0x02;
        assert_eq!(sniff(&hello), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_a_client_hello_fragmented_across_records() {
        let mut hello = client_hello(&sni_extension("example.com"));
        // Shrink the record so the handshake body no longer fits inside it.
        let shorter = (hello.len() - 5 - 10) as u16;
        hello[3..5].copy_from_slice(&shorter.to_be_bytes());
        hello.truncate(5 + shorter as usize);
        assert_eq!(sniff(&hello), SniffOutcome::NotThisOne);
    }

    #[test]
    fn discards_a_server_name_that_is_not_a_hostname() {
        let hello = client_hello(&sni_extension("has space"));
        assert_eq!(sniff(&hello), found(None));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --locked --lib sniff::tls`

Expected: FAIL — 8 of 9 tests fail, the stub returns `NotThisOne` for
everything.

- [ ] **Step 3: Implement the sniffer**

Replace the stub in `src/sniff/tls.rs` (keep the `mod tests` block) with:

```rust
use super::{Sniffed, SniffOutcome, SniffedProtocol, normalize_host};

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Reads big-endian fields out of a slice. Every accessor returns `None` when
/// the slice runs out, which the caller turns into "read more" — never into a
/// rejection, because a short buffer is the normal case here.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

pub fn sniff(buf: &[u8]) -> SniffOutcome {
    // `None` anywhere below means the buffer ended early, which is always
    // "read more"; a definite rejection is returned explicitly.
    parse(buf).unwrap_or(SniffOutcome::NeedMore)
}

fn found(domain: Option<String>) -> SniffOutcome {
    SniffOutcome::Found(Sniffed {
        protocol: SniffedProtocol::Tls,
        domain,
    })
}

fn parse(buf: &[u8]) -> Option<SniffOutcome> {
    let mut record = Cursor::new(buf);

    if record.u8()? != CONTENT_TYPE_HANDSHAKE {
        return Some(SniffOutcome::NotThisOne);
    }

    // The record-layer version is legacy and is 3.1 or 3.3 in practice, never
    // the negotiated version.
    let major = record.u8()?;
    let minor = record.u8()?;
    if major != 0x03 || (minor != 0x01 && minor != 0x03) {
        return Some(SniffOutcome::NotThisOne);
    }

    let record_len = record.u16()? as usize;
    let fragment = record.take(record_len)?;

    let mut handshake = Cursor::new(fragment);
    if handshake.u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Some(SniffOutcome::NotThisOne);
    }

    let body_len = handshake.u24()?;
    if body_len > handshake.remaining() {
        // The ClientHello is split across records. Reassembling the record
        // layer to chase it is out of proportion to how rarely this happens,
        // and returning NeedMore would spin until the deadline for a buffer
        // that can never satisfy the parse.
        return Some(SniffOutcome::NotThisOne);
    }
    let body = handshake.take(body_len)?;

    let mut hello = Cursor::new(body);
    hello.skip(2)?; // legacy_version
    hello.skip(32)?; // random
    let session_id_len = hello.u8()? as usize;
    hello.skip(session_id_len)?;
    let cipher_suites_len = hello.u16()? as usize;
    hello.skip(cipher_suites_len)?;
    let compression_len = hello.u8()? as usize;
    hello.skip(compression_len)?;

    // A ClientHello with no extensions block at all is legal, and has no SNI.
    if hello.remaining() == 0 {
        return Some(found(None));
    }

    let extensions_len = hello.u16()? as usize;
    let extensions = hello.take(extensions_len)?;

    // From here the whole ClientHello is in hand, so it is TLS whatever else
    // happens; a malformed extension block costs us the name, not the verdict.
    Some(found(find_server_name(extensions)))
}

fn find_server_name(extensions: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(extensions);
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16()?;
        let extension_len = cursor.u16()? as usize;
        let data = cursor.take(extension_len)?;
        if extension_type == EXTENSION_SERVER_NAME {
            return parse_server_name_list(data);
        }
    }
    None
}

fn parse_server_name_list(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.take(list_len)?;

    let mut entries = Cursor::new(list);
    while entries.remaining() > 0 {
        let name_type = entries.u8()?;
        let name_len = entries.u16()? as usize;
        let name = entries.take(name_len)?;
        if name_type == NAME_TYPE_HOST_NAME {
            return normalize_host(name);
        }
    }
    None
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked --lib sniff::tls`

Expected: `test result: ok. 9 passed`

- [ ] **Step 5: Commit**

```bash
git add src/sniff/tls.rs
git commit -m "sniff: parse the TLS ClientHello server name"
```

---

### Task 5: The HTTP sniffer

**Files:**
- Modify: `src/sniff/http.rs`

- [ ] **Step 1: Write the failing tests**

Replace `src/sniff/http.rs` with the tests only, keeping the stub:

```rust
use super::{Sniffed, SniffOutcome, SniffedProtocol};

pub fn sniff(_buf: &[u8]) -> SniffOutcome {
    SniffOutcome::NotThisOne
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(name: Option<&str>) -> SniffOutcome {
        SniffOutcome::Found(Sniffed {
            protocol: SniffedProtocol::Http,
            domain: name.map(str::to_string),
        })
    }

    #[test]
    fn finds_the_host_header() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn accepts_any_header_case() {
        let request = b"GET / HTTP/1.1\r\nhOsT:example.com\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn strips_the_port_from_the_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn reads_the_connect_target() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn prefers_the_absolute_uri_over_the_host_header() {
        let request =
            b"GET http://uri.example/path?q=1 HTTP/1.1\r\nHost: header.example\r\n\r\n";
        assert_eq!(sniff(request), found(Some("uri.example")));
    }

    #[test]
    fn recognises_http_without_a_host_header() {
        let request = b"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(sniff(request), found(None));
    }

    #[test]
    fn needs_more_while_the_request_line_is_partial() {
        for prefix in [&b""[..], &b"G"[..], &b"GET"[..], &b"GET / HTTP/1."[..]] {
            assert_eq!(sniff(prefix), SniffOutcome::NeedMore, "prefix {prefix:?}");
        }
    }

    #[test]
    fn needs_more_while_the_host_header_is_partial() {
        let request = b"GET / HTTP/1.1\r\nHost: exam";
        assert_eq!(sniff(request), SniffOutcome::NeedMore);
    }

    #[test]
    fn rejects_non_http_bytes() {
        assert_eq!(sniff(b"\x16\x03\x01\x00\x05"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_an_unknown_protocol_version() {
        assert_eq!(sniff(b"GET / HTTP/2.0\r\n\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"GET / RTSP/1.0\r\n\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_a_malformed_request_line() {
        assert_eq!(sniff(b"GET HTTP/1.1\r\n\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"GET / / HTTP/1.1\r\n\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn gives_up_on_an_endless_header_block() {
        let mut request = b"GET / HTTP/1.1\r\nX: ".to_vec();
        request.extend(std::iter::repeat(b'a').take(9000));
        assert_eq!(sniff(&request), found(None));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --locked --lib sniff::http`

Expected: FAIL — 9 of 12 fail.

- [ ] **Step 3: Implement the sniffer**

Replace the stub in `src/sniff/http.rs` (keep `mod tests`) with:

```rust
use super::{Sniffed, SniffOutcome, SniffedProtocol, normalize_host};

/// Methods, with the separating space, so that a prefix comparison also tells
/// us whether a short buffer could still become one of them.
const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"PUT ",
    b"HEAD ",
    b"POST ",
    b"PATCH ",
    b"TRACE ",
    b"DELETE ",
    b"CONNECT ",
    b"OPTIONS ",
];

/// Past this much buffered data without a complete header block, stop waiting.
/// Well above any real request head, and below the peek loop's own ceiling.
const MAX_HEADER_BYTES: usize = 8 * 1024;

enum MethodMatch {
    Full,
    Partial,
    No,
}

pub fn sniff(buf: &[u8]) -> SniffOutcome {
    match method_match(buf) {
        MethodMatch::No => return SniffOutcome::NotThisOne,
        MethodMatch::Partial => return SniffOutcome::NeedMore,
        MethodMatch::Full => {}
    }

    let line_end = match find(buf, b"\r\n") {
        Some(i) => i,
        None if buf.len() < MAX_HEADER_BYTES => return SniffOutcome::NeedMore,
        None => return SniffOutcome::NotThisOne,
    };

    let mut parts = buf[..line_end].split(|&b| b == b' ');
    let method = match parts.next() {
        Some(m) => m,
        None => return SniffOutcome::NotThisOne,
    };
    let target = match parts.next() {
        Some(t) => t,
        None => return SniffOutcome::NotThisOne,
    };
    let version = match parts.next() {
        Some(v) => v,
        None => return SniffOutcome::NotThisOne,
    };
    if parts.next().is_some() {
        return SniffOutcome::NotThisOne;
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return SniffOutcome::NotThisOne;
    }

    if method == b"CONNECT" {
        return found(normalize_host(target));
    }

    if let Some(rest) = strip_http_scheme(target) {
        let end = rest
            .iter()
            .position(|&b| b == b'/' || b == b'?' || b == b'#')
            .unwrap_or(rest.len());
        return found(normalize_host(&rest[..end]));
    }

    let headers = &buf[line_end + 2..];
    if let Some(value) = host_header(headers) {
        return found(normalize_host(value));
    }

    // No Host yet. Either the header block is finished and there is none, or
    // more is coming.
    if find(headers, b"\r\n\r\n").is_some() {
        return found(None);
    }
    if buf.len() < MAX_HEADER_BYTES {
        SniffOutcome::NeedMore
    } else {
        found(None)
    }
}

fn found(domain: Option<String>) -> SniffOutcome {
    SniffOutcome::Found(Sniffed {
        protocol: SniffedProtocol::Http,
        domain,
    })
}

fn method_match(buf: &[u8]) -> MethodMatch {
    let mut partial = false;
    for method in METHODS {
        if buf.len() >= method.len() {
            if &buf[..method.len()] == method {
                return MethodMatch::Full;
            }
        } else if method.starts_with(buf) {
            partial = true;
        }
    }
    if partial { MethodMatch::Partial } else { MethodMatch::No }
}

fn strip_http_scheme(target: &[u8]) -> Option<&[u8]> {
    for scheme in [&b"http://"[..], &b"https://"[..]] {
        if target.len() > scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Some(&target[scheme.len()..]);
        }
    }
    None
}

/// The value of the first complete `Host:` line, or `None` when there is no
/// complete one — which covers both "not sent" and "not yet arrived". The
/// caller distinguishes them by looking for the end of the header block.
fn host_header(headers: &[u8]) -> Option<&[u8]> {
    let mut rest = headers;
    loop {
        let end = find(rest, b"\r\n")?;
        let line = &rest[..end];
        if line.is_empty() {
            return None; // end of the header block
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            return Some(&line[5..]);
        }
        rest = &rest[end + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked --lib sniff::http`

Expected: `test result: ok. 12 passed`

- [ ] **Step 5: Commit**

```bash
git add src/sniff/http.rs
git commit -m "sniff: parse the HTTP/1.x request line and Host header"
```

---

### Task 6: The peek loop

**Files:**
- Modify: `src/sniff/peek.rs`

- [ ] **Step 1: Write the failing tests**

Replace `src/sniff/peek.rs` with:

```rust
use std::time::Duration;

use tokio::io::AsyncRead;

use super::{Sniffed, SniffedProtocol};

pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;

pub struct PeekResult {
    pub sniffed: Option<Sniffed>,
    pub buffered: Vec<u8>,
}

pub async fn peek_stream<S>(
    _stream: &mut S,
    _prefix: &[u8],
    _protocols: &[SniffedProtocol],
    _timeout: Duration,
    _max_bytes: usize,
) -> PeekResult
where
    S: AsyncRead + Unpin + ?Sized,
{
    PeekResult {
        sniffed: None,
        buffered: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    /// Yields the given chunks one read at a time, then either EOF or, if
    /// `stall` is set, nothing at all — the shape a connection has when the
    /// client is waiting for the server to speak first.
    struct ChunkedStream {
        chunks: VecDeque<Vec<u8>>,
        stall: bool,
    }

    impl ChunkedStream {
        fn new(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                stall: false,
            }
        }

        fn stalling(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                stall: true,
            }
        }
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.chunks.push_front(chunk[n..].to_vec());
                    }
                    Poll::Ready(Ok(()))
                }
                None if self.stall => Poll::Pending,
                None => Poll::Ready(Ok(())), // EOF
            }
        }
    }

    const TLS_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x38, 0x01, 0x00, 0x00, 0x34, 0x03, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x0a, 0x00, 0x00, 0x07, 0x65, 0x78, 0x2e, 0x63, 0x6f, 0x6d,
    ];

    #[tokio::test]
    async fn finds_the_name_in_the_prefix_without_reading() {
        let mut stream = ChunkedStream::stalling(vec![]);
        let result = peek_stream(
            &mut stream,
            TLS_HELLO,
            &[SniffedProtocol::Tls],
            Duration::from_millis(300),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert_eq!(result.sniffed.unwrap().domain.as_deref(), Some("ex.com"));
        assert_eq!(result.buffered, TLS_HELLO);
    }

    #[tokio::test]
    async fn reassembles_a_name_split_across_reads() {
        let (head, tail) = TLS_HELLO.split_at(9);
        let mut stream = ChunkedStream::new(vec![head, tail]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_millis(300),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert_eq!(result.sniffed.unwrap().domain.as_deref(), Some("ex.com"));
        assert_eq!(result.buffered, TLS_HELLO);
    }

    #[tokio::test]
    async fn returns_early_when_every_sniffer_rejects() {
        let mut stream = ChunkedStream::stalling(vec![b"SSH-2.0-OpenSSH_9.6\r\n"]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls, SniffedProtocol::Http],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, b"SSH-2.0-OpenSSH_9.6\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_what_it_read_when_the_deadline_passes() {
        let partial = &TLS_HELLO[..9];
        let mut stream = ChunkedStream::stalling(vec![partial]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_millis(300),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, partial);
    }

    #[tokio::test]
    async fn stops_at_eof() {
        let mut stream = ChunkedStream::new(vec![&TLS_HELLO[..9]]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, &TLS_HELLO[..9]);
    }

    #[tokio::test]
    async fn never_buffers_past_the_cap() {
        let filler = vec![0x16u8, 0x03, 0x01, 0xff, 0xff];
        let mut chunks: Vec<&[u8]> = Vec::new();
        for _ in 0..64 {
            chunks.push(&filler);
        }
        let mut stream = ChunkedStream::new(chunks);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_secs(30),
            32,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert!(
            result.buffered.len() <= 32,
            "buffered {} bytes, cap was 32",
            result.buffered.len()
        );
    }

    #[tokio::test]
    async fn reads_nothing_when_no_protocols_are_enabled() {
        let mut stream = ChunkedStream::stalling(vec![TLS_HELLO]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert!(result.buffered.is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --locked --lib sniff::peek`

Expected: FAIL — 5 of 7 fail; the stub buffers nothing.

- [ ] **Step 3: Implement the loop**

Replace the stub `peek_stream` in `src/sniff/peek.rs` with:

```rust
/// Ceiling on how much is buffered before sniffing gives up. Well above any
/// real ClientHello even with post-quantum key shares, and far below the
/// 65540-byte record the format allows.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;

const INITIAL_CAPACITY: usize = 1024;
const READ_CHUNK: usize = 2048;

pub struct PeekResult {
    pub sniffed: Option<Sniffed>,
    /// Everything that was read, `prefix` included. This must reach the remote
    /// unchanged whatever the outcome.
    pub buffered: Vec<u8>,
}

/// Read until a sniffer recognises the traffic, the deadline passes, the cap
/// is reached, or the peer stops talking.
///
/// This never fails. A sniff that goes wrong is not a connection that goes
/// wrong: the caller routes by address instead, and the bytes read so far are
/// handed back intact.
pub async fn peek_stream<S>(
    stream: &mut S,
    prefix: &[u8],
    protocols: &[SniffedProtocol],
    timeout: Duration,
    max_bytes: usize,
) -> PeekResult
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffered = Vec::with_capacity(INITIAL_CAPACITY.max(prefix.len()));
    buffered.extend_from_slice(prefix);

    let sniffed = tokio::time::timeout(
        timeout,
        run(stream, &mut buffered, protocols, max_bytes),
    )
    .await
    .unwrap_or(None);

    PeekResult { sniffed, buffered }
}

async fn run<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    protocols: &[SniffedProtocol],
    max_bytes: usize,
) -> Option<Sniffed>
where
    S: AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;

    let mut live: Vec<SniffedProtocol> = protocols.to_vec();

    loop {
        let mut still_live = Vec::with_capacity(live.len());
        for protocol in &live {
            match protocol.sniff(buffered) {
                SniffOutcome::Found(sniffed) => return Some(sniffed),
                SniffOutcome::NeedMore => still_live.push(*protocol),
                SniffOutcome::NotThisOne => {}
            }
        }
        live = still_live;

        // Nobody is still interested, so no amount of reading will help.
        if live.is_empty() || buffered.len() >= max_bytes {
            return None;
        }

        // Read into a fixed buffer rather than the Vec's spare capacity, so
        // the cap is exact and a cancelled read cannot leave a partly-grown
        // Vec behind.
        let mut chunk = [0u8; READ_CHUNK];
        let want = READ_CHUNK.min(max_bytes - buffered.len());
        match stream.read(&mut chunk[..want]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
        }
    }
}
```

Adjust the imports at the top of the file to:

```rust
use std::time::Duration;

use tokio::io::AsyncRead;

use super::{Sniffed, SniffOutcome, SniffedProtocol};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked --lib sniff::peek`

Expected: `test result: ok. 7 passed`

- [ ] **Step 5: Run the whole sniff module**

Run: `cargo test --locked --lib sniff::`

Expected: `test result: ok. 34 passed` (6 + 9 + 12 + 7).

- [ ] **Step 6: Commit**

```bash
git add src/sniff/peek.rs
git commit -m "sniff: add the bounded peek loop"
```

---

### Task 7: `SniffConfig` and its deserializer

**Files:**
- Create: `src/config/types/sniff.rs`
- Modify: `src/config/types/mod.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/config/types/sniff.rs`:

```rust
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::option_util::NoneOrSome;
use crate::sniff::{SniffSettings, SniffedProtocol};

fn default_sniff_timeout_ms() -> u32 {
    300
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SniffProtocolConfig {
    Tls,
    Http,
}

impl From<SniffProtocolConfig> for SniffedProtocol {
    fn from(value: SniffProtocolConfig) -> Self {
        match value {
            SniffProtocolConfig::Tls => SniffedProtocol::Tls,
            SniffProtocolConfig::Http => SniffedProtocol::Http,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SniffConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "NoneOrSome::is_unspecified")]
    pub protocols: NoneOrSome<SniffProtocolConfig>,
    pub timeout_ms: u32,
}

impl SniffConfig {
    /// The runtime view, or `None` when this listener does not sniff.
    pub fn to_settings(&self) -> Option<SniffSettings> {
        if !self.enabled {
            return None;
        }
        let protocols: Vec<SniffedProtocol> = if self.protocols.is_unspecified() {
            vec![SniffedProtocol::Tls, SniffedProtocol::Http]
        } else {
            self.protocols.iter().map(|p| (*p).into()).collect()
        };
        if protocols.is_empty() {
            return None;
        }
        Some(SniffSettings {
            protocols,
            timeout: Duration::from_millis(self.timeout_ms as u64),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SniffFields {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(alias = "protocol", default)]
    protocols: NoneOrSome<SniffProtocolConfig>,
    #[serde(default = "default_sniff_timeout_ms")]
    timeout_ms: u32,
}

impl<'de> Deserialize<'de> for SniffConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Hand-written rather than `#[serde(untagged)]`: an untagged enum
        // discards the inner error and reports "data did not match any
        // variant", which for a config file is useless. A visitor keeps
        // "unknown variant `tsl`, expected `tls` or `http`" intact.
        struct SniffVisitor;

        impl<'de> serde::de::Visitor<'de> for SniffVisitor {
            type Value = SniffConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a boolean or a sniff settings map")
            }

            fn visit_bool<E>(self, enabled: bool) -> Result<SniffConfig, E>
            where
                E: serde::de::Error,
            {
                Ok(SniffConfig {
                    enabled,
                    protocols: NoneOrSome::Unspecified,
                    timeout_ms: default_sniff_timeout_ms(),
                })
            }

            fn visit_map<M>(self, map: M) -> Result<SniffConfig, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let fields =
                    SniffFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(SniffConfig {
                    enabled: fields.enabled,
                    protocols: fields.protocols,
                    timeout_ms: fields.timeout_ms,
                })
            }
        }

        deserializer.deserialize_any(SniffVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_true_enables_both_protocols_with_the_default_timeout() {
        let config: SniffConfig = serde_yaml::from_str("true").unwrap();
        assert!(config.enabled);
        assert_eq!(config.timeout_ms, 300);

        let settings = config.to_settings().unwrap();
        assert_eq!(
            settings.protocols,
            vec![SniffedProtocol::Tls, SniffedProtocol::Http]
        );
        assert_eq!(settings.timeout, Duration::from_millis(300));
    }

    #[test]
    fn shorthand_false_disables() {
        let config: SniffConfig = serde_yaml::from_str("false").unwrap();
        assert!(!config.enabled);
        assert!(config.to_settings().is_none());
    }

    #[test]
    fn a_map_without_enabled_is_enabled() {
        let config: SniffConfig = serde_yaml::from_str("protocols: [tls]").unwrap();
        assert!(config.enabled);
        let settings = config.to_settings().unwrap();
        assert_eq!(settings.protocols, vec![SniffedProtocol::Tls]);
    }

    #[test]
    fn timeout_is_read_in_milliseconds() {
        let config: SniffConfig =
            serde_yaml::from_str("enabled: true\ntimeout_ms: 50").unwrap();
        assert_eq!(
            config.to_settings().unwrap().timeout,
            Duration::from_millis(50)
        );
    }

    #[test]
    fn a_zero_timeout_is_accepted() {
        let config: SniffConfig =
            serde_yaml::from_str("enabled: true\ntimeout_ms: 0").unwrap();
        assert_eq!(
            config.to_settings().unwrap().timeout,
            Duration::from_millis(0)
        );
    }

    #[test]
    fn an_unknown_protocol_is_rejected_by_name() {
        let error = serde_yaml::from_str::<SniffConfig>("protocols: [tsl]")
            .expect_err("tsl is not a protocol");
        let message = error.to_string();
        assert!(message.contains("tls"), "message was: {message}");
        assert!(message.contains("http"), "message was: {message}");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        serde_yaml::from_str::<SniffConfig>("enabled: true\nsniff_timeout: 5")
            .expect_err("sniff_timeout is not a field");
    }

    #[test]
    fn round_trips_through_yaml() {
        let config: SniffConfig =
            serde_yaml::from_str("enabled: true\nprotocols: [tls]\ntimeout_ms: 120").unwrap();
        let encoded = serde_yaml::to_string(&config).unwrap();
        let decoded: SniffConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(config, decoded);
    }
}
```

- [ ] **Step 2: Register the module**

In `src/config/types/mod.rs`, add `pub mod sniff;` to the module list and this
to the re-exports:

```rust
pub use sniff::{SniffConfig, SniffProtocolConfig};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test --locked --lib config::types::sniff`

Expected: `test result: ok. 8 passed`

- [ ] **Step 4: Commit**

```bash
git add src/config/types/sniff.rs src/config/types/mod.rs
git commit -m "config: add the sniff settings type"
```

---

### Task 8: Wire `sniff` into the server and TUN configs

**Files:**
- Modify: `src/config/types/server.rs:162-186`, `src/config/types/tun.rs:52`,
  `src/config/validate.rs`

- [ ] **Step 1: Write the failing tests**

Add to the test module at the end of `src/config/validate.rs`:

```rust
    #[test]
    fn sniff_enabled_with_an_empty_protocol_list_is_rejected() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff:
    enabled: true
    protocols: []
"#,
        )
        .unwrap();

        let error = expect_error(configs);
        assert!(
            error.to_string().contains("protocol list is empty"),
            "message was: {error}"
        );
    }

    #[test]
    fn sniff_disabled_with_an_empty_protocol_list_is_accepted() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff:
    enabled: false
    protocols: []
"#,
        )
        .unwrap();

        create_server_configs(configs).expect("a disabled sniff block is not validated");
    }

    #[test]
    fn sniff_shorthand_parses_on_a_server() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff: true
"#,
        )
        .unwrap();

        create_server_configs(configs).expect("sniff: true should be accepted");
    }
```

`expect_error` already exists in that module from the rule-set work. If it does
not, add:

```rust
    fn expect_error(configs: Vec<Config>) -> std::io::Error {
        match create_server_configs(configs) {
            Ok(_) => panic!("expected a validation error"),
            Err(e) => e,
        }
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --locked --lib config::validate::tests::sniff`

Expected: FAIL — `unknown field 'sniff'`.

- [ ] **Step 3: Add the field to both configs**

In `src/config/types/server.rs`, inside `pub struct ServerConfig`, after the
`dns` field:

```rust
    /// Protocol sniffing for this listener. Off when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniff: Option<SniffConfig>,
```

Add `use super::sniff::SniffConfig;` to that file's imports (match the file's
existing import style).

In `src/config/types/tun.rs`, inside `pub struct TunConfig`, add the same field
and import.

- [ ] **Step 4: Add validation**

In `src/config/validate.rs`, add this function next to the other validators:

```rust
/// A sniff block that is on but can never sniff anything is a typo, not a
/// preference. Fail at load rather than quietly doing nothing at runtime.
fn validate_sniff_config(
    sniff: &Option<super::types::SniffConfig>,
    context: &str,
) -> std::io::Result<()> {
    let Some(sniff) = sniff else {
        return Ok(());
    };
    if !sniff.enabled {
        return Ok(());
    }
    if !sniff.protocols.is_unspecified() && sniff.protocols.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{context}: sniff is enabled but its protocol list is empty; \
                 drop `protocols` to sniff tls and http, or set `enabled: false`"
            ),
        ));
    }
    Ok(())
}
```

Call it from `validate_server_config`, immediately after the QUIC/TCP transport
checks:

```rust
    validate_sniff_config(
        &server_config.sniff,
        &format!("server at {}", server_config.bind_location),
    )?;
```

and from `validate_tun_config`, immediately after the ICMP check:

```rust
    validate_sniff_config(&config.sniff, "TUN")?;
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --locked --lib config::`

Expected: all pass, including the three new ones.

- [ ] **Step 6: Commit**

```bash
git add src/config/types/server.rs src/config/types/tun.rs src/config/validate.rs
git commit -m "config: accept a sniff block on servers and on the TUN"
```

---

### Task 9: Sniff in the shared TCP forward path

**Files:**
- Modify: `src/tcp/tcp_forward.rs`, `src/tcp/tcp_server.rs`,
  `src/quic_server.rs`

- [ ] **Step 1: Add the hook to `forward_tcp`**

In `src/tcp/tcp_forward.rs`, add `pub sniff: Option<SniffSettings>` to
`ForwardRequest`, import `crate::sniff::{self, SniffSettings}` and
`crate::sniff::peek::{DEFAULT_MAX_BYTES, peek_stream}`, and replace the top of
`forward_tcp` (from the destructuring down to the `setup_client_stream_future`
binding) with:

```rust
    let ForwardRequest {
        remote_location,
        mut server_stream,
        server_need_initial_flush,
        mut connection_success_response,
        initial_remote_data,
        proxy_selector,
        resolver,
        sniff,
    } = request;

    let mut initial_data: Vec<u8> = initial_remote_data
        .map(|d| d.into_vec())
        .unwrap_or_default();
    let mut judged: ResolvedLocation = remote_location.clone().into();

    if let Some(settings) = sniff.as_ref()
        && let Some(addr) = sniff::sniff_target(&remote_location)
    {
        // The success response has to go first here. A SOCKS5 client sends
        // nothing until it sees one, so sniffing before it would time out on
        // an empty buffer. The cost is telling the client the connection
        // succeeded before we know it can, which is the same trade sing-box
        // and Xray make, and it only applies to listeners that opted in.
        if let Some(data) = connection_success_response.take() {
            write_all(&mut server_stream, &data).await?;
            server_stream.flush().await?;
        }

        let result = peek_stream(
            &mut server_stream,
            &initial_data,
            &settings.protocols,
            settings.timeout,
            DEFAULT_MAX_BYTES,
        )
        .await;

        initial_data = result.buffered;

        if let Some(name) = result.sniffed.as_ref().and_then(|s| s.domain.as_deref()) {
            log::debug!("sniffed {name} for {remote_location}");
            judged = sniff::judged_location(name, addr);
        }
    }

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(&mut server_stream, proxy_selector, resolver, judged),
    );
```

Then replace the two writes further down with:

```rust
    if let Some(data) = connection_success_response {
        write_all(&mut server_stream, &data).await?;
        // server_need_initial_flush should be set to true by the handler if
        // it's needed. Already written above when sniffing ran.
    }

    let client_need_initial_flush = if initial_data.is_empty() {
        false
    } else {
        write_all(&mut client_stream, &initial_data).await?;
        true
    };
```

Let-chains are already in use in this codebase (`src/tcp/tcp_server.rs:57`), so
the `if let … && let …` form above compiles on the pinned toolchain.

- [ ] **Step 2: Thread the settings through the TCP server**

In `src/tcp/tcp_server.rs`, add the parameter to the three functions that carry
a connection from the accept loop to `forward_tcp`.

`run_tcp_server`:

```rust
async fn run_tcp_server(
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    sniff: Option<SniffSettings>,
) -> std::io::Result<()> {
```

and inside its accept loop, next to the existing clones:

```rust
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        let cloned_sniff = sniff.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_stream(stream, cloned_handler, cloned_resolver, cloned_sniff).await
            {
```

`run_unix_server` takes the same extra parameter and clones it the same way.

`process_stream`:

```rust
pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    sniff: Option<SniffSettings>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
```

and its `TcpForward` arm passes it straight through:

```rust
            crate::tcp::tcp_forward::forward_tcp(crate::tcp::tcp_forward::ForwardRequest {
                remote_location,
                server_stream,
                server_need_initial_flush,
                connection_success_response,
                initial_remote_data,
                proxy_selector,
                resolver,
                sniff,
            })
            .await
```

In `start_tcp_servers`, add `sniff` to the `ServerConfig` destructuring and
resolve it once, before the accept loops are spawned:

```rust
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        sniff,
        ..
    } = config;

    // Resolved once per listener rather than per connection: the protocol list
    // and the timeout do not change while the server runs.
    let sniff = sniff.as_ref().and_then(|s| s.to_settings());
```

then pass `sniff.clone()` into each `run_tcp_server` / `run_unix_server` spawn.

Add `use crate::sniff::SniffSettings;` to the file's imports.

- [ ] **Step 3: Thread the settings through the QUIC server**

In `src/quic_server.rs`, `process_streams` gains the same parameter:

```rust
async fn process_streams(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    (send, recv): (quinn::SendStream, quinn::RecvStream),
    sniff: Option<SniffSettings>,
) -> std::io::Result<()> {
```

Its `TcpForward` arm becomes the same `ForwardRequest` block as in Step 2. At
the spawn site (`src/quic_server.rs:95-101`), clone it alongside the resolver
and the handler:

```rust
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        let cloned_sniff = sniff.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_streams(cloned_resolver, cloned_handler, stream, cloned_sniff).await
            {
                error!("Failed to process streams: {e}");
            }
        });
```

The chain is `start_quic_servers` → `start_quic_server`
(`src/quic_server.rs:28`) → `process_connection` (`src/quic_server.rs:77`) →
`process_streams`. Each of the three intermediate functions gains a
`sniff: Option<SniffSettings>` parameter and clones it where it fans out.
`start_quic_servers` already receives the whole `ServerConfig`, so it computes
the value with the same `sniff.as_ref().and_then(|s| s.to_settings())` line.
Add `use crate::sniff::SniffSettings;` to the file's imports.

- [ ] **Step 4: Build**

Run: `cargo clippy --locked --lib --bins -- -D warnings`

Expected: clean.

- [ ] **Step 5: Verify nothing regressed with sniffing off**

Run: `cargo test --locked --lib`

Expected: unchanged results. With `sniff` `None` the function must take exactly
the path it took before Task 9.

- [ ] **Step 6: Commit**

```bash
git add src/tcp/tcp_forward.rs src/tcp/tcp_server.rs src/quic_server.rs
git commit -m "tcp: sniff the destination hostname before routing"
```

---

### Task 10: Sniff in the TUN path

**Files:**
- Modify: `src/tun/mod.rs`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block created in Task 1:

```rust
    /// A local stream that offers a ClientHello once and then stalls, which is
    /// what an application looks like right after the smoltcp handshake.
    struct HelloThenStall {
        hello: Option<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for HelloThenStall {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.hello.take() {
                Some(hello) => {
                    buf.put_slice(&hello);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Ready(Ok(())), // EOF
            }
        }
    }

    impl AsyncWrite for HelloThenStall {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A ClientHello whose SNI is `ex.com`, byte-identical to the one used in
    /// the peek-loop tests.
    const TLS_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x38, 0x01, 0x00, 0x00, 0x34, 0x03, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x0a, 0x00, 0x00, 0x07, 0x65, 0x78, 0x2e, 0x63, 0x6f, 0x6d,
    ];

    /// A SOCKS5 server that records the target address the client asked for
    /// and then closes.
    async fn spawn_socks_server_recording_target(
        seen: Arc<Mutex<Vec<u8>>>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // VER CMD RSV ATYP
            let mut req = [0u8; 4];
            stream.read_exact(&mut req).await.unwrap();
            let address = match req[3] {
                0x01 => {
                    let mut v4 = [0u8; 4];
                    stream.read_exact(&mut v4).await.unwrap();
                    v4.to_vec()
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut name = vec![0u8; len[0] as usize];
                    stream.read_exact(&mut name).await.unwrap();
                    name
                }
                other => panic!("unexpected address type {other}"),
            };
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            *seen.lock().unwrap() = address;

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        addr
    }

    #[tokio::test]
    async fn tun_sniffs_the_sni_and_sends_the_name_upstream() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let socks_addr = spawn_socks_server_recording_target(seen.clone()).await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = selector_through_socks(socks_addr, resolver.clone());

        let local = HelloThenStall {
            hello: Some(TLS_HELLO.to_vec()),
            written: Arc::new(Mutex::new(Vec::new())),
        };

        let target = NetLocation::new(
            crate::address::Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        let settings = crate::sniff::SniffSettings {
            protocols: vec![crate::sniff::SniffedProtocol::Tls],
            timeout: std::time::Duration::from_millis(300),
        };

        handle_tcp_connection(local, target, selector, resolver, Some(&settings))
            .await
            .unwrap();

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            b"ex.com",
            "the sniffed name should be the address sent to the proxy"
        );
    }
```

Update the Task 1 test's call to pass `None` for the new parameter.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --locked --lib tun::tests`

Expected: FAIL — the signature does not take a fifth argument.

- [ ] **Step 3: Add the hook**

In `src/tun/mod.rs`, extend the signature:

```rust
async fn handle_tcp_connection<S>(
    connection: S,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    sniff: Option<&crate::sniff::SniffSettings>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut connection = connection;
    let mut sniffed_prefix: Vec<u8> = Vec::new();
    let mut judged: crate::address::ResolvedLocation = target.clone().into();

    if let Some(settings) = sniff
        && let Some(addr) = crate::sniff::sniff_target(&target)
    {
        let result = crate::sniff::peek::peek_stream(
            &mut connection,
            &[],
            &settings.protocols,
            settings.timeout,
            crate::sniff::peek::DEFAULT_MAX_BYTES,
        )
        .await;
        sniffed_prefix = result.buffered;
        if let Some(name) = result.sniffed.as_ref().and_then(|s| s.domain.as_deref()) {
            debug!("sniffed {name} for {target}");
            judged = crate::sniff::judged_location(name, addr);
        }
    }

    let decision = proxy_selector.judge(judged, &resolver).await?;
```

In the `Allow` arm, after the `early_data` write added in Task 1 and before
`copy_bidirectional`:

```rust
                    if !sniffed_prefix.is_empty() {
                        use tokio::io::AsyncWriteExt;
                        remote.write_all(&sniffed_prefix).await?;
                        remote.flush().await?;
                    }
```

- [ ] **Step 4: Thread the settings from the config**

In `run_tun_server`, add a `sniff: Option<SniffSettings>` parameter, clone it
into each spawned connection task, and pass `sniff.as_ref()`.

In `run_tun_from_config`, compute it before the call:

```rust
    let sniff = config.sniff.as_ref().and_then(|s| s.to_settings());
```

and pass it to `run_tun_server`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --locked --lib tun::tests`

Expected: `test result: ok. 2 passed`

- [ ] **Step 6: Build clean**

Run: `cargo clippy --locked --lib --bins -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/tun/mod.rs
git commit -m "tun: sniff the destination hostname before routing"
```

---

### Task 11: End-to-end tests over real sockets

Two things need proving on the real path rather than in isolation. First, that
whatever the sniff outcome, the remote receives exactly what the client sent —
a lost or duplicated byte here never surfaces as an error. Second, that the
recovered name is what routing actually matched, and that the success response
really does go out before sniffing starts.

These live inside `src/tcp/tcp_forward.rs` rather than in `tests/`, because
`src/lib.rs` keeps `address`, `client_proxy_selector`, `tcp` and `option_util`
private. Widening five modules to `pub` for a test would be a worse trade than
keeping the test in the crate.

**Files:**
- Modify: `src/tcp/tcp_forward.rs`

- [ ] **Step 1: Write the tests**

Append to `src/tcp/tcp_forward.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::address::{Address, NetLocation, NetLocationMask};
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::config::{ClientChain, ClientChainHop, ClientConfig, ConfigSelection};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::sniff::{SniffSettings, SniffedProtocol};
    use crate::tcp::chain_builder::build_client_chain_group;

    use super::*;

    /// A ClientHello whose SNI is `ex.com`, byte-identical to the one the
    /// peek-loop tests use.
    const TLS_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x38, 0x01, 0x00, 0x00, 0x34, 0x03, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x0a, 0x00, 0x00, 0x07, 0x65, 0x78, 0x2e, 0x63, 0x6f, 0x6d,
    ];

    /// Accepts one connection, reads it to EOF and reports everything it got.
    async fn spawn_recorder() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received).await;
            let _ = tx.send(received);
        });

        (addr, rx)
    }

    fn direct_group(resolver: Arc<dyn Resolver>) -> crate::client_proxy_chain::ClientChainGroup {
        let chain = ClientChain {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
        };
        build_client_chain_group(NoneOrSome::One(chain), resolver)
    }

    fn allow_everything(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
        let rule = ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_allow(None, direct_group(resolver)),
        );
        Arc::new(ClientProxySelector::new(vec![rule]))
    }

    struct Outcome {
        upstream_received: Vec<u8>,
        client_received: Vec<u8>,
    }

    /// Runs one connection through `forward_tcp` and returns what each side saw.
    ///
    /// `payload` is written by the client only after it has read
    /// `expect_before_payload` bytes, which is how a SOCKS5 client behaves: it
    /// says nothing until it has the success reply.
    async fn drive(
        payload: &[u8],
        connection_success_response: Option<Box<[u8]>>,
        sniff: Option<SniffSettings>,
        selector: Option<Arc<ClientProxySelector>>,
        upstream: Option<SocketAddr>,
    ) -> Outcome {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        let (upstream_addr, received) = match upstream {
            Some(addr) => (addr, None),
            None => {
                let (addr, rx) = spawn_recorder().await;
                (addr, Some(rx))
            }
        };

        let selector = selector.unwrap_or_else(|| allow_everything(resolver.clone()));

        let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound.local_addr().unwrap();

        let expect_before_payload = connection_success_response
            .as_ref()
            .map(|r| r.len())
            .unwrap_or(0);

        let server_resolver = resolver.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = inbound.accept().await.unwrap();
            forward_tcp(ForwardRequest {
                remote_location: NetLocation::new(
                    Address::Ipv4(Ipv4Addr::LOCALHOST),
                    upstream_addr.port(),
                ),
                server_stream: Box::new(stream),
                server_need_initial_flush: false,
                connection_success_response,
                initial_remote_data: None,
                proxy_selector: selector,
                resolver: server_resolver,
                sniff,
            })
            .await
        });

        let mut client = TcpStream::connect(inbound_addr).await.unwrap();

        let mut client_received = vec![0u8; expect_before_payload];
        if expect_before_payload > 0 {
            client.read_exact(&mut client_received).await.unwrap();
        }

        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        let _ = server.await.unwrap();

        let upstream_received = match received {
            Some(rx) => rx.await.unwrap(),
            None => Vec::new(),
        };

        Outcome {
            upstream_received,
            client_received,
        }
    }

    fn tls_and_http() -> Option<SniffSettings> {
        Some(SniffSettings {
            protocols: vec![SniffedProtocol::Tls, SniffedProtocol::Http],
            timeout: Duration::from_millis(300),
        })
    }

    #[tokio::test]
    async fn a_sniffed_client_hello_reaches_the_remote_unchanged() {
        let outcome = drive(TLS_HELLO, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, TLS_HELLO);
    }

    #[tokio::test]
    async fn an_http_request_reaches_the_remote_unchanged() {
        let request = b"GET / HTTP/1.1\r\nHost: ex.com\r\n\r\nbody";
        let outcome = drive(request, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, request);
    }

    #[tokio::test]
    async fn unrecognised_traffic_reaches_the_remote_unchanged() {
        let payload = b"SSH-2.0-OpenSSH_9.6\r\nand then some more bytes";
        let outcome = drive(payload, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, payload);
    }

    #[tokio::test]
    async fn traffic_that_stalls_mid_handshake_reaches_the_remote_unchanged() {
        // A prefix that keeps the TLS sniffer asking for more until the
        // deadline, so the whole timeout path is exercised.
        let partial = &TLS_HELLO[..9];
        let outcome = drive(partial, None, tls_and_http(), None, None).await;
        assert_eq!(outcome.upstream_received, partial);
    }

    #[tokio::test]
    async fn the_stream_is_unchanged_with_sniffing_off() {
        let outcome = drive(TLS_HELLO, None, None, None, None).await;
        assert_eq!(outcome.upstream_received, TLS_HELLO);
    }

    #[tokio::test]
    async fn the_success_response_goes_out_before_sniffing_starts() {
        // The client here writes nothing until it has read the response, so
        // this only completes if the response was written first. With the old
        // ordering it would deadlock until the sniff deadline and the payload
        // would arrive after.
        let response: Box<[u8]> = b"READY".to_vec().into_boxed_slice();
        let outcome = drive(TLS_HELLO, Some(response), tls_and_http(), None, None).await;

        assert_eq!(outcome.client_received, b"READY");
        assert_eq!(outcome.upstream_received, TLS_HELLO);
    }

    #[tokio::test]
    async fn routing_matches_the_sniffed_name_not_the_address() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let (upstream_addr, received) = spawn_recorder().await;

        // Only a rule naming the sniffed host allows the connection. Without
        // sniffing the destination is 127.0.0.1 and the block rule wins.
        // `matches_domain` (src/client_proxy_selector.rs:419) matches a suffix
        // at a label boundary, so the mask is the bare parent domain.
        let selector = Arc::new(ClientProxySelector::new(vec![
            ConnectRule::new(
                vec![NetLocationMask::from("com").unwrap()],
                vec![],
                ConnectAction::new_allow(None, direct_group(resolver.clone())),
            ),
            ConnectRule::new(vec![NetLocationMask::ANY], vec![], ConnectAction::new_block()),
        ]));

        let outcome = drive(
            TLS_HELLO,
            None,
            tls_and_http(),
            Some(selector),
            Some(upstream_addr),
        )
        .await;
        let _ = outcome;

        let upstream_received =
            tokio::time::timeout(Duration::from_secs(5), received)
                .await
                .expect("the domain rule should have allowed the connection")
                .unwrap();

        assert_eq!(upstream_received, TLS_HELLO);
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --locked --lib tcp::tcp_forward`

Expected: `test result: ok. 7 passed`

- [ ] **Step 3: Commit**

```bash
git add src/tcp/tcp_forward.rs
git commit -m "tcp: cover sniffing end to end over real sockets"
```

---

### Task 12: Documentation and example

**Files:**
- Create: `examples/sniff.yaml`
- Modify: `CONFIG.md`, `README.md`, `ROADMAP.md`

- [ ] **Step 1: Write the example**

Create `examples/sniff.yaml`:

```yaml
# Route by domain even when the client only gives us an address.
#
# An application with its own DoH resolver never asks our DNS, so Fake IP never
# sees the name. Sniffing recovers it from the first bytes of the connection:
# the TLS ClientHello, or the HTTP request line and Host header.
#
# The name is used for routing only. A direct connection still dials the
# original address; a proxied one sends the name upstream for the exit to
# resolve.

- address: 0.0.0.0:1080
  protocol:
    type: socks

  sniff: true
  # The long form, with the defaults spelled out:
  #   sniff:
  #     enabled: true
  #     protocols: [tls, http]
  #     timeout_ms: 300
  #
  # timeout_ms: 0 means "sniff whatever is already buffered and wait for
  # nothing" -- useful when no added latency is acceptable.

  rules:
    # Local networks never leave the machine.
    - masks: ["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"]
      action: allow
      client_chain:
        protocol:
          type: direct

    # This now matches a connection opened straight to an IP address, because
    # the ClientHello named the host.
    - masks: ["*.example.com"]
      action: allow
      client_chain:
        protocol:
          type: direct

    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:1080"
        protocol:
          type: socks
```

- [ ] **Step 2: Document it in CONFIG.md**

Add `  - [Protocol sniffing](#protocol-sniffing)` to the table of contents,
directly under the `- [Rules System](#rules-system)` entry and after the
existing `  - [Rule-sets](#rule-sets)` line. Then add this section at the end
of the Rules System chapter, after the Rule-sets section:

```markdown
### Protocol sniffing

A domain rule needs a domain. When a client hands over a bare address — an app
with its own DoH resolver, one that dials a literal IP, or a client configured
for `socks5` rather than `socks5h` — every domain rule and every rule-set
silently stops matching.

Sniffing recovers the name from the first bytes of the connection: the
`server_name` extension of a TLS ClientHello, or the request line and `Host`
header of an HTTP/1.x request. It is off by default and enabled per listener.

```yaml
- address: 0.0.0.0:1080
  protocol:
    type: socks
  sniff: true
```

The long form spells out the defaults:

```yaml
  sniff:
    enabled: true
    protocols: [tls, http]
    timeout_ms: 300
```

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` inside a `sniff:` block | Whether to sniff at all |
| `protocols` | `[tls, http]` | Which sniffers to run. An empty list with `enabled: true` is a config error |
| `timeout_ms` | `300` | How long to wait for the client's first bytes |

`timeout_ms: 0` is valid and means "sniff whatever has already been buffered
and wait for nothing". Use it when no added latency is acceptable.

The recovered name is used **for routing only**. A direct connection still
dials the original address and performs no DNS lookup; a connection routed
through a proxy sends the name upstream, so the exit node resolves it — which
is what a client using `socks5h` is asking for. CIDR masks keep matching the
real address either way.

Some connections are never sniffed:

- a destination that is already a hostname, because there is nothing to
  recover;
- ports 25, 465, 587, 143, 993, 110 and 995 — SMTP, IMAP and POP3, where the
  server speaks first, so waiting would stall the connection for the whole
  timeout and learn nothing.

Sniffing can never itself fail a connection. If nothing is recognised, if the
protocol carries no name, or if the client says nothing before the deadline,
the connection is routed by address exactly as it would have been. Successful
sniffs are logged at `debug`.

One consequence worth stating plainly: with `sniff` enabled the proxy reads the
first bytes of application payload before deciding where to route it. Those
bytes are not stored, are not logged above `debug`, live only in a
per-connection buffer capped at 16 KiB, and reach the remote unchanged. This is
why the feature is off unless you turn it on.

Also note that with sniffing enabled, protocols that send a success response —
SOCKS5 and HTTP `CONNECT` — send it **before** the upstream connection is
attempted, because the client will not send anything to sniff until it has one.
A client therefore sees the connection open and then close, rather than an
error code, when the upstream is unreachable.
```

- [ ] **Step 3: Mention it in README.md**

Add one line to the feature list next to the rule-sets line:

```markdown
- Protocol sniffing: recover the destination hostname from the TLS ClientHello or the HTTP Host header, so domain rules work on connections opened straight to an IP address
```

- [ ] **Step 4: Update ROADMAP.md**

Rewrite Tier 1 item 2 as done, in the shape item 1 already has: a link to the
spec and the plan, what shipped, and what was deferred (a QUIC sniffer, DNS
sniffing, protocol-only sniffers and a `protocol` rule matcher). Update the
comparison table row for "Protocol sniffing (SNI, Host, QUIC, DNS)" to read
`SNI and Host, TCP only`. Update the "Item 1 is done" note under the Tier 1
heading.

- [ ] **Step 5: Verify the example parses**

Run: `cargo run --locked -- --dry-run examples/sniff.yaml`

Expected: exits 0 with no error.

- [ ] **Step 6: Commit**

```bash
git add CONFIG.md README.md ROADMAP.md examples/sniff.yaml
git commit -m "docs: document protocol sniffing"
```

---

### Task 13: CI smoke test

**Files:**
- Modify: `.github/workflows/build.yml:136`

- [ ] **Step 1: Add the example to the dry-run list**

`examples/sniff.yaml` needs no external files, so it goes straight into the
existing loop. Change:

```yaml
          for cfg in socks_basic multi_hop_chain tun_vpn tun_fake_ip amneziawg_client; do
```

to:

```yaml
          for cfg in socks_basic multi_hop_chain tun_vpn tun_fake_ip amneziawg_client sniff; do
```

- [ ] **Step 2: Check the file is valid YAML**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/build.yml'))"`

Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: dry-run the sniffing example"
```

---

### Task 14: Final verification

**Files:** none

- [ ] **Step 1: Format**

Run: `cargo fmt --check`

Expected: no output.

- [ ] **Step 2: Lint**

Run: `cargo clippy --locked --lib --bins --tests -- -D warnings`

Expected: clean.

- [ ] **Step 3: Full test suite**

Run: `cargo test --locked`

Expected: everything passes except the three pre-existing
`dns::proxy_runtime::tests::test_connect_tcp_*` failures, which assume
`10.255.255.1` is a black hole and fail on hosts that route `10.0.0.0/8`.
Record the exact counts.

- [ ] **Step 4: Test with the ffi feature**

Run: `cargo test --locked --features ffi`

Expected: the same three failures and nothing new.

- [ ] **Step 5: Confirm sniffing is genuinely off by default**

Run: `rg -n 'sniff' examples/*.yaml | rg -v 'sniff.yaml'`

Expected: no output. No existing example turns it on, so no existing
deployment changes behaviour on upgrade.

- [ ] **Step 6: Measure the binary**

```bash
cargo build --release --locked
stat -c %s target/release/shoes
```

Expected: within a few kilobytes of the pre-task size. No new dependency was
added, so a large jump means something was pulled in by accident — check with
`cargo tree -e normal --depth 1`.

- [ ] **Step 7: Manual end-to-end check**

Start a listener with `sniff: true` and a rule matching `*.example.com`
directly, point `curl` at it by address rather than name, and confirm from the
debug log that the name was recovered:

```bash
RUST_LOG=debug cargo run --locked -- examples/sniff.yaml
# in another shell:
curl -v --socks5 127.0.0.1:1080 --resolve example.com:443:93.184.216.34 https://example.com/
```

Expected: a `sniffed example.com for 93.184.216.34:443` line in the log.

- [ ] **Step 8: Commit anything outstanding and report**

```bash
git status --short
```

Expected: clean. Report the test counts, the binary size delta, and the log
line from Step 7.

---

## Notes for the implementer

- `src/main.rs` declares its own module tree independently of `src/lib.rs`.
  Anything added under `src/` needs a declaration in **both**, or the binary
  target fails to build while the library target succeeds.
- `NoneOrSome::len` and several other helpers are `#[cfg(test)]`. If a
  non-test code path needs one, write the `match` locally rather than widening
  the API.
- `NoneOrSome` refuses to deserialize an empty sequence in some positions and
  round-trips badly when serialized as `[]`. Where a field can legitimately be
  empty, skip serializing it.
- `ValidatedConfigs` does not implement `Debug`, so `unwrap_err()` on
  `create_server_configs` will not compile. Use the `expect_error` helper.
- The three `dns::proxy_runtime` test failures predate this work. Do not try to
  fix them here.
