# Control API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a feature-gated, auth-protected HTTP control API to shoes so a separate web panel can read/apply config and observe live connections, metrics, and logs — with zero footprint on iOS/Android builds.

**Architecture:** A non-default `control-api` Cargo feature gates a new `src/api/` module (hyper server) plus a `src/connection_registry.rs` that the TCP/Unix accept path feeds via a `CountingStream` wrapper. When the feature is off, the registry and wrapper are zero-sized shims that inline away, so the hot path and mobile artifacts are unchanged. shoes stays stateless; the panel owns persistence and UI.

**Tech Stack:** Rust, tokio, hyper (already a dep), serde/serde_json, dashmap, subtle, Server-Sent Events for streaming.

## Global Constraints

- **Feature is non-default:** `control-api` MUST NOT be in `default`. Mobile/FFI builds never pass it.
- **No heavy new deps:** only `serde_json` may be added (feature-gated). Reuse `hyper`, `hyper-util`, `tokio`, `serde`, `dashmap`, `subtle`, `parking_lot`, `rustls`.
- **Feature-off must compile to nothing on the hot path:** every registry/counting call site outside `src/api/` goes through a shim whose methods are `#[inline]` no-ops when the feature is off. No `#[cfg]` blocks scattered through `tcp_server.rs`.
- **Hot path touches only per-connection atomics:** the per-poll path bumps only a connection's own (uncontended) `up`/`down` atomics. Global metrics counters are updated once per connection (in `register`/`Drop`), never per poll, so there is no shared cache-line contention across connections. Event and log broadcast sends are guarded by `receiver_count() > 0` so an idle (no panel watching) server pays only an atomic load.
- **Auth on every endpoint:** constant-time bearer-token compare via `subtle`. Default bind `127.0.0.1`.
- **shoes stays stateless:** no persistence, no history, no users. Live state + event stream only.
- **Lint gate:** `cargo clippy --locked --features control-api -- -D warnings` and `cargo fmt --all -- --check` must pass. Run clippy, not just `cargo test`.
- **Rust edition 2024**, toolchain per repo (`LINT_TOOLCHAIN` 1.97 in CI).

---

## File structure

**New files:**
- `src/connection_registry.rs` — connection registry, `ConnectionInfo`, `ConnectionHandle` (RAII), `CountingStream`, global accessor, and the feature-off shim. Compiled always; body differs by `#[cfg(feature = "control-api")]`.
- `src/api/mod.rs` — server bootstrap (bind/TLS/auth), hyper service, route dispatch. `#[cfg(feature = "control-api")]`.
- `src/api/handlers.rs` — endpoint handlers. Feature-gated.
- `src/api/logsink.rs` — `BroadcastLogWriter` + ring buffer. Feature-gated.
- `src/api/config_section.rs` — the `ControlApiConfig` config type + parsing. Feature-gated.

**Modified files:**
- `Cargo.toml` — add the `control-api` feature and the gated `serde_json` dep.
- `src/lib.rs` — `pub mod connection_registry;` (always) and `#[cfg(feature = "control-api")] pub mod api;`.
- `src/tcp/tcp_server.rs` — register + wrap in `run_tcp_server`/`run_unix_server`; set target in `process_stream`.
- `src/quic_server.rs` — register + wrap the accepted QUIC stream (same pattern).
- `src/main.rs` — start the API server when configured; add `BroadcastLogWriter` to the logger writers.
- `.github/workflows/build.yml` — build the server binary with `--features control-api`.
- `.github/workflows/mobile.yml` — assert built libs export no `api::` symbols.
- `.github/workflows/test.yml` — run tests with `--features control-api`.

---

## Phase 1 — Connection registry + CountingStream

### Task 1: `CountingStream` byte-counting wrapper

**Files:**
- Create: `src/connection_registry.rs`
- Modify: `src/lib.rs` (add `pub mod connection_registry;`)
- Test: inline `#[cfg(test)] mod tests` in `src/connection_registry.rs`

**Interfaces:**
- Produces: `CountingStream<S>` with `pub fn new(inner: S, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> Self`. `up` counts bytes read from the client, `down` counts bytes written to the client. Implements `AsyncStream` (via `AsyncRead + AsyncWrite + AsyncPing`).

- [ ] **Step 1: Add the module to `src/lib.rs`**

Add near the other `pub mod` lines:
```rust
pub mod connection_registry;
```

- [ ] **Step 2: Write the failing test**

In `src/connection_registry.rs`:
```rust
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// Wraps a client stream and counts bytes in each direction. `up` is bytes read
/// from the client (client -> proxy); `down` is bytes written to the client
/// (proxy -> client). Applied once at the accept edge, so it is protocol-agnostic
/// and covers every downstream copy path without touching them.
pub struct CountingStream<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> Self {
        Self { inner, up, down }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_bytes_in_both_directions() {
        let (mut a, b) = tokio::io::duplex(64);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let mut counted = CountingStream::new(b, up.clone(), down.clone());

        // Peer writes 5 bytes; counted reads them -> up += 5.
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        assert_eq!(up.load(Ordering::Relaxed), 5);

        // counted writes 3 bytes to the peer -> down += 3.
        counted.write_all(b"abc").await.unwrap();
        assert_eq!(down.load(Ordering::Relaxed), 3);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --features control-api --lib connection_registry::tests::counts_bytes_in_both_directions`
Expected: FAIL — `CountingStream` does not implement `AsyncRead`/`AsyncWrite` yet.

- [ ] **Step 4: Implement the trait impls**

Append to `src/connection_registry.rs`:
```rust
impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let read = buf.filled().len() - before;
            if read > 0 {
                self.up.fetch_add(read as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // Forward vectored writes so wrapping the stream never silently disables a
    // vectored fast path the inner stream supports.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for CountingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for CountingStream<S> {}
```

- [ ] **Step 5: Run the test — expect PASS**

Run: `cargo test --features control-api --lib connection_registry::tests::counts_bytes_in_both_directions`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/connection_registry.rs src/lib.rs
git commit -m "feat(api): CountingStream wrapper for per-connection byte accounting"
```

---

### Task 2: The registry, `ConnectionInfo`, `ConnectionHandle`, and the feature-off shim

**Files:**
- Modify: `src/connection_registry.rs`
- Test: inline tests

**Interfaces:**
- Produces (feature on AND off — same signatures, shim bodies when off):
  - `pub fn register(client_addr: SocketAddr, inbound: &'static str) -> ConnectionHandle`
  - `ConnectionHandle::counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>)` — `(up, down)`; shim returns two fresh zeroed atomics.
  - `ConnectionHandle::set_target(&self, target: String)` — no-op in shim.
  - `pub fn snapshot() -> Vec<ConnectionSnapshot>` — empty in shim.
  - `pub fn subscribe_events() -> tokio::sync::broadcast::Receiver<ConnectionEvent>` (feature on only; used by `src/api`).
  - `pub fn metrics_counters() -> MetricsCounters` (feature on only) — O(1) read of the global counters, used by `/api/metrics`.
  - `MetricsCounters { active_connections: u64, total_connections: u64, total_up_bytes: u64, total_down_bytes: u64 }`.
  - `ConnectionSnapshot { id: u64, inbound: &'static str, protocol: String, client_addr: SocketAddr, target: Option<String>, started_unix: u64, up_bytes: u64, down_bytes: u64 }` — serde `Serialize`.
  - `ConnectionEvent { Open(ConnectionSnapshot), Close { id: u64, up_bytes: u64, down_bytes: u64, ended_unix: u64 } }`.

**Test note:** the registry and its counters are process-global, so registry
tests must not assert absolute counts under the default parallel test runner.
Serialize them behind a shared `Mutex` guard (as `socket_util`'s
`protection_tests::serialise()` does) and assert on a specific entry's fields /
relative deltas, not `snapshot().len()`.

- [ ] **Step 1: Write the failing test (feature-on behavior)**

Add to the `tests` module:
```rust
#[test]
fn register_deregister_and_snapshot() {
    // Registry state is process-global; use a unique client_addr so this test
    // matches only its own entry regardless of other tests running in parallel,
    // and assert on that entry rather than on absolute counts.
    let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();
    let handle = register(addr, "socks");
    handle.set_target("example.com:443".to_string());
    let (up, down) = handle.counters();
    up.fetch_add(10, Ordering::Relaxed);
    down.fetch_add(20, Ordering::Relaxed);

    let mine = snapshot()
        .into_iter()
        .find(|c| c.client_addr == addr)
        .expect("our connection should be in the snapshot");
    assert_eq!(mine.inbound, "socks");
    assert_eq!(mine.target.as_deref(), Some("example.com:443"));
    assert_eq!(mine.up_bytes, 10);
    assert_eq!(mine.down_bytes, 20);

    drop(handle);
    assert!(snapshot().into_iter().all(|c| c.client_addr != addr));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --features control-api --lib connection_registry::tests::register_deregister_and_snapshot`
Expected: FAIL — `register`/`snapshot` not defined.

- [ ] **Step 3: Implement the real registry (feature on)**

Add to `src/connection_registry.rs`:
```rust
use std::net::SocketAddr;

#[cfg(feature = "control-api")]
mod imp {
    use super::*;
    use std::sync::LazyLock;
    use dashmap::DashMap;
    use serde::Serialize;
    use tokio::sync::broadcast;

    static EPOCH: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    // Global counters for O(1) /metrics. These are updated per connection (in
    // register / Drop), NEVER per poll — the per-poll hot path touches only a
    // connection's own uncontended atomics, so there is no shared-cache-line
    // contention across connections. Byte totals are monotonic counters folded
    // in when a connection closes (standard Prometheus counter semantics).
    static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_UP_BYTES: AtomicU64 = AtomicU64::new(0);
    static TOTAL_DOWN_BYTES: AtomicU64 = AtomicU64::new(0);

    pub struct MetricsCounters {
        pub active_connections: u64,
        pub total_connections: u64,
        pub total_up_bytes: u64,
        pub total_down_bytes: u64,
    }

    pub fn metrics_counters() -> MetricsCounters {
        MetricsCounters {
            active_connections: ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
            total_connections: TOTAL_CONNECTIONS.load(Ordering::Relaxed),
            total_up_bytes: TOTAL_UP_BYTES.load(Ordering::Relaxed),
            total_down_bytes: TOTAL_DOWN_BYTES.load(Ordering::Relaxed),
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    struct Entry {
        inbound: &'static str,
        client_addr: SocketAddr,
        started_unix: u64,
        up: Arc<AtomicU64>,
        down: Arc<AtomicU64>,
        protocol: parking_lot::Mutex<String>,
        target: parking_lot::Mutex<Option<String>>,
    }

    struct Registry {
        entries: DashMap<u64, Arc<Entry>>,
        events: broadcast::Sender<ConnectionEvent>,
    }

    static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
        entries: DashMap::new(),
        events: broadcast::channel(1024).0,
    });

    #[derive(Clone, Serialize)]
    pub struct ConnectionSnapshot {
        pub id: u64,
        pub inbound: &'static str,
        pub protocol: String,
        pub client_addr: SocketAddr,
        pub target: Option<String>,
        pub started_unix: u64,
        pub up_bytes: u64,
        pub down_bytes: u64,
    }

    #[derive(Clone, Serialize)]
    #[serde(tag = "event", rename_all = "lowercase")]
    pub enum ConnectionEvent {
        Open(ConnectionSnapshot),
        Close { id: u64, up_bytes: u64, down_bytes: u64, ended_unix: u64 },
    }

    pub struct ConnectionHandle {
        id: u64,
        entry: Arc<Entry>,
    }

    pub fn register(client_addr: SocketAddr, inbound: &'static str) -> ConnectionHandle {
        LazyLock::force(&EPOCH);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            inbound,
            client_addr,
            started_unix: unix_now(),
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            protocol: parking_lot::Mutex::new(String::new()),
            target: parking_lot::Mutex::new(None),
        });
        REGISTRY.entries.insert(id, entry.clone());
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        // Only build + send the event if a panel is actually streaming; otherwise
        // a connection open costs just the receiver_count() atomic load.
        if REGISTRY.events.receiver_count() > 0 {
            let _ = REGISTRY.events.send(ConnectionEvent::Open(entry_snapshot(id, &entry)));
        }
        ConnectionHandle { id, entry }
    }

    fn entry_snapshot(id: u64, e: &Entry) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id,
            inbound: e.inbound,
            protocol: e.protocol.lock().clone(),
            client_addr: e.client_addr,
            target: e.target.lock().clone(),
            started_unix: e.started_unix,
            up_bytes: e.up.load(Ordering::Relaxed),
            down_bytes: e.down.load(Ordering::Relaxed),
        }
    }

    impl ConnectionHandle {
        pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
            (self.entry.up.clone(), self.entry.down.clone())
        }
        pub fn set_target(&self, target: String) {
            *self.entry.target.lock() = Some(target);
        }
        pub fn set_protocol(&self, protocol: &str) {
            *self.entry.protocol.lock() = protocol.to_string();
        }
    }

    impl Drop for ConnectionHandle {
        fn drop(&mut self) {
            REGISTRY.entries.remove(&self.id);
            let up = self.entry.up.load(Ordering::Relaxed);
            let down = self.entry.down.load(Ordering::Relaxed);
            // Fold this connection's totals into the global counters once, here.
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            TOTAL_UP_BYTES.fetch_add(up, Ordering::Relaxed);
            TOTAL_DOWN_BYTES.fetch_add(down, Ordering::Relaxed);
            if REGISTRY.events.receiver_count() > 0 {
                let _ = REGISTRY.events.send(ConnectionEvent::Close {
                    id: self.id,
                    up_bytes: up,
                    down_bytes: down,
                    ended_unix: unix_now(),
                });
            }
        }
    }

    pub fn snapshot() -> Vec<ConnectionSnapshot> {
        REGISTRY
            .entries
            .iter()
            .map(|kv| entry_snapshot(*kv.key(), kv.value()))
            .collect()
    }

    pub fn subscribe_events() -> broadcast::Receiver<ConnectionEvent> {
        REGISTRY.events.subscribe()
    }
}

#[cfg(feature = "control-api")]
pub use imp::{
    ConnectionEvent, ConnectionHandle, ConnectionSnapshot, MetricsCounters, metrics_counters,
    register, snapshot, subscribe_events,
};
```

- [ ] **Step 4: Implement the shim (feature off)**

Append:
```rust
#[cfg(not(feature = "control-api"))]
mod imp {
    use super::*;

    /// Zero-sized handle; all methods inline to nothing.
    pub struct ConnectionHandle;

    #[inline(always)]
    pub fn register(_client_addr: SocketAddr, _inbound: &'static str) -> ConnectionHandle {
        ConnectionHandle
    }

    impl ConnectionHandle {
        #[inline(always)]
        pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
            (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
        }
        #[inline(always)]
        pub fn set_target(&self, _target: String) {}
        #[inline(always)]
        pub fn set_protocol(&self, _protocol: &str) {}
    }
}

#[cfg(not(feature = "control-api"))]
pub use imp::{ConnectionHandle, register};
```

- [ ] **Step 5: Run the test — expect PASS**

Run: `cargo test --features control-api --lib connection_registry::tests::register_deregister_and_snapshot`
Expected: PASS. Then confirm the shim compiles: `cargo build --lib` (no feature) succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/connection_registry.rs
git commit -m "feat(api): connection registry with live snapshot, events, and feature-off shim"
```

---

### Task 3: Wire registration + counting into the accept path

**Files:**
- Modify: `src/tcp/tcp_server.rs:28-114` (`run_tcp_server`, `run_unix_server`), `src/tcp/tcp_server.rs:127` (`process_stream`)
- Modify: `src/quic_server.rs` (accepted-stream handoff — same pattern)

**Interfaces:**
- Consumes: `connection_registry::{register, ConnectionHandle, CountingStream}`.
- Produces: `process_stream` gains a `handle: ConnectionHandle` parameter that it uses to set the target after setup and that it drops when the connection ends.

- [ ] **Step 1: Add the `counted` cfg helper to `connection_registry.rs`**

```rust
/// Wrap a client stream so its bytes are counted, using the handle's counters.
/// Feature-off: identity (returns the stream unchanged), so there is no wrapper
/// in the hot path.
#[cfg(feature = "control-api")]
pub fn counted<S: crate::async_stream::AsyncStream>(
    stream: S,
    handle: &ConnectionHandle,
) -> CountingStream<S> {
    let (up, down) = handle.counters();
    CountingStream::new(stream, up, down)
}

#[cfg(not(feature = "control-api"))]
#[inline(always)]
pub fn counted<S: crate::async_stream::AsyncStream>(
    stream: S,
    _handle: &ConnectionHandle,
) -> S {
    stream
}
```

- [ ] **Step 2: Change `process_stream` to take a handle and set the target**

In `src/tcp/tcp_server.rs`, add the parameter and set the target from the setup result. The signature becomes:
```rust
pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    sniff: Option<SniffSettings>,
    handle: crate::connection_registry::ConnectionHandle,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
```
After `setup_result` is obtained (the `TcpServerSetupResult`), record the target and protocol before the copy loop. For the `TcpForward`/`BidirectionalUdp`/etc. variants that carry a `remote_location`, add:
```rust
if let Some(loc) = setup_result_remote_location(&setup_result) {
    handle.set_target(loc.to_string());
}
```
Add a small helper next to `process_stream`:
```rust
fn setup_result_remote_location(
    r: &TcpServerSetupResult,
) -> Option<&crate::address::NetLocation> {
    match r {
        TcpServerSetupResult::TcpForward { remote_location, .. } => Some(remote_location),
        TcpServerSetupResult::BidirectionalUdp { remote_location, .. } => Some(remote_location),
        _ => None,
    }
}
```
`handle` is moved into `process_stream` and dropped when it returns, which deregisters the connection and emits the `Close` event.

- [ ] **Step 3: Register + wrap at each accept site**

In `run_tcp_server`, replace the spawn block (lines ~60-71) with:
```rust
let cloned_resolver = resolver.clone();
let cloned_handler = server_handler.clone();
let cloned_sniff = sniff.clone();
let inbound_label: &'static str = "tcp"; // see Step 4 for a real label
tokio::spawn(async move {
    let handle = crate::connection_registry::register(addr, inbound_label);
    let stream = crate::connection_registry::counted(stream, &handle);
    if let Err(e) =
        process_stream(stream, cloned_handler, cloned_resolver, cloned_sniff, handle).await
    {
        error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
    } else {
        debug!("{}:{} finished successfully", addr.ip(), addr.port());
    }
});
```
Apply the identical change to `run_unix_server` (its `addr` is a Unix `SocketAddr`; use a synthesized `SocketAddr` of `0.0.0.0:0` for the registry `client_addr`, since Unix peers have no IP — `let client_addr = "0.0.0.0:0".parse().unwrap();`), and to the QUIC accept site in `src/quic_server.rs` (wrap the `QuicStream` the same way; QUIC streams implement `AsyncStream`).

- [ ] **Step 4: Give each inbound a stable label**

`run_tcp_server` already receives `bind_address`. Thread a `&'static str` inbound label from the server-construction site (the config already names/derives each server). If a name is not readily available, use a leaked `String` of `format!("{bind_address}")` created once per listener at startup (`Box::leak`), NOT per connection. Add a `inbound_label: &'static str` parameter to `run_tcp_server`/`run_unix_server` and pass it from their caller in the same file.

- [ ] **Step 5: Build both feature states**

Run:
```
cargo build --features control-api
cargo build
```
Expected: both compile. The no-feature build has `counted()` as identity and `register()` as a no-op returning a ZST.

- [ ] **Step 6: Integration test — a live connection appears in the snapshot**

Add `tests/` or an inline feature-gated test that starts a minimal SOCKS server via the existing test helpers, opens a proxied connection, and asserts `connection_registry::snapshot()` is non-empty with growing `up_bytes`/`down_bytes`, then empty after close. (Reuse `quic_outbound::testing`/socks test scaffolding.) If a full proxy harness is heavy here, defer this assertion to Task 9's end-to-end API test and keep Task 3 to the build check.

- [ ] **Step 7: Commit**

```bash
git add src/tcp/tcp_server.rs src/quic_server.rs src/connection_registry.rs
git commit -m "feat(api): register and byte-count connections at the accept edge"
```

---

## Phase 2 — HTTP server, auth, and request/response endpoints

### Task 4: Config section + Cargo feature

**Files:**
- Modify: `Cargo.toml`
- Create: `src/api/config_section.rs`
- Modify: `src/lib.rs` (`#[cfg(feature = "control-api")] pub mod api;`)
- Create: `src/api/mod.rs` (stub `pub mod config_section;` + `pub mod handlers; pub mod logsink;` added in later tasks)

**Interfaces:**
- Produces: `ControlApiConfig { bind: SocketAddr, token: String, config_path: PathBuf, tls: Option<TlsPaths> }`, deserialized from a `control_api` YAML section. `TlsPaths { cert: PathBuf, key: PathBuf }`.

- [ ] **Step 1: Add the feature and dep to `Cargo.toml`**

Under `[features]`:
```toml
control-api = ["dep:serde_json"]
```
Move `serde_json` from `[dev-dependencies]` to `[dependencies]` as optional:
```toml
serde_json = { version = "*", optional = true }
```
(Keep it in `[dev-dependencies]` too if other dev code needs it unconditionally, or gate those tests.)

- [ ] **Step 2: Write the failing test**

`src/api/config_section.rs`:
```rust
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlApiConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    pub token: String,
    pub config_path: PathBuf,
    #[serde(default)]
    pub tls: Option<TlsPaths>,
}

fn default_bind() -> SocketAddr {
    "127.0.0.1:9000".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_minimal_section() {
        let yaml = "token: secret\nconfig_path: /etc/shoes/config.yaml\n";
        let cfg: ControlApiConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.token, "secret");
        assert_eq!(cfg.bind, "127.0.0.1:9000".parse().unwrap());
        assert!(cfg.tls.is_none());
    }
}
```

- [ ] **Step 3: Create `src/api/mod.rs` with the module declaration**

```rust
//! Feature-gated HTTP control API for a management panel.
pub mod config_section;
```
Add to `src/lib.rs`:
```rust
#[cfg(feature = "control-api")]
pub mod api;
```

- [ ] **Step 4: Run the test — expect PASS**

Run: `cargo test --features control-api --lib api::config_section::tests::parses_minimal_section`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/api/mod.rs src/api/config_section.rs
git commit -m "feat(api): control-api feature, serde_json dep, and config section"
```

---

### Task 5: HTTP server skeleton + bearer auth + `/api/status`

**Files:**
- Create: `src/api/handlers.rs`
- Modify: `src/api/mod.rs`
- Test: inline feature-gated tests in `src/api/mod.rs`

**Interfaces:**
- Produces:
  - `pub async fn serve(config: ControlApiConfig) -> std::io::Result<()>` — binds and serves until error.
  - `fn authorized(req_headers: &hyper::HeaderMap, token: &str) -> bool` — constant-time bearer check.
  - `GET /api/status` → `200 {"version": "...", "uptime_secs": N, "connections": N}`.

- [ ] **Step 1: Write the failing test (auth + status)**

In `src/api/mod.rs` tests, start `serve` on an ephemeral port and hit it with a raw TCP request (or `hyper` client), asserting:
- no `Authorization` header → `401`.
- correct `Bearer <token>` → `200` and body contains `"version"`.
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config_section::ControlApiConfig;

    async fn spawn() -> (std::net::SocketAddr, String) {
        let token = "test-token".to_string();
        let cfg = ControlApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            token: token.clone(),
            config_path: "/nonexistent".into(),
            tls: None,
        };
        let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_on(listener, cfg));
        (addr, token)
    }

    #[tokio::test]
    async fn status_requires_auth() {
        let (addr, token) = spawn().await;
        let unauth = http_get(addr, "/api/status", None).await;
        assert_eq!(unauth.0, 401);
        let ok = http_get(addr, "/api/status", Some(&token)).await;
        assert_eq!(ok.0, 200);
        assert!(ok.1.contains("version"));
    }
}
```
(Provide small `http_get(addr, path, token) -> (u16, String)` and `http_put` test helpers using a minimal `hyper` client or raw `TcpStream` writes; keep them in the test module.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --features control-api --lib api::tests::status_requires_auth`
Expected: FAIL — `serve_on`/`serve` not defined.

- [ ] **Step 3: Implement the server, auth, and status**

`src/api/mod.rs` (using the already-present `hyper` + `hyper-util` server, `http_body_util::Full`):
```rust
pub mod config_section;
pub mod handlers;
#[cfg(feature = "control-api")]
pub mod logsink;

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use subtle::ConstantTimeEq;

use config_section::ControlApiConfig;

struct ApiState {
    token: String,
    config_path: std::path::PathBuf,
    started: std::time::Instant,
}

pub async fn serve(config: ControlApiConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    log::info!("control API listening on {}", config.bind);
    serve_on(listener, config).await
}

async fn serve_on(listener: tokio::net::TcpListener, config: ControlApiConfig) -> std::io::Result<()> {
    let state = Arc::new(ApiState {
        token: config.token,
        config_path: config.config_path,
        started: std::time::Instant::now(),
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let io = hyper_util::rt::TokioIo::new(stream);
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, state).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        });
    }
}

fn authorized(headers: &hyper::HeaderMap, token: &str) -> bool {
    let Some(v) = headers.get(hyper::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(v) = v.to_str() else { return false };
    let Some(bearer) = v.strip_prefix("Bearer ") else {
        return false;
    };
    bearer.as_bytes().ct_eq(token.as_bytes()).into()
}

fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn route(req: Request<hyper::body::Incoming>, state: Arc<ApiState>) -> Response<Full<Bytes>> {
    if !authorized(req.headers(), &state.token) {
        return json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#.to_string());
    }
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/api/status") => handlers::status(&state),
        _ => json(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.to_string()),
    }
}
```
`src/api/handlers.rs`:
```rust
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::ApiState;

pub fn status(state: &ApiState) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.started.elapsed().as_secs(),
        "connections": crate::connection_registry::snapshot().len(),
    });
    super::json(StatusCode::OK, body.to_string())
}
```
(Make `ApiState`, `json`, and `authorized` `pub(crate)` so `handlers` can use them.)

- [ ] **Step 4: Run the test — expect PASS**

Run: `cargo test --features control-api --lib api::tests::status_requires_auth`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/mod.rs src/api/handlers.rs
git commit -m "feat(api): hyper server, constant-time bearer auth, GET /api/status"
```

---

### Task 6: `/api/connections`, `/api/metrics`, and config `GET`/`PUT`

**Files:**
- Modify: `src/api/handlers.rs`, `src/api/mod.rs` (routes)
- Test: inline tests

**Interfaces:**
- Produces:
  - `GET /api/connections` → `200 [ConnectionSnapshot, ...]`.
  - `GET /api/metrics` → `200 text/plain` Prometheus exposition.
  - `GET /api/config` → `200` current managed config file as JSON.
  - `PUT /api/config` → validate + apply; `200` on success, `400 {"error": "..."}` on validation failure with the running config unchanged.

- [ ] **Step 1: Write failing tests**

Tests: `/api/connections` returns `[]` initially; `/api/metrics` returns text containing `shoes_connections_active`; `PUT /api/config` with invalid YAML returns 400; `GET`/`PUT` round-trip on a temp file (write a valid minimal config, `GET` it, `PUT` it back, assert 200 and file unchanged-or-equivalent). Use `tempfile` (already a dev-dep).

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --features control-api --lib api::tests`
Expected: FAIL — handlers/routes missing.

- [ ] **Step 3: Implement handlers**

`src/api/handlers.rs` additions:
```rust
pub fn connections(_state: &ApiState) -> Response<Full<Bytes>> {
    let snap = crate::connection_registry::snapshot();
    super::json(StatusCode::OK, serde_json::to_string(&snap).unwrap())
}

pub fn metrics(_state: &ApiState) -> Response<Full<Bytes>> {
    // O(1): read the global counters, do NOT scan the connection map. Byte
    // totals are cumulative over closed connections (a still-open connection's
    // bytes are attributed when it closes), which is correct counter semantics.
    let m = crate::connection_registry::metrics_counters();
    let body = format!(
        "# TYPE shoes_connections_active gauge\nshoes_connections_active {}\n\
         # TYPE shoes_connections_total counter\nshoes_connections_total {}\n\
         # TYPE shoes_up_bytes_total counter\nshoes_up_bytes_total {}\n\
         # TYPE shoes_down_bytes_total counter\nshoes_down_bytes_total {}\n",
        m.active_connections, m.total_connections, m.total_up_bytes, m.total_down_bytes,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn get_config(state: &ApiState) -> Response<Full<Bytes>> {
    match std::fs::read_to_string(&state.config_path) {
        Ok(text) => match serde_yaml::from_str::<serde_yaml::Value>(&text) {
            Ok(value) => super::json(StatusCode::OK, serde_json::to_string(&value).unwrap()),
            Err(e) => super::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": format!("stored config is not valid yaml: {e}")}).to_string(),
            ),
        },
        Err(e) => super::json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": format!("cannot read config: {e}")}).to_string(),
        ),
    }
}

pub async fn put_config(state: &ApiState, body: Bytes) -> Response<Full<Bytes>> {
    // 1. JSON body -> yaml text.
    let value: serde_yaml::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return super::json(StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string());
        }
    };
    let yaml_text = match serde_yaml::to_string(&value) {
        Ok(t) => t,
        Err(e) => {
            return super::json(StatusCode::BAD_REQUEST,
                serde_json::json!({"error": format!("cannot serialize: {e}")}).to_string());
        }
    };
    // 2. Validate by parsing through the real config loader against the yaml text.
    if let Err(e) = crate::config::validate_config_str(&yaml_text) {
        return super::json(StatusCode::BAD_REQUEST,
            serde_json::json!({"error": format!("invalid config: {e}")}).to_string());
    }
    // 3. Atomic write: temp file in the same dir + rename; the file watcher reloads.
    if let Err(e) = atomic_write(&state.config_path, yaml_text.as_bytes()) {
        return super::json(StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": format!("write failed: {e}")}).to_string());
    }
    super::json(StatusCode::OK, r#"{"status":"applied"}"#.to_string())
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
```
Add a thin `crate::config::validate_config_str(&str) -> Result<(), String>` in `src/config/` that parses the YAML through the existing loader/validator without applying it (reuse the existing `load_configs`/validation entry — extract the validation-only step). `tempfile` must be a non-dev dep under the feature: add `tempfile = { version = "*", optional = true }` to the `control-api` feature deps.

Wire the routes in `route()`: for `PUT /api/config`, read the body with `http_body_util::BodyExt::collect` first, then call `handlers::put_config(&state, bytes).await`.

- [ ] **Step 4: Run the tests — expect PASS**

Run: `cargo test --features control-api --lib api::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/handlers.rs src/api/mod.rs src/config/*.rs Cargo.toml Cargo.lock
git commit -m "feat(api): connections, metrics, and validated config GET/PUT"
```

---

## Phase 3 — SSE streams + log broadcast

### Task 7: `BroadcastLogWriter` + `/api/logs` SSE

**Files:**
- Create: `src/api/logsink.rs`
- Modify: `src/api/mod.rs` (route), `src/main.rs` (install the writer)
- Test: inline tests

**Interfaces:**
- Produces: `BroadcastLogWriter` (impl `crate::logging::LogWriter`), `pub fn global_log_stream() -> (Vec<String>, broadcast::Receiver<String>)` returning the ring-buffer replay plus a live receiver. `GET /api/logs` → SSE stream (`text/event-stream`).

- [ ] **Step 1: Write the failing test**

Assert that pushing a formatted record through `BroadcastLogWriter` makes it appear on a subscriber and in the ring buffer:
```rust
#[test]
fn broadcast_log_writer_delivers() {
    let (writer, _) = super::install_for_test();
    let (replay_before, mut rx) = super::global_log_stream();
    assert!(replay_before.is_empty());
    // Simulate a formatted line.
    writer.emit("[t INFO x] hello");
    let (replay_after, _) = super::global_log_stream();
    assert!(replay_after.iter().any(|l| l.contains("hello")));
    assert!(rx.try_recv().unwrap().contains("hello"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --features control-api --lib api::logsink::tests::broadcast_log_writer_delivers`
Expected: FAIL.

- [ ] **Step 3: Implement the sink**

`src/api/logsink.rs`:
```rust
use std::collections::VecDeque;
use std::sync::LazyLock;

use log::Record;
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::logging::LogWriter;

const RING_CAPACITY: usize = 500;

struct Shared {
    ring: Mutex<VecDeque<String>>,
    tx: broadcast::Sender<String>,
}

static SHARED: LazyLock<Shared> = LazyLock::new(|| Shared {
    ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
    tx: broadcast::channel(1024).0,
});

pub struct BroadcastLogWriter;

impl BroadcastLogWriter {
    pub fn new() -> Self {
        LazyLock::force(&SHARED);
        BroadcastLogWriter
    }
    pub fn emit(&self, line: &str) {
        {
            let mut ring = SHARED.ring.lock();
            if ring.len() == RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(line.to_string());
        }
        // Only pay for the broadcast (and its second allocation) when a panel is
        // actually streaming logs; otherwise this is just the ring push above.
        if SHARED.tx.receiver_count() > 0 {
            let _ = SHARED.tx.send(line.to_string());
        }
    }
}

impl LogWriter for BroadcastLogWriter {
    fn write_log(&self, _record: &Record, formatted: &str) {
        self.emit(formatted);
    }
    fn flush(&self) {}
}

/// Ring-buffer replay plus a live receiver. New SSE clients replay then tail.
pub fn global_log_stream() -> (Vec<String>, broadcast::Receiver<String>) {
    let replay = SHARED.ring.lock().iter().cloned().collect();
    (replay, SHARED.tx.subscribe())
}
```

- [ ] **Step 4: SSE endpoint**

Because SSE is a long-lived streaming body, use `hyper`'s streaming body (`http_body_util::StreamBody` + `futures::stream`). Add to `mod.rs`:
```rust
// GET /api/logs and /api/events return text/event-stream bodies built from a
// broadcast receiver. Lagged receivers get a "data: {\"lag\":N}\n\n" marker
// rather than backpressure; the loop continues.
```
Provide `sse_response(stream)` that maps each `String` message to `Bytes::from(format!("data: {msg}\n\n"))`. Route `GET /api/logs`: replay the ring buffer first, then stream live lines. Route wiring returns a `Response<BoxBody>`, so change the handler return type to a boxed body (`http_body_util::combinators::BoxBody<Bytes, Infallible>`) used uniformly by all handlers (wrap the `Full` responses with `.boxed()`).

- [ ] **Step 5: Install the writer in `main.rs`**

Where `main.rs` builds the `Vec<Box<dyn LogWriter>>` for `init_multi_logger`, add (feature-gated) the broadcast writer when a `control_api` section is configured:
```rust
#[cfg(feature = "control-api")]
if control_api_configured {
    writers.push(Box::new(crate::api::logsink::BroadcastLogWriter::new()));
}
```

- [ ] **Step 6: Run tests — expect PASS**

Run: `cargo test --features control-api --lib api::logsink`
Expected: PASS. Add a `install_for_test()` helper returning a `BroadcastLogWriter` bound to the same `SHARED`.

- [ ] **Step 7: Commit**

```bash
git add src/api/logsink.rs src/api/mod.rs src/main.rs
git commit -m "feat(api): broadcast log sink and GET /api/logs SSE"
```

---

### Task 8: `/api/events` SSE (connection open/close + metric ticks)

**Files:**
- Modify: `src/api/mod.rs`, `src/api/handlers.rs`
- Test: inline tests

**Interfaces:**
- Consumes: `connection_registry::subscribe_events()`.
- Produces: `GET /api/events` → SSE of `ConnectionEvent` JSON, plus a periodic `{"event":"metrics", ...}` tick every 5s.

- [ ] **Step 1: Write the failing test**

Start `serve`, open an SSE client to `/api/events`, then register a connection via `connection_registry::register(...)` and assert an `"open"` event arrives; drop the handle and assert a `"close"` event arrives.

- [ ] **Step 2: Run to verify it fails, then implement**

Implement the route: subscribe to events, and `tokio::select!` between the events receiver and a 5s `tokio::time::interval` that emits a metrics-snapshot event. Serialize each `ConnectionEvent` with `serde_json::to_string` into an SSE `data:` frame. Reuse `sse_response` from Task 7.

- [ ] **Step 3: Run test — expect PASS**

Run: `cargo test --features control-api --lib api::tests::events_stream`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/api/mod.rs src/api/handlers.rs
git commit -m "feat(api): GET /api/events SSE for connection and metric events"
```

---

## Phase 4 — Startup wiring, build/CI, and end-to-end test

### Task 9: Start the API from `main.rs` + end-to-end test

**Files:**
- Modify: `src/main.rs`
- Test: `tests/control_api.rs` (feature-gated integration test)

**Interfaces:**
- Consumes: `api::serve`, `api::config_section::ControlApiConfig`.

- [ ] **Step 1: Parse the `control_api` section and spawn the server**

In `main.rs`, after configs are loaded and before/alongside the server loop, if a `control_api` section is present (feature-gated), spawn `tokio::spawn(api::serve(cfg))` once. It runs for the process lifetime, independent of config reloads (the panel keeps talking to it across reloads).

- [ ] **Step 2: Write the end-to-end test**

`tests/control_api.rs` (only compiled with the feature): start shoes' API `serve` on an ephemeral port pointed at a temp config file; assert `GET /api/status` 200, `PUT` an invalid config → 400 and the file is unchanged, `PUT` a valid config → 200 and the file now contains it, `GET /api/connections` → `[]`.

- [ ] **Step 3: Run — expect PASS**

Run: `cargo test --features control-api --test control_api`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs tests/control_api.rs
git commit -m "feat(api): start the control API from main and add an end-to-end test"
```

---

### Task 10: CI wiring + the mobile symbol guard

**Files:**
- Modify: `.github/workflows/build.yml`, `.github/workflows/test.yml`, `.github/workflows/mobile.yml`

- [ ] **Step 1: Build the server binary with the feature**

In `build.yml`, change the two build steps to add `--features control-api`:
```yaml
run: cargo build --release --locked --features control-api --target ${{ matrix.target }}
run: cross build --release --locked --features control-api --target ${{ matrix.target }}
```

- [ ] **Step 2: Run tests with the feature**

In `test.yml`, add a step:
```yaml
- name: Run tests with the control API enabled
  run: cargo test --locked --features control-api
```

- [ ] **Step 3: Assert mobile builds exclude the API**

In `mobile.yml`, after the Android/iOS build, add a step that greps the built artifact for control-plane symbols and fails if present:
```yaml
- name: Assert control API is not compiled into the mobile library
  run: |
    set -euo pipefail
    lib=output/android/... # the .so path; iOS uses the .a
    if nm "$lib" 2>/dev/null | grep -q 'control_api\|api::serve'; then
      echo "control-api symbols leaked into the mobile library"; exit 1
    fi
    echo "OK: no control-api symbols"
```
(Adjust the symbol pattern to what `nm`/`strings` actually shows for this crate; verify locally by building both feature states and diffing `nm` output.)

- [ ] **Step 4: Lint gate locally before pushing**

Run:
```
cargo fmt --all -- --check
cargo clippy --locked --features control-api -- -D warnings
cargo clippy --locked -- -D warnings
```
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/build.yml .github/workflows/test.yml .github/workflows/mobile.yml
git commit -m "ci: build server binary with control-api and guard mobile builds against it"
```

---

## Self-review notes (addressed)

- **Spec coverage:** feature gate (Task 4/10), module layout (Tasks 1–8), API surface — status (5), connections/metrics/config (6), logs (7), events (8) — registry + counting wrapper (1–3), logs seam (7), config apply via validate + atomic-write + existing watcher (6/9), security/auth (5), build/CI + symbol guard (10), tests throughout. TUN is explicitly out of scope (spec Known limits) — not wired in Task 3.
- **Refinement over spec:** `GET/PUT /api/config` operates on **one managed config file** (`config_path` in the section), not the merged in-memory set, because `main.rs` loads a *list* of files; this round-trips safely. Recorded here and in the config section.
- **Open items for the implementer to resolve against live code:** the exact inbound-label source (Task 3 Step 4), the precise `nm` symbol pattern for the mobile guard (Task 10 Step 3), and extracting a `validate_config_str` entry point from the existing loader (Task 6 Step 3). Each is called out inline rather than left implicit.
