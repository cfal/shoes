# Named Outbounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every outbound a stable identifier, and report upload, download and active-connection counts per outbound through `shoes::control::stats::snapshot()`.

**Architecture:** An optional `name` on `ClientConfig` resolves during validation to a non-empty key (name, else `direct`, else the address). Each key gets an `Arc<OutboundCounters>` in a process-global registry, populated from the whole config so every configured server is listed at zero. `ClientProxyChain` carries counter handles parallel to its hop pools; at connect time it wraps the returned stream in a counting adapter holding the **exit** hop's handle.

**Tech Stack:** Rust 2024, tokio, serde/serde_yaml, `pin_project_lite`, `std::sync::atomic`.

**Spec:** `docs/superpowers/specs/2026-08-26-named-outbounds-design.md`

## Global Constraints

- **Rust toolchain is not on `PATH`.** The rustup shim is dangling — invoking `cargo` directly fails with `could not execute process 'rustc -vV'`. Every command in this plan must be run after:
  ```bash
  export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
  ```
- **`name` is optional.** Every config that exists today, including ones shipped inside released mobile apps, must keep loading unchanged.
- **A config that does not use `name` must round-trip byte-identically.** Use `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- **Direction convention at the outbound is the inverse of `src/tun/traffic.rs`.** There, a read is upload. Here, a **read is download** and a **write is upload**. Do not reuse `TrafficCountingStream`.
- **Bytes are credited to the exit hop**, never to the relay, and each connection is credited exactly once.
- **New modules must be declared in BOTH `src/lib.rs` and `src/main.rs`**, alphabetically. The two module lists are maintained separately.
- **Do not change the meaning of the three existing `StatsSnapshot` fields.**
- Commit after every task. Author must be `ayastrebov@gmail.com` (repo default `user.email` is already correct).

## File Structure

| File | Responsibility |
| --- | --- |
| `src/config/types/client.rs` (modify) | The `name` field and `ClientConfig::stats_key()` |
| `src/outbound_stats.rs` (create) | `OutboundCounters`, `OutboundStats`, the process-global registry |
| `src/outbound_counting_stream.rs` (create) | The two counting adapters, byte-level and message-level |
| `src/config/validate.rs` (modify) | Walk the config and register every outbound's key |
| `src/client_proxy_chain.rs` (modify) | Carry counter handles; wrap at the two connect points |
| `src/control/stats.rs` (modify) | Expose `outbounds` on the snapshot |
| `CONFIG.md`, `CHANGELOG.md` (modify) | Document the field |

---

### Task 1: The `name` field and its key

**Files:**
- Modify: `src/config/types/client.rs:543-571` (the `ClientConfig` struct and its `Default` impl)
- Test: `src/config/types/client.rs` (new `#[cfg(test)] mod named_outbound_tests` at end of file)

**Interfaces:**
- Consumes: nothing
- Produces: `ClientConfig::name: Option<String>`; `ClientConfig::stats_key(&self) -> std::io::Result<String>`

- [ ] **Step 1: Write the failing tests**

Append to `src/config/types/client.rs`:

```rust
#[cfg(test)]
mod named_outbound_tests {
    use super::*;

    fn parse(yaml: &str) -> ClientConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn a_name_round_trips_through_yaml() {
        let config = parse("name: Frankfurt\naddress: fra1.example:443\nprotocol:\n  type: socks\n");
        let encoded = serde_yaml::to_string(&config).unwrap();
        let decoded: ClientConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(decoded.name.as_deref(), Some("Frankfurt"));
    }

    /// A config that does not use the field must serialize exactly as it did
    /// before the field existed, because the desktop config editor
    /// re-serializes whatever it loads.
    #[test]
    fn an_absent_name_is_not_serialized() {
        let config = parse("address: fra1.example:443\nprotocol:\n  type: socks\n");
        let encoded = serde_yaml::to_string(&config).unwrap();
        assert!(!encoded.contains("name"), "unexpected name in: {encoded}");
    }

    #[test]
    fn a_name_is_the_key_when_present() {
        let config = parse("name: Frankfurt\naddress: fra1.example:443\nprotocol:\n  type: socks\n");
        assert_eq!(config.stats_key().unwrap(), "Frankfurt");
    }

    #[test]
    fn an_unnamed_outbound_is_keyed_by_its_address() {
        let config = parse("address: fra1.example:443\nprotocol:\n  type: socks\n");
        assert_eq!(config.stats_key().unwrap(), "fra1.example:443");
    }

    /// Every direct outbound carries NetLocation::UNSPECIFIED, and the default
    /// rule action is a direct chain, so an address fallback would collide them
    /// all on "0.0.0.0:0".
    #[test]
    fn a_direct_outbound_is_keyed_direct_not_by_its_empty_address() {
        let config = ClientConfig::default();
        assert!(config.protocol.is_direct());
        assert_eq!(config.stats_key().unwrap(), "direct");
    }

    /// Silently falling through to the address would be undebuggable.
    #[test]
    fn a_blank_name_is_rejected() {
        let config = parse("name: \"   \"\naddress: fra1.example:443\nprotocol:\n  type: socks\n");
        let err = config.stats_key().unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "unhelpful message: {err}"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib config::types::client::named_outbound_tests
```

Expected: compile error — `no field 'name' on type 'ClientConfig'` and `no method named 'stats_key'`.

- [ ] **Step 3: Add the field**

In `src/config/types/client.rs`, add as the first field of `ClientConfig` (before `bind_interface`):

```rust
    /// A stable, human-meaningful identifier for this outbound. Optional: an
    /// outbound without one is keyed by its address, which works but is
    /// neither stable across config edits nor meaningful to show a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
```

And in the `Default` impl, add as the first field:

```rust
            name: None,
```

- [ ] **Step 4: Add `stats_key`**

Immediately after the `Default for ClientConfig` impl block:

```rust
impl ClientConfig {
    /// The key this outbound's traffic is counted against.
    ///
    /// A name if one is set; otherwise `direct` for a direct outbound, whose
    /// address is unspecified and would otherwise collide with every other
    /// direct outbound on `0.0.0.0:0`; otherwise the address.
    pub fn stats_key(&self) -> std::io::Result<String> {
        if let Some(name) = &self.name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "an outbound 'name' is empty; remove the field or give it a value",
                ));
            }
            return Ok(trimmed.to_string());
        }

        if self.protocol.is_direct() && self.address.is_unspecified() {
            return Ok("direct".to_string());
        }

        Ok(self.address.to_string())
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test --lib config::types::client::named_outbound_tests
```

Expected: 6 passed.

- [ ] **Step 6: Run the whole config suite for regressions**

```bash
cargo test --lib config
```

Expected: all pass, including `groups::tests::test_example_files_load_and_validate`.

- [ ] **Step 7: Commit**

```bash
git add src/config/types/client.rs
git commit -m "config: an outbound can carry a name"
```

---

### Task 2: The counter registry

**Files:**
- Create: `src/outbound_stats.rs`
- Modify: `src/lib.rs:58-107` (module list), `src/main.rs` (module list)
- Test: in `src/outbound_stats.rs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `pub struct OutboundCounters` with `add_upload(&self, u64)`, `add_download(&self, u64)`, `connection_opened(&self)`, `connection_closed(&self)`
  - `pub struct OutboundStats { pub name: String, pub upload_bytes: u64, pub download_bytes: u64, pub active_connections: usize }`
  - `pub fn register(key: &str, address: &str) -> std::io::Result<Arc<OutboundCounters>>`
  - `pub fn reset()`
  - `pub fn unattributed() -> Arc<OutboundCounters>`
  - `pub fn snapshot_all() -> Vec<OutboundStats>`
  - `#[cfg(test)] pub fn reset_for_test()` and `pub static REGISTRY_TEST_LOCK: Mutex<()>`

**Why conflict detection lives here:** the alternative is threading a
`HashMap<String, String>` of seen keys through `expand_selection` and the group
resolver, which are separate call paths. Storing the first address alongside
the counters makes `register` self-checking and callable from anywhere.

- [ ] **Step 1: Write the failing tests**

Create `src/outbound_stats.rs` containing ONLY this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registered_outbound_starts_at_zero() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        register("Frankfurt", "fra1.example:443").unwrap();
        let all = snapshot_all();

        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Frankfurt");
        assert_eq!(all[0].upload_bytes, 0);
        assert_eq!(all[0].download_bytes, 0);
        assert_eq!(all[0].active_connections, 0);
    }

    /// Group expansion clones a ClientConfig into every group that references
    /// it, so the same server arrives many times and must share one counter.
    #[test]
    fn registering_the_same_key_twice_returns_the_same_counter() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let a = register("Frankfurt", "fra1.example:443").unwrap();
        let b = register("Frankfurt", "fra1.example:443").unwrap();
        a.add_upload(100);
        b.add_upload(50);

        let all = snapshot_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].upload_bytes, 150);
    }

    /// Asymmetric values: equal ones would pass with the two transposed.
    #[test]
    fn upload_and_download_are_not_transposed() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let c = register("Frankfurt", "fra1.example:443").unwrap();
        c.add_upload(7);
        c.add_download(9999);

        let all = snapshot_all();
        assert_eq!(all[0].upload_bytes, 7);
        assert_eq!(all[0].download_bytes, 9999);
    }

    #[test]
    fn the_connection_count_rises_and_falls() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let c = register("Frankfurt", "fra1.example:443").unwrap();
        c.connection_opened();
        c.connection_opened();
        assert_eq!(snapshot_all()[0].active_connections, 2);

        c.connection_closed();
        assert_eq!(snapshot_all()[0].active_connections, 1);
    }

    /// An unmatched close must floor rather than wrap, as the equivalent
    /// counter in tun::traffic does.
    #[test]
    fn an_unmatched_close_floors_at_zero() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let c = register("Frankfurt", "fra1.example:443").unwrap();
        c.connection_closed();
        assert_eq!(snapshot_all()[0].active_connections, 0);
    }

    /// A GUI redrawing on a timer must not see its own rows reorder.
    #[test]
    fn the_snapshot_is_sorted_by_name() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        register("zurich", "zrh:443").unwrap();
        register("amsterdam", "ams:443").unwrap();
        register("frankfurt", "fra:443").unwrap();

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert_eq!(names, vec!["amsterdam", "frankfurt", "zurich"]);
    }

    /// A name must identify one server. Addresses are compared rather than
    /// whole configs, so one server reachable with two sets of credentials
    /// stays legal.
    #[test]
    fn one_key_on_two_addresses_is_rejected() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        register("Frankfurt", "fra1.example:443").unwrap();
        let err = register("Frankfurt", "fra2.example:443").unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Frankfurt"), "must name the name: {msg}");
        assert!(msg.contains("fra1.example:443"), "must name both: {msg}");
        assert!(msg.contains("fra2.example:443"), "must name both: {msg}");
    }

    /// A reload must replace the list, not accumulate servers from the config
    /// that was just discarded — and stale entries would also produce false
    /// address conflicts.
    #[test]
    fn reset_clears_a_previous_load() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        register("Frankfurt", "fra1.example:443").unwrap();
        reset();
        register("Frankfurt", "fra2.example:443").unwrap();

        assert_eq!(snapshot_all().len(), 1);
    }

    /// Traffic through a chain built without counters must not panic or be
    /// attributed to a real server.
    #[test]
    fn unattributed_traffic_is_not_listed() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        unattributed().add_upload(500);
        assert!(snapshot_all().is_empty());
    }
}
```

- [ ] **Step 2: Declare the module and run the tests to verify they fail**

Add `mod outbound_stats;` to `src/lib.rs` after `mod option_util;`, and `mod outbound_stats;` to `src/main.rs` in the same alphabetical position.

```bash
cargo test --lib outbound_stats
```

Expected: compile errors — `cannot find function 'register'`, `cannot find function 'snapshot_all'`, etc.

- [ ] **Step 3: Write the implementation**

Prepend to `src/outbound_stats.rs`, above the test module:

```rust
//! Per-outbound counters, keyed by the name an outbound carries in the config.
//!
//! Process-global rather than per-service, for the same reason
//! `crate::tun::traffic` is: `crate::control::start` documents one service per
//! process, and `crate::control::stats::snapshot` is a free function with no
//! service handle to thread a registry through.
//!
//! The registry is populated during config validation rather than on first
//! use, so a host lists every configured server at zero before any of them has
//! carried a byte. An empty list on a fresh connection would read as "no
//! servers", which is wrong.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// The counters for one outbound.
#[derive(Debug, Default)]
pub struct OutboundCounters {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    active_connections: AtomicUsize,
}

impl OutboundCounters {
    /// Bytes sent towards the outbound.
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Bytes received from the outbound.
    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Floors at zero: cleanup paths can run more than once for one stream,
    /// and a wrapped count would read as billions of live connections.
    pub fn connection_closed(&self) {
        let _ = self
            .active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

/// A point-in-time reading for one outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundStats {
    pub name: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
}

/// The counters for one outbound, plus the address it was first registered
/// with — kept so a second registration under the same key can be checked
/// rather than silently merging two different servers.
struct Entry {
    counters: Arc<OutboundCounters>,
    address: String,
}

type Registry = RwLock<HashMap<String, Entry>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register an outbound and get its counters.
///
/// Idempotent for the same key and address: group expansion clones a
/// `ClientConfig` into every referencing group, so one server arrives many
/// times and all the clones must share one counter.
///
/// The same key with a *different* address is a config mistake and is
/// rejected. Addresses are compared rather than whole configs: structural
/// equality would demand `PartialEq` across `ClientProxyConfig`,
/// `Redacted<String>` and the transport types, and would reject the legitimate
/// case of one server reachable with two sets of credentials.
pub fn register(key: &str, address: &str) -> std::io::Result<Arc<OutboundCounters>> {
    if let Some(existing) = registry().read().unwrap().get(key) {
        if existing.address != address {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "two outbounds are named \"{key}\" but have different addresses \
                     ({} and {address}); a name must identify one server",
                    existing.address
                ),
            ));
        }
        return Ok(existing.counters.clone());
    }

    let mut guard = registry().write().unwrap();
    // Re-check: another thread may have inserted between the read and write.
    if let Some(existing) = guard.get(key) {
        if existing.address != address {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "two outbounds are named \"{key}\" but have different addresses \
                     ({} and {address}); a name must identify one server",
                    existing.address
                ),
            ));
        }
        return Ok(existing.counters.clone());
    }

    let counters = Arc::new(OutboundCounters::default());
    guard.insert(
        key.to_string(),
        Entry {
            counters: counters.clone(),
            address: address.to_string(),
        },
    );
    Ok(counters)
}

/// Drop every registration. Called at the start of a config load, so a reload
/// replaces the list rather than accumulating servers from the config it just
/// discarded — stale entries would also produce false address conflicts.
pub fn reset() {
    registry().write().unwrap().clear();
}

/// Counters that are never listed, for a chain built without attribution —
/// tests, and any future construction path that has no config behind it.
/// Traffic through such a chain is counted into a void rather than being
/// credited to some arbitrary server.
pub fn unattributed() -> Arc<OutboundCounters> {
    static UNATTRIBUTED: OnceLock<Arc<OutboundCounters>> = OnceLock::new();
    UNATTRIBUTED
        .get_or_init(|| Arc::new(OutboundCounters::default()))
        .clone()
}

/// Every registered outbound, sorted by name so a host redrawing on a timer
/// does not reorder its own rows.
pub fn snapshot_all() -> Vec<OutboundStats> {
    let guard = registry().read().unwrap();
    let mut out: Vec<OutboundStats> = guard
        .iter()
        .map(|(name, entry)| OutboundStats {
            name: name.clone(),
            upload_bytes: entry.counters.upload_bytes.load(Ordering::Relaxed),
            download_bytes: entry.counters.download_bytes.load(Ordering::Relaxed),
            active_connections: entry.counters.active_connections.load(Ordering::Relaxed),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The registry is process-global, so tests that touch it must not run
/// concurrently. Take this lock first in every such test.
#[cfg(test)]
pub static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn reset_for_test() {
    reset();
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --lib outbound_stats
```

Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/outbound_stats.rs src/lib.rs src/main.rs
git commit -m "stats: a registry of per-outbound counters"
```

---

### Task 3: The counting adapters

**Files:**
- Create: `src/outbound_counting_stream.rs`
- Modify: `src/lib.rs`, `src/main.rs` (module lists)
- Test: in `src/outbound_counting_stream.rs`

**Interfaces:**
- Consumes: `crate::outbound_stats::{OutboundCounters, register, reset_for_test, REGISTRY_TEST_LOCK}`
- Produces:
  - `pub struct OutboundCountingStream<S>` with `pub fn new(inner: S, counters: Arc<OutboundCounters>) -> Self`
  - `pub struct OutboundCountingMessageStream<S>` with the same constructor shape

- [ ] **Step 1: Write the failing tests**

Create `src/outbound_counting_stream.rs` with ONLY this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, register, reset_for_test, snapshot_all};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// At the outbound a read is DOWNLOAD and a write is UPLOAD — the inverse
    /// of tun::traffic, whose stream sits on the device side. The byte counts
    /// here are deliberately different sizes, because equal ones would pass
    /// with the two transposed.
    #[tokio::test]
    async fn a_read_is_download_and_a_write_is_upload() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = register("Frankfurt", "fra1.example:443").unwrap();

        let (mut peer, local) = tokio::io::duplex(4096);
        peer.write_all(&[0u8; 9]).await.unwrap();

        let mut counting = OutboundCountingStream::new(local, counters);
        let mut buf = [0u8; 9];
        counting.read_exact(&mut buf).await.unwrap();
        counting.write_all(&[0u8; 3]).await.unwrap();
        counting.flush().await.unwrap();

        let all = snapshot_all();
        assert_eq!(all[0].download_bytes, 9, "a read must count as download");
        assert_eq!(all[0].upload_bytes, 3, "a write must count as upload");
    }

    #[tokio::test]
    async fn a_connection_is_counted_for_its_lifetime() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = register("Frankfurt", "fra1.example:443").unwrap();

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingStream::new(local, counters);
        assert_eq!(snapshot_all()[0].active_connections, 1);

        drop(counting);
        assert_eq!(snapshot_all()[0].active_connections, 0);
    }

    /// A datagram session is not a connection: active_connections counts TCP
    /// today, and folding datagrams in would change what a host is reading.
    #[tokio::test]
    async fn a_message_stream_counts_bytes_but_not_connections() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = register("Frankfurt", "fra1.example:443").unwrap();

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingMessageStream::new(local, counters);
        assert_eq!(snapshot_all()[0].active_connections, 0);
        drop(counting);
    }
}
```

- [ ] **Step 2: Declare the module and run the tests to verify they fail**

Add `mod outbound_counting_stream;` to `src/lib.rs` and `src/main.rs`, immediately before `mod outbound_stats;`.

```bash
cargo test --lib outbound_counting_stream
```

Expected: compile error — `cannot find type 'OutboundCountingStream'`.

- [ ] **Step 3: Write the byte-level adapter**

Prepend to `src/outbound_counting_stream.rs`:

```rust
//! Counting adapters that credit an outbound for what passes through it.
//!
//! The direction convention here is the INVERSE of
//! `crate::tun::traffic::TrafficCountingStream`. That one sits on the device
//! side, where a read is bytes travelling device to proxy — upload. These sit
//! at the outbound, where a read is bytes arriving from the server — download.
//! Reusing that type here would silently transpose the two figures, and no
//! test that only checks totals would notice.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
};
use crate::outbound_stats::OutboundCounters;

pin_project_lite::pin_project! {
    /// Counts application payload bytes to and from one outbound, and holds a
    /// live-connection slot for as long as it exists.
    pub struct OutboundCountingStream<S> {
        #[pin]
        inner: S,
        counters: Arc<OutboundCounters>,
    }

    impl<S> PinnedDrop for OutboundCountingStream<S> {
        fn drop(this: Pin<&mut Self>) {
            this.project().counters.connection_closed();
        }
    }
}

impl<S> OutboundCountingStream<S> {
    pub fn new(inner: S, counters: Arc<OutboundCounters>) -> Self {
        counters.connection_opened();
        Self { inner, counters }
    }

    /// Credit bytes that never travelled through this stream: `early_data`
    /// read by the final hop while completing its own handshake. Dropping it
    /// would lose the first bytes of every such connection — a small number,
    /// but a systematically biased one.
    pub fn count_early_data(&self, len: usize) {
        self.counters.add_download(len as u64);
    }
}

impl<S: tokio::io::AsyncRead> tokio::io::AsyncRead for OutboundCountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.counters.add_download(n as u64);
            }
        }
        result
    }
}

impl<S: tokio::io::AsyncWrite> tokio::io::AsyncWrite for OutboundCountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n @ 1..)) = &result {
            this.counters.add_upload(*n as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for OutboundCountingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        self.project().inner.poll_write_ping(cx)
    }
}

impl<S> crate::async_stream::AsyncStream for OutboundCountingStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + AsyncPing + Unpin + Send + Sync
{
}
```

- [ ] **Step 4: Write the message-level adapter**

Append to the same file, before the test module:

```rust
pin_project_lite::pin_project! {
    /// The datagram equivalent, counting payload lengths as the UDP router
    /// already sees them.
    ///
    /// Deliberately does NOT touch `active_connections`: that figure counts
    /// TCP connections today, and folding datagram sessions into it would
    /// silently change what an existing host is reading.
    pub struct OutboundCountingMessageStream<S> {
        #[pin]
        inner: S,
        counters: Arc<OutboundCounters>,
    }
}

impl<S> OutboundCountingMessageStream<S> {
    pub fn new(inner: S, counters: Arc<OutboundCounters>) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncReadMessage> AsyncReadMessage for OutboundCountingMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.counters.add_download(n as u64);
            }
        }
        result
    }
}

impl<S: AsyncWriteMessage> AsyncWriteMessage for OutboundCountingMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let result = this.inner.poll_write_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            this.counters.add_upload(buf.len() as u64);
        }
        result
    }
}

impl<S: AsyncFlushMessage> AsyncFlushMessage for OutboundCountingMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush_message(cx)
    }
}

impl<S: AsyncShutdownMessage> AsyncShutdownMessage for OutboundCountingMessageStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown_message(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for OutboundCountingMessageStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        self.project().inner.poll_write_ping(cx)
    }
}

impl<S> crate::async_stream::AsyncMessageStream for OutboundCountingMessageStream<S> where
    S: AsyncReadMessage
        + AsyncWriteMessage
        + AsyncFlushMessage
        + AsyncShutdownMessage
        + AsyncPing
        + Unpin
        + Send
{
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test --lib outbound_counting_stream
```

Expected: 3 passed.

If the message-stream test fails to compile because `tokio::io::DuplexStream` does not implement the message traits, replace its body with a hand-written stub that does — the assertion under test is only that `active_connections` stays at zero.

- [ ] **Step 6: Commit**

```bash
git add src/outbound_counting_stream.rs src/lib.rs src/main.rs
git commit -m "stats: counting adapters for the outbound side"
```

---

### Task 4: Register every outbound during validation

**Files:**
- Modify: `src/config/validate.rs:163` (after group resolution), `:2024-2037` (`expand_selection`), `:54` (`create_server_configs` entry)
- Test: `src/config/validate.rs` (new test module)

**Interfaces:**
- Consumes: `ClientConfig::stats_key()` (Task 1), `crate::outbound_stats::{register, reset}` (Task 2)
- Produces: no new public API — registration is a side effect of `create_server_configs`

**Two registration points, both idempotent:**
1. After `resolve_client_groups_topologically` at line 163, so a group that is
   defined but never referenced by a rule still appears in the list.
2. Inside `expand_selection` at line 2024, the single funnel every chain hop
   passes through — inline hops included, which is the more common form.

- [ ] **Step 1: Write the failing tests**

Append to the end of `src/config/validate.rs`:

```rust
#[cfg(test)]
mod outbound_registration_tests {
    use crate::config::load_config_str;
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};

    fn validate(yaml: &str) -> std::io::Result<()> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|_| ())
    }

    fn names() -> Vec<String> {
        snapshot_all().into_iter().map(|o| o.name).collect()
    }

    #[test]
    fn every_configured_outbound_is_listed_before_it_carries_traffic() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- client_group: eu
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
    - name: Amsterdam
      address: "ams1.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains: [eu]
"#,
        )
        .unwrap();

        let got = names();
        assert!(got.contains(&"Frankfurt".to_string()), "got {got:?}");
        assert!(got.contains(&"Amsterdam".to_string()), "got {got:?}");
    }

    /// Group expansion clones a config into every referencing group; all the
    /// clones are one server and must produce one entry.
    #[test]
    fn a_group_referenced_twice_yields_one_entry() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- client_group: base
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
- client_group: a
  client_proxies: [base]
- client_group: b
  client_proxies: [base]
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains: [a, b]
"#,
        )
        .unwrap();

        let count = names().iter().filter(|n| *n == "Frankfurt").count();
        assert_eq!(count, 1, "one server must have one counter");
    }

    /// An inline hop is the more common form and must be listed too.
    #[test]
    fn an_inline_hop_is_registered() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains:
        - name: Inline
          address: "fra1.example:443"
          protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(names().contains(&"Inline".to_string()), "got {:?}", names());
    }

    #[test]
    fn one_name_on_two_different_servers_is_rejected() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let err = validate(
            r#"
- client_group: eu
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
    - name: Frankfurt
      address: "fra2.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains: [eu]
"#,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Frankfurt"), "must name the name: {msg}");
        assert!(msg.contains("fra1.example:443"), "must name both: {msg}");
        assert!(msg.contains("fra2.example:443"), "must name both: {msg}");
    }

    /// Nearly every config has at least one direct outbound, and two of them
    /// must not read as a conflict on the unspecified address.
    #[test]
    fn two_direct_outbounds_do_not_conflict() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "10.0.0.0/8"
      action: allow
      client_chains: [{protocol: {type: direct}}]
    - masks: "0.0.0.0/0"
      action: allow
      client_chains: [{protocol: {type: direct}}]
"#,
        )
        .unwrap();

        let count = names().iter().filter(|n| *n == "direct").count();
        assert_eq!(count, 1);
    }

    /// Loading a second config must not inherit the first one's servers.
    #[test]
    fn a_second_load_replaces_the_list() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let first = r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains:
        - name: First
          address: "fra1.example:443"
          protocol: {type: socks}
"#;
        let second = r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains:
        - name: Second
          address: "ams1.example:443"
          protocol: {type: socks}
"#;

        validate(first).unwrap();
        validate(second).unwrap();

        let got = names();
        assert!(got.contains(&"Second".to_string()), "got {got:?}");
        assert!(!got.contains(&"First".to_string()), "stale entry: {got:?}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib config::validate::outbound_registration_tests
```

Expected: four fail on an empty or stale snapshot; `one_name_on_two_different_servers_is_rejected` fails because validation succeeds.

- [ ] **Step 3: Clear the registry at the start of a load**

In `create_server_configs` (`src/config/validate.rs:54`), as the very first statement of the function body:

```rust
    // A load replaces the outbound list rather than adding to it: stale
    // entries from a discarded config would be listed as live servers and
    // would also produce false address conflicts.
    crate::outbound_stats::reset();
```

- [ ] **Step 4: Register every group member**

Immediately after line 163, `let mut client_groups = resolve_client_groups_topologically(raw_client_groups)?;`, add:

```rust
    // Register group members even when no rule references the group, so a
    // configured server is listed whether or not traffic can reach it yet.
    for configs in client_groups.values() {
        for config in configs {
            crate::outbound_stats::register(&config.stats_key()?, &config.address.to_string())?;
        }
    }
```

- [ ] **Step 5: Register every expanded hop**

Replace `expand_selection` (`src/config/validate.rs:2024`) with:

```rust
fn expand_selection(
    selection: &ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<Vec<ClientConfig>> {
    let configs = match selection {
        ConfigSelection::Config(config) => vec![config.clone()],
        ConfigSelection::GroupName(name) => {
            client_groups.get(name).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unknown client group: {name}"),
                )
            })?
        }
    };

    // Every chain hop funnels through here, inline ones included, which is the
    // form that would otherwise go unlisted. Registration is idempotent, so a
    // hop that came from an already-registered group costs nothing.
    for config in &configs {
        crate::outbound_stats::register(&config.stats_key()?, &config.address.to_string())?;
    }

    Ok(configs)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test --lib config::validate::outbound_registration_tests
```

Expected: 6 passed.

- [ ] **Step 7: Run the whole config suite**

```bash
cargo test --lib config
```

Expected: all pass. `groups::tests::test_example_files_load_and_validate` loads every file in `examples/`, so a false conflict there surfaces here. If it fails, an example genuinely has two different servers under one address key — fix the example, not the check.

- [ ] **Step 8: Commit**

```bash
git add src/config/validate.rs
git commit -m "config: register every outbound's counters at load"
```

---

### Task 5: Carry counter handles on the chain

**Files:**
- Modify: `src/client_proxy_chain.rs:82-101` (`ClientProxyChainKind`), `:156-216` (`new`, `new_terminal`), `:550-586` (selection helpers)
- Test: in `src/client_proxy_chain.rs`

**Interfaces:**
- Consumes: `crate::outbound_stats::{OutboundCounters, unattributed}` (Task 2)
- Produces:
  - `ClientProxyChain::with_counters(self, initial: Vec<Arc<OutboundCounters>>, subsequent: Vec<Vec<Arc<OutboundCounters>>>) -> Self`
  - `ClientProxyChain::with_terminal_counters(self, counters: Vec<Arc<OutboundCounters>>) -> Self`
  - `fn select_from_pool<'a>(pool: &'a [InitialHopEntry], index: &AtomicU32) -> (&'a InitialHopEntry, usize)`
  - `fn select_terminal<'a>(pool: &'a [Arc<dyn TerminalConnector>], index: &AtomicU32) -> (&'a Arc<dyn TerminalConnector>, usize)`
  - `fn select_subsequent<'a>(hops: &'a [Vec<Box<dyn ProxyConnector>>], indices: &[AtomicU32]) -> Vec<(&'a dyn ProxyConnector, usize)>`

**Why a builder rather than new parameters:** `ClientProxyChain::new` has more than ten call sites, all in this file's tests. Adding parameters would churn every one of them for no benefit. `new` fills the counter vectors with `unattributed()` handles sized to the pools; `with_counters` replaces them.

- [ ] **Step 1: Write the failing test**

Append to the existing test module in `src/client_proxy_chain.rs`:

```rust
    #[test]
    fn a_chain_without_counters_is_unattributed_not_empty() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        // One handle per pool member, so indexing after selection is always
        // in bounds rather than needing a bounds check on the hot path.
        assert_eq!(chain.initial_counter_len(), 1);
    }

    #[test]
    fn with_counters_replaces_the_unattributed_handles() {
        let counters =
            crate::outbound_stats::register("Frankfurt", "fra1.example:443").unwrap();
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![])
            .with_counters(vec![counters.clone()], vec![]);
        assert!(Arc::ptr_eq(&chain.initial_counter(0), &counters));
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib client_proxy_chain
```

Expected: compile error — `no method named 'with_counters'`.

- [ ] **Step 3: Add the fields**

In `ClientProxyChainKind::StreamChain`, add after `subsequent_next_indices`:

```rust
        /// One handle per member of `initial_hop`, same order.
        initial_hop_counters: Vec<Arc<OutboundCounters>>,
        /// One handle per member of each pool in `subsequent_hops`, same order.
        subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>>,
```

In `ClientProxyChainKind::Terminal`, add after `next_index`:

```rust
        connector_counters: Vec<Arc<OutboundCounters>>,
```

In `new`, build them before constructing `Self`:

```rust
        let initial_hop_counters = vec![crate::outbound_stats::unattributed(); initial_hop.len()];
        let subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>> = subsequent_hops
            .iter()
            .map(|hop| vec![crate::outbound_stats::unattributed(); hop.len()])
            .collect();
```

In `new_terminal`:

```rust
        let connector_counters = vec![crate::outbound_stats::unattributed(); connectors.len()];
```

- [ ] **Step 4: Add the builder methods and test accessors**

In `impl ClientProxyChain`:

```rust
    /// Attach the counters for each pool member, in the same order the pools
    /// were built. Panics on a length mismatch: that is a construction bug in
    /// `chain_builder`, and silently mis-attributing traffic would be worse
    /// than a loud failure at startup.
    pub fn with_counters(
        mut self,
        initial: Vec<Arc<OutboundCounters>>,
        subsequent: Vec<Vec<Arc<OutboundCounters>>>,
    ) -> Self {
        if let ClientProxyChainKind::StreamChain {
            initial_hop,
            subsequent_hops,
            initial_hop_counters,
            subsequent_hop_counters,
            ..
        } = &mut self.kind
        {
            assert_eq!(initial.len(), initial_hop.len(), "initial counter count");
            assert_eq!(subsequent.len(), subsequent_hops.len(), "hop count");
            for (given, hop) in subsequent.iter().zip(subsequent_hops.iter()) {
                assert_eq!(given.len(), hop.len(), "pool counter count");
            }
            *initial_hop_counters = initial;
            *subsequent_hop_counters = subsequent;
        }
        self
    }

    pub fn with_terminal_counters(mut self, counters: Vec<Arc<OutboundCounters>>) -> Self {
        if let ClientProxyChainKind::Terminal {
            connectors,
            connector_counters,
            ..
        } = &mut self.kind
        {
            assert_eq!(counters.len(), connectors.len(), "terminal counter count");
            *connector_counters = counters;
        }
        self
    }

    /// The counters this connection's bytes belong to: the exit hop's, which
    /// is the last subsequent hop when there is one and the initial hop
    /// otherwise.
    fn exit_counters(
        initial_hop_counters: &[Arc<OutboundCounters>],
        subsequent_hop_counters: &[Vec<Arc<OutboundCounters>>],
        initial_idx: usize,
        subsequent_indices: &[usize],
    ) -> Arc<OutboundCounters> {
        match (subsequent_hop_counters.last(), subsequent_indices.last()) {
            (Some(pool), Some(&idx)) => pool[idx].clone(),
            _ => initial_hop_counters[initial_idx].clone(),
        }
    }

    #[cfg(test)]
    fn initial_counter_len(&self) -> usize {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop_counters,
                ..
            } => initial_hop_counters.len(),
            ClientProxyChainKind::Terminal { .. } => 0,
        }
    }

    #[cfg(test)]
    fn initial_counter(&self, i: usize) -> Arc<OutboundCounters> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop_counters,
                ..
            } => initial_hop_counters[i].clone(),
            ClientProxyChainKind::Terminal { .. } => panic!("not a stream chain"),
        }
    }
```

- [ ] **Step 5: Make the selection helpers return indices**

Replace the three helpers at the bottom of the file:

```rust
fn select_from_pool<'a>(
    pool: &'a [InitialHopEntry],
    index: &AtomicU32,
) -> (&'a InitialHopEntry, usize) {
    if pool.len() == 1 {
        (&pool[0], 0)
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize % pool.len();
        (&pool[idx], idx)
    }
}

fn select_terminal<'a>(
    pool: &'a [Arc<dyn TerminalConnector>],
    index: &AtomicU32,
) -> (&'a Arc<dyn TerminalConnector>, usize) {
    if pool.len() == 1 {
        (&pool[0], 0)
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize % pool.len();
        (&pool[idx], idx)
    }
}

fn select_subsequent<'a>(
    hops: &'a [Vec<Box<dyn ProxyConnector>>],
    indices: &[AtomicU32],
) -> Vec<(&'a dyn ProxyConnector, usize)> {
    hops.iter()
        .enumerate()
        .map(|(i, hop)| {
            if hop.len() == 1 {
                (hop[0].as_ref(), 0)
            } else {
                let idx = indices[i].fetch_add(1, Ordering::Relaxed) as usize % hop.len();
                (hop[idx].as_ref(), idx)
            }
        })
        .collect()
}
```

Then fix the call sites the compiler points at. In `connect_tcp`, the two bindings become:

```rust
                let (entry, initial_idx) = select_from_pool(initial_hop, initial_hop_next_index);
                let selected = select_subsequent(subsequent_hops, subsequent_next_indices);
                let subsequent_indices: Vec<usize> = selected.iter().map(|(_, i)| *i).collect();
                let subsequent_proxies: Vec<&dyn ProxyConnector> =
                    selected.into_iter().map(|(p, _)| p).collect();
```

and in the `Terminal` arm, `let (connector, _idx) = select_terminal(connectors, next_index);`.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cargo test --lib client_proxy_chain
```

Expected: all pass, including the two new ones.

- [ ] **Step 7: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: carry a counter handle for every pool member"
```

---

### Task 6: Build the chain with real counters

**Files:**
- Modify: `src/tcp/chain_builder.rs:20-130` (`build_client_proxy_chain`), `:131` (`build_terminal_connector`)
- Test: in `src/tcp/chain_builder.rs`

**Interfaces:**
- Consumes: `ClientConfig::stats_key()` (Task 1), `register` (Task 2), `with_counters` / `with_terminal_counters` (Task 5)
- Produces: chains whose counter handles correspond to their pool members

- [ ] **Step 1: Write the failing test**

Append to the test module in `src/tcp/chain_builder.rs`:

```rust
    #[test]
    fn the_built_chain_carries_the_configured_names() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let mut relay = socks_config(1080);
        relay.name = Some("relay".to_string());
        let mut exit = socks_config(1081);
        exit.name = Some("exit".to_string());

        let _chain = build_client_proxy_chain(
            crate::option_util::OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(relay)),
                ClientChainHop::Single(ConfigSelection::Config(exit)),
            ]),
            test_resolver(),
        );

        let names: Vec<String> = crate::outbound_stats::snapshot_all()
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert!(names.contains(&"relay".to_string()), "got {names:?}");
        assert!(names.contains(&"exit".to_string()), "got {names:?}");
    }
```

If the test module has no `test_resolver` helper, find the one the existing tests use:

```bash
grep -n 'fn test_resolver\|Resolver' src/tcp/chain_builder.rs | head
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib chain_builder::tests::the_built_chain_carries_the_configured_names
```

Expected: FAIL — the snapshot is empty, because nothing registers.

- [ ] **Step 3: Collect the keys while building**

In `build_client_proxy_chain`, the `hops: Vec<Vec<ClientConfig>>` value is assembled before any connector is constructed. Immediately after it, and before the configs are consumed, derive the counters in the same shape:

```rust
    // Same shape as `hops`, so a pool index selects the same member in both.
    let hop_counters: Vec<Vec<Arc<OutboundCounters>>> = hops
        .iter()
        .map(|pool| {
            pool.iter()
                .map(|config| {
                    // Both calls only fail on input validation has already
                    // rejected by the time a chain is built: a blank name, or
                    // one name on two addresses.
                    crate::outbound_stats::register(
                        &config.stats_key().expect("validated config"),
                        &config.address.to_string(),
                    )
                    .expect("validated config")
                })
                .collect()
        })
        .collect();
```

- [ ] **Step 4: Attach them at construction**

Where the function currently returns `ClientProxyChain::new(initial_hop, subsequent_hops)`, split `hop_counters` the same way the hops are split — the first entry is the initial hop, the rest are subsequent — and chain the builder:

```rust
    let mut counters_iter = hop_counters.into_iter();
    let initial_counters = counters_iter.next().expect("at least one hop");
    let subsequent_counters: Vec<Vec<Arc<OutboundCounters>>> = counters_iter.collect();

    ClientProxyChain::new(initial_hop, subsequent_hops)
        .with_counters(initial_counters, subsequent_counters)
```

For the terminal path, where the function returns `ClientProxyChain::new_terminal(connectors)`, attach `hop_counters` flattened — a terminal chain is a single hop, so `hop_counters` has exactly one pool:

```rust
    ClientProxyChain::new_terminal(connectors)
        .with_terminal_counters(hop_counters.into_iter().next().expect("one hop"))
```

- [ ] **Step 5: Run to verify it passes**

```bash
cargo test --lib chain_builder
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/tcp/chain_builder.rs
git commit -m "chain: build with the counters the config names"
```

---

### Task 7: Count TCP traffic against the exit hop

**Files:**
- Modify: `src/client_proxy_chain.rs:279-380` (`connect_tcp`)
- Test: in `src/client_proxy_chain.rs`

**Interfaces:**
- Consumes: `OutboundCountingStream` (Task 3), `exit_counters` and the indexed helpers (Task 5)
- Produces: `connect_tcp` returns a wrapped stream

- [ ] **Step 1: Write the failing tests**

Append to the test module in `src/client_proxy_chain.rs`. These drive real connections through mock connectors; follow the pattern the existing `connect_tcp` tests in this module use for building a working mock.

```rust
    /// The relay is where the bytes physically flow; the exit is the server a
    /// person means. The exit must be credited and the relay left at zero.
    #[tokio::test]
    async fn a_two_hop_chain_credits_the_exit_not_the_relay() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let relay = crate::outbound_stats::register("relay", "relay:1080").unwrap();
        let exit = crate::outbound_stats::register("exit", "exit:1081").unwrap();

        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
        )
        .with_counters(vec![relay.clone()], vec![vec![relay], vec![exit]]);

        let result = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();
        drop(result);

        let by_name = |n: &str| {
            crate::outbound_stats::snapshot_all()
                .into_iter()
                .find(|o| o.name == n)
                .unwrap()
        };
        assert_eq!(by_name("relay").active_connections, 0);
        assert_eq!(by_name("exit").active_connections, 0);
        // The exit held the slot while the stream was alive; the relay never did.
        assert_eq!(by_name("relay").upload_bytes, 0);
    }

    /// A single-hop chain has no subsequent hop, so the initial hop IS the exit.
    #[tokio::test]
    async fn a_single_hop_chain_credits_its_only_hop() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let only = crate::outbound_stats::register("only", "only:1080").unwrap();
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![])
            .with_counters(vec![only], vec![]);

        let result = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();

        assert_eq!(
            crate::outbound_stats::snapshot_all()[0].active_connections,
            1,
            "the slot must be held while the stream is alive"
        );
        drop(result);
        assert_eq!(
            crate::outbound_stats::snapshot_all()[0].active_connections,
            0
        );
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib client_proxy_chain
```

Expected: FAIL — `active_connections` stays at zero throughout, because nothing wraps.

- [ ] **Step 3: Wrap in the StreamChain arm**

At the end of the `StreamChain` arm of `connect_tcp`, replace `Ok(result)` with:

```rust
                let counters = Self::exit_counters(
                    initial_hop_counters,
                    subsequent_hop_counters,
                    initial_idx,
                    &subsequent_indices,
                );

                let counting = OutboundCountingStream::new(result.client_stream, counters);
                // early_data never travels through the stream, so it would
                // otherwise be lost from the count entirely.
                if let Some(data) = &result.early_data {
                    counting.count_early_data(data.len());
                }

                Ok(TcpClientSetupResult {
                    client_stream: Box::new(counting),
                    early_data: result.early_data,
                })
```

Destructure `initial_hop_counters` and `subsequent_hop_counters` in the `match &self.kind` pattern at the top of the arm, replacing the trailing `..` with the two new bindings.

- [ ] **Step 4: Wrap in the Terminal arm**

```rust
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
                connector_counters,
            } => {
                let (connector, idx) = select_terminal(connectors, next_index);
                debug!("Terminal TCP connect -> {}", remote_location.location());
                let result = connector.connect_tcp(resolver, remote_location).await?;

                let counting =
                    OutboundCountingStream::new(result.client_stream, connector_counters[idx].clone());
                if let Some(data) = &result.early_data {
                    counting.count_early_data(data.len());
                }

                Ok(TcpClientSetupResult {
                    client_stream: Box::new(counting),
                    early_data: result.early_data,
                })
            }
```

- [ ] **Step 5: Run to verify they pass**

```bash
cargo test --lib client_proxy_chain
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: count TCP bytes against the exit hop"
```

---

### Task 8: Count UDP traffic against the exit hop

**Files:**
- Modify: `src/client_proxy_chain.rs:385-470` (`connect_udp_bidirectional`)
- Test: in `src/client_proxy_chain.rs`

**Interfaces:**
- Consumes: `OutboundCountingMessageStream` (Task 3)
- Produces: `connect_udp_bidirectional` returns a wrapped message stream

**Note:** this function already computes its final-hop index explicitly as `pool_idx`, in both the `udp_uses_initial_hop` branch and the multi-hop branch. Use that index directly rather than deriving one.

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn udp_bytes_are_credited_to_the_final_hop() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let only = crate::outbound_stats::register("only", "only:1080").unwrap();
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![])
            .with_counters(vec![only], vec![]);

        let mut stream = chain
            .connect_udp_bidirectional(&test_resolver(), test_location())
            .await
            .unwrap();

        use crate::async_stream::AsyncWriteMessageExt;
        stream.write_message(&[0u8; 11]).await.unwrap();

        assert_eq!(crate::outbound_stats::snapshot_all()[0].upload_bytes, 11);
        // A datagram session is not a connection.
        assert_eq!(
            crate::outbound_stats::snapshot_all()[0].active_connections,
            0
        );
    }
```

If there is no `AsyncWriteMessageExt`, drive the write through `poll_write_message` with a manual context, following whatever the existing message-stream tests in the repo do:

```bash
grep -rn 'poll_write_message' src --include=*.rs | grep -i test | head
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib client_proxy_chain::tests::udp_bytes_are_credited_to_the_final_hop
```

Expected: FAIL — `upload_bytes` is 0.

- [ ] **Step 3: Wrap both branches**

Add `initial_hop_counters` and `subsequent_hop_counters` to the `StreamChain` destructuring pattern in `connect_udp_bidirectional`.

In the `udp_uses_initial_hop` branch, `pool_idx` already indexes `initial_hop`, so the counters are `initial_hop_counters[pool_idx].clone()`. Wrap whatever the two `match entry` arms return:

```rust
                    let counters = initial_hop_counters[pool_idx].clone();
                    let stream = match entry {
                        // ... unchanged arms, each yielding Box<dyn AsyncMessageStream>
                    }?;
                    Ok(Box::new(OutboundCountingMessageStream::new(stream, counters)))
```

In the multi-hop branch, `pool_idx` indexes the final hop pool, so the counters are `subsequent_hop_counters.last().expect("non-empty")[pool_idx].clone()`. Wrap the value the branch returns in the same way.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --lib client_proxy_chain
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: count UDP payload against the final hop"
```

---

### Task 9: Expose the figures, and document the field

**Files:**
- Modify: `src/control/stats.rs:1-40`, `CONFIG.md:456-460`, `CONFIG.md:1014`, `CHANGELOG.md:3`
- Test: in `src/control/stats.rs`

**Interfaces:**
- Consumes: `crate::outbound_stats::{OutboundStats, snapshot_all}` (Task 2)
- Produces: `StatsSnapshot::outbounds: Vec<OutboundStats>`

- [ ] **Step 1: Write the failing test**

Append to the test module in `src/control/stats.rs`:

```rust
    #[test]
    fn the_snapshot_carries_every_registered_outbound() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        crate::outbound_stats::register("Amsterdam", "ams1.example:443")
            .unwrap()
            .add_download(4096);
        crate::outbound_stats::register("Frankfurt", "fra1.example:443").unwrap();

        let snap = snapshot();
        let names: Vec<&str> = snap.outbounds.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, vec!["Amsterdam", "Frankfurt"]);
        assert_eq!(snap.outbounds[0].download_bytes, 4096);
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib control::stats
```

Expected: compile error — `no field 'outbounds' on type 'StatsSnapshot'`.

- [ ] **Step 3: Extend the snapshot**

`StatsSnapshot` currently derives `Copy`, which a `Vec` forbids. Change the derive to `#[derive(Debug, Clone, PartialEq, Eq)]` and add the field:

```rust
    /// One entry per configured outbound, sorted by name. Populated at config
    /// load, so a host lists every server at zero before any traffic flows.
    pub outbounds: Vec<OutboundStats>,
```

In `snapshot()`, add `outbounds: crate::outbound_stats::snapshot_all(),` to the constructed value.

- [ ] **Step 4: Replace the module header comment**

The header of `src/control/stats.rs` currently explains why per-outbound figures are impossible. That is no longer true. Replace it with:

```rust
//! Counters a host displays.
//!
//! Two layers. `upload_bytes` and `download_bytes` are process-wide totals
//! measured at the TUN edge (`crate::tun::traffic`), so in server mode, where
//! nothing increments them, they stay at zero. `outbounds` is measured at the
//! outbound instead (`crate::outbound_stats`), and is populated in every mode.
//!
//! The two will not agree to the byte: the TUN-edge counter also sees the
//! sniffed prefix and anything a connection wrote before it failed. The
//! difference is explainable, not zero.
//!
//! Outbound naming is specified in
//! `docs/superpowers/specs/2026-08-26-named-outbounds-design.md`.
```

- [ ] **Step 5: Run the test and the whole suite**

```bash
cargo test --lib control::stats
cargo test --lib
```

Expected: all pass. If anything failed to build because it copied a `StatsSnapshot`, add `.clone()` at that site — the type is no longer `Copy`.

- [ ] **Step 6: Document the field**

In `CONFIG.md`, in the `## Client Config` block at line ~456, add as the first line of the YAML sample:

```yaml
name: string                   # Optional; identifies this outbound in stats
```

And under `### Client Proxy Group` at line ~1014, give the two sample proxies names so the shape is visible in context.

Add to `CHANGELOG.md` immediately under `## Unreleased`:

```markdown
### Named outbounds

An outbound can carry a `name`, and `control::stats::snapshot()` reports
upload, download and active-connection counts against it. An outbound without
a name is keyed by its address, so existing configs get the same figures under
a less friendly label; a `direct` outbound is keyed `direct`, since its address
is unspecified and would otherwise collide with every other direct outbound.

Bytes are credited to the **exit** hop of a chain rather than to the relay the
socket actually opens, because the exit is the server a person means. Two
outbounds sharing a name but not an address are rejected at config load.
```

- [ ] **Step 7: Commit**

```bash
git add src/control/stats.rs CONFIG.md CHANGELOG.md
git commit -m "stats: report bytes per named outbound"
```

---

## Final verification

- [ ] **Full suite**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --all-targets 2>&1 | tail -20
```

Expected: no failures.

- [ ] **Lint gate** — the repo's gate is `-D warnings` with `--tests`

```bash
cargo clippy --all-targets -- -D warnings
```

- [ ] **Formatting**

```bash
cargo fmt --check
```

- [ ] **Every example still loads** — this is the real regression net for a config schema change

```bash
cargo test --lib config::types::groups::tests::test_example_files_load_and_validate
```

- [ ] **Windows still builds**, since `outbound_stats` must not depend on the `cfg(unix)`-only TUN module

```bash
cargo check --target x86_64-pc-windows-msvc 2>&1 | tail -5
```

If the target is not installed, skip this and note it in the PR — CI covers it.
