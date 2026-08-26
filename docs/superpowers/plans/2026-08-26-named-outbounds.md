# Named Outbounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every outbound a stable identifier, and report upload, download and active-connection counts per outbound through `shoes::control::stats::snapshot()`.

**Architecture:** An optional `name` on `ClientConfig` resolves to a non-empty key (name, else `direct`, else the address). Validation builds a conflict-checked `OutboundSet` of keys and returns it in `ValidatedConfigs` without touching global state; the two places a service actually starts install that set into a process-global registry. `ClientProxyChain` carries counter handles parallel to its hop pools and, at connect time, wraps the returned stream in a counting adapter holding the **exit** hop's handle. Everything that holds runtime state is behind the `control-stats` feature, as the repo's RSS policy requires.

**Tech Stack:** Rust 2024, tokio, serde/serde_yaml, `pin_project_lite` 0.2, `std::sync::atomic`.

**Spec:** `docs/superpowers/specs/2026-08-26-named-outbounds-design.md`

## Global Constraints

- **Rust toolchain is not on `PATH`.** Invoking `cargo` directly fails with `could not execute process 'rustc -vV'`. Every command in this plan must be run after:
  ```bash
  export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
  ```
- **Feature gate.** Runtime state (`OutboundCounters`, the registry, both adapters, the chain's counter handles, the wrapping) is behind `#[cfg(feature = "control-stats")]`. Config rules (`name`, `stats_key`, `OutboundSet`, the conflict check) are unconditional. Tests of gated code run with `--features control-stats`.
- **Validation is pure.** `create_server_configs` must not read or write the global registry — it is also what `--dry-run` and the config editor call.
- **`name` is optional**, and a config without one must round-trip byte-identically: `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- **Direction at the outbound is the inverse of `src/tun/traffic.rs`.** There, a read is upload. Here a **read is download**, a **write is upload**. Do not reuse `TrafficCountingStream`.
- **Bytes are credited to the exit hop**, never the relay; each connection credited exactly once.
- **New modules go in BOTH `src/lib.rs` and `src/main.rs`**, alphabetically — the two lists are maintained separately.
- **The three existing `StatsSnapshot` fields keep their meaning.**
- Commit after every task. Author is `ayastrebov@gmail.com` (the repo's `user.email` is already set).

## File Structure

| File | Responsibility |
| --- | --- |
| `src/config/types/client.rs` (modify) | The `name` field and `ClientConfig::stats_key()` |
| `src/outbound_stats.rs` (create) | Unconditional `OutboundSet` + conflict check; gated `OutboundCounters`, registry, `install` |
| `src/outbound_counting_stream.rs` (create, gated) | The two counting adapters |
| `src/config/validate.rs` (modify) | Thread an `OutboundSet` through expansion; return it in `ValidatedConfigs` |
| `src/control/mod.rs`, `src/main.rs` (modify) | `install` the set where a service starts |
| `src/client_proxy_chain.rs` (modify) | Carry counter handles; wrap at the two connect points |
| `src/tcp/chain_builder.rs` (modify) | Attach the handles the config names |
| `src/control/stats.rs` (modify) | Expose `outbounds` on the snapshot |
| `CONFIG.md`, `CHANGELOG.md` (modify) | Document the field |

---

### Task 1: The `name` field and its key

**Files:**
- Modify: `src/config/types/client.rs:543-571` (`ClientConfig` and its `Default`)
- Test: same file, new `mod named_outbound_tests` at the end

**Interfaces:**
- Consumes: `NetLocation::is_unspecified()` (`src/address.rs:121`), `ClientProxyConfig::is_direct()` (`src/config/types/client.rs:723`), `Display for NetLocation` (`src/address.rs:198`)
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
    /// before the field existed: the desktop config editor re-serializes
    /// whatever it loads.
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
    /// rule action is a direct chain, so an address fallback would collide
    /// them all on "0.0.0.0:0".
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
        assert!(err.to_string().contains("empty"), "unhelpful message: {err}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib config::types::client::named_outbound_tests
```

Expected: compile error — `no field 'name' on type 'ClientConfig'`, `no method named 'stats_key'`.

- [ ] **Step 3: Add the field**

In `src/config/types/client.rs`, add as the **first** field of `pub struct ClientConfig` (before `bind_interface`):

```rust
    /// A stable, human-meaningful identifier for this outbound. Optional: an
    /// outbound without one is keyed by its address, which works but is
    /// neither stable across config edits nor meaningful to show a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
```

In `impl Default for ClientConfig`, add as the first field: `name: None,`

- [ ] **Step 4: Add `stats_key`**

Immediately after the `impl Default for ClientConfig` block:

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

### Task 2: The outbound set and the counter registry

**Files:**
- Create: `src/outbound_stats.rs`
- Modify: `src/lib.rs` (module list, alphabetical after `option_util`), `src/main.rs` (same)
- Test: in `src/outbound_stats.rs`

**Interfaces:**
- Consumes: nothing
- Produces, unconditional:
  - `pub struct OutboundSet` — `Default`, `insert(&mut self, key: &str, address: &str) -> std::io::Result<()>`, `len(&self) -> usize`, `is_empty(&self) -> bool`, `contains(&self, key: &str) -> bool`, `iter(&self) -> impl Iterator<Item = (&str, &str)>`
- Produces, `#[cfg(feature = "control-stats")]`:
  - `pub struct OutboundCounters` — `add_upload(&self, u64)`, `add_download(&self, u64)`, `connection_opened(&self)`, `connection_closed(&self)`
  - `pub struct OutboundStats { pub name: String, pub upload_bytes: u64, pub download_bytes: u64, pub active_connections: usize }`
  - `pub fn install(set: &OutboundSet)` — replaces the registry contents
  - `pub fn register(key: &str, address: &str) -> std::io::Result<Arc<OutboundCounters>>` — idempotent, conflict-checked
  - `pub fn unattributed() -> Arc<OutboundCounters>`
  - `pub fn snapshot_all() -> Vec<OutboundStats>`
  - `#[cfg(test)] pub fn reset_for_test()`, `pub static REGISTRY_TEST_LOCK: Mutex<()>`

**Why the set is separate from the registry:** validation builds the set and must not touch global state (it also serves `--dry-run` and the editor). The registry is installed from the set only where a service starts. One conflict function serves both.

- [ ] **Step 1: Write the failing tests**

Create `src/outbound_stats.rs` containing only:

```rust
#[cfg(test)]
mod set_tests {
    use super::*;

    #[test]
    fn a_key_is_recorded_with_its_address() {
        let mut set = OutboundSet::default();
        set.insert("Frankfurt", "fra1.example:443").unwrap();
        assert!(set.contains("Frankfurt"));
        assert_eq!(set.len(), 1);
    }

    /// Group expansion clones a ClientConfig into every referencing group, so
    /// the same server arrives many times and must not be a conflict.
    #[test]
    fn the_same_key_and_address_twice_is_one_entry() {
        let mut set = OutboundSet::default();
        set.insert("Frankfurt", "fra1.example:443").unwrap();
        set.insert("Frankfurt", "fra1.example:443").unwrap();
        assert_eq!(set.len(), 1);
    }

    /// Addresses are compared rather than whole configs, so one server
    /// reachable with two sets of credentials stays legal.
    #[test]
    fn one_key_on_two_addresses_is_rejected_naming_both() {
        let mut set = OutboundSet::default();
        set.insert("Frankfurt", "fra1.example:443").unwrap();
        let err = set.insert("Frankfurt", "fra2.example:443").unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Frankfurt"), "must name the name: {msg}");
        assert!(msg.contains("fra1.example:443"), "must name both: {msg}");
        assert!(msg.contains("fra2.example:443"), "must name both: {msg}");
    }
}

#[cfg(all(test, feature = "control-stats"))]
mod registry_tests {
    use super::*;

    fn set_of(entries: &[(&str, &str)]) -> OutboundSet {
        let mut set = OutboundSet::default();
        for (k, a) in entries {
            set.insert(k, a).unwrap();
        }
        set
    }

    #[test]
    fn an_installed_outbound_starts_at_zero() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let all = snapshot_all();

        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Frankfurt");
        assert_eq!(all[0].upload_bytes, 0);
        assert_eq!(all[0].download_bytes, 0);
        assert_eq!(all[0].active_connections, 0);
    }

    /// A reload replaces the list rather than accumulating servers from the
    /// config it just discarded — stale entries would also read as false
    /// address conflicts.
    #[test]
    fn installing_a_second_set_replaces_the_first() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("First", "fra1.example:443")]));
        install(&set_of(&[("Second", "ams1.example:443")]));

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert_eq!(names, vec!["Second"]);
    }

    #[test]
    fn registering_an_installed_key_returns_its_counter() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let a = register("Frankfurt", "fra1.example:443").unwrap();
        let b = register("Frankfurt", "fra1.example:443").unwrap();
        a.add_upload(100);
        b.add_upload(50);

        let all = snapshot_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].upload_bytes, 150);
    }

    #[test]
    fn registering_a_conflicting_address_is_rejected() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let err = register("Frankfurt", "fra2.example:443").unwrap_err();
        assert!(err.to_string().contains("fra2.example:443"));
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

    /// An unmatched close floors rather than wraps, as tun::traffic does.
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

        install(&set_of(&[
            ("zurich", "zrh:443"),
            ("amsterdam", "ams:443"),
            ("frankfurt", "fra:443"),
        ]));

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert_eq!(names, vec!["amsterdam", "frankfurt", "zurich"]);
    }

    /// Traffic through a chain built without counters must neither panic nor
    /// be credited to a real server.
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

Add `mod outbound_stats;` to `src/lib.rs` after `mod option_util;` (line 79), and to `src/main.rs` in the same alphabetical position.

```bash
cargo test --features control-stats --lib outbound_stats
```

Expected: compile errors — `cannot find type 'OutboundSet'`, etc.

- [ ] **Step 3: Write the unconditional half**

Prepend to `src/outbound_stats.rs`:

```rust
//! Per-outbound identity and counters, keyed by the name an outbound carries
//! in the config.
//!
//! Two halves. [`OutboundSet`] is what validation builds: every key with its
//! address, conflict-checked, pure — `create_server_configs` also serves
//! `--dry-run` and the config editor, and must not touch live state. The
//! registry below it is process-global runtime state, installed from a set
//! only where a service actually starts, and compiled only with
//! `control-stats`, per the RSS policy `Cargo.toml` states and
//! `crate::tun::traffic` applies.
//!
//! Process-global rather than per-service for the reason `tun::traffic` gives:
//! `crate::control::start` documents one service per process, and
//! `crate::control::stats::snapshot` is a free function with no handle to
//! thread a registry through.

use std::collections::HashMap;

/// The message for one name on two servers. One function, so validation and
/// the registry cannot disagree about what a conflict looks like.
fn conflict(key: &str, first: &str, second: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "two outbounds are named \"{key}\" but have different addresses \
             ({first} and {second}); a name must identify one server"
        ),
    )
}

/// Every outbound a config mentions, keyed, with the address each key was
/// first seen with.
///
/// Group expansion clones a `ClientConfig` into every referencing group, so
/// one server arrives many times; the same key with the same address is
/// therefore expected. The same key with a *different* address is a config
/// mistake. Addresses are compared rather than whole configs: structural
/// equality would demand `PartialEq` across `ClientProxyConfig`,
/// `Redacted<String>` and the transport types, and would reject the legitimate
/// case of one server reachable with two sets of credentials.
#[derive(Debug, Default, Clone)]
pub struct OutboundSet {
    entries: HashMap<String, String>,
}

impl OutboundSet {
    pub fn insert(&mut self, key: &str, address: &str) -> std::io::Result<()> {
        match self.entries.get(key) {
            Some(first) if first != address => Err(conflict(key, first, address)),
            Some(_) => Ok(()),
            None => {
                self.entries.insert(key.to_string(), address.to_string());
                Ok(())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, a)| (k.as_str(), a.as_str()))
    }
}
```

- [ ] **Step 4: Write the gated half**

Append after the unconditional half, before the test modules:

```rust
#[cfg(feature = "control-stats")]
mod registry {
    use super::{OutboundSet, conflict};
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

        /// Floors at zero: cleanup paths can run more than once for one
        /// stream, and a wrapped count would read as billions of connections.
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

    struct Entry {
        counters: Arc<OutboundCounters>,
        address: String,
    }

    type Registry = RwLock<HashMap<String, Entry>>;

    fn registry() -> &'static Registry {
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
    }

    /// Replace the registry with the outbounds of the config that is about to
    /// run, each at zero. Called where a service starts, never from
    /// validation: a reload replaces the list rather than accumulating.
    pub fn install(set: &OutboundSet) {
        let fresh: HashMap<String, Entry> = set
            .iter()
            .map(|(key, address)| {
                (
                    key.to_string(),
                    Entry {
                        counters: Arc::new(OutboundCounters::default()),
                        address: address.to_string(),
                    },
                )
            })
            .collect();
        *registry().write().unwrap() = fresh;
    }

    /// The counters for a key, inserting if absent. Idempotent for the same
    /// key and address; the same key with a different address is rejected
    /// with the same message validation uses.
    pub fn register(key: &str, address: &str) -> std::io::Result<Arc<OutboundCounters>> {
        {
            let guard = registry().read().unwrap();
            if let Some(existing) = guard.get(key) {
                if existing.address != address {
                    return Err(conflict(key, &existing.address, address));
                }
                return Ok(existing.counters.clone());
            }
        }

        let mut guard = registry().write().unwrap();
        // Another thread may have inserted between the read and the write.
        if let Some(existing) = guard.get(key) {
            if existing.address != address {
                return Err(conflict(key, &existing.address, address));
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

    /// Counters that are never listed, for a chain built without attribution
    /// — tests, and any construction path with no config behind it. Traffic
    /// through such a chain is counted into a void rather than credited to
    /// some arbitrary server.
    pub fn unattributed() -> Arc<OutboundCounters> {
        static UNATTRIBUTED: OnceLock<Arc<OutboundCounters>> = OnceLock::new();
        UNATTRIBUTED
            .get_or_init(|| Arc::new(OutboundCounters::default()))
            .clone()
    }

    /// Every registered outbound, sorted by name so a host redrawing on a
    /// timer does not reorder its own rows.
    ///
    /// `allow(dead_code)` for the reason `tun::traffic` gives: the only reader
    /// is `crate::control::stats`, and main.rs has no `control`, so the binary
    /// compiles this with nothing to call it.
    #[allow(dead_code)]
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

    /// The registry is process-global and cargo runs tests in parallel, so
    /// every test that touches it takes this first.
    #[cfg(test)]
    pub static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(test)]
    pub fn reset_for_test() {
        registry().write().unwrap().clear();
    }
}

#[cfg(feature = "control-stats")]
pub use registry::*;
```

- [ ] **Step 5: Run the tests to verify they pass, with and without the feature**

```bash
cargo test --features control-stats --lib outbound_stats
cargo test --lib outbound_stats
```

Expected: 12 passed with the feature; 3 passed without.

- [ ] **Step 6: Commit**

```bash
git add src/outbound_stats.rs src/lib.rs src/main.rs
git commit -m "stats: an outbound set for validation, a registry for runtime"
```

---

### Task 3: The counting adapters

**Files:**
- Create: `src/outbound_counting_stream.rs`
- Modify: `src/lib.rs`, `src/main.rs` — declare as `#[cfg(feature = "control-stats")] mod outbound_counting_stream;` immediately before `mod outbound_stats;`
- Test: in the new file

**Interfaces:**
- Consumes: `crate::outbound_stats::OutboundCounters` (Task 2); `crate::async_stream::{AsyncPing, AsyncStream, AsyncMessageStream, AsyncReadMessage, AsyncWriteMessage, AsyncFlushMessage, AsyncShutdownMessage}` (`src/async_stream.rs:14-197`)
- Produces:
  - `pub struct OutboundCountingStream<S>` — `new(inner: S, counters: Arc<OutboundCounters>) -> Self`, `count_early_data(&self, len: usize)`
  - `pub struct OutboundCountingMessageStream<S>` — `new(inner: S, counters: Arc<OutboundCounters>) -> Self`

- [ ] **Step 1: Write the failing tests**

Create `src/outbound_counting_stream.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, register, reset_for_test, snapshot_all};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// At the outbound a read is DOWNLOAD and a write is UPLOAD — the inverse
    /// of tun::traffic, whose stream sits on the device side. The two byte
    /// counts are deliberately different, because equal ones would pass with
    /// the directions transposed.
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

    #[tokio::test]
    async fn early_data_is_credited_as_download() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = register("Frankfurt", "fra1.example:443").unwrap();

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingStream::new(local, counters);
        counting.count_early_data(17);

        assert_eq!(snapshot_all()[0].download_bytes, 17);
    }

    /// A datagram session is not a connection: active_connections counts TCP
    /// today, and folding datagrams in would change what a host is reading.
    #[tokio::test]
    async fn a_message_stream_does_not_hold_a_connection_slot() {
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

`OutboundCountingMessageStream::new` has no trait bounds, so wrapping a bare `DuplexStream` compiles; the test only reads the connection count.

- [ ] **Step 2: Declare the module and run the tests to verify they fail**

```bash
cargo test --features control-stats --lib outbound_counting_stream
```

Expected: compile error — `cannot find type 'OutboundCountingStream'`.

- [ ] **Step 3: Write the byte-level adapter**

Prepend to the file:

```rust
//! Counting adapters that credit an outbound for what passes through it.
//!
//! The direction convention here is the INVERSE of
//! `crate::tun::traffic::TrafficCountingStream`. That one sits on the device
//! side, where a read is bytes travelling device to proxy — upload. These sit
//! at the outbound, where a read is bytes arriving from the server — download.
//! Reusing that type would silently transpose the two figures, and no test
//! that only checks totals would notice.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::outbound_stats::OutboundCounters;

pin_project_lite::pin_project! {
    /// Counts application payload bytes to and from one outbound, and holds
    /// a live-connection slot for as long as it exists.
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
    /// the final hop read while completing its own handshake. Dropping it
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

impl<S> AsyncStream for OutboundCountingStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + AsyncPing + Unpin + Send + Sync
{
}
```

- [ ] **Step 4: Write the message-level adapter**

Append before the test module:

```rust
pin_project_lite::pin_project! {
    /// The datagram equivalent, counting payload lengths as the UDP router
    /// already sees them.
    ///
    /// Deliberately does NOT touch `active_connections`: that figure counts
    /// TCP connections today, and folding datagram sessions in would silently
    /// change what an existing host is reading.
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

impl<S> AsyncMessageStream for OutboundCountingMessageStream<S> where
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
cargo test --features control-stats --lib outbound_counting_stream
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/outbound_counting_stream.rs src/lib.rs src/main.rs
git commit -m "stats: counting adapters for the outbound side"
```

---

### Task 4: Validation builds the set

**Files:**
- Modify: `src/config/validate.rs:39-43` (`ValidatedConfigs`), `:54` (`create_server_configs`), `:163` (after group resolution), `:225` (the `Ok(ValidatedConfigs {..})`), `:2024` (`expand_selection`) and the functions between
- Modify: `src/main.rs:413`, `src/control/mod.rs:315` — the two exact-struct destructures of `ValidatedConfigs`
- Test: `src/config/validate.rs`, new `mod outbound_set_tests` at the end

**Interfaces:**
- Consumes: `ClientConfig::stats_key()` (Task 1), `OutboundSet` (Task 2)
- Produces: `ValidatedConfigs::outbounds: OutboundSet`

**How the set is threaded.** `expand_selection` (`:2024`) is the single funnel every chain hop passes through — inline hops included — and it is reached from two roots: `validate_rule_config` (`:1806`) and the DNS-spec expansion (`:574`). Give `expand_selection` a `&mut OutboundSet` parameter and let the compiler drive the rest: every function it flags gets `outbounds: &mut OutboundSet` as its **last** parameter and passes it through unchanged, until `create_server_configs` owns the value. Group members are added once more at line 163 so a group nothing references is still listed.

- [ ] **Step 1: Write the failing tests**

Append to `src/config/validate.rs`:

```rust
#[cfg(test)]
mod outbound_set_tests {
    use crate::config::load_config_str;
    use crate::outbound_stats::OutboundSet;

    fn validate(yaml: &str) -> std::io::Result<OutboundSet> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|v| v.outbounds)
    }

    #[test]
    fn every_configured_outbound_is_in_the_set() {
        let set = validate(
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
      client_chain: eu
"#,
        )
        .unwrap();

        assert!(set.contains("Frankfurt"));
        assert!(set.contains("Amsterdam"));
    }

    /// A group nothing references is still a configured server.
    #[test]
    fn an_unreferenced_group_is_still_listed() {
        let set = validate(
            r#"
- client_group: spare
  client_proxies:
    - name: Spare
      address: "spare.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(set.contains("Spare"));
    }

    /// Group expansion clones a config into every referencing group; the
    /// clones are one server.
    #[test]
    fn a_group_referenced_twice_yields_one_entry() {
        let set = validate(
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

        // "direct" is always present from the built-in group, so the count is
        // the built-in plus Frankfurt.
        assert!(set.contains("Frankfurt"));
        assert_eq!(set.len(), 2, "{:?}", set.iter().collect::<Vec<_>>());
    }

    /// An inline hop is the more common form and must be listed too.
    #[test]
    fn an_inline_hop_is_in_the_set() {
        let set = validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Inline
        address: "fra1.example:443"
        protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(set.contains("Inline"));
    }

    #[test]
    fn one_name_on_two_different_servers_is_rejected() {
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
"#,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Frankfurt"), "must name the name: {msg}");
        assert!(msg.contains("fra1.example:443"), "must name both: {msg}");
        assert!(msg.contains("fra2.example:443"), "must name both: {msg}");
    }

    /// Nearly every config has a direct outbound, and two of them must not
    /// read as a conflict on the unspecified address.
    #[test]
    fn two_direct_outbounds_are_one_entry() {
        let set = validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "10.0.0.0/8"
      action: allow
      client_chain:
        protocol: {type: direct}
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        protocol: {type: direct}
"#,
        )
        .unwrap();

        assert!(set.contains("direct"));
        assert_eq!(set.len(), 1);
    }

    /// The dry-run and editor property: validating touches no live state.
    #[cfg(feature = "control-stats")]
    #[test]
    fn validating_does_not_change_the_registry() {
        use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Draft
        address: "draft.example:443"
        protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(snapshot_all().is_empty(), "validation must not install");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test --features control-stats --lib config::validate::outbound_set_tests
```

Expected: compile error — `no field 'outbounds' on type 'ValidatedConfigs'`.

- [ ] **Step 3: Add the field**

In `src/config/validate.rs`, extend `ValidatedConfigs` (`:39`):

```rust
pub struct ValidatedConfigs {
    pub configs: Vec<Config>,
    /// Expanded DNS groups in topological order (bootstrap deps first).
    pub dns_groups: Vec<ExpandedDnsGroup>,
    /// Every outbound the config mentions, keyed and conflict-checked. Built
    /// here and installed where a service starts — never here, because this
    /// function also serves `--dry-run` and the config editor.
    pub outbounds: crate::outbound_stats::OutboundSet,
}
```

- [ ] **Step 4: Fix the two exact-struct destructures**

They will fail to compile until they name the new field.

`src/control/mod.rs:315`:

```rust
    let crate::config::ValidatedConfigs {
        configs: validated_configs,
        dns_groups,
        outbounds,
    } = create_server_configs(configs)?;
```

`src/main.rs:413`:

```rust
            let config::ValidatedConfigs {
                configs: server_configs,
                dns_groups,
                outbounds,
            } = server_configs;
```

Both `outbounds` bindings are consumed in Task 5; until then, prefix them `_outbounds` to keep the build warning-free, and rename in Task 5.

- [ ] **Step 5: Thread the set through expansion**

Replace `expand_selection` (`:2024`):

```rust
fn expand_selection(
    selection: &ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
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

    // Every chain hop funnels through here, inline ones included, which is
    // the form that would otherwise go unlisted. Insertion is idempotent, so
    // a hop that came from a group costs nothing.
    for config in &configs {
        outbounds.insert(&config.stats_key()?, &config.address.to_string())?;
    }

    Ok(configs)
}
```

Now build:

```bash
cargo check --features control-stats
```

Each error is a caller that must pass the set. Add `outbounds: &mut crate::outbound_stats::OutboundSet` as the last parameter of every flagged function and pass `outbounds` through. The chain is `expand_chain_hop` (`:1990`) → `expand_client_chain` (`:1972`) → its two callers at `:574` and `:1806` → their enclosing functions → up to `create_server_configs`. Repeat `cargo check` until it is clean.

- [ ] **Step 6: Own the set in `create_server_configs`**

At the top of the function body:

```rust
    let mut outbounds = crate::outbound_stats::OutboundSet::default();
```

Immediately after line 163 (`let mut client_groups = resolve_client_groups_topologically(raw_client_groups)?;`):

```rust
    // A group nothing references is still a configured server, and a person
    // expects to see it listed at zero rather than missing.
    for configs in client_groups.values() {
        for config in configs {
            outbounds.insert(&config.stats_key()?, &config.address.to_string())?;
        }
    }
```

Pass `&mut outbounds` at every call the compiler flagged in Step 5, and add `outbounds,` to the `Ok(ValidatedConfigs { .. })` at line ~225.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test --features control-stats --lib config::validate::outbound_set_tests
cargo test --lib config
```

Expected: 7 passed, then the whole config suite green. `groups::tests::test_example_files_load_and_validate` loads every file in `examples/`, so a false conflict there surfaces here; if one does, an example genuinely has two servers under one address key — fix the example, not the check.

- [ ] **Step 8: Commit**

```bash
git add src/config/validate.rs src/control/mod.rs src/main.rs
git commit -m "config: validation returns the set of named outbounds"
```

---

### Task 5: Install the set where a service starts

**Files:**
- Modify: `src/control/mod.rs:315-320`, `src/main.rs:413-418`

**Interfaces:**
- Consumes: `ValidatedConfigs::outbounds` (Task 4), `crate::outbound_stats::install` (Task 2)
- Produces: a populated registry before any chain is built

- [ ] **Step 1: Write the failing test**

Append to `src/control/mod.rs`:

```rust
#[cfg(all(test, feature = "control-stats"))]
mod outbound_install_tests {
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};

    /// Preparing a service is the commitment to running it, so this is where
    /// the registry is replaced — and where a host's list appears at zero.
    #[tokio::test]
    async fn preparing_a_service_installs_its_outbounds() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        let yaml = r#"
- address: "127.0.0.1:0"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Frankfurt
        address: "fra1.example:443"
        protocol: {type: socks}
"#;
        // prepare_from_config needs no device for a server-only config.
        let _prepared = super::prepare_from_config(yaml, super::DevicePolicy::Owned)
            .await
            .unwrap();

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert!(names.contains(&"Frankfurt".to_string()), "got {names:?}");
        assert!(names.contains(&"direct".to_string()), "got {names:?}");
    }
}
```

If `DevicePolicy::Owned` is not the variant name, find the right one:

```bash
grep -n 'pub enum DevicePolicy' -A 8 src/control/device.rs
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features control-stats --lib control::outbound_install_tests
```

Expected: FAIL — the snapshot is empty.

- [ ] **Step 3: Install in `prepare_from_config`**

In `src/control/mod.rs`, rename `_outbounds` back to `outbounds` in the destructure, and immediately after it:

```rust
    // Replace, not add: a reload through this path must not carry the
    // previous config's servers into the new list.
    #[cfg(feature = "control-stats")]
    crate::outbound_stats::install(&outbounds);
    #[cfg(not(feature = "control-stats"))]
    let _ = outbounds;
```

- [ ] **Step 4: Install in the binary's start path**

In `src/main.rs`, after the destructure at `:413` (rename `_outbounds` to `outbounds`), add the same four lines.

- [ ] **Step 5: Run to verify it passes, and that both features build**

```bash
cargo test --features control-stats --lib control::outbound_install_tests
cargo check
cargo check --features control-stats
```

Expected: 1 passed; both checks clean.

- [ ] **Step 6: Commit**

```bash
git add src/control/mod.rs src/main.rs
git commit -m "stats: install the outbound list where a service starts"
```

---

### Task 6: Carry counter handles on the chain

**Files:**
- Modify: `src/client_proxy_chain.rs:82-101` (`ClientProxyChainKind`), `:156-216` (`new`, `new_terminal`), `:550-586` (selection helpers)
- Test: the existing `mod tests` in the same file

**Interfaces:**
- Consumes: `crate::outbound_stats::{OutboundCounters, unattributed}` (Task 2)
- Produces (all `#[cfg(feature = "control-stats")]`):
  - `ClientProxyChain::with_counters(self, initial: Vec<Arc<OutboundCounters>>, subsequent: Vec<Vec<Arc<OutboundCounters>>>) -> Self`
  - `ClientProxyChain::with_terminal_counters(self, counters: Vec<Arc<OutboundCounters>>) -> Self`
  - `fn exit_counters(initial: &[Arc<OutboundCounters>], subsequent: &[Vec<Arc<OutboundCounters>>], initial_idx: usize, subsequent_indices: &[usize]) -> Arc<OutboundCounters>`
- Produces (unconditional — the selection helpers now also return the index chosen):
  - `fn select_from_pool<'a>(pool: &'a [InitialHopEntry], index: &AtomicU32) -> (&'a InitialHopEntry, usize)`
  - `fn select_terminal<'a>(pool: &'a [Arc<dyn TerminalConnector>], index: &AtomicU32) -> (&'a Arc<dyn TerminalConnector>, usize)`
  - `fn select_subsequent<'a>(hops: &'a [Vec<Box<dyn ProxyConnector>>], indices: &[AtomicU32]) -> Vec<(&'a dyn ProxyConnector, usize)>`

**Why a builder rather than new parameters:** `ClientProxyChain::new` has more than ten call sites, all tests in this file. `new` fills the counter vectors with `unattributed()` sized to the pools; `with_counters` replaces them.

- [ ] **Step 1: Write the failing tests**

Append inside the existing `mod tests`:

```rust
    #[cfg(feature = "control-stats")]
    #[test]
    fn a_chain_without_counters_is_unattributed_not_empty() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        // One handle per pool member, so indexing after selection is always
        // in bounds rather than needing a bounds check on the hot path.
        assert_eq!(chain.initial_counter_len(), 1);
    }

    #[cfg(feature = "control-stats")]
    #[test]
    fn with_counters_replaces_the_unattributed_handles() {
        let counters =
            crate::outbound_stats::register("Frankfurt", "fra1.example:443").unwrap();
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![])
            .with_counters(vec![counters.clone()], vec![]);
        assert!(Arc::ptr_eq(&chain.initial_counter(0), &counters));
    }

    /// The exit is the last subsequent hop when there is one, else the
    /// initial hop.
    #[cfg(feature = "control-stats")]
    #[test]
    fn exit_counters_picks_the_last_hop() {
        use crate::outbound_stats::unattributed;
        let a = Arc::new(crate::outbound_stats::OutboundCounters::default());
        let b = Arc::new(crate::outbound_stats::OutboundCounters::default());
        let c = Arc::new(crate::outbound_stats::OutboundCounters::default());

        let two_hop = ClientProxyChain::exit_counters(
            &[a.clone()],
            &[vec![b.clone()], vec![unattributed(), c.clone()]],
            0,
            &[0, 1],
        );
        assert!(Arc::ptr_eq(&two_hop, &c));

        let single = ClientProxyChain::exit_counters(&[unattributed(), a.clone()], &[], 1, &[]);
        assert!(Arc::ptr_eq(&single, &a));
    }
```

`OutboundCounters::default()` is reachable: it is `#[derive(Default)]` and `pub` in Task 2.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features control-stats --lib client_proxy_chain
```

Expected: compile error — `no method named 'with_counters'`.

- [ ] **Step 3: Add the fields**

Add `use crate::outbound_stats::OutboundCounters;` under `#[cfg(feature = "control-stats")]` at the top of the file.

In `ClientProxyChainKind::StreamChain`, after `subsequent_next_indices`:

```rust
        /// One handle per member of `initial_hop`, same order.
        #[cfg(feature = "control-stats")]
        initial_hop_counters: Vec<Arc<OutboundCounters>>,
        /// One handle per member of each pool in `subsequent_hops`, same order.
        #[cfg(feature = "control-stats")]
        subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>>,
```

In `ClientProxyChainKind::Terminal`, after `next_index`:

```rust
        #[cfg(feature = "control-stats")]
        connector_counters: Vec<Arc<OutboundCounters>>,
```

In `new`, before `Self { .. }` is constructed:

```rust
        #[cfg(feature = "control-stats")]
        let initial_hop_counters =
            vec![crate::outbound_stats::unattributed(); initial_hop.len()];
        #[cfg(feature = "control-stats")]
        let subsequent_hop_counters: Vec<Vec<Arc<OutboundCounters>>> = subsequent_hops
            .iter()
            .map(|hop| vec![crate::outbound_stats::unattributed(); hop.len()])
            .collect();
```

and add both to the struct literal under `#[cfg(feature = "control-stats")]`. Same in `new_terminal`:

```rust
        #[cfg(feature = "control-stats")]
        let connector_counters =
            vec![crate::outbound_stats::unattributed(); connectors.len()];
```

Every existing `match &self.kind { ClientProxyChainKind::StreamChain { .. } }` pattern already ends in `..` (e.g. `as_stream_chain`), so it keeps compiling.

- [ ] **Step 4: Add the builders and `exit_counters`**

In `impl ClientProxyChain`:

```rust
    /// Attach the counters for each pool member, in the order the pools were
    /// built. Panics on a length mismatch: that is a construction bug in
    /// `chain_builder`, and silently mis-attributing traffic would be worse
    /// than a loud failure at startup.
    #[cfg(feature = "control-stats")]
    pub fn with_counters(
        mut self,
        initial: Vec<Arc<OutboundCounters>>,
        subsequent: Vec<Vec<Arc<OutboundCounters>>>,
    ) -> Self {
        match &mut self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                initial_hop_counters,
                subsequent_hop_counters,
                ..
            } => {
                assert_eq!(initial.len(), initial_hop.len(), "initial counter count");
                assert_eq!(subsequent.len(), subsequent_hops.len(), "hop count");
                for (given, hop) in subsequent.iter().zip(subsequent_hops.iter()) {
                    assert_eq!(given.len(), hop.len(), "pool counter count");
                }
                *initial_hop_counters = initial;
                *subsequent_hop_counters = subsequent;
            }
            ClientProxyChainKind::Terminal { .. } => {
                panic!("with_counters on a terminal chain; use with_terminal_counters")
            }
        }
        self
    }

    #[cfg(feature = "control-stats")]
    pub fn with_terminal_counters(mut self, counters: Vec<Arc<OutboundCounters>>) -> Self {
        match &mut self.kind {
            ClientProxyChainKind::Terminal {
                connectors,
                connector_counters,
                ..
            } => {
                assert_eq!(counters.len(), connectors.len(), "terminal counter count");
                *connector_counters = counters;
            }
            ClientProxyChainKind::StreamChain { .. } => {
                panic!("with_terminal_counters on a stream chain; use with_counters")
            }
        }
        self
    }

    /// The counters this connection's bytes belong to: the exit hop's, which
    /// is the last subsequent hop when there is one and the initial hop
    /// otherwise.
    #[cfg(feature = "control-stats")]
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

    #[cfg(all(test, feature = "control-stats"))]
    fn initial_counter_len(&self) -> usize {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop_counters,
                ..
            } => initial_hop_counters.len(),
            ClientProxyChainKind::Terminal { .. } => 0,
        }
    }

    #[cfg(all(test, feature = "control-stats"))]
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

Replace the three helpers at `:550-586`:

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

Then fix the call sites the compiler points at. In `connect_tcp` (`:292-294`):

```rust
                let (entry, initial_idx) = select_from_pool(initial_hop, initial_hop_next_index);
                let selected = select_subsequent(subsequent_hops, subsequent_next_indices);
                let subsequent_indices: Vec<usize> = selected.iter().map(|(_, i)| *i).collect();
                let subsequent_proxies: Vec<&dyn ProxyConnector> =
                    selected.into_iter().map(|(p, _)| p).collect();
```

In the `Terminal` arm of `connect_tcp` and of `connect_udp_bidirectional`: `let (connector, idx) = select_terminal(connectors, next_index);`. In the `else` branch of `connect_udp_bidirectional` (`:434`): `let (entry, _initial_idx) = select_from_pool(initial_hop, initial_hop_next_index);`.

Until Tasks 8 and 9 use them, `initial_idx`, `subsequent_indices` and `idx` are unused; prefix them with `_` for now and un-prefix in those tasks.

- [ ] **Step 6: Run the tests, both ways**

```bash
cargo test --features control-stats --lib client_proxy_chain
cargo test --lib client_proxy_chain
```

Expected: all pass both ways.

- [ ] **Step 7: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: carry a counter handle for every pool member"
```

---

### Task 7: Build the chain with the counters the config names

**Files:**
- Modify: `src/tcp/chain_builder.rs:53-57` (after the empty-hops check), `:61-70` (terminal return), `:127` (stream return)
- Test: the existing `mod tests` in the same file

**Interfaces:**
- Consumes: `ClientConfig::stats_key()` (Task 1), `register` (Task 2), `with_counters` / `with_terminal_counters` (Task 6), the module's existing `socks_config(port)` and `mock_resolver()` helpers (`:237-251`)
- Produces: chains whose counter handles correspond to their pool members

- [ ] **Step 1: Write the failing test**

Append inside the existing `mod tests`:

```rust
    #[cfg(feature = "control-stats")]
    #[test]
    fn the_built_chain_registers_the_configured_names() {
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
            mock_resolver(),
        );

        let names: Vec<String> = crate::outbound_stats::snapshot_all()
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert!(names.contains(&"relay".to_string()), "got {names:?}");
        assert!(names.contains(&"exit".to_string()), "got {names:?}");
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features control-stats --lib chain_builder::tests::the_built_chain_registers_the_configured_names
```

Expected: FAIL — the snapshot is empty.

- [ ] **Step 3: Collect the handles while building**

In `build_client_proxy_chain`, immediately after the `if hops.is_empty() { panic!(..) }` check (`:53-55`) and before the terminal check:

```rust
    // Same shape as `hops`, so a pool index selects the same member in both.
    // register() only fails on what validation already rejected — a blank
    // name, or one name on two addresses — so a failure here is a bug.
    #[cfg(feature = "control-stats")]
    let hop_counters: Vec<Vec<Arc<crate::outbound_stats::OutboundCounters>>> = hops
        .iter()
        .map(|pool| {
            pool.iter()
                .map(|config| {
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

- [ ] **Step 4: Attach at both construction points**

Replace `return ClientProxyChain::new_terminal(connectors);` (`:69`):

```rust
        let chain = ClientProxyChain::new_terminal(connectors);
        #[cfg(feature = "control-stats")]
        let chain = chain.with_terminal_counters(
            hop_counters.into_iter().next().expect("one hop"),
        );
        return chain;
```

Replace the tail `ClientProxyChain::new(initial_hop, subsequent_hops)` (`:127`):

```rust
    let chain = ClientProxyChain::new(initial_hop, subsequent_hops);
    #[cfg(feature = "control-stats")]
    let chain = {
        let mut counters = hop_counters.into_iter();
        let initial = counters.next().expect("at least one hop");
        chain.with_counters(initial, counters.collect())
    };
    chain
}
```

- [ ] **Step 5: Run to verify it passes, both ways**

```bash
cargo test --features control-stats --lib chain_builder
cargo test --lib chain_builder
```

- [ ] **Step 6: Commit**

```bash
git add src/tcp/chain_builder.rs
git commit -m "chain: build with the counters the config names"
```

---

### Task 8: Count TCP traffic against the exit hop

**Files:**
- Modify: `src/client_proxy_chain.rs:279-383` (`connect_tcp`)
- Test: the existing `mod tests` in the same file

**Interfaces:**
- Consumes: `OutboundCountingStream` (Task 3); `exit_counters`, the indexed helpers (Task 6); `crate::async_stream::testing::TestStream` (`src/async_stream.rs:516`, a duplex half that satisfies `AsyncStream`); `NetLocation::from_ip_addr(IpAddr, u16)` (`src/address.rs:148`); `ResolvedLocation::new(NetLocation)` (`src/address.rs:227`); `NativeResolver::new()`
- Produces: `connect_tcp` returns a wrapped stream; and these test helpers, used again by Task 9:
  - `struct PipeSocket` — a `SocketConnector` whose `connect` hands out one half of a duplex pipe, once; `PipeSocket::new() -> (Box<dyn SocketConnector>, tokio::io::DuplexStream)` returns the connector and the peer half
  - `struct PassthroughProxy` — a `ProxyConnector` whose `setup_tcp_stream` returns the stream unchanged; `passthrough(port: u16) -> Box<dyn ProxyConnector>`
  - `fn test_location() -> ResolvedLocation`, `fn test_resolver() -> Arc<dyn Resolver>`

**Why new mocks:** the module's existing `MockSocketConnector` and `MockProxyConnector` return `Err("not implemented")` from every connect method. They test structure, not connections. Counting can only be tested through a connection that completes.

- [ ] **Step 1: Add the connecting mocks**

Append inside the existing `mod tests`:

```rust
    /// A socket that actually connects: hands out one half of a duplex pipe
    /// and lets the test keep the other, so bytes can be driven through.
    #[cfg(feature = "control-stats")]
    #[derive(Debug)]
    struct PipeSocket {
        half: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
    }

    #[cfg(feature = "control-stats")]
    impl PipeSocket {
        fn new() -> (Box<dyn SocketConnector>, tokio::io::DuplexStream) {
            let (ours, theirs) = tokio::io::duplex(4096);
            let socket = Self {
                half: std::sync::Mutex::new(Some(ours)),
            };
            (Box::new(socket), theirs)
        }
    }

    #[cfg(feature = "control-stats")]
    #[async_trait]
    impl SocketConnector for PipeSocket {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            let half = self
                .half
                .lock()
                .unwrap()
                .take()
                .expect("PipeSocket connects once");
            Ok(Box::new(crate::async_stream::testing::TestStream(half)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other("PipeSocket has no native UDP"))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// A proxy hop that performs no handshake: the stream goes out as it
    /// came in. Enough to prove which hop's counter a chain credits.
    #[cfg(feature = "control-stats")]
    #[derive(Debug)]
    struct PassthroughProxy {
        location: NetLocation,
    }

    #[cfg(feature = "control-stats")]
    #[async_trait]
    impl ProxyConnector for PassthroughProxy {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            true
        }

        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: None,
            })
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Ok(Box::new(SinkMessageStream::default()))
        }
    }

    #[cfg(feature = "control-stats")]
    fn passthrough(port: u16) -> Box<dyn ProxyConnector> {
        Box::new(PassthroughProxy {
            location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        })
    }

    /// A message stream that accepts every write and never yields a read.
    #[cfg(feature = "control-stats")]
    #[derive(Debug, Default)]
    struct SinkMessageStream;

    #[cfg(feature = "control-stats")]
    impl crate::async_stream::AsyncReadMessage for SinkMessageStream {
        fn poll_read_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[cfg(feature = "control-stats")]
    impl crate::async_stream::AsyncWriteMessage for SinkMessageStream {
        fn poll_write_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "control-stats")]
    impl crate::async_stream::AsyncFlushMessage for SinkMessageStream {
        fn poll_flush_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "control-stats")]
    impl crate::async_stream::AsyncShutdownMessage for SinkMessageStream {
        fn poll_shutdown_message(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "control-stats")]
    impl crate::async_stream::AsyncPing for SinkMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<bool>> {
            std::task::Poll::Ready(Ok(false))
        }
    }

    #[cfg(feature = "control-stats")]
    impl AsyncMessageStream for SinkMessageStream {}

    #[cfg(feature = "control-stats")]
    fn test_location() -> ResolvedLocation {
        ResolvedLocation::new(NetLocation::from_ip_addr(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
        ))
    }

    #[cfg(feature = "control-stats")]
    fn test_resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }
```

If `IpAddr`/`Ipv4Addr`/`NetLocation`/`ResolvedLocation`/`TcpClientSetupResult`/`AsyncMessageStream`/`async_trait` are not already imported in the test module, add the `use` lines the compiler names — the existing mocks in the same module use all of them.

- [ ] **Step 2: Write the failing tests**

Append inside `mod tests`:

```rust
    /// The relay is where the bytes physically flow; the exit is the server a
    /// person means. Only the exit may be credited.
    #[cfg(feature = "control-stats")]
    #[tokio::test]
    async fn a_two_hop_chain_credits_the_exit_not_the_relay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let direct = crate::outbound_stats::register("direct", "0.0.0.0:0").unwrap();
        let relay = crate::outbound_stats::register("relay", "relay:1080").unwrap();
        let exit = crate::outbound_stats::register("exit", "exit:1081").unwrap();

        let (socket, mut peer) = PipeSocket::new();
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(socket)],
            vec![vec![passthrough(1080)], vec![passthrough(1081)]],
        )
        .with_counters(vec![direct], vec![vec![relay], vec![exit]]);

        let mut result = chain
            .connect_tcp(test_location(), &test_resolver())
            .await
            .unwrap();

        // Deliberately asymmetric, so a transposition cannot pass.
        result.client_stream.write_all(&[1u8; 5]).await.unwrap();
        peer.write_all(&[2u8; 13]).await.unwrap();
        let mut buf = [0u8; 13];
        result.client_stream.read_exact(&mut buf).await.unwrap();

        let by_name = |n: &str| {
            crate::outbound_stats::snapshot_all()
                .into_iter()
                .find(|o| o.name == n)
                .unwrap()
        };
        assert_eq!(by_name("exit").upload_bytes, 5);
        assert_eq!(by_name("exit").download_bytes, 13);
        assert_eq!(by_name("exit").active_connections, 1);
        assert_eq!(by_name("relay").upload_bytes, 0);
        assert_eq!(by_name("relay").download_bytes, 0);
        assert_eq!(by_name("relay").active_connections, 0);
        assert_eq!(by_name("direct").active_connections, 0);

        drop(result);
        assert_eq!(by_name("exit").active_connections, 0);
    }

    /// A single-hop chain has no subsequent hop, so the initial hop IS the
    /// exit — and a pool credits the member actually selected.
    #[cfg(feature = "control-stats")]
    #[tokio::test]
    async fn a_pool_credits_the_member_selected() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let first = crate::outbound_stats::register("first", "first:1").unwrap();
        let second = crate::outbound_stats::register("second", "second:2").unwrap();

        let (socket_a, _peer_a) = PipeSocket::new();
        let (socket_b, _peer_b) = PipeSocket::new();
        let chain = ClientProxyChain::new(
            vec![
                InitialHopEntry::Direct(socket_a),
                InitialHopEntry::Direct(socket_b),
            ],
            vec![],
        )
        .with_counters(vec![first, second], vec![]);

        // Round-robin: the first connection takes member 0, the second member 1.
        let a = chain.connect_tcp(test_location(), &test_resolver()).await.unwrap();
        let b = chain.connect_tcp(test_location(), &test_resolver()).await.unwrap();

        let all = crate::outbound_stats::snapshot_all();
        assert_eq!(all.iter().find(|o| o.name == "first").unwrap().active_connections, 1);
        assert_eq!(all.iter().find(|o| o.name == "second").unwrap().active_connections, 1);

        drop(a);
        drop(b);
        let all = crate::outbound_stats::snapshot_all();
        assert!(all.iter().all(|o| o.active_connections == 0));
    }
```

- [ ] **Step 3: Run to verify they fail**

```bash
cargo test --features control-stats --lib client_proxy_chain
```

Expected: the two new tests FAIL — `active_connections` and the byte counts stay at zero, because nothing wraps.

- [ ] **Step 4: Wrap in the StreamChain arm**

Add `initial_hop_counters` and `subsequent_hop_counters` to the `StreamChain` destructuring pattern at the top of `connect_tcp`'s match arm (under `#[cfg(feature = "control-stats")]` on each binding), un-prefix `initial_idx` and `subsequent_indices`, and replace the arm's final `Ok(result)` with:

```rust
                #[cfg(feature = "control-stats")]
                let result = {
                    let counters = Self::exit_counters(
                        initial_hop_counters,
                        subsequent_hop_counters,
                        initial_idx,
                        &subsequent_indices,
                    );
                    let counting = crate::outbound_counting_stream::OutboundCountingStream::new(
                        result.client_stream,
                        counters,
                    );
                    // early_data never travels through the stream and would
                    // otherwise be lost from the count.
                    if let Some(data) = &result.early_data {
                        counting.count_early_data(data.len());
                    }
                    TcpClientSetupResult {
                        client_stream: Box::new(counting),
                        early_data: result.early_data,
                    }
                };

                Ok(result)
```

- [ ] **Step 5: Wrap in the Terminal arm**

```rust
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
                #[cfg(feature = "control-stats")]
                connector_counters,
            } => {
                let (connector, idx) = select_terminal(connectors, next_index);
                debug!("Terminal TCP connect -> {}", remote_location.location());
                let result = connector.connect_tcp(resolver, remote_location).await?;

                #[cfg(feature = "control-stats")]
                let result = {
                    let counting = crate::outbound_counting_stream::OutboundCountingStream::new(
                        result.client_stream,
                        connector_counters[idx].clone(),
                    );
                    if let Some(data) = &result.early_data {
                        counting.count_early_data(data.len());
                    }
                    TcpClientSetupResult {
                        client_stream: Box::new(counting),
                        early_data: result.early_data,
                    }
                };
                #[cfg(not(feature = "control-stats"))]
                let _ = idx;

                Ok(result)
            }
```

- [ ] **Step 6: Run to verify they pass, both ways**

```bash
cargo test --features control-stats --lib client_proxy_chain
cargo test --lib client_proxy_chain
```

- [ ] **Step 7: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: count TCP bytes against the exit hop"
```

---

### Task 9: Count UDP payload against the final hop

**Files:**
- Modify: `src/client_proxy_chain.rs:385-540` (`connect_udp_bidirectional`)
- Test: the existing `mod tests`

**Interfaces:**
- Consumes: `OutboundCountingMessageStream` (Task 3); `PipeSocket`, `passthrough`, `test_location`, `test_resolver` (Task 8)
- Produces: `connect_udp_bidirectional` returns a wrapped message stream

**Note:** this function already computes its final-hop index explicitly as `pool_idx` in both branches. Use that index; do not derive another.

- [ ] **Step 1: Write the failing test**

Append inside `mod tests`:

```rust
    #[cfg(feature = "control-stats")]
    #[tokio::test]
    async fn udp_payload_is_credited_to_the_final_hop_without_a_connection_slot() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let only = crate::outbound_stats::register("only", "only:1080").unwrap();
        let (socket, _peer) = PipeSocket::new();
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket,
                proxy: passthrough(1080),
            }],
            vec![],
        )
        .with_counters(vec![only], vec![]);

        let mut stream = chain
            .connect_udp_bidirectional(&test_resolver(), test_location())
            .await
            .unwrap();

        use crate::async_stream::AsyncWriteMessage;
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_write_message(cx, &[0u8; 11]))
            .await
            .unwrap();

        let only = crate::outbound_stats::snapshot_all().into_iter().next().unwrap();
        assert_eq!(only.upload_bytes, 11);
        // A datagram session is not a connection.
        assert_eq!(only.active_connections, 0);
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --features control-stats --lib client_proxy_chain::tests::udp_payload_is_credited_to_the_final_hop_without_a_connection_slot
```

Expected: FAIL — `upload_bytes` is 0.

- [ ] **Step 3: Wrap the `udp_uses_initial_hop` branch**

Add `initial_hop_counters` and `subsequent_hop_counters` to the destructuring pattern at the top of `connect_udp_bidirectional` (each under `#[cfg(feature = "control-stats")]`). In the `if *udp_uses_initial_hop` branch, `pool_idx` indexes `initial_hop`. Bind the branch's `match entry { .. }` to a value and wrap it:

```rust
                    let stream = match entry {
                        InitialHopEntry::Direct(socket) => {
                            debug!("Chain UDP: Direct connection (native UDP)");
                            socket.connect_udp_bidirectional(resolver, target).await?
                        }
                        InitialHopEntry::Proxy { socket, proxy } => {
                            debug!(
                                "Chain UDP: Proxy {} (UDP, no subsequent)",
                                proxy.proxy_location()
                            );
                            let proxy_loc = proxy.proxy_location().into();
                            let stream = socket.connect(resolver, &proxy_loc).await?;
                            proxy.setup_udp_bidirectional(stream, target).await?
                        }
                    };

                    #[cfg(feature = "control-stats")]
                    let stream: Box<dyn AsyncMessageStream> = Box::new(
                        crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                            stream,
                            initial_hop_counters[pool_idx].clone(),
                        ),
                    );

                    Ok(stream)
```

- [ ] **Step 4: Wrap the multi-hop branch**

There, `pool_idx` indexes the final hop pool. Replace the branch's tail `final_proxy.setup_udp_bidirectional(stream, target).await`:

```rust
                    let stream = final_proxy.setup_udp_bidirectional(stream, target).await?;

                    #[cfg(feature = "control-stats")]
                    let stream: Box<dyn AsyncMessageStream> = Box::new(
                        crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                            stream,
                            subsequent_hop_counters
                                .last()
                                .expect("multi-hop branch has a final pool")[pool_idx]
                                .clone(),
                        ),
                    );

                    Ok(stream)
```

- [ ] **Step 5: Wrap the Terminal arm**

```rust
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
                #[cfg(feature = "control-stats")]
                connector_counters,
            } => {
                let (connector, idx) = select_terminal(connectors, next_index);
                debug!("Terminal UDP connect -> {}", target.location());
                let stream = connector.connect_udp_bidirectional(resolver, target).await?;

                #[cfg(feature = "control-stats")]
                let stream: Box<dyn AsyncMessageStream> = Box::new(
                    crate::outbound_counting_stream::OutboundCountingMessageStream::new(
                        stream,
                        connector_counters[idx].clone(),
                    ),
                );
                #[cfg(not(feature = "control-stats"))]
                let _ = idx;

                Ok(stream)
            }
```

- [ ] **Step 6: Run to verify it passes, both ways**

```bash
cargo test --features control-stats --lib client_proxy_chain
cargo test --lib client_proxy_chain
```

- [ ] **Step 7: Commit**

```bash
git add src/client_proxy_chain.rs
git commit -m "chain: count UDP payload against the final hop"
```

---

### Task 10: Expose the figures, and document the field

**Files:**
- Modify: `src/control/stats.rs:1-40`, `CONFIG.md:~456` and `~1014`, `CHANGELOG.md:3`
- Test: the existing test module in `src/control/stats.rs`

**Interfaces:**
- Consumes: `crate::outbound_stats::{OutboundStats, snapshot_all}` (Task 2)
- Produces: `StatsSnapshot::outbounds: Vec<OutboundStats>`

`src/control/stats.rs` is compiled only with `control-stats` (`src/control/mod.rs:19`), so nothing here needs its own `cfg`.

- [ ] **Step 1: Write the failing test**

Append inside the existing `mod tests`:

```rust
    #[test]
    fn the_snapshot_carries_every_installed_outbound() {
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
cargo test --features control-stats --lib control::stats
```

Expected: compile error — `no field 'outbounds' on type 'StatsSnapshot'`.

- [ ] **Step 3: Extend the snapshot**

`StatsSnapshot` derives `Copy` (`:12`), which a `Vec` forbids. Change the derive to `#[derive(Debug, Clone, PartialEq, Eq)]` and add:

```rust
    /// One entry per configured outbound, sorted by name. Installed when the
    /// service starts, so a host lists every server at zero before any
    /// traffic flows.
    pub outbounds: Vec<crate::outbound_stats::OutboundStats>,
```

In `snapshot()`, add `outbounds: crate::outbound_stats::snapshot_all(),`.

- [ ] **Step 4: Replace the module header**

The current header explains why per-outbound figures are impossible. Replace lines 1-9 with:

```rust
//! Counters a host displays.
//!
//! Two layers. `upload_bytes` and `download_bytes` are process-wide totals
//! measured at the TUN edge (`crate::tun::traffic`), so in server mode, where
//! nothing increments them, they stay at zero. `outbounds` is measured at the
//! outbound instead (`crate::outbound_stats`) and is populated in every mode.
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
cargo test --features control-stats --lib control::stats
cargo test --features control-stats --lib
```

If anything fails to build because it copied a `StatsSnapshot`, add `.clone()` at that site — the type is no longer `Copy`.

- [ ] **Step 6: Document the field**

In `CONFIG.md`, in the `## Client Config` YAML block (~line 456), add as the first line:

```yaml
name: string                   # Optional; identifies this outbound in stats
```

Under `### Client Proxy Group` (~line 1014), give the two sample proxies `name: proxy-1` and `name: proxy-2` so the shape is visible in context.

In `CHANGELOG.md`, immediately under `## Unreleased`:

```markdown
### Named outbounds

An outbound can carry a `name`, and with the `control-stats` feature
`control::stats::snapshot()` reports upload, download and active-connection
counts against it. An outbound without a name is keyed by its address, so
existing configs get the same figures under a less friendly label; a `direct`
outbound is keyed `direct`, since its address is unspecified and would
otherwise collide with every other direct outbound.

Bytes are credited to the **exit** hop of a chain rather than to the relay the
socket actually opens, because the exit is the server a person means. Two
outbounds sharing a name but not an address are rejected at config load, on
every build.
```

- [ ] **Step 7: Commit**

```bash
git add src/control/stats.rs CONFIG.md CHANGELOG.md
git commit -m "stats: report bytes per named outbound"
```

---

## Final verification

- [ ] **Full suite, both ways**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --all-targets 2>&1 | tail -5
cargo test --features control-stats --all-targets 2>&1 | tail -5
```

- [ ] **Lint gate, both ways** — the repo's gate is `-D warnings` with `--tests`

```bash
cargo clippy --all-targets -- -D warnings
cargo clippy --features control-stats --all-targets -- -D warnings
```

- [ ] **Formatting**

```bash
cargo fmt --check
```

- [ ] **Every example still loads**

```bash
cargo test --lib config::types::groups::tests::test_example_files_load_and_validate
```

- [ ] **Windows still builds** — `outbound_stats` must not depend on the `cfg(unix)`-only TUN module

```bash
cargo check --target x86_64-pc-windows-msvc --features control-stats 2>&1 | tail -3
```

If the target is not installed, skip and note it in the PR — CI covers it.
