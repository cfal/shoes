//! Per-outbound identity and counters, keyed by the name an outbound carries
//! in the config.
//!
//! Two halves. [`OutboundSet`] is what validation builds: every key with its
//! address, conflict-checked, pure -- `create_server_configs` also serves
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

/// The key a direct outbound always takes, and therefore the one name a
/// config cannot use for anything else.
///
/// `create_server_configs` seeds a built-in `direct` client group, so this key
/// is present in every config whether or not one was written.
pub const DIRECT_KEY: &str = "direct";

/// The message for one name on two servers. One function, so validation and
/// the registry cannot disagree about what a conflict looks like.
fn conflict(key: &str, first: &str, second: &str) -> std::io::Error {
    // `direct` is taken before a config is read, so the generic message would
    // blame someone for a duplicate they never wrote.
    if key == DIRECT_KEY {
        return std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "\"{DIRECT_KEY}\" is reserved: it is the key every direct outbound \
                 is counted against, so it cannot also name {second}. Choose \
                 another name for that outbound."
            ),
        );
    }

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

/// `allow(dead_code)` for the reason `tun::traffic` gives about its own
/// accessors: the binary declares its modules in main.rs, and which of these
/// have a caller depends on the build. `iter` is used by the registry, which
/// is behind `control-stats`; the rest serve tests. They are the accessors a
/// set type owes its callers either way.
#[allow(dead_code)]
impl OutboundSet {
    pub fn insert(&mut self, key: &str, address: &str) -> std::io::Result<()> {
        match self.entries.get(key) {
            Some(first) if first != address => Err(conflict(key, first, address)),
            Some(_) => Ok(()),
            None => {
                self.warn_if_the_same_server_is_also_unnamed(key, address);
                self.entries.insert(key.to_string(), address.to_string());
                Ok(())
            }
        }
    }

    /// One server written with a `name` in one chain and without one in
    /// another gets two keys, so a host shows it as two rows and its bytes
    /// divide between them by which chain served the connection.
    ///
    /// A warning rather than a merge: choosing which key wins would be
    /// guessing, and two *named* keys on one address is a legitimate way to
    /// track one server reached with different credentials. Only the
    /// named/unnamed mix is reported, because only that one is unintentional
    /// -- it is what a config looks like part-way through adopting `name`.
    fn warn_if_the_same_server_is_also_unnamed(&self, key: &str, address: &str) {
        let incoming_is_unnamed = key == address;
        for existing in self.entries.iter().filter(|(_, a)| *a == address) {
            let (existing_key, _) = existing;
            let existing_is_unnamed = existing_key == address;
            if incoming_is_unnamed != existing_is_unnamed {
                let (named, unnamed) = if incoming_is_unnamed {
                    (existing_key.as_str(), key)
                } else {
                    (key, existing_key.as_str())
                };
                log::warn!(
                    "outbound {address} is named \"{named}\" in one chain and unnamed in \
                     another, so its traffic will be reported under both \"{named}\" and \
                     \"{unnamed}\". Give it the same name everywhere to see one figure."
                );
                return;
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

/// The registry is process-global and cargo runs tests in parallel, so every
/// test that touches it -- directly, or through a path that installs -- takes
/// this first. Unconditional so that tests of unfeatured code which still
/// reach an install (`control::prepare_from_config`) can hold it too.
///
/// `allow(dead_code)`: with `control-stats` off there is no registry, so the
/// tests that take it are compiled out and nothing refers to it.
#[cfg(test)]
#[allow(dead_code)]
pub static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "control-stats")]
mod registry {
    use super::OutboundSet;
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
            let _ =
                self.active_connections
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
        /// The address this key was installed with. Carried for a Debug dump
        /// and for the conflict message an `OutboundSet` produces; nothing
        /// reads it at runtime, because conflicts are settled at config load.
        #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    /// The counters for a key, or [`unattributed`] if the running config does
    /// not declare it.
    ///
    /// A read, never a write: `install` is the only writer, so the list a host
    /// sees is exactly the set the running config declared. Building a chain
    /// must not be able to add a server to that list -- which it could, before
    /// this was a lookup, from any code path that built a chain without a
    /// config behind it.
    pub fn lookup(key: &str) -> Arc<OutboundCounters> {
        registry()
            .read()
            .unwrap()
            .get(key)
            .map(|entry| entry.counters.clone())
            .unwrap_or_else(unattributed)
    }

    /// Counters that are never listed, for a chain built without attribution
    /// -- tests, and any construction path with no config behind it. Traffic
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

    #[cfg(test)]
    pub fn reset_for_test() {
        registry().write().unwrap().clear();
    }
}

#[cfg(feature = "control-stats")]
pub use registry::*;

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

    /// Naming a server in one chain but not another splits its counters. The
    /// set still holds both keys -- the point is that the operator is told.
    #[test]
    fn a_server_named_in_one_place_and_not_another_keeps_both_keys() {
        let mut set = OutboundSet::default();
        set.insert("A", "same.example:443").unwrap();
        set.insert("same.example:443", "same.example:443").unwrap();

        assert!(set.contains("A"));
        assert!(set.contains("same.example:443"));
        assert_eq!(set.len(), 2);
    }

    /// Two named keys on one address is deliberate -- one server reached with
    /// different credentials -- and must not be reported as a mistake.
    #[test]
    fn two_named_keys_on_one_address_are_allowed() {
        let mut set = OutboundSet::default();
        set.insert("A", "same.example:443").unwrap();
        set.insert("B", "same.example:443").unwrap();
        assert_eq!(set.len(), 2);
    }

    /// The reserved key is taken before a config is read, so the message must
    /// not read as "you wrote this name twice".
    #[test]
    fn the_reserved_direct_name_says_it_is_reserved() {
        let mut set = OutboundSet::default();
        set.insert(DIRECT_KEY, "0.0.0.0:0").unwrap();
        let err = set.insert(DIRECT_KEY, "1.2.3.4:1080").unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("reserved"), "got: {msg}");
        assert!(
            msg.contains("1.2.3.4:1080"),
            "must name the outbound: {msg}"
        );
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

    /// Two lookups of one key are the same counter, which is what makes the
    /// clones group expansion produces share a total.
    #[test]
    fn two_lookups_of_a_key_share_one_counter() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let a = lookup("Frankfurt");
        let b = lookup("Frankfurt");
        a.add_upload(100);
        b.add_upload(50);

        let all = snapshot_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].upload_bytes, 150);
    }

    /// A lookup must not be able to add a server to a host's list. Before
    /// this was a read, any code path that built a chain could.
    #[test]
    fn looking_up_an_unknown_key_lists_nothing() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        lookup("Somewhere else").add_upload(500);

        let all = snapshot_all();
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(all[0].name, "Frankfurt");
        assert_eq!(all[0].upload_bytes, 0);
    }

    /// Asymmetric values: equal ones would pass with the two transposed.
    #[test]
    fn upload_and_download_are_not_transposed() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let c = lookup("Frankfurt");
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

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let c = lookup("Frankfurt");
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

        install(&set_of(&[("Frankfurt", "fra1.example:443")]));
        let c = lookup("Frankfurt");
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
