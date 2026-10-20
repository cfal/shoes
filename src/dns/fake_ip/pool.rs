use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;

use ipnetwork::IpNetwork;
use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[path = "persistence.rs"]
mod persistence;
use persistence::SnapshotStore;

use super::FakeIpOptions;
use super::options::invalid;

#[derive(Debug, Clone)]
struct Range {
    network: IpNetwork,
    first: u128,
    last: u128,
    cursor: u128,
}

impl Range {
    fn parse(value: &str, ipv6: bool, seed: u128) -> io::Result<Self> {
        let network: IpNetwork = value
            .parse()
            .map_err(|e| invalid(format!("invalid fake IP range {value}: {e}")))?;
        if network.is_ipv6() != ipv6 || network.ip() != network.network() {
            return Err(invalid(
                "fake IP range must have the specified family and no host bits",
            ));
        }
        if let IpNetwork::V6(range) = network {
            let mapped: ipnetwork::Ipv6Network = "::ffff:0:0/96".parse().unwrap();
            if range.contains(mapped.network()) || mapped.contains(range.network()) {
                return Err(invalid(
                    "fake IPv6 range must not overlap IPv4-mapped addresses",
                ));
            }
        }
        let (base, last) = match network {
            IpNetwork::V4(net) => (
                u32::from(net.network()) as u128,
                u32::from(net.broadcast()).saturating_sub(1) as u128,
            ),
            IpNetwork::V6(net) => (u128::from(net.network()), u128::from(net.broadcast())),
        };
        // Keep the network and conventional virtual-DNS address out of the pool.
        let first = base
            .checked_add(2)
            .ok_or_else(|| invalid("fake IP range too small"))?;
        if first > last {
            return Err(invalid("fake IP range has no allocatable addresses"));
        }
        Ok(Self {
            network,
            first,
            last,
            cursor: first + seed % (last - first + 1),
        })
    }

    fn take(&mut self) -> IpAddr {
        let current = self.cursor;
        self.cursor = if current == self.last {
            self.first
        } else {
            current + 1
        };
        match self.network {
            IpNetwork::V4(_) => Ipv4Addr::from(current as u32).into(),
            IpNetwork::V6(_) => Ipv6Addr::from(current).into(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Entry {
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
}

#[derive(Debug)]
struct State {
    owner: String,
    closed: bool,
    forward: LruCache<String, Entry>,
    reverse: HashMap<IpAddr, String>,
    v4: Option<Range>,
    v6: Option<Range>,
    v4_reserved: usize,
    v6_reserved: usize,
    revision: u64,
    checkpoint_revision: Option<u64>,
    misses: u64,
    evictions: u64,
    wraps: u64,
}

impl State {
    fn cached_allocation(&mut self, name: &str, ipv6: bool) -> io::Result<Option<IpAddr>> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Some(entry) = self.forward.get(name) else {
            return Ok(None);
        };
        let ip = if ipv6 { entry.v6 } else { entry.v4 };
        self.revision = self.revision.wrapping_add(1);
        Ok(ip)
    }
}

/// Bounded mappings with a cursor independent of LRU eviction.
pub struct FakeIpPool {
    state: Mutex<State>,
    store: Option<SnapshotStore>,
    pub(super) persistence_admission: std::sync::Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for FakeIpPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock();
        f.debug_struct("FakeIpPool")
            .field("entries", &state.forward.len())
            .field("misses", &state.misses)
            .field("evictions", &state.evictions)
            .field("wraps", &state.wraps)
            .finish()
    }
}

impl FakeIpPool {
    pub fn validate(options: &FakeIpOptions) -> io::Result<()> {
        let (v4, v6) = Self::ranges(options, 0)?;
        if options
            .state_file
            .as_ref()
            .and_then(|path| path.file_name())
            .is_some_and(|name| {
                let bytes = name.as_encoded_bytes();
                bytes[bytes.len().saturating_sub(5)..].eq_ignore_ascii_case(b".lock")
            })
        {
            return Err(invalid(
                "fake DNS state_file suffix .lock is reserved for ownership locks",
            ));
        }
        if options.state_file.is_some() && options.max_entries > persistence::MAX_PERSISTENT_ENTRIES
        {
            return Err(invalid(format!(
                "persistent fake IP max_entries must not exceed {}",
                persistence::MAX_PERSISTENT_ENTRIES
            )));
        }
        if options.state_file.is_some()
            && [v4.as_ref(), v6.as_ref()]
                .into_iter()
                .flatten()
                .any(|range| range.first == range.last)
        {
            return Err(invalid(
                "persistent fake IP families require at least two addresses",
            ));
        }
        let capacity = [v4, v6].iter().flatten().fold(0u128, |total, range| {
            total.saturating_add(range.last - range.first + 1)
        });
        if options.max_entries == 0 || options.max_entries as u128 > capacity {
            return Err(invalid(
                "fake IP max_entries must be positive and fit the address ranges",
            ));
        }
        Ok(())
    }

    fn ranges(options: &FakeIpOptions, seed: u128) -> io::Result<(Option<Range>, Option<Range>)> {
        let v4 = options
            .ipv4_range
            .as_deref()
            .map(|s| Range::parse(s, false, seed))
            .transpose()?;
        let v6 = options
            .ipv6_range
            .as_deref()
            .map(|s| Range::parse(s, true, seed))
            .transpose()?;
        if v4.is_none() && v6.is_none() {
            return Err(invalid("fake IP requires at least one address family"));
        }
        Ok((v4, v6))
    }

    #[cfg(test)]
    pub fn new(options: &FakeIpOptions) -> io::Result<Self> {
        Self::with_seed(options, rand::random())
    }

    #[cfg(test)]
    fn with_seed(options: &FakeIpOptions, seed: u128) -> io::Result<Self> {
        Self::with_owner(options, seed, "")
    }

    pub(crate) fn new_scoped(options: &FakeIpOptions, owner: &str) -> io::Result<Self> {
        Self::with_owner(options, rand::random(), owner)
    }

    fn with_owner(options: &FakeIpOptions, seed: u128, owner: &str) -> io::Result<Self> {
        Self::validate(options)?;
        let (v4, v6) = Self::ranges(options, seed)?;
        let mut forward = LruCache::unbounded();
        forward.resize(NonZeroUsize::new(options.max_entries).unwrap());
        let mut state = State {
            owner: owner.into(),
            closed: false,
            forward,
            reverse: HashMap::new(),
            v4,
            v6,
            v4_reserved: 0,
            v6_reserved: 0,
            revision: 0,
            checkpoint_revision: None,
            misses: 0,
            evictions: 0,
            wraps: 0,
        };
        let store = options
            .state_file
            .as_ref()
            .map(|path| SnapshotStore::open(path, &mut state))
            .transpose()?;
        Ok(Self {
            state: Mutex::new(state),
            store,
            persistence_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }

    pub(crate) fn persistent(&self) -> bool {
        self.store.is_some()
    }

    pub(crate) fn state_file_matches(&self, path: Option<&std::path::Path>) -> io::Result<bool> {
        match (&self.store, path) {
            (Some(store), Some(path)) => store.matches_path(path),
            (None, None) => Ok(true),
            _ => Ok(false),
        }
    }

    pub(crate) fn checkpoint(&self) -> io::Result<()> {
        if let Some(store) = &self.store {
            let _serial = store.serial.lock();
            let state = self.state.lock();
            if state.checkpoint_revision == Some(state.revision) {
                return Ok(());
            }
            let revision = state.revision;
            let snapshot = persistence::Snapshot::from_state(&state);
            drop(state);
            store.write(&snapshot)?;
            // Cache hits can change LRU order while the snapshot is being written.
            self.state.lock().checkpoint_revision = Some(revision);
        }
        Ok(())
    }

    pub(crate) fn shutdown_checkpoint(&self) -> io::Result<()> {
        let _serial = self.store.as_ref().map(|store| store.serial.lock());
        let mut state = self.state.lock();
        state.closed = true;
        state.v4_reserved = 0;
        state.v6_reserved = 0;
        state.revision = state.revision.wrapping_add(1);
        if let Some(store) = &self.store {
            let revision = state.revision;
            let snapshot = persistence::Snapshot::from_state(&state);
            drop(state);
            store.write(&snapshot)?;
            self.state.lock().checkpoint_revision = Some(revision);
        }
        Ok(())
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        let state = self.state.lock();
        [state.v4.as_ref(), state.v6.as_ref()]
            .iter()
            .flatten()
            .any(|r| r.network.contains(ip))
    }

    pub fn has_family(&self, ipv6: bool) -> bool {
        let state = self.state.lock();
        if ipv6 {
            state.v6.is_some()
        } else {
            state.v4.is_some()
        }
    }

    pub fn restore(&self, ip: IpAddr) -> io::Result<Option<String>> {
        let ip = ip.to_canonical();
        let mut state = self.state.lock();
        if let Some(name) = state.reverse.get(&ip).cloned() {
            state.forward.get(&name);
            state.revision = state.revision.wrapping_add(1);
            return Ok(Some(name));
        }
        if [state.v4.as_ref(), state.v6.as_ref()]
            .iter()
            .flatten()
            .any(|r| r.network.contains(ip))
        {
            state.misses = state.misses.saturating_add(1);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown fake IP address",
            ));
        }
        Ok(None)
    }

    pub fn allocate(&self, name: &str, ipv6: bool) -> io::Result<IpAddr> {
        let name = canonical_hostname(name).ok_or_else(|| invalid("invalid fake DNS hostname"))?;
        {
            let mut state = self.state.lock();
            if let Some(ip) = state.cached_allocation(&name, ipv6)? {
                return Ok(ip);
            }
        }
        let _serial = self.store.as_ref().map(|store| store.serial.lock());
        let mut state = self.state.lock();
        if let Some(ip) = state.cached_allocation(&name, ipv6)? {
            return Ok(ip);
        }
        if let Some(store) = &self.store {
            let remaining = if ipv6 {
                state.v6_reserved
            } else {
                state.v4_reserved
            };
            if remaining == 0 {
                let (snapshot, count) = store.reservation(&state, ipv6)?;
                drop(state);
                store.write(&snapshot)?;
                state = self.state.lock();
                if ipv6 {
                    state.v6_reserved = count;
                } else {
                    state.v4_reserved = count;
                }
            }
            if ipv6 {
                state.v6_reserved -= 1;
            } else {
                state.v4_reserved -= 1;
            }
        }
        let range = if ipv6 { &mut state.v6 } else { &mut state.v4 };
        let range = range
            .as_mut()
            .ok_or_else(|| invalid("fake IP family disabled"))?;
        let wrapped = range.cursor == range.last;
        let ip = range.take();
        if wrapped {
            state.wraps = state.wraps.saturating_add(1);
            log::warn!(
                "Fake IP allocation wrapped its configured range; stale addresses may be reused"
            );
        }

        if let Some(previous) = state.reverse.remove(&ip)
            && let Some(entry) = state.forward.peek_mut(&previous)
        {
            if ipv6 {
                entry.v6 = None;
            } else {
                entry.v4 = None;
            }
            if entry.v4.is_none() && entry.v6.is_none() {
                state.forward.pop(&previous);
            }
        }
        if !state.forward.contains(&name) {
            if state.forward.len() == state.forward.cap().get()
                && let Some((_, entry)) = state.forward.pop_lru()
            {
                state.evictions = state.evictions.saturating_add(1);
                for address in [entry.v4, entry.v6].into_iter().flatten() {
                    state.reverse.remove(&address);
                }
            }
            state.forward.put(name.clone(), Entry::default());
        }
        let entry = state.forward.get_mut(&name).unwrap();
        if ipv6 {
            entry.v6 = Some(ip);
        } else {
            entry.v4 = Some(ip);
        }
        state.reverse.insert(ip, name);
        state.revision = state.revision.wrapping_add(1);
        Ok(ip)
    }
}

pub(super) fn canonical_hostname(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(capacity: usize) -> FakeIpOptions {
        FakeIpOptions {
            ipv4_range: Some("198.18.0.0/29".into()),
            max_entries: capacity,
            ..Default::default()
        }
    }

    fn consistent(pool: &FakeIpPool) {
        let state = pool.state.lock();
        assert!(state.forward.len() <= state.forward.cap().get());
        let mut count = 0;
        for (name, entry) in state.forward.iter() {
            for ip in [entry.v4, entry.v6].into_iter().flatten() {
                assert_eq!(state.reverse.get(&ip), Some(name));
                count += 1;
            }
        }
        assert_eq!(count, state.reverse.len());
    }

    #[test]
    fn cache_checks_track_missing_families_but_do_not_touch_closed_pools() {
        let pool = FakeIpPool::with_seed(&options(2), 0).unwrap();
        pool.allocate("a.example", false).unwrap();
        pool.allocate("b.example", false).unwrap();
        let revision = pool.state.lock().revision;
        assert_eq!(
            pool.allocate("a.example", true).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        {
            let state = pool.state.lock();
            assert_eq!(state.revision, revision + 2);
            assert_eq!(state.forward.peek_mru().unwrap().0, "a.example");
        }
        pool.shutdown_checkpoint().unwrap();
        let revision = pool.state.lock().revision;
        assert_eq!(
            pool.allocate("b.example", false).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let state = pool.state.lock();
        assert_eq!(state.revision, revision);
        assert_eq!(state.forward.peek_mru().unwrap().0, "a.example");
    }

    #[test]
    fn full_range_reuse_not_lru_reuse() {
        let pool = FakeIpPool::with_seed(&options(2), 0).unwrap();
        let first = pool.allocate("a.example", false).unwrap();
        assert_eq!(first.to_string(), "198.18.0.2");
        for i in 3..=6 {
            let ip = pool.allocate(&format!("name{i}.example"), false).unwrap();
            assert_eq!(ip.to_string(), format!("198.18.0.{i}"));
            consistent(&pool);
        }
        assert_eq!(
            pool.restore(first).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(pool.allocate("wrap.example", false).unwrap(), first);
        assert_eq!(
            pool.restore(first).unwrap().as_deref(),
            Some("wrap.example")
        );
        consistent(&pool);
    }

    #[test]
    fn reverse_lookup_refreshes_and_names_canonicalize() {
        let pool = FakeIpPool::with_seed(&options(2), 0).unwrap();
        let a = pool.allocate("A.Example.", false).unwrap();
        assert_eq!(pool.allocate("a.example", false).unwrap(), a);
        let b = pool.allocate("b.example", false).unwrap();
        pool.restore(a).unwrap();
        pool.allocate("c.example", false).unwrap();
        assert!(pool.restore(a).unwrap().is_some());
        assert_eq!(pool.restore(b).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(
            pool.restore("192.0.2.1".parse().unwrap())
                .unwrap()
                .is_none()
        );
        assert!(pool.restore("198.18.0.1".parse().unwrap()).is_err());
        consistent(&pool);
    }

    #[test]
    fn dual_family_wrap_preserves_other_family() {
        let options = FakeIpOptions {
            ipv6_range: Some("2001:2::/126".into()),
            ..options(4)
        };
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        let a4 = pool.allocate("a.example", false).unwrap();
        let a6 = pool.allocate("a.example", true).unwrap();
        pool.allocate("b.example", true).unwrap();
        assert_eq!(pool.allocate("c.example", true).unwrap(), a6);
        assert_eq!(pool.restore(a4).unwrap().as_deref(), Some("a.example"));
        assert_eq!(pool.restore(a6).unwrap().as_deref(), Some("c.example"));
        consistent(&pool);
    }

    #[test]
    fn bounded_churn_keeps_inverse_maps() {
        let options = FakeIpOptions {
            ipv6_range: Some("2001:2::/124".into()),
            ..options(3)
        };
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        for i in 0..2000 {
            pool.allocate(&format!("n{}.example", i % 23), i % 3 == 0)
                .unwrap();
            consistent(&pool);
        }
    }

    #[test]
    fn hostname_validation() {
        for invalid in [
            "",
            ".",
            "127.0.0.1.",
            "::1",
            "a..b",
            "a_b.example",
            "-a.example",
            "a-.example",
            "a\\032b.example",
        ] {
            assert!(canonical_hostname(invalid).is_none(), "{invalid}");
        }
        assert_eq!(
            canonical_hostname("XN--BCHER-KVA.Example.").as_deref(),
            Some("xn--bcher-kva.example")
        );
    }

    #[test]
    fn validation_is_checked_and_allocation_free() {
        assert!(
            FakeIpPool::validate(&FakeIpOptions {
                ipv4_range: None,
                ipv6_range: Some("8000::/1".into()),
                max_entries: usize::MAX,
                ..Default::default()
            })
            .is_ok()
        );
        for range in ["198.18.0.0/31", "198.18.0.1/24", "2001:2::/48", "bad"] {
            assert!(
                FakeIpPool::validate(&FakeIpOptions {
                    ipv4_range: Some(range.into()),
                    ..options(1)
                })
                .is_err()
            );
        }
        assert!(FakeIpPool::validate(&options(0)).is_err());
        assert!(FakeIpPool::validate(&options(6)).is_err());
    }

    #[test]
    fn persistent_capacity_fits_snapshot_read_limit() {
        let mut options = FakeIpOptions {
            ipv6_range: Some("2001:2::/64".into()),
            state_file: Some("state.json".into()),
            max_entries: (256 * 1024 * 1024 - 4096) / 700,
            ..Default::default()
        };
        assert!(FakeIpPool::validate(&options).is_ok());
        options.max_entries += 1;
        assert!(FakeIpPool::validate(&options).is_err());
        options.state_file = None;
        assert!(FakeIpPool::validate(&options).is_ok());
    }
}
