//! Fake IP allocation.
//!
//! A bidirectional map between domain names and addresses drawn from a private
//! IPv4 range. The DNS side hands a fake address to the client immediately, and
//! the connect side turns it back into the original domain, so no real
//! resolution happens on the device and none leaks outside the tunnel.

use std::io;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;

/// Default ceiling on live mappings.
///
/// A `/16` offers 65,534 addresses, and holding that many domains costs a few
/// megabytes — real money against an iOS packet-tunnel's ~50 MB budget. The
/// working set of a phone is far smaller than the pool, so cap the map and let
/// the LRU recycle. Raise it with `max_entries` if you have the headroom.
pub const DEFAULT_MAX_ENTRIES: usize = 8192;

/// The smallest prefix accepted. Anything wider is almost certainly a typo, and
/// the pool would reserve a quarter of the IPv4 space.
const MIN_PREFIX_LEN: u8 = 8;

/// The largest prefix accepted. A `/30` leaves two usable addresses; `/31` and
/// `/32` leave none once the network and broadcast addresses are excluded.
const MAX_PREFIX_LEN: u8 = 30;

/// A validated IPv4 CIDR that fake addresses are drawn from.
///
/// Construction is the only way to build one, so every `FakeIpNetwork` in the
/// program is known to have a usable host range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeIpNetwork {
    /// Network address with host bits cleared.
    network: u32,
    mask: u32,
    prefix_len: u8,
}

impl FakeIpNetwork {
    /// Parse a CIDR such as `198.18.0.0/16`.
    ///
    /// Returns an error rather than panicking on a bad prefix: this runs on the
    /// config path of a library whose callers are Kotlin and Swift, where an
    /// unwinding panic is undefined behaviour rather than a stack trace.
    pub fn parse(s: &str) -> io::Result<Self> {
        let (addr_str, prefix_str) = s.split_once('/').ok_or_else(|| {
            invalid(format!(
                "fake_ip network '{}' must be CIDR notation, e.g. 198.18.0.0/16",
                s
            ))
        })?;

        let addr: Ipv4Addr = addr_str
            .trim()
            .parse()
            .map_err(|e| invalid(format!("fake_ip network '{}': {}", addr_str, e)))?;

        let prefix_len: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|e| invalid(format!("fake_ip prefix '{}': {}", prefix_str, e)))?;

        Self::new(addr, prefix_len)
    }

    /// Build from an address and prefix length.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> io::Result<Self> {
        if !(MIN_PREFIX_LEN..=MAX_PREFIX_LEN).contains(&prefix_len) {
            return Err(invalid(format!(
                "fake_ip prefix length {} is out of range, must be {}-{}",
                prefix_len, MIN_PREFIX_LEN, MAX_PREFIX_LEN
            )));
        }

        let mask = u32::MAX << (32 - prefix_len);
        Ok(Self {
            network: u32::from(addr) & mask,
            mask,
            prefix_len,
        })
    }

    /// True if `ip` falls inside this network.
    ///
    /// This is the hot path — every outbound connection asks it — so it stays a
    /// mask and compare with no locking.
    #[inline]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }

    /// Addresses available for allocation, excluding the network and broadcast
    /// addresses.
    pub fn usable_addresses(&self) -> u32 {
        // MAX_PREFIX_LEN keeps host_bits >= 2, so this cannot underflow.
        (!self.mask) - 1
    }

    fn address_at(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.network + offset)
    }

    fn offset_of(&self, ip: Ipv4Addr) -> u32 {
        u32::from(ip) - self.network
    }
}

impl std::fmt::Display for FakeIpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.prefix_len)
    }
}

/// The two maps, kept as exact inverses of each other.
struct PoolState {
    /// Recency order lives here; eviction pops from this side.
    domain_to_ip: LruCache<Arc<str>, Ipv4Addr>,
    /// The reverse direction, read once per outbound connection.
    ip_to_domain: FxHashMap<Ipv4Addr, Arc<str>>,
    /// Next never-used offset, walking up until the pool is full.
    next_offset: u32,
    /// Highest offset this pool will hand out.
    max_offset: u32,
}

/// Allocates fake addresses and maps them back to domains.
///
/// Cheap to clone behind an `Arc`; every method takes `&self`.
pub struct FakeIpPool {
    network: FakeIpNetwork,
    state: Mutex<PoolState>,
}

impl FakeIpPool {
    /// Create a pool over `network`, holding at most `max_entries` mappings.
    ///
    /// The effective capacity is the smaller of `max_entries` and the addresses
    /// the network can supply.
    pub fn new(network: FakeIpNetwork, max_entries: usize) -> io::Result<Self> {
        if max_entries == 0 {
            return Err(invalid("fake_ip max_entries must be greater than zero"));
        }

        // usable_addresses() is at least 2 for every accepted prefix, so the
        // capacity below is always non-zero.
        let max_offset = std::cmp::min(max_entries as u64, u64::from(network.usable_addresses()));
        let max_offset = max_offset as u32;

        let capacity = NonZeroUsize::new(max_offset as usize)
            .ok_or_else(|| invalid("fake_ip network has no usable addresses"))?;

        Ok(Self {
            network,
            state: Mutex::new(PoolState {
                domain_to_ip: LruCache::new(capacity),
                ip_to_domain: FxHashMap::default(),
                next_offset: 1, // offset 0 is the network address
                max_offset,
            }),
        })
    }

    /// Number of addresses this pool will hand out before it starts recycling.
    pub fn capacity(&self) -> u32 {
        self.state.lock().max_offset
    }

    /// True if `ip` was drawn from this pool's range.
    #[inline]
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        self.network.contains(ip)
    }

    /// Return the address for `domain`, allocating one if it has none.
    ///
    /// Allocating recycles the least recently used mapping once the pool is
    /// full, so this never fails.
    pub fn assign(&self, domain: &str) -> Ipv4Addr {
        let mut state = self.state.lock();

        // `get` rather than `peek`: this is also what marks the domain as
        // recently used, which is what keeps an active domain from being
        // recycled out from under a live connection.
        if let Some(ip) = state.domain_to_ip.get(domain) {
            return *ip;
        }

        let offset = if state.next_offset <= state.max_offset {
            let offset = state.next_offset;
            state.next_offset += 1;
            offset
        } else {
            match state.domain_to_ip.pop_lru() {
                Some((_evicted_domain, evicted_ip)) => {
                    state.ip_to_domain.remove(&evicted_ip);
                    self.network.offset_of(evicted_ip)
                }
                // Unreachable in practice: next_offset only passes max_offset
                // after that many insertions. Recycling offset 1 is still a
                // consistent state, so prefer it to a panic in a VPN data path.
                None => 1,
            }
        };

        let ip = self.network.address_at(offset);
        let domain: Arc<str> = Arc::from(domain);

        // Both maps hold the same Arc, so a domain is stored once.
        state.domain_to_ip.put(Arc::clone(&domain), ip);
        state.ip_to_domain.insert(ip, domain);

        ip
    }

    /// Recover the domain a fake address stands for.
    ///
    /// Returns `None` for an address outside the pool, or one whose mapping has
    /// been recycled.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<Arc<str>> {
        if !self.is_fake_ip(ip) {
            return None;
        }
        let state = self.state.lock();
        state.ip_to_domain.get(&ip).cloned()
    }

    /// Live mapping count. Assertions only — nothing in the data path needs it,
    /// and it is deliberately not called `len`, since this is not a collection.
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.state.lock().ip_to_domain.len()
    }
}

impl std::fmt::Debug for FakeIpPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIpPool")
            .field("network", &self.network)
            .field("entries", &self.state.lock().ip_to_domain.len())
            .finish()
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(cidr: &str, max_entries: usize) -> FakeIpPool {
        FakeIpPool::new(FakeIpNetwork::parse(cidr).unwrap(), max_entries).unwrap()
    }

    #[test]
    fn parses_cidr_and_clears_host_bits() {
        let network = FakeIpNetwork::parse("198.18.7.9/16").unwrap();
        assert_eq!(network.to_string(), "198.18.0.0/16");
        assert_eq!(network.usable_addresses(), 65534);
    }

    #[test]
    fn rejects_malformed_cidr() {
        for bad in [
            "198.18.0.0",     // no prefix
            "not-an-ip/16",   // bad address
            "198.18.0.0/abc", // bad prefix
            "198.18.0.0/7",   // wider than MIN_PREFIX_LEN
            "198.18.0.0/31",  // no usable hosts
            "198.18.0.0/33",  // not a v4 prefix at all
            "fd00::/16",      // v6 is not supported
        ] {
            assert!(
                FakeIpNetwork::parse(bad).is_err(),
                "expected '{}' to be rejected",
                bad
            );
        }
    }

    #[test]
    fn contains_only_its_own_range() {
        let network = FakeIpNetwork::parse("198.18.0.0/16").unwrap();
        assert!(network.contains("198.18.0.1".parse().unwrap()));
        assert!(network.contains("198.18.255.254".parse().unwrap()));
        assert!(!network.contains("198.19.0.1".parse().unwrap()));
        assert!(!network.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn assigns_sequentially_from_one() {
        let pool = pool("198.18.0.0/16", 8192);
        assert_eq!(pool.assign("example.com"), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(pool.assign("example.org"), Ipv4Addr::new(198, 18, 0, 2));
    }

    #[test]
    fn assignment_is_stable_for_the_same_domain() {
        let pool = pool("198.18.0.0/16", 8192);
        let first = pool.assign("example.com");
        pool.assign("other.example");
        assert_eq!(pool.assign("example.com"), first);
        assert_eq!(pool.entry_count(), 2);
    }

    #[test]
    fn round_trips_domain_through_address() {
        let pool = pool("198.18.0.0/16", 8192);
        let ip = pool.assign("example.com");
        assert_eq!(pool.lookup(ip).as_deref(), Some("example.com"));
    }

    #[test]
    fn lookup_rejects_addresses_outside_the_pool() {
        let pool = pool("198.18.0.0/16", 8192);
        pool.assign("example.com");
        assert_eq!(pool.lookup("8.8.8.8".parse().unwrap()), None);
        assert_eq!(pool.lookup("198.19.0.1".parse().unwrap()), None);
    }

    #[test]
    fn capacity_is_clamped_by_the_network_size() {
        // A /30 supplies two usable addresses even though 8192 were requested.
        let pool = pool("198.18.0.0/30", 8192);
        assert_eq!(pool.capacity(), 2);
    }

    #[test]
    fn capacity_is_clamped_by_max_entries() {
        // A /16 could supply 65534, but the ceiling wins.
        let pool = pool("198.18.0.0/16", 100);
        assert_eq!(pool.capacity(), 100);
    }

    #[test]
    fn recycles_the_least_recently_used_mapping_when_full() {
        let pool = pool("198.18.0.0/16", 2);

        let first = pool.assign("first.example");
        let second = pool.assign("second.example");

        // Touching `second` makes `first` the least recently used.
        assert_eq!(pool.assign("second.example"), second);

        let third = pool.assign("third.example");
        assert_eq!(third, first, "the recycled address should be reused");

        // The old mapping is gone in both directions, not just the LRU side.
        assert_eq!(pool.lookup(third).as_deref(), Some("third.example"));
        assert_eq!(
            pool.entry_count(),
            2,
            "the pool must not grow past its capacity"
        );
    }

    /// The reverse map is what the connect path reads. If eviction ever left a
    /// stale entry there, a connection would be routed to the wrong domain.
    #[test]
    fn both_maps_stay_exact_inverses_under_churn() {
        let pool = pool("198.18.0.0/24", 16);

        for i in 0..200 {
            pool.assign(&format!("host{}.example", i));
        }

        let state = pool.state.lock();
        assert_eq!(state.domain_to_ip.len(), state.ip_to_domain.len());
        assert!(state.ip_to_domain.len() <= 16);

        for (domain, ip) in state.domain_to_ip.iter() {
            assert_eq!(
                state.ip_to_domain.get(ip).map(|d| d.as_ref()),
                Some(domain.as_ref()),
                "domain_to_ip and ip_to_domain disagree about {}",
                ip
            );
        }
    }

    #[test]
    fn every_assigned_address_stays_inside_the_network() {
        let pool = pool("198.18.0.0/24", 64);
        for i in 0..500 {
            let ip = pool.assign(&format!("host{}.example", i));
            assert!(pool.is_fake_ip(ip), "{} escaped the pool range", ip);
            assert_ne!(ip, Ipv4Addr::new(198, 18, 0, 0), "network address issued");
            assert_ne!(
                ip,
                Ipv4Addr::new(198, 18, 0, 255),
                "broadcast address issued"
            );
        }
    }

    #[test]
    fn exhausting_a_tiny_pool_never_panics() {
        let pool = pool("198.18.0.0/30", 8192);
        for i in 0..50 {
            pool.assign(&format!("host{}.example", i));
        }
        assert_eq!(pool.entry_count(), 2);
    }

    #[test]
    fn rejects_zero_max_entries() {
        let network = FakeIpNetwork::parse("198.18.0.0/16").unwrap();
        assert!(FakeIpPool::new(network, 0).is_err());
    }
}
