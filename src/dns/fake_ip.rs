use lru::LruCache;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

pub static GLOBAL_FAKE_IP_MANAGER: OnceLock<Arc<FakeIpManager>> = OnceLock::new();

pub struct FakeIpManager {
    // IPv4 Network and Mask
    network: u32,
    mask: u32,
    state: RwLock<FakeIpState>,
}

struct FakeIpState {
    domain_to_ip: LruCache<String, Ipv4Addr>,
    ip_to_domain: FxHashMap<Ipv4Addr, String>,
    next_offset: u32,
    max_offset: u32,
}

impl FakeIpManager {
    /// Creates a new FakeIpManager given an IPv4 network and a prefix length (e.g., 198.18.0.0, 16)
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Arc<Self> {
        assert!(prefix_len <= 30 && prefix_len >= 8, "Prefix length must be between 8 and 30");
        let net_u32 = u32::from(network);
        let mask = !0u32 << (32 - prefix_len);
        let network_addr = net_u32 & mask;
        let max_offset = !mask - 1; // Exclude broadcast
        let capacity = NonZeroUsize::new(max_offset as usize).expect("Capacity cannot be zero");

        Arc::new(Self {
            network: network_addr,
            mask,
            state: RwLock::new(FakeIpState {
                domain_to_ip: LruCache::new(capacity),
                ip_to_domain: FxHashMap::default(),
                next_offset: 1, // Start from 1, exclude network address
                max_offset,
            }),
        })
    }

    /// Fast check to see if an IP belongs to the FakeIP range
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        (ip_u32 & self.mask) == self.network
    }

    /// Lookup a Fake IP for a domain. If it doesn't exist, allocates a new one.
    pub fn lookup_domain(&self, domain: &str) -> Ipv4Addr {
        let mut state = self.state.write();

        // Already assigned?
        if let Some(ip) = state.domain_to_ip.get(domain) {
            return *ip;
        }

        // Need new IP
        let offset = if state.next_offset <= state.max_offset {
            let o = state.next_offset;
            state.next_offset += 1;
            o
        } else {
            // Pool exhausted, evict the LRU
            let (_old_domain, old_ip) = state.domain_to_ip.pop_lru().expect("Cache full but empty");
            state.ip_to_domain.remove(&old_ip);
            u32::from(old_ip) - self.network
        };

        let new_ip = Ipv4Addr::from(self.network + offset);

        // Put to caches
        state.domain_to_ip.put(domain.to_string(), new_ip);
        state.ip_to_domain.insert(new_ip, domain.to_string());

        new_ip
    }

    /// Lookup a domain by its Fake IP.
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<String> {
        let state = self.state.read();
        state.ip_to_domain.get(&ip).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_manager() {
        // 198.18.0.0/30 has only 2 usable IPs: 198.18.0.1 and .2
        let mgr = FakeIpManager::new(Ipv4Addr::new(198, 18, 0, 0), 30);
        
        let ip1 = mgr.lookup_domain("google.com");
        assert_eq!(ip1, Ipv4Addr::new(198, 18, 0, 1));
        assert!(mgr.is_fake_ip(ip1));

        let ip2 = mgr.lookup_domain("youtube.com");
        assert_eq!(ip2, Ipv4Addr::new(198, 18, 0, 2));

        // Pool is full. Next allocation should evict google.com (least recently used)
        let ip3 = mgr.lookup_domain("facebook.com");
        assert_eq!(ip3, Ipv4Addr::new(198, 18, 0, 1));

        // Now google.com is gone
        assert_eq!(mgr.lookup_ip(Ipv4Addr::new(198, 18, 0, 1)), Some("facebook.com".to_string()));

        // Lookup youtube again to make it recently used
        let ip2_again = mgr.lookup_domain("youtube.com");
        assert_eq!(ip2_again, Ipv4Addr::new(198, 18, 0, 2));

        // Now evict again, it should pop facebook.com because youtube.com is recently used
        let ip4 = mgr.lookup_domain("twitter.com");
        assert_eq!(ip4, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(mgr.lookup_ip(Ipv4Addr::new(198, 18, 0, 1)), Some("twitter.com".to_string()));
    }
}