//! Fake IP DNS.
//!
//! A DNS query for `example.com` is answered immediately with an address from a
//! private pool instead of a real one. The client connects to that address, and
//! the TUN turns it back into `example.com` before the connection is routed, so
//! the name reaches the proxy and is resolved at the far end.
//!
//! Two things come out of that:
//!
//! * **No DNS leak.** Nothing is resolved on the device, so no query reaches a
//!   local resolver. Queries this module does not answer — everything that is
//!   not an A record — are forwarded through the tunnel rather than answered
//!   locally.
//! * **One less round trip.** The client skips waiting for a real resolution
//!   before it can connect.
//!
//! It also means routing rules see the domain rather than an address, so
//! hostname-based rules work for traffic that arrived over the TUN.
//!
//! # Shape
//!
//! [`FakeIpPool`] owns the mapping. [`FakeIpResponder`] decides what to do with
//! a query and is pure — no sockets, no runtime — so the policy is testable on
//! its own. The TUN wires them in: interception in the UDP path, restoration
//! where a packet's destination becomes a routable location.
//!
//! The pool is passed explicitly rather than held in a global. A VPN service is
//! started and stopped repeatedly in one process, and a process-lifetime
//! singleton would carry one session's mappings into the next.

mod bypass;
mod pool;
mod responder;

pub use bypass::BypassList;
pub use pool::{DEFAULT_MAX_ENTRIES, FakeIpNetwork, FakeIpPool};
pub use responder::{DnsDecision, FakeIpResponder};

/// The port a DNS query arrives on. Traffic to this port is offered to the
/// responder no matter which server address the client chose, so an app that
/// hardcodes a public resolver is intercepted the same as one that follows the
/// system settings.
pub const DNS_PORT: u16 = 53;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::address::{Address, NetLocation};

/// Turn a packet's destination into a routable location, restoring the original
/// domain if the address came from `pool`.
///
/// This is the counterpart to the DNS side, and it runs *before* routing rules
/// are applied, so hostname rules match traffic that arrived over the TUN. With
/// no pool configured it is the plain address conversion.
pub fn destination_to_net_location(
    addr: SocketAddr,
    pool: Option<&Arc<FakeIpPool>>,
) -> NetLocation {
    if let std::net::IpAddr::V4(v4) = addr.ip()
        && let Some(pool) = pool
        && let Some(domain) = pool.lookup(v4)
    {
        return NetLocation::new(Address::Hostname(domain.to_string()), addr.port());
    }

    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Arc<FakeIpPool> {
        Arc::new(FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 64).unwrap())
    }

    #[test]
    fn restores_the_domain_behind_a_fake_address() {
        let pool = pool();
        let ip = pool.assign("example.com");
        let addr = SocketAddr::from((ip, 443));

        let location = destination_to_net_location(addr, Some(&pool));
        assert_eq!(
            location.address(),
            &Address::Hostname("example.com".to_string())
        );
        assert_eq!(location.port(), 443);
    }

    #[test]
    fn leaves_real_addresses_alone() {
        let pool = pool();
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let location = destination_to_net_location(addr, Some(&pool));
        assert_eq!(
            location.address(),
            &Address::Ipv4("1.1.1.1".parse().unwrap())
        );
    }

    /// An address inside the pool range that was never handed out, or whose
    /// mapping has been recycled, must stay an address rather than becoming
    /// some other domain.
    #[test]
    fn leaves_unmapped_pool_addresses_alone() {
        let pool = pool();
        let addr: SocketAddr = "198.18.9.9:443".parse().unwrap();
        let location = destination_to_net_location(addr, Some(&pool));
        assert_eq!(
            location.address(),
            &Address::Ipv4("198.18.9.9".parse().unwrap())
        );
    }

    #[test]
    fn without_a_pool_it_is_the_plain_conversion() {
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let location = destination_to_net_location(addr, None);
        assert_eq!(
            location.address(),
            &Address::Ipv4("1.1.1.1".parse().unwrap())
        );

        let v6: SocketAddr = "[2606:4700::1111]:443".parse().unwrap();
        let location = destination_to_net_location(v6, None);
        assert_eq!(
            location.address(),
            &Address::Ipv6("2606:4700::1111".parse().unwrap())
        );
    }
}
