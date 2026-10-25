//! DNS resolver module with configurable DNS servers.
//!
//! Supports:
//! - System resolver (NativeResolver)
//! - UDP DNS
//! - TCP DNS
//! - DNS-over-TLS (DoT) - requires `hickory-tls` feature
//! - DNS-over-HTTPS (DoH) - requires `hickory-https` feature
//!
//! TCP-based protocols (tcp://, tls://, https://) support routing through
//! proxy chains via the ProxyRuntimeProvider.

mod builder;
mod composite_resolver;
mod exchange;
pub mod fake_ip;
mod guard;
mod hickory_resolver;
mod message;
mod parsed;
mod proxy_runtime;
mod system;

pub(crate) use guard::{SyntheticDnsAnswer, real_only};

/// Binds a TCP listener and a UDP socket on one loopback port, as DNS servers listen. A
/// free TCP port does not imply a free UDP port, so retry with new ports.
#[cfg(test)]
pub(crate) async fn bind_tcp_and_udp() -> (tokio::net::TcpListener, tokio::net::UdpSocket) {
    let ip = std::net::Ipv4Addr::LOCALHOST;
    for _ in 0..64 {
        let tcp = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        match tokio::net::UdpSocket::bind((ip, port)).await {
            Ok(udp) => return (tcp, udp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("binding UDP port {port}: {error}"),
        }
    }
    panic!("no port was free for both TCP and UDP");
}

#[allow(unused_imports)]
pub use builder::{
    DnsRegistry, DnsSnapshotTask, build_dns_registry, build_dns_registry_for_runtime,
    build_dns_registry_reusing, build_dns_registry_with_limits,
};
pub use parsed::{IpStrategy, ParsedDnsUrl};
#[cfg(all(test, unix))]
pub(crate) use proxy_runtime::ProxyRuntimeProvider;
