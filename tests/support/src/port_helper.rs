//! Port allocation and readiness helper for tests
//!
//! Provides centralized port allocation with tracking and synchronization.
//! All tests should use PortHelper instead of directly allocating ports.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, sleep, timeout};

/// Helper for allocating random ports and waiting for them to be ready.
/// Tracks all listener ports so we can wait for them to be ready before tests run.
#[derive(Default)]
pub struct PortHelper {
    listener_addrs: Vec<SocketAddr>,
}

impl PortHelper {
    /// Create a new PortHelper
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a random available address (IP, port) for a listening server.
    /// Returns (IP as String, port) where IP is in range 127.0.0.1-127.0.0.255.
    /// This address will be tracked and waited for in wait_for_all_ports().
    pub fn get_listener_port(&mut self) -> (String, u16) {
        let (ip, port) = get_random_addr();
        self.listener_addrs
            .push(format!("{ip}:{port}").parse().unwrap());
        (ip, port)
    }

    /// Get a random available address for a client/connector.
    /// This address will NOT be tracked (clients don't listen).
    pub fn get_port(&mut self) -> (String, u16) {
        get_random_addr()
    }

    /// Get a random available address for a QUIC/UDP listener.
    /// This address will NOT be tracked for TCP readiness checks since QUIC uses UDP.
    /// Use this for Hysteria2, TUIC, and other QUIC-based servers.
    pub fn get_quic_listener_port(&mut self) -> (String, u16) {
        get_random_udp_addr()
    }

    /// Get a random available port on 127.0.0.1 for a listening server.
    ///
    /// IMPORTANT: This is required for tests using libcronet (sing-box naive outbound).
    /// libcronet rejects connections to non-127.0.0.1 loopback addresses (e.g., 127.x.y.z)
    /// with "connection refused" or "invalid argument" errors. This appears to be a
    /// security restriction in Chromium's network stack.
    ///
    /// Returns ("127.0.0.1", port).
    pub fn get_localhost_listener_port(&mut self) -> (String, u16) {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("failed to allocate a localhost test port");
        let port = listener
            .local_addr()
            .expect("failed to read allocated localhost test port")
            .port();
        let addr = ("127.0.0.1".to_string(), port);
        self.listener_addrs
            .push(format!("{}:{}", addr.0, addr.1).parse().unwrap());
        addr
    }

    pub fn get_ipv6_listener_port(&mut self) -> (String, u16) {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .expect("failed to allocate an IPv6 test port");
        let address = listener
            .local_addr()
            .expect("failed to read the allocated IPv6 test port");
        self.listener_addrs.push(address);
        (address.ip().to_string(), address.port())
    }

    /// Wait for all tracked listener addresses to be ready for connections.
    /// Waits for all addresses in parallel with a 30 second timeout per address.
    /// If any address doesn't become ready, returns an error.
    pub async fn wait_for_all_ports(&mut self) -> std::io::Result<()> {
        use futures::future::join_all;

        let futures: Vec<_> = std::mem::take(&mut self.listener_addrs)
            .into_iter()
            .map(|addr| wait_for_addr(addr, Duration::from_secs(30)))
            .collect();

        let results = join_all(futures).await;

        // Check if any failed
        for result in results {
            result?;
        }

        Ok(())
    }
}

/// Get a random available address (IP, port) by generating random IP in 127.0.0.1-255 range
/// and random port. This dramatically reduces collision probability in parallel test execution
/// by expanding the address space.
fn get_random_addr() -> (String, u16) {
    use rand::RngExt;
    let mut rng = rand::rng();

    for _ in 0..10 {
        // Generate random IP in 127.0.0.1-255 range
        let ip_suffix1: u8 = rng.random_range(0..=255);
        let ip_suffix2: u8 = rng.random_range(0..=255);
        let ip_suffix3: u8 = rng.random_range(1..=255);
        let ip = Ipv4Addr::new(127, ip_suffix1, ip_suffix2, ip_suffix3);
        if ip == Ipv4Addr::LOCALHOST {
            // don't use localhost since it might be used up
            continue;
        }

        if let Ok(listener) = TcpListener::bind((ip, 0)) {
            let port = listener.local_addr().unwrap().port();
            if UdpSocket::bind((ip, port)).is_ok() {
                return (ip.to_string(), port);
            }
        }
    }

    unreachable!();
}

fn get_random_udp_addr() -> (String, u16) {
    let (ip, _) = get_random_addr();
    let socket = UdpSocket::bind(format!("{ip}:0")).expect("failed to allocate a UDP test port");
    let port = socket
        .local_addr()
        .expect("failed to read allocated UDP test port")
        .port();
    (ip, port)
}

/// Wait for an address (IP, port) to be ready for connections by attempting TCP connections.
/// Retries every 100ms for up to the specified timeout duration.
/// Returns Ok(()) if address becomes available, Err if timeout is reached.
async fn wait_for_addr(addr: SocketAddr, wait_timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + wait_timeout;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Address {addr} did not become ready within {wait_timeout:?}"),
            ));
        }

        let remaining = deadline - now;
        if timeout(remaining, TcpStream::connect(addr))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            return Ok(());
        }

        // Wait a bit before retrying
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_only_waits_for_pending_listeners() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut ports = PortHelper::new();
        ports.listener_addrs.push(addr);

        ports.wait_for_all_ports().await.unwrap();
        drop(listener);

        ports.wait_for_all_ports().await.unwrap();
    }

    #[tokio::test]
    async fn readiness_uses_the_shared_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let wait_timeout = Duration::from_millis(25);
        let started = Instant::now();
        let error = wait_for_addr(addr, wait_timeout).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
