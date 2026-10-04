use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

fn setting(name: &str, default: usize, min: usize, max: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => match value.parse::<usize>() {
            Ok(value) if (min..=max).contains(&value) => value,
            _ => {
                log::warn!("Invalid {name}; using {default} (allowed {min}..={max})");
                default
            }
        },
        Err(_) => default,
    }
}

/// Process-wide, startup-only settings. TUN-specific budgets remain in TunConfig.
#[derive(Debug)]
pub struct ResourceLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_streams: usize,
    pub max_streams_per_connection: usize,
    pub max_udp_destinations: usize,
    pub quic_receive_window: usize,
    pub quic_send_window: usize,
    pub quic_stream_window: usize,
    pub quic_memory_bytes: usize,
    pub quic_socket_buffer: usize,
}

pub static LIMITS: LazyLock<ResourceLimits> = LazyLock::new(|| ResourceLimits {
    max_connections: setting("SHOES_MAX_CONNECTIONS", 256, 1, 1_000_000),
    max_connections_per_ip: setting("SHOES_MAX_CONNECTIONS_PER_IP", 64, 1, 1_000_000),
    max_streams: setting("SHOES_MAX_STREAMS", 512, 1, 1_000_000),
    max_streams_per_connection: setting("SHOES_MAX_STREAMS_PER_CONNECTION", 64, 1, 65535),
    max_udp_destinations: setting("SHOES_MAX_UDP_DESTINATIONS", 64, 1, 65535),
    quic_receive_window: setting("SHOES_QUIC_RECEIVE_WINDOW", 2 << 20, 65536, 64 << 20),
    quic_send_window: setting("SHOES_QUIC_SEND_WINDOW", 2 << 20, 65536, 64 << 20),
    quic_stream_window: setting("SHOES_QUIC_STREAM_WINDOW", 256 << 10, 16384, 64 << 20),
    quic_memory_bytes: setting("SHOES_QUIC_MEMORY_BYTES", 64 << 20, 1 << 20, 1 << 30),
    quic_socket_buffer: setting("SHOES_QUIC_SOCKET_BUFFER", 1 << 20, 65536, 16 << 20),
});

struct Budget {
    slots: Arc<Semaphore>,
    total: usize,
    peak: AtomicUsize,
    rejected: AtomicU64,
}

impl Budget {
    fn new(total: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(total)),
            total,
            peak: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    fn acquire(&self, count: u32) -> Option<OwnedSemaphorePermit> {
        match self.slots.clone().try_acquire_many_owned(count) {
            Ok(permit) => {
                self.peak.fetch_max(
                    self.total - self.slots.available_permits(),
                    Ordering::Relaxed,
                );
                Some(permit)
            }
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            active: self.total - self.slots.available_permits(),
            peak: self.peak.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

static CONNECTIONS: LazyLock<Budget> = LazyLock::new(|| Budget::new(LIMITS.max_connections));
static STREAMS: LazyLock<Budget> = LazyLock::new(|| Budget::new(LIMITS.max_streams));
static QUIC_BYTES: LazyLock<Budget> = LazyLock::new(|| Budget::new(LIMITS.quic_memory_bytes));
static PEERS: LazyLock<Mutex<HashMap<IpAddr, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PEER_REJECTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    peer: Option<IpAddr>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(peer) = self.peer {
            let mut peers = PEERS.lock();
            if let Some(count) = peers.get_mut(&peer) {
                *count -= 1;
                if *count == 0 {
                    peers.remove(&peer);
                }
            }
        }
    }
}

pub(crate) fn try_connection(peer: Option<IpAddr>) -> Option<ConnectionPermit> {
    let permit = CONNECTIONS.acquire(1)?;
    let peer = peer.map(|ip| match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    });
    if let Some(peer) = peer {
        let mut peers = PEERS.lock();
        let count = peers.entry(peer).or_default();
        if *count >= LIMITS.max_connections_per_ip {
            PEER_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
    }
    Some(ConnectionPermit {
        _global: permit,
        peer,
    })
}

pub(crate) fn try_stream() -> Option<OwnedSemaphorePermit> {
    STREAMS.acquire(1)
}

pub(crate) fn exhausted() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "process resource budget exhausted",
    )
}

const DATAGRAM_BUFFER: usize = 256 << 10;

/// Reserve configured QUIC buffering allowances, not an estimate of total RSS.
pub(crate) fn try_quic_memory() -> Option<OwnedSemaphorePermit> {
    QUIC_BYTES.acquire(
        (LIMITS.quic_receive_window + LIMITS.quic_send_window + 2 * DATAGRAM_BUFFER) as u32,
    )
}

pub(crate) fn configure_quic(config: &mut quinn::ServerConfig, uni_streams: u32) {
    config
        .max_incoming(LIMITS.max_connections.min(128))
        .incoming_buffer_size(65536)
        .incoming_buffer_size_total(1 << 20);
    let transport = Arc::get_mut(&mut config.transport).unwrap();
    configure_quic_transport(transport);
    transport
        .max_concurrent_bidi_streams((LIMITS.max_streams_per_connection as u32).into())
        .max_concurrent_uni_streams(uni_streams.into());
}

pub(crate) fn configure_quic_transport(transport: &mut quinn::TransportConfig) {
    transport
        .receive_window((LIMITS.quic_receive_window as u32).into())
        .send_window(LIMITS.quic_send_window as u64)
        .stream_receive_window(
            (LIMITS.quic_stream_window.min(LIMITS.quic_receive_window) as u32).into(),
        )
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_BUFFER);
}

#[derive(Debug)]
pub struct BudgetSnapshot {
    pub active: usize,
    pub peak: usize,
    pub rejected: u64,
}

#[derive(Debug)]
pub struct ResourceSnapshot {
    pub connections: BudgetSnapshot,
    pub streams: BudgetSnapshot,
    pub quic_buffer_bytes: BudgetSnapshot,
    pub peer_rejections: u64,
}

impl std::fmt::Display for BudgetSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "active={} peak={} refused={}", self.active, self.peak, self.rejected)
    }
}

impl std::fmt::Display for ResourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connections[{}] streams[{}] quic_reserved_bytes[{}] per_ip_refused={}",
            self.connections, self.streams, self.quic_buffer_bytes, self.peer_rejections)
    }
}

pub fn snapshot() -> ResourceSnapshot {
    ResourceSnapshot {
        connections: CONNECTIONS.snapshot(),
        streams: STREAMS.snapshot(),
        quic_buffer_bytes: QUIC_BYTES.snapshot(),
        peer_rejections: PEER_REJECTIONS.load(Ordering::Relaxed),
    }
}

pub(crate) struct ResourceReporter(tokio::task::AbortHandle);

impl ResourceReporter {
    pub fn start() -> Self {
        log::info!("Process resource limits: {:?}", *LIMITS);
        let task = tokio::spawn(async {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                log::info!("Resource usage: {}", snapshot());
            }
        });
        Self(task.abort_handle())
    }
}

impl Drop for ResourceReporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_bound_work_and_return_on_drop() {
        let budget = Budget::new(3);
        let first = budget.acquire(2).unwrap();
        assert!(budget.acquire(2).is_none());
        let second = budget.acquire(1).unwrap();
        assert_eq!(budget.snapshot().active, 3);
        assert_eq!(budget.snapshot().peak, 3);
        assert_eq!(budget.snapshot().rejected, 1);
        drop(first);
        drop(second);
        assert_eq!(budget.snapshot().active, 0);
        assert!(budget.acquire(3).is_some());
    }

    #[test]
    fn peer_entries_are_released_with_connections() {
        let peer: IpAddr = "198.51.100.254".parse().unwrap();
        let permit = try_connection(Some(peer)).unwrap();
        assert_eq!(PEERS.lock().get(&peer), Some(&1));
        drop(permit);
        assert!(!PEERS.lock().contains_key(&peer));
    }

    #[tokio::test]
    async fn cancelled_work_returns_its_budget() {
        let budget = Budget::new(1);
        let permit = budget.acquire(1).unwrap();
        let task = tokio::spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        task.abort();
        let _ = task.await;
        assert_eq!(budget.snapshot().active, 0);
    }

    #[test]
    fn environment_limits_apply_in_a_fresh_process() {
        if std::env::var_os("SHOES_RESOURCE_TEST_CHILD").is_some() {
            assert_eq!(LIMITS.max_connections, 2);
            assert_eq!(LIMITS.max_connections_per_ip, 1);
            let peer: IpAddr = "192.0.2.1".parse().unwrap();
            let first = try_connection(Some(peer)).unwrap();
            assert!(try_connection(Some(peer)).is_none());
            let second = try_connection(None).unwrap();
            assert!(try_connection(None).is_none());
            drop(first);
            drop(second);
            assert_eq!(snapshot().connections.active, 0);
            assert!(PEERS.lock().is_empty());
        } else {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "resources::tests::environment_limits_apply_in_a_fresh_process", "--quiet"])
                .env("SHOES_RESOURCE_TEST_CHILD", "1")
                .env("SHOES_MAX_CONNECTIONS", "2")
                .env("SHOES_MAX_CONNECTIONS_PER_IP", "1")
                .status().unwrap();
            assert!(status.success());
        }
    }
}
