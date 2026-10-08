use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use parking_lot::{Mutex, RwLock};

use crate::config::GlobalLimits;

static LIMITS: LazyLock<RwLock<GlobalLimits>> = LazyLock::new(Default::default);

pub(crate) fn limits() -> GlobalLimits {
    *LIMITS.read()
}

pub(crate) fn configure(limits: GlobalLimits) -> std::io::Result<()> {
    limits.validate()?;
    let mut current = LIMITS.write();
    CONNECTIONS.set_limit(limits.max_connections);
    STREAMS.set_limit(limits.max_streams);
    QUIC_BYTES.set_limit(limits.quic_memory_bytes);
    *current = limits;
    Ok(())
}

#[derive(Debug, Default)]
struct BudgetState {
    limit: Option<usize>,
    active: usize,
    peak: usize,
    rejected: u64,
}

#[derive(Debug)]
pub(crate) struct Budget(Mutex<BudgetState>);

impl Budget {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self(Mutex::new(BudgetState {
            limit,
            ..Default::default()
        }))
    }

    fn set_limit(&self, limit: Option<usize>) {
        // Keep outstanding reservations when a config reload changes admission policy.
        self.0.lock().limit = limit;
    }

    pub(crate) fn acquire(self: &Arc<Self>, count: usize) -> Option<BudgetPermit> {
        let mut state = self.0.lock();
        let active = state.active.checked_add(count)?;
        if state.limit.is_some_and(|limit| active > limit) {
            state.rejected += 1;
            return None;
        }
        state.active = active;
        state.peak = state.peak.max(active);
        Some(BudgetPermit {
            budget: self.clone(),
            count,
        })
    }

    pub(crate) fn snapshot(&self) -> BudgetSnapshot {
        let state = self.0.lock();
        BudgetSnapshot {
            active: state.active,
            peak: state.peak,
            rejected: state.rejected,
        }
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        let state = self.0.lock();
        state
            .limit
            .unwrap_or(usize::MAX)
            .saturating_sub(state.active)
    }
}

#[derive(Debug)]
pub(crate) struct BudgetPermit {
    budget: Arc<Budget>,
    count: usize,
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        self.budget.0.lock().active -= self.count;
    }
}

static CONNECTIONS: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(None)));
static STREAMS: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(None)));
static QUIC_BYTES: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(None)));
static PEERS: LazyLock<Mutex<HashMap<IpAddr, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PEER_REJECTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ConnectionPermit {
    _global: BudgetPermit,
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
    let limits = LIMITS.read();
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
        if limits
            .max_connections_per_ip
            .is_some_and(|limit| *count >= limit)
        {
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

pub(crate) fn try_stream() -> Option<BudgetPermit> {
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
pub(crate) fn try_quic_memory(bytes: usize) -> Option<BudgetPermit> {
    QUIC_BYTES.acquire(bytes)
}

pub(crate) fn quic_memory_exhausted(bytes: usize) -> std::io::Error {
    let state = QUIC_BYTES.0.lock();
    let limit = state
        .limit
        .map_or_else(|| "unlimited".to_owned(), |limit| limit.to_string());
    std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        format!(
            "QUIC memory budget exhausted: requested {bytes} bytes, active {} bytes, live cap {limit}",
            state.active,
        ),
    )
}

pub(crate) fn configure_quic(
    config: &mut quinn::ServerConfig,
    bidi_streams: u32,
    uni_streams: u32,
) -> usize {
    let limits = limits();
    // Pending Initials are buffered before connection memory is reserved.
    config
        .max_incoming(limits.max_connections.unwrap_or(128).min(128))
        .incoming_buffer_size(65536)
        .incoming_buffer_size_total(1 << 20);
    let transport = Arc::get_mut(&mut config.transport).unwrap();
    let memory_bytes = configure_quic_transport(transport);
    // Quinn eagerly allocates advertised stream credit. Unlimited admission keeps
    // the protocol's existing flow-control window rather than advertising infinity.
    let (bidi_streams, uni_streams) = match limits.max_streams_per_connection {
        Some(limit) => {
            let limit = limit as u32;
            (limit, uni_streams.min(limit))
        }
        None => (bidi_streams, uni_streams),
    };
    transport
        .max_concurrent_bidi_streams(bidi_streams.into())
        .max_concurrent_uni_streams(uni_streams.into());
    memory_bytes
}

/// Returns the per-connection allowance from the same limits used to configure the windows.
pub(crate) fn configure_quic_transport(transport: &mut quinn::TransportConfig) -> usize {
    configure_quic_transport_with_limits(transport, limits())
}

pub(crate) fn configure_quic_transport_with_limits(
    transport: &mut quinn::TransportConfig,
    limits: GlobalLimits,
) -> usize {
    transport
        .receive_window((limits.quic_receive_window as u32).into())
        .send_window(limits.quic_send_window as u64)
        .stream_receive_window(
            (limits.quic_stream_window.min(limits.quic_receive_window) as u32).into(),
        )
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_BUFFER);
    limits.quic_receive_window + limits.quic_send_window + 2 * DATAGRAM_BUFFER
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
        write!(
            f,
            "active={} peak={} refused={}",
            self.active, self.peak, self.rejected
        )
    }
}

impl std::fmt::Display for ResourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "connections[{}] streams[{}] quic_reserved_bytes[{}] per_ip_refused={}",
            self.connections, self.streams, self.quic_buffer_bytes, self.peer_rejections
        )
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
        log::info!("Process resource limits: {:?}", limits());
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
    fn unlimited_budget_tracks_usage_without_a_semaphore_ceiling() {
        let budget = Arc::new(Budget::new(None));
        let permit = budget.acquire(usize::MAX).unwrap();
        assert_eq!(budget.snapshot().active, usize::MAX);
        assert!(budget.acquire(1).is_none());
        drop(permit);
        assert_eq!(budget.snapshot().active, 0);
        assert!(budget.acquire(1024).is_some());
    }

    #[test]
    fn permits_bound_work_and_return_on_drop() {
        let budget = Arc::new(Budget::new(Some(3)));
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
        let budget = Arc::new(Budget::new(Some(1)));
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
    fn yaml_limits_apply_in_a_fresh_process() {
        if std::env::var_os("SHOES_RESOURCE_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "resources::tests::yaml_limits_apply_in_a_fresh_process",
                    "--quiet",
                ])
                .env("SHOES_RESOURCE_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let defaults = limits();
        assert!(defaults.max_connections.is_none());
        assert!(defaults.max_connections_per_ip.is_none());
        assert!(defaults.max_streams.is_none());
        assert!(defaults.quic_memory_bytes.is_none());
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let connections: Vec<_> = (0..1024)
            .map(|_| try_connection(Some(peer)).unwrap())
            .collect();
        let streams: Vec<_> = (0..1024).map(|_| try_stream().unwrap()).collect();
        let memory = QUIC_BYTES.acquire(128 << 20).unwrap();
        drop((connections, streams, memory));

        let configs = serde_yaml::from_str(
            r#"- global_limits:
    max_connections: 2
    max_connections_per_ip: 1
    max_streams: 1
    quic_memory_bytes: 16777216
"#,
        )
        .unwrap();
        let config = crate::config::create_server_configs(configs).unwrap();
        configure(config.global_limits).unwrap();
        assert_eq!(limits().max_connections, Some(2));
        assert_eq!(limits().max_connections_per_ip, Some(1));
        let first = try_connection(Some(peer)).unwrap();
        assert!(try_connection(Some(peer)).is_none());
        let second = try_connection(None).unwrap();
        assert!(try_connection(None).is_none());
        drop(first);
        drop(second);
        assert_eq!(snapshot().connections.active, 0);
        assert!(PEERS.lock().is_empty());

        let stream = try_stream().unwrap();
        assert!(try_stream().is_none());
        configure(defaults).unwrap();
        let second_stream = try_stream().unwrap();
        assert_eq!(snapshot().streams.active, 2);
        drop((stream, second_stream));
        assert_eq!(snapshot().streams.active, 0);
    }

    #[test]
    fn changing_limits_preserves_outstanding_reservations() {
        let budget = Arc::new(Budget::new(None));
        let first = budget.acquire(3).unwrap();
        budget.set_limit(Some(2));
        assert_eq!(budget.snapshot().active, 3);
        assert!(budget.acquire(1).is_none());
        drop(first);
        let second = budget.acquire(2).unwrap();
        assert!(budget.acquire(1).is_none());
        budget.set_limit(None);
        let third = budget.acquire(1024).unwrap();
        drop((second, third));
        assert_eq!(budget.snapshot().active, 0);
    }

    #[test]
    fn concurrent_admission_does_not_exceed_explicit_limit() {
        let budget = Arc::new(Budget::new(Some(4)));
        let barrier = std::sync::Barrier::new(9);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let permit = budget.acquire(1);
                    barrier.wait();
                    barrier.wait();
                    drop(permit);
                });
            }
            barrier.wait();
            assert_eq!(budget.snapshot().active, 4);
            assert_eq!(budget.snapshot().rejected, 4);
            barrier.wait();
        });
        assert_eq!(budget.snapshot().active, 0);
        assert_eq!(budget.snapshot().peak, 4);
    }
}
