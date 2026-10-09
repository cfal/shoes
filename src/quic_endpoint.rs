use std::cell::RefCell;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::resources::BudgetPermit;
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::AbortOnDropHandle;

const LISTENER_CLOSE_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct ListenerRuntime {
    endpoint_started: AtomicBool,
    retired: CancellationToken,
}

impl Runtime for ListenerRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(deadline)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Quinn 0.11 spawns the endpoint driver synchronously before exposing the
        // endpoint. Later spawns are connection drivers; recheck this on upgrades.
        if self.endpoint_started.swap(true, Ordering::Relaxed) {
            quinn::TokioRuntime.spawn(future);
            return;
        }
        let mut driver = AbortOnDropHandle::new(tokio::spawn(future));
        let retired = self.retired.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = &mut driver => {},
                _ = async {
                    retired.cancelled().await;
                    tokio::time::sleep(LISTENER_CLOSE_GRACE).await;
                } => {},
            }
            // Dropping the endpoint driver closes its connection-event channels.
            // Connection drivers then terminate and wake application waiters.
        });
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        quinn::TokioRuntime.now()
    }
}

tokio::task_local! {
    static CONNECTION_MEMORY: RefCell<Option<BudgetPermit>>;
}

/// Quinn replaces connection pollers on rebind, so this wrapper deliberately
/// exposes no rebinding API. Reload creates fresh endpoints instead.
#[derive(Debug)]
pub(crate) struct QuicEndpoint {
    inner: quinn::Endpoint,
    // Transport windows belong to this endpoint, not the latest config generation.
    memory_bytes: usize,
    _driver_retirement: Option<DropGuard>,
}

impl QuicEndpoint {
    pub fn new(
        config: Option<quinn::ServerConfig>,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
    ) -> io::Result<Self> {
        Self::with_release(config, socket, memory_bytes, None)
    }

    pub fn listen(
        config: quinn::ServerConfig,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
    ) -> io::Result<(Self, oneshot::Receiver<()>)> {
        let (release, released) = oneshot::channel();
        let endpoint = Self::with_release(Some(config), socket, memory_bytes, Some(release))?;
        Ok((endpoint, released))
    }

    fn with_release(
        config: Option<quinn::ServerConfig>,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
        release: Option<oneshot::Sender<()>>,
    ) -> io::Result<Self> {
        let (runtime, retirement): (Arc<dyn Runtime>, _) = if release.is_some() {
            let retired = CancellationToken::new();
            let runtime = ListenerRuntime {
                endpoint_started: AtomicBool::new(false),
                retired: retired.clone(),
            };
            (Arc::new(runtime), Some(retired.drop_guard()))
        } else {
            (Arc::new(quinn::TokioRuntime), None)
        };
        let socket = MemorySocket {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
            endpoint_memory: None,
            _release: release,
        };
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            config,
            Arc::new(socket),
            runtime,
        )
        .map(|inner| Self {
            inner,
            memory_bytes,
            _driver_retirement: retirement,
        })
    }

    pub fn set_default_client_config(&mut self, config: quinn::ClientConfig) {
        self.inner.set_default_client_config(config);
    }

    pub fn connect(&self, address: SocketAddr, name: &str) -> io::Result<quinn::Connecting> {
        let memory = crate::resources::try_quic_memory(self.memory_bytes)
            .ok_or_else(|| crate::resources::quic_memory_exhausted(self.memory_bytes))?;
        self.connect_with_memory(address, name, memory)
    }

    fn connect_with_memory(
        &self,
        address: SocketAddr,
        name: &str,
        memory: BudgetPermit,
    ) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.inner.connect(address, name).map_err(io::Error::other)
        })
    }

    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await.map(|inner| Incoming {
            inner,
            memory_bytes: self.memory_bytes,
        })
    }

    pub fn close(&self, code: quinn::VarInt, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    #[cfg(test)]
    async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

pub(crate) struct Incoming {
    inner: quinn::Incoming,
    memory_bytes: usize,
}

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    pub fn refuse(self) {
        self.inner.refuse();
    }

    pub fn accept(self) -> io::Result<quinn::Connecting> {
        let Some(memory) = crate::resources::try_quic_memory(self.memory_bytes) else {
            let error = crate::resources::quic_memory_exhausted(self.memory_bytes);
            self.refuse();
            return Err(error);
        };
        self.accept_with_memory(memory)
    }

    fn accept_with_memory(self, memory: BudgetPermit) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.inner.accept().map_err(io::Error::from)
        })
    }
}

/// For a dedicated single-connection endpoint, such as Hickory's H3 client.
/// Pooled endpoints must reserve each connection through QuicEndpoint instead.
pub(crate) fn socket_with_memory(
    socket: std::net::UdpSocket,
    memory: BudgetPermit,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    Ok(Arc::new(MemorySocket {
        inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
        endpoint_memory: Some(memory),
        _release: None,
    }))
}

#[derive(Debug)]
struct MemorySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    endpoint_memory: Option<BudgetPermit>,
    // Field order signals retirement only after the native socket has been dropped.
    _release: Option<oneshot::Sender<()>>,
}

impl AsyncUdpSocket for MemorySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        if self.endpoint_memory.is_some() {
            return self.inner.clone().create_io_poller();
        }
        // Quinn creates one poller synchronously inside connect/accept. Its State
        // drops protocol stream/datagram buffers before dropping this poller,
        // including when application handles survive driver completion.
        let memory = CONNECTION_MEMORY.with(|memory| {
            memory
                .borrow_mut()
                .take()
                .expect("QUIC memory reserved once per connection")
        });
        Box::pin(MemoryPoller {
            inner: self.inner.clone().create_io_poller(),
            _memory: memory,
            _socket: self,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct MemoryPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    _memory: BudgetPermit,
    // The delegated poller owns a socket reference and must drop before the release signal.
    _socket: Arc<MemorySocket>,
}

impl UdpPoller for MemoryPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::resources::Budget;
    use bytes::Bytes;
    use tokio::time::timeout;

    #[tokio::test(start_paused = true)]
    async fn listener_runtime_cancels_only_the_endpoint_driver_after_grace() {
        let retired = CancellationToken::new();
        let runtime = ListenerRuntime {
            endpoint_started: AtomicBool::new(false),
            retired: retired.clone(),
        };
        let endpoint = Arc::new(());
        let owned_endpoint = endpoint.clone();
        runtime.spawn(Box::pin(async move {
            let _owned = owned_endpoint;
            std::future::pending::<()>().await;
        }));
        let connection = Arc::new(());
        let owned_connection = connection.clone();
        let (finish, finished) = oneshot::channel();
        runtime.spawn(Box::pin(async move {
            let _owned = owned_connection;
            let _ = finished.await;
        }));
        tokio::task::yield_now().await;
        retired.cancel();
        tokio::task::yield_now().await;
        tokio::time::advance(LISTENER_CLOSE_GRACE - Duration::from_millis(1)).await;
        assert_eq!(Arc::strong_count(&endpoint), 2);
        tokio::time::advance(Duration::from_millis(2)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(Arc::strong_count(&endpoint), 1);
        assert_eq!(Arc::strong_count(&connection), 2);
        finish.send(()).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&connection), 1);
    }

    #[tokio::test]
    async fn listener_runtime_reaps_a_completed_driver_and_its_watcher() {
        let metrics = tokio::runtime::Handle::current().metrics();
        let baseline = metrics.num_alive_tasks();
        let runtime = ListenerRuntime {
            endpoint_started: AtomicBool::new(false),
            retired: CancellationToken::new(),
        };
        runtime.spawn(Box::pin(async {}));
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(metrics.num_alive_tasks(), baseline);
    }

    #[tokio::test]
    async fn endpoint_cancellation_wakes_retained_handles_before_releasing_memory() {
        let (client_config, server_config) = configs();
        let (server, mut released) = QuicEndpoint::listen(
            server_config,
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            1,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        let budget = Arc::new(Budget::new(Some(1)));
        let (client_conn, server_conn) = tokio::join!(
            async { client.connect(address, "localhost").unwrap().await.unwrap() },
            async {
                server
                    .accept()
                    .await
                    .unwrap()
                    .accept_with_memory(budget.acquire(1).unwrap())
                    .unwrap()
                    .await
                    .unwrap()
            },
        );
        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        client_send.write_all(b"x").await.unwrap();
        let (mut server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
        server_recv.read_exact(&mut [0]).await.unwrap();
        // No close() here: channel termination must wake handles on its own.
        drop(server);
        timeout(Duration::from_secs(3), server_conn.closed())
            .await
            .unwrap();
        assert!(server_send.write_all(b"x").await.is_err());
        assert!(server_recv.read(&mut [0]).await.is_err());
        assert_eq!(
            released.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert_eq!(budget.snapshot().active, 1);
        drop((server_conn, server_send, server_recv));
        assert!(
            timeout(Duration::from_secs(1), released)
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(budget.snapshot().active, 0);
        drop(std::net::UdpSocket::bind(address).unwrap());
        client.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn socket_release_waits_for_delegated_poller() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let (release, mut released) = oneshot::channel();
        let socket = Arc::new(MemorySocket {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
            endpoint_memory: None,
            _release: Some(release),
        });
        let budget = Arc::new(Budget::new(Some(1)));
        let poller = CONNECTION_MEMORY.sync_scope(RefCell::new(budget.acquire(1)), || {
            socket.clone().create_io_poller()
        });
        drop(socket);
        assert_eq!(
            released.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert!(std::net::UdpSocket::bind(address).is_err());
        drop(poller);
        assert!(released.await.is_err());
        assert_eq!(budget.available_permits(), 1);
        drop(std::net::UdpSocket::bind(address).unwrap());
    }

    async fn wait_for_slot(budget: &Arc<Budget>) -> BudgetPermit {
        loop {
            if let Some(permit) = budget.acquire(1) {
                return permit;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn configs() -> (quinn::ClientConfig, quinn::ServerConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        (client_config, server_config)
    }

    fn endpoints() -> (QuicEndpoint, QuicEndpoint) {
        let (client_config, server_config) = configs();
        endpoints_with_configs(client_config, server_config, 1)
    }

    fn endpoints_with_configs(
        client_config: quinn::ClientConfig,
        server_config: quinn::ServerConfig,
        memory_bytes: usize,
    ) -> (QuicEndpoint, QuicEndpoint) {
        let server = QuicEndpoint::new(
            Some(server_config),
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            memory_bytes,
        )
        .unwrap();
        let mut client = QuicEndpoint::new(
            None,
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            memory_bytes,
        )
        .unwrap();
        client.set_default_client_config(client_config);
        (client, server)
    }

    #[tokio::test]
    async fn pending_handshake_backlog_does_not_limit_active_connections() {
        let (client_config, mut server_config) = configs();
        let memory_bytes = crate::resources::configure_quic(&mut server_config, 100, 0);
        let server = QuicEndpoint::new(
            Some(server_config),
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            memory_bytes,
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        let address = SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
        let mut pending = Vec::new();
        timeout(Duration::from_secs(5), async {
            for _ in 0..128 {
                let connecting = client.connect(address, "localhost").unwrap();
                let incoming = server.accept().await.unwrap();
                // Holding Incoming without accepting it keeps its transport backlog slot.
                pending.push((connecting, incoming));
            }
        })
        .await
        .unwrap();

        let extra = client.connect(address, "localhost").unwrap();
        assert!(
            timeout(Duration::from_secs(1), server.accept())
                .await
                .is_err(),
            "pending handshakes exceeded the transport backlog",
        );

        let mut active = Vec::new();
        timeout(Duration::from_secs(10), async {
            for (connecting, incoming) in pending {
                let (connected, accepted) = tokio::join!(connecting, incoming.accept().unwrap());
                active.push((connected.unwrap(), accepted.unwrap()));
            }
            let incoming = server.accept().await.unwrap();
            let (connected, accepted) = tokio::join!(extra, incoming.accept().unwrap());
            active.push((connected.unwrap(), accepted.unwrap()));
        })
        .await
        .unwrap();
        assert_eq!(active.len(), 129);
        for (connected, accepted) in [&active[0], active.last().unwrap()] {
            connected
                .send_datagram(Bytes::from_static(b"active"))
                .unwrap();
            assert_eq!(
                timeout(Duration::from_secs(5), accepted.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                b"active"[..],
            );
        }
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
        drop(active);
    }

    #[tokio::test]
    async fn endpoint_reservations_survive_window_reload() {
        use crate::config::GlobalLimits;

        if std::env::var_os("SHOES_QUIC_RELOAD_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "quic_endpoint::tests::endpoint_reservations_survive_window_reload",
                    "--nocapture",
                ])
                .env("SHOES_QUIC_RELOAD_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let configured_endpoints = || {
            let (mut client_config, mut server_config) = configs();
            let memory_bytes = crate::resources::configure_quic(&mut server_config, 100, 0);
            let mut transport = quinn::TransportConfig::default();
            assert_eq!(
                crate::resources::configure_quic_transport(&mut transport),
                memory_bytes,
            );
            client_config.transport_config(Arc::new(transport));
            endpoints_with_configs(client_config, server_config, memory_bytes)
        };
        crate::resources::configure(GlobalLimits::default()).unwrap();
        let (large_client, large_server) = configured_endpoints();
        crate::resources::configure(GlobalLimits {
            quic_memory_bytes: Some(1 << 20),
            quic_receive_window: 65536,
            quic_send_window: 65536,
            quic_stream_window: 16384,
            ..Default::default()
        })
        .unwrap();
        let (small_client, small_server) = configured_endpoints();
        let large_address =
            SocketAddr::from(([127, 0, 0, 1], large_server.local_addr().unwrap().port()));
        let small_address =
            SocketAddr::from(([127, 0, 0, 1], small_server.local_addr().unwrap().port()));
        assert_eq!(
            large_client
                .connect(small_address, "localhost")
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::ConnectionRefused,
        );
        let connecting = small_client.connect(large_address, "localhost").unwrap();
        let incoming = timeout(Duration::from_secs(5), large_server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            incoming.accept().err().unwrap().kind(),
            io::ErrorKind::ConnectionRefused,
        );
        assert!(
            timeout(Duration::from_secs(5), connecting)
                .await
                .unwrap()
                .is_err()
        );
        timeout(Duration::from_secs(5), small_client.wait_idle())
            .await
            .unwrap();
        assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);

        let small_reservation = 2 * 65536 + (512 << 10);
        crate::resources::configure(GlobalLimits {
            quic_memory_bytes: Some(2 * small_reservation),
            ..Default::default()
        })
        .unwrap();
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    small_client
                        .connect(small_address, "localhost")
                        .unwrap()
                        .await
                        .unwrap()
                },
                async {
                    small_server
                        .accept()
                        .await
                        .unwrap()
                        .accept()
                        .unwrap()
                        .await
                        .unwrap()
                },
            )
        })
        .await
        .unwrap();
        assert_eq!(
            crate::resources::snapshot().quic_buffer_bytes.active,
            2 * small_reservation,
        );
        client.close(0u32.into(), b"done");
        drop((client, server));
        timeout(Duration::from_secs(5), async {
            tokio::join!(small_client.wait_idle(), small_server.wait_idle());
        })
        .await
        .unwrap();
        assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
    }

    async fn connect(
        client: &QuicEndpoint,
        server: &QuicEndpoint,
        client_budget: &Arc<Budget>,
        server_budget: &Arc<Budget>,
    ) -> (quinn::Connection, quinn::Connection) {
        let address = SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
        timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    client
                        .connect_with_memory(
                            address,
                            "localhost",
                            client_budget.acquire(1).unwrap(),
                        )
                        .unwrap()
                        .await
                        .unwrap()
                },
                async {
                    let incoming = server.accept().await.unwrap();
                    let connecting = incoming
                        .accept_with_memory(server_budget.acquire(1).unwrap())
                        .unwrap();
                    // Exercise TUIC's incoming 0.5-RTT path as well as ordinary clients.
                    connecting.into_0rtt().unwrap().0
                },
            )
        })
        .await
        .unwrap()
    }

    struct Payload {
        bytes: Vec<u8>,
        live: Arc<AtomicUsize>,
        budget: Arc<Budget>,
    }

    impl AsRef<[u8]> for Payload {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            assert_eq!(
                self.budget.available_permits(),
                0,
                "payload outlived reservation"
            );
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn payload(live: &Arc<AtomicUsize>, budget: &Arc<Budget>) -> Bytes {
        live.fetch_add(1, Ordering::SeqCst);
        Bytes::from_owner(Payload {
            bytes: vec![0; 1 << 20],
            live: live.clone(),
            budget: budget.clone(),
        })
    }

    #[tokio::test]
    async fn churn_reservations_cover_draining_without_waiting_for_other_connections() {
        let (client, server) = endpoints();
        let client_budget = Arc::new(Budget::new(Some(2)));
        let server_budget = Arc::new(Budget::new(Some(2)));
        let live = Arc::new(AtomicUsize::new(0));
        let (keeper, keeper_peer) = connect(&client, &server, &client_budget, &server_budget).await;
        for _ in 0..4 {
            let (connection, peer) =
                connect(&client, &server, &client_budget, &server_budget).await;
            let (mut send, recv) = connection.open_bi().await.unwrap();
            send.write_all(b"open").await.unwrap();
            let (mut peer_send, peer_recv) = peer.accept_bi().await.unwrap();
            send.write_chunk(payload(&live, &client_budget))
                .await
                .unwrap();
            peer_send
                .write_chunk(payload(&live, &server_budget))
                .await
                .unwrap();
            drop((connection, peer, send, recv, peer_send, peer_recv));
            assert_eq!(live.load(Ordering::SeqCst), 2);
            assert!(client_budget.acquire(1).is_none());
            assert!(server_budget.acquire(1).is_none());

            let client_slot = timeout(Duration::from_secs(5), wait_for_slot(&client_budget))
                .await
                .unwrap();
            let server_slot = timeout(Duration::from_secs(5), wait_for_slot(&server_budget))
                .await
                .unwrap();
            assert_eq!(live.load(Ordering::SeqCst), 0);
            drop((client_slot, server_slot));
            keeper
                .send_datagram(Bytes::from_static(b"still active"))
                .unwrap();
            assert_eq!(
                timeout(Duration::from_secs(1), keeper_peer.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                b"still active"[..],
            );
        }
        drop((keeper, keeper_peer));
        timeout(Duration::from_secs(5), client.wait_idle())
            .await
            .unwrap();
        timeout(Duration::from_secs(5), server.wait_idle())
            .await
            .unwrap();
        assert_eq!(client_budget.available_permits(), 2);
        assert_eq!(server_budget.available_permits(), 2);
    }

    #[tokio::test]
    async fn reservations_survive_driver_completion_until_last_stream_handle_drops() {
        let (client, server) = endpoints();
        let client_budget = Arc::new(Budget::new(Some(1)));
        let server_budget = Arc::new(Budget::new(Some(1)));
        let live = Arc::new(AtomicUsize::new(0));
        let (connection, peer) = connect(&client, &server, &client_budget, &server_budget).await;
        let (mut send, recv) = connection.open_bi().await.unwrap();
        send.write_chunk(payload(&live, &client_budget))
            .await
            .unwrap();
        connection.close(0u32.into(), b"closed with handles alive");
        timeout(Duration::from_secs(5), client.wait_idle())
            .await
            .unwrap();
        timeout(Duration::from_secs(5), server.wait_idle())
            .await
            .unwrap();
        assert_eq!(client_budget.available_permits(), 0);
        assert_eq!(server_budget.available_permits(), 0);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        drop((connection, send));
        assert_eq!(client_budget.available_permits(), 0);
        drop(recv);
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(client_budget.available_permits(), 1);
        drop(peer);
        assert_eq!(server_budget.available_permits(), 1);
    }

    #[tokio::test]
    async fn socket_reservation_survives_draining_and_retained_streams() {
        let (client_config, server_config) = configs();
        let budget = Arc::new(Budget::new(Some(1)));
        let socket = socket_with_memory(
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            budget.acquire(1).unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        client.set_default_client_config(client_config);
        let server = QuicEndpoint::new(
            Some(server_config),
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            1,
        )
        .unwrap();
        let server_budget = Arc::new(Budget::new(Some(1)));
        let address = SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
        let (connection, peer) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                async { client.connect(address, "localhost").unwrap().await.unwrap() },
                async {
                    server
                        .accept()
                        .await
                        .unwrap()
                        .accept_with_memory(server_budget.acquire(1).unwrap())
                        .unwrap()
                        .await
                        .unwrap()
                },
            )
        })
        .await
        .unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let (mut send, recv) = connection.open_bi().await.unwrap();
        send.write_chunk(payload(&live, &budget)).await.unwrap();
        connection.close(0u32.into(), b"closed with handles alive");
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        timeout(Duration::from_secs(5), client.wait_idle())
            .await
            .unwrap();
        drop((client, connection, send));
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        drop(recv);
        let _returned = timeout(Duration::from_secs(5), wait_for_slot(&budget))
            .await
            .unwrap();
        assert_eq!(live.load(Ordering::SeqCst), 0);
        drop(peer);
        timeout(Duration::from_secs(5), server.wait_idle())
            .await
            .unwrap();
        assert_eq!(server_budget.available_permits(), 1);
    }

    #[tokio::test]
    async fn failed_and_cancelled_handshakes_return_reservations() {
        let (client, _server) = endpoints();
        let budget = Arc::new(Budget::new(Some(1)));
        assert!(
            client
                .connect_with_memory(
                    "127.0.0.1:0".parse().unwrap(),
                    "localhost",
                    budget.acquire(1).unwrap(),
                )
                .is_err()
        );
        assert_eq!(budget.available_permits(), 1);
        let unreachable = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], unreachable.local_addr().unwrap().port()));
        let connecting = client
            .connect_with_memory(address, "localhost", budget.acquire(1).unwrap())
            .unwrap();
        drop(connecting);
        assert_eq!(budget.available_permits(), 0);
        timeout(Duration::from_secs(5), client.wait_idle())
            .await
            .unwrap();
        assert_eq!(budget.available_permits(), 1);
    }
}
