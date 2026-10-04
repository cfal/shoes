use std::cell::RefCell;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::OwnedSemaphorePermit;

tokio::task_local! {
    static CONNECTION_MEMORY: RefCell<Option<OwnedSemaphorePermit>>;
}

/// Quinn replaces connection pollers on rebind, so this wrapper deliberately
/// exposes no rebinding API. Reload creates fresh endpoints instead.
#[derive(Debug)]
pub(crate) struct QuicEndpoint(quinn::Endpoint);

impl QuicEndpoint {
    pub fn new(
        config: Option<quinn::ServerConfig>,
        socket: std::net::UdpSocket,
    ) -> io::Result<Self> {
        let socket = MemorySocket(quinn::TokioRuntime.wrap_udp_socket(socket)?);
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            config,
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .map(Self)
    }

    pub fn set_default_client_config(&mut self, config: quinn::ClientConfig) {
        self.0.set_default_client_config(config);
    }

    pub fn connect(&self, address: SocketAddr, name: &str) -> io::Result<quinn::Connecting> {
        let memory = crate::resources::try_quic_memory().ok_or_else(crate::resources::exhausted)?;
        self.connect_with_memory(address, name, memory)
    }

    fn connect_with_memory(
        &self,
        address: SocketAddr,
        name: &str,
        memory: OwnedSemaphorePermit,
    ) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.0.connect(address, name).map_err(io::Error::other)
        })
    }

    pub async fn accept(&self) -> Option<Incoming> {
        self.0.accept().await.map(Incoming)
    }

    pub fn close(&self, code: quinn::VarInt, reason: &[u8]) {
        self.0.close(code, reason);
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    #[cfg(test)]
    async fn wait_idle(&self) {
        self.0.wait_idle().await;
    }
}

pub(crate) struct Incoming(quinn::Incoming);

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    pub fn refuse(self) {
        self.0.refuse();
    }

    pub fn accept(self) -> io::Result<quinn::Connecting> {
        let Some(memory) = crate::resources::try_quic_memory() else {
            self.refuse();
            return Err(crate::resources::exhausted());
        };
        self.accept_with_memory(memory)
    }

    fn accept_with_memory(self, memory: OwnedSemaphorePermit) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.0.accept().map_err(io::Error::from)
        })
    }
}

#[derive(Debug)]
struct MemorySocket(Arc<dyn AsyncUdpSocket>);

impl AsyncUdpSocket for MemorySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
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
            inner: self.0.clone().create_io_poller(),
            _memory: memory,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.0.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.0.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

#[derive(Debug)]
struct MemoryPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    _memory: OwnedSemaphorePermit,
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

    use bytes::Bytes;
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    fn endpoints() -> (QuicEndpoint, QuicEndpoint) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let server = QuicEndpoint::new(
            Some(server_config),
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
        )
        .unwrap();
        let mut client =
            QuicEndpoint::new(None, std::net::UdpSocket::bind("0.0.0.0:0").unwrap()).unwrap();
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        (client, server)
    }

    async fn connect(
        client: &QuicEndpoint,
        server: &QuicEndpoint,
        client_budget: &Arc<Semaphore>,
        server_budget: &Arc<Semaphore>,
    ) -> (quinn::Connection, quinn::Connection) {
        let address = SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
        timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    client
                        .connect_with_memory(
                            address,
                            "localhost",
                            client_budget.clone().try_acquire_owned().unwrap(),
                        )
                        .unwrap()
                        .await
                        .unwrap()
                },
                async {
                    let incoming = server.accept().await.unwrap();
                    let connecting = incoming
                        .accept_with_memory(server_budget.clone().try_acquire_owned().unwrap())
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
        budget: Arc<Semaphore>,
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

    fn payload(live: &Arc<AtomicUsize>, budget: &Arc<Semaphore>) -> Bytes {
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
        let client_budget = Arc::new(Semaphore::new(2));
        let server_budget = Arc::new(Semaphore::new(2));
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
            assert!(client_budget.clone().try_acquire_owned().is_err());
            assert!(server_budget.clone().try_acquire_owned().is_err());

            let client_slot = timeout(
                Duration::from_secs(5),
                client_budget.clone().acquire_owned(),
            )
            .await
            .unwrap()
            .unwrap();
            let server_slot = timeout(
                Duration::from_secs(5),
                server_budget.clone().acquire_owned(),
            )
            .await
            .unwrap()
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
        let client_budget = Arc::new(Semaphore::new(1));
        let server_budget = Arc::new(Semaphore::new(1));
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
    async fn failed_and_cancelled_handshakes_return_reservations() {
        let (client, _server) = endpoints();
        let budget = Arc::new(Semaphore::new(1));
        assert!(
            client
                .connect_with_memory(
                    "127.0.0.1:0".parse().unwrap(),
                    "localhost",
                    budget.clone().try_acquire_owned().unwrap(),
                )
                .is_err()
        );
        assert_eq!(budget.available_permits(), 1);
        let unreachable = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], unreachable.local_addr().unwrap().port()));
        let connecting = client
            .connect_with_memory(
                address,
                "localhost",
                budget.clone().try_acquire_owned().unwrap(),
            )
            .unwrap();
        drop(connecting);
        assert_eq!(budget.available_permits(), 0);
        timeout(Duration::from_secs(5), client.wait_idle())
            .await
            .unwrap();
        assert_eq!(budget.available_permits(), 1);
    }
}
