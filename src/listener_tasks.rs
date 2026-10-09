use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

tokio::task_local! {
    static QUIC_RETIREMENTS: QuicRetirements;
}

/// Collects listener socket releases without including outbound QUIC used by draining TCP tasks.
#[derive(Clone, Default)]
pub(crate) struct QuicRetirements(Arc<Mutex<Vec<oneshot::Receiver<()>>>>);

impl QuicRetirements {
    pub async fn track<F: Future>(&self, startup: F) -> F::Output {
        QUIC_RETIREMENTS.scope(self.clone(), startup).await
    }

    pub async fn wait(&self) -> io::Result<()> {
        let releases = std::mem::take(&mut *self.0.lock());
        tokio::time::timeout(Duration::from_secs(5), async {
            for released in releases {
                // Sender destruction, rather than a sent value, confirms socket release.
                let _ = released.await;
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC listener sockets did not retire",
            )
        })
    }
}

pub(crate) struct QuicListener(pub crate::quic_endpoint::QuicEndpoint);

impl QuicListener {
    pub fn bind_all(
        address: std::net::SocketAddr,
        config: quinn::ServerConfig,
        count: usize,
        memory_bytes: usize,
    ) -> std::io::Result<Vec<Self>> {
        let reuse_port = cfg!(all(
            unix,
            not(any(target_os = "solaris", target_os = "illumos"))
        ));
        let count = if reuse_port { count } else { count.min(1) };
        (0..count)
            .map(|_| {
                let socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                    address.is_ipv6(),
                    None,
                    Some(address),
                    reuse_port,
                    Some(crate::resources::limits().quic_socket_buffer),
                )?;
                let (endpoint, released) = crate::quic_endpoint::QuicEndpoint::listen(
                    config.clone(),
                    socket.into(),
                    memory_bytes,
                )?;
                let _ = QUIC_RETIREMENTS.try_with(|retirements| {
                    retirements.0.lock().push(released);
                });
                Ok(Self(endpoint))
            })
            .collect()
    }
}

impl std::ops::Deref for QuicListener {
    type Target = crate::quic_endpoint::QuicEndpoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        // Old reuse-port sockets must not keep serving a previous QUIC generation.
        self.0.close(0u32.into(), b"server listener stopped");
    }
}

/// Accepted connections may drain after reload, but cannot outlive its deadline.
pub(crate) struct ListenerTasks {
    tasks: JoinSet<()>,
    grace: Duration,
}

impl ListenerTasks {
    pub fn immediate() -> Self {
        Self::with_grace(Duration::ZERO)
    }

    pub fn new() -> Self {
        Self::with_grace(Duration::from_secs(
            crate::resources::limits().reload_grace_secs,
        ))
    }

    fn with_grace(grace: Duration) -> Self {
        Self {
            tasks: JoinSet::new(),
            grace,
        }
    }

    pub fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(future);
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub async fn join_next(&mut self) {
        if let Some(Err(error)) = self.tasks.join_next().await {
            log::warn!("Connection task failed: {error}");
        }
    }
}

impl Drop for ListenerTasks {
    fn drop(&mut self) {
        if self.tasks.is_empty() || self.grace.is_zero() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut tasks = std::mem::take(&mut self.tasks);
        let deadline = tokio::time::Instant::now() + self.grace;
        runtime.spawn(async move {
            let drained = tokio::time::timeout_at(deadline, async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        log::warn!("Draining connection task failed: {error}");
                    }
                }
            })
            .await;
            if drained.is_err() {
                log::info!(
                    "Reload grace expired; cancelling {} connections",
                    tasks.len()
                );
                tasks.shutdown().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn retirement_timeout_is_an_error() {
        let retirements = QuicRetirements::default();
        let (_socket, released) = oneshot::channel();
        retirements.0.lock().push(released);
        assert_eq!(
            retirements.wait().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn retirement_does_not_wait_for_a_slow_peer_close_timer() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .initial_rtt(Duration::from_secs(2));
        let retirements = QuicRetirements::default();
        let listener = retirements
            .track(async {
                QuicListener::bind_all("127.0.0.1:0".parse().unwrap(), config, 1, 1)
                    .unwrap()
                    .pop()
                    .unwrap()
            })
            .await;
        let address = listener.local_addr().unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting = client.connect(address, "localhost").unwrap();
        let incoming = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        client.close(0u32.into(), b"abandon handshake");
        drop((connecting, client));
        let pending = incoming.accept().unwrap();
        drop(pending);
        drop(listener);
        tokio::time::timeout(Duration::from_secs(3), retirements.wait())
            .await
            .unwrap()
            .unwrap();
        drop(std::net::UdpSocket::bind(address).unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn reload_preserves_active_work_then_cancels_stalled_connections() {
        let marker = Arc::new(());
        let owned = marker.clone();
        let mut tasks = ListenerTasks::with_grace(Duration::from_secs(300));
        let (tx, rx) = oneshot::channel();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            tx.send(()).unwrap();
        });
        tasks.spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        drop(tasks);
        tokio::time::advance(Duration::from_secs(61)).await;
        rx.await.unwrap();
        assert_eq!(Arc::strong_count(&marker), 2);
        tokio::time::advance(Duration::from_secs(240)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[tokio::test]
    async fn zero_grace_cancels_immediately() {
        let marker = Arc::new(());
        let owned = marker.clone();
        let mut tasks = ListenerTasks::with_grace(Duration::ZERO);
        tasks.spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        });
        drop(tasks);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[tokio::test]
    async fn quic_reload_disconnects_connections_and_accepts_new_peers() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let memory_bytes = crate::resources::configure_quic(&mut server_config, 100, 0);
        let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        #[cfg(windows)]
        assert_eq!(
            QuicListener::bind_all(
                "0.0.0.0:0".parse().unwrap(),
                server_config.clone(),
                4,
                memory_bytes,
            )
            .unwrap()
            .len(),
            1,
        );
        let occupied = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        assert!(
            QuicListener::bind_all(
                occupied.local_addr().unwrap(),
                server_config.clone(),
                1,
                memory_bytes,
            )
            .is_err()
        );
        let create_listener = |address| {
            QuicListener::bind_all(address, server_config.clone(), 1, memory_bytes)
                .unwrap()
                .pop()
                .unwrap()
        };
        let retirements = QuicRetirements::default();
        let listener = retirements
            .track(async { create_listener("0.0.0.0:0".parse().unwrap()) })
            .await;
        let bind_address = listener.local_addr().unwrap();
        let target = std::net::SocketAddr::from(([127, 0, 0, 1], bind_address.port()));
        let create_client = || {
            let mut client = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
            client.set_default_client_config(client_config.clone());
            client
        };
        let client = create_client();
        let (client_conn, server_conn) = tokio::join!(
            async { client.connect(target, "localhost").unwrap().await.unwrap() },
            async {
                listener
                    .accept()
                    .await
                    .unwrap()
                    .accept()
                    .unwrap()
                    .await
                    .unwrap()
            },
        );
        client_conn
            .send_datagram(bytes::Bytes::from_static(b"before"))
            .unwrap();
        assert_eq!(server_conn.read_datagram().await.unwrap(), b"before"[..]);

        drop(listener);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), server_conn.closed())
                .await
                .unwrap(),
            quinn::ConnectionError::LocallyClosed,
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), client_conn.closed())
                .await
                .unwrap(),
            quinn::ConnectionError::ApplicationClosed(_),
        ));
        drop(server_conn);
        drop(client_conn);
        retirements.wait().await.unwrap();
        // A non-reuse socket proves retirement released the kernel port, not just Quinn state.
        drop(std::net::UdpSocket::bind(bind_address).unwrap());
        let listener = create_listener(bind_address);
        for _ in 0..12 {
            let client = create_client();
            let (connected, accepted) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    async { client.connect(target, "localhost").unwrap().await },
                    async { listener.accept().await.unwrap().accept().unwrap().await },
                )
            })
            .await
            .expect("reload lost a new QUIC handshake");
            connected.unwrap().close(0u32.into(), b"done");
            accepted.unwrap();
        }
    }
}
