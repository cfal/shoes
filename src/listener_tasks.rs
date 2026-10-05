use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;

pub(crate) struct QuicListener(pub crate::quic_endpoint::QuicEndpoint);

impl QuicListener {
    pub fn bind_all(
        address: std::net::SocketAddr,
        config: quinn::ServerConfig,
        count: usize,
        memory_bytes: usize,
    ) -> std::io::Result<Vec<Self>> {
        (0..count)
            .map(|_| {
                let socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                    address.is_ipv6(),
                    None,
                    Some(address),
                    true,
                    Some(crate::resources::limits().quic_socket_buffer),
                )?;
                crate::quic_endpoint::QuicEndpoint::new(
                    Some(config.clone()),
                    socket.into(),
                    memory_bytes,
                )
                .map(Self)
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
    use std::sync::Arc;
    use tokio::sync::oneshot;

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
        let listener = create_listener("0.0.0.0:0".parse().unwrap());
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
        // Match the config watcher's debounce before rebinding the listener.
        tokio::time::sleep(Duration::from_secs(3)).await;
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
