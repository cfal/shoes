use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio_util::task::AbortOnDropHandle;

use super::{Protocol, session::Pool, udp::Association};
use crate::{
    async_stream::{AsyncReadMessage, AsyncStream},
    config::quic_client::{Secret, TuicClientConfig, TuicUdpMode},
    quic_endpoint::QuicEndpoint,
    tcp::carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey},
};

#[derive(Debug)]
struct Dialer {
    endpoint: Arc<QuicEndpoint>,
    address: SocketAddr,
    attempts: AtomicUsize,
    key: RouteKey,
}

#[async_trait::async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn open_quic(&self) -> io::Result<QuicCarrier> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(QuicCarrier {
            connection: self
                .endpoint
                .connect(self.address, "localhost")?
                .await
                .map_err(io::Error::other)?,
            _endpoint: self.endpoint.clone(),
        })
    }
}

fn endpoints() -> (quinn::Endpoint, Arc<Dialer>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let server_config = quinn::ServerConfig::with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let server = quinn::Endpoint::server(server_config, "0.0.0.0:0".parse().unwrap()).unwrap();
    let mut client =
        QuicEndpoint::new(None, std::net::UdpSocket::bind("0.0.0.0:0").unwrap(), 1).unwrap();
    client.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
    );
    let address = SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
    (
        server,
        Arc::new(Dialer {
            endpoint: Arc::new(client),
            address,
            attempts: AtomicUsize::new(0),
            key: RouteKey(vec![42]),
        }),
    )
}

fn protocol() -> Protocol {
    Protocol::Tuic(TuicClientConfig {
        uuid: Secret("01234567-89ab-4def-8123-456789abcdef".into()),
        password: Secret("password".into()),
        udp_relay_mode: TuicUdpMode::Native,
        udp_enabled: true,
        heartbeat_interval_secs: 1,
    })
}

#[tokio::test]
async fn generations_singleflight_reauthenticate_and_drain_after_retirement() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server, dialer) = endpoints();
        let (accepted, mut connections) = tokio::sync::mpsc::channel(4);
        let peer = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let connection = incoming.await.unwrap();
                let mut auth = connection.accept_uni().await.unwrap();
                let bytes = auth.read_to_end(50).await.unwrap();
                assert_eq!(&bytes[..2], &[5, 0]);
                let mut token = [0; 32];
                connection
                    .export_keying_material(&mut token, &bytes[2..18], b"password")
                    .unwrap();
                assert_eq!(&bytes[18..], token);
                accepted.send(connection).await.unwrap();
            }
        }));
        let pool = Pool::default();
        let (first, same) = tokio::join!(
            pool.get(dialer.clone(), protocol(), false),
            pool.get(dialer.clone(), protocol(), true)
        );
        let first = first.unwrap();
        let same = same.unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1);
        drop(same);
        let old_peer = connections.recv().await.unwrap();
        let target = crate::address::NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let mut old_udp = Association::new(first.clone(), target.clone())
            .unwrap()
            .unwrap();
        old_peer.close(1u32.into(), b"reconnect");
        first.connection().closed().await;
        let second = pool.get(dialer.clone(), protocol(), false).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2);
        let new_peer = connections.recv().await.unwrap();
        let new_udp = Association::new(second.clone(), target).unwrap().unwrap();
        let mut buffer = [0; 64];
        let mut buffer = tokio::io::ReadBuf::new(&mut buffer);
        assert!(
            std::future::poll_fn(
                |cx| std::pin::Pin::new(&mut old_udp).poll_read_message(cx, &mut buffer)
            )
            .await
            .is_err()
        );
        drop((first, old_udp, pool, dialer));
        // A lease, rather than the retired connector, owns this connection now.
        assert!(new_peer.close_reason().is_none());
        assert!(second.connection().close_reason().is_none());
        assert_eq!(new_peer.read_datagram().await.unwrap().as_ref(), &[5, 4]);
        drop(second);
        assert!(new_peer.close_reason().is_none());
        drop(new_udp);
        new_peer.closed().await;
        drop(peer);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abandoned_h3_auth_is_closed_when_its_connector_retires() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, dialer) = endpoints();
        let (accepted, received) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut h3: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let (_request, _stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            accepted.send(connection.clone()).unwrap();
            connection.closed().await;
        });
        let pool = Arc::new(Pool::default());
        let waiter_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            waiter_pool
                .get(
                    dialer,
                    Protocol::Hysteria2(crate::config::quic_client::Hysteria2ClientConfig {
                        password: Secret("password".into()),
                        udp_enabled: true,
                        obfs: None,
                        hopping: None,
                    }),
                    false,
                )
                .await
        });
        let connection = received.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert!(connection.close_reason().is_none());
        drop(pool);
        connection.closed().await;
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_placement_is_checked_in_builder_and_mixed_pools() {
    use crate::{
        config::ClientChain,
        resolver::{NativeResolver, Resolver},
        tcp::chain_builder::try_build_client_proxy_chain,
    };
    use serde_json::json;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    for protocol in [
        json!({"type":"hysteria2", "password":"password"}),
        json!({"type":"tuic", "password":"password", "uuid":"01234567-89ab-4def-8123-456789abcdef"}),
    ] {
        let native = json!({"address":"127.0.0.1:443", "protocol":protocol});
        let next = json!({"address":"127.0.0.1:8443", "protocol":{"type":"vless", "user_id":"01234567-89ab-4def-8123-456789abcdef"}});
        for valid in [
            native.clone(),
            json!([native.clone(), next.clone()]),
            json!([{"pool": [native.clone(), next.clone()]}]),
        ] {
            let chain: ClientChain = serde_json::from_value(valid).unwrap();
            assert!(try_build_client_proxy_chain(chain.hops, resolver.clone()).is_ok());
        }
        let mut wrong_transport = native.clone();
        wrong_transport["transport"] = json!("tcp");
        let nested = json!({"address":"127.0.0.1:443", "protocol":{"type":"tls", "verify":false, "protocol":protocol}});
        for invalid in [wrong_transport, json!([next, native]), nested] {
            let chain: ClientChain = serde_json::from_value(invalid).unwrap();
            assert!(try_build_client_proxy_chain(chain.hops, resolver.clone()).is_err());
        }
    }
}

#[tokio::test]
async fn closed_generations_are_evicted_without_another_dial() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, dialer) = endpoints();
        let accepting = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut auth = connection.accept_uni().await.unwrap();
            auth.read_to_end(50).await.unwrap();
            connection.close(1u32.into(), b"test failure");
            (server, connection)
        });
        let pool = Pool::default();
        let generation = pool.get(dialer, protocol(), false).await.unwrap();
        let weak = Arc::downgrade(&generation);
        generation.connection().closed().await;
        drop(generation);
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        drop((pool, accepting.await.unwrap()));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn last_retired_tcp_lease_drains_fin_and_unacknowledged_tail() {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(Duration::from_secs(8), async {
        let (server, dialer) = endpoints();
        let (accepted, received) = tokio::sync::oneshot::channel();
        let accepting = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(50)
                .await
                .unwrap();
            accepted.send(connection.clone()).unwrap();
            connection.closed().await;
            drop(server);
        });
        let pool = Pool::default();
        let generation = pool.get(dialer, protocol(), false).await.unwrap();
        let connection = received.await.unwrap();
        let target = crate::address::NetLocation::from_str("127.0.0.1:1234", None).unwrap();
        let mut stream = super::tuic::connect(generation, &target.into())
            .await
            .unwrap()
            .client_stream;
        let data = vec![42; 32768];
        stream.write_all(&data).await.unwrap();
        drop((pool, stream));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        let bytes = recv.read_to_end(65536).await.unwrap();
        assert_eq!(&bytes[9..], data);
        connection.closed().await;
        accepting.await.unwrap();
    })
    .await
    .unwrap();
}
