use super::{CLEANUP, Snapshot, restored, sample};
use crate::quic_endpoint::QuicEndpoint;
use std::sync::Arc;
use tokio::time::timeout;

pub(super) async fn exercise(baseline: &Snapshot) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    for cycle in 0..8 {
        let (server, mut released) = QuicEndpoint::listen(
            server_config.clone(),
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            1024,
        )
        .unwrap();
        let bound = server.local_addr().unwrap();
        let address = ([127, 0, 0, 1], bound.port()).into();
        let mut client =
            QuicEndpoint::new(None, std::net::UdpSocket::bind("0.0.0.0:0").unwrap(), 1024).unwrap();
        for _ in 0..4 {
            // Missing client config rejects after acquiring the memory permit.
            assert!(client.connect(address, "localhost").is_err());
            assert_eq!(sample().quic_bytes, baseline.quic_bytes);
        }
        client.set_default_client_config(client_config.clone());
        let (client_conn, server_conn) = timeout(CLEANUP, async {
            tokio::join!(
                async { client.connect(address, "localhost").unwrap().await.unwrap() },
                async {
                    let incoming = server.accept().await.unwrap();
                    let connecting = incoming.accept().unwrap();
                    connecting.await.unwrap()
                },
            )
        })
        .await
        .unwrap();
        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        let payload = format!("quic-retention-{cycle}\0exact-bytes");
        let (mut peer_send, mut peer_recv) = timeout(CLEANUP, async {
            send.write_all(payload.as_bytes()).await.unwrap();
            let (mut peer_send, mut peer_recv) = server_conn.accept_bi().await.unwrap();
            let mut bytes = vec![0; payload.len()];
            peer_recv.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, payload.as_bytes());
            peer_send.write_all(&bytes).await.unwrap();
            recv.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, payload.as_bytes());
            (peer_send, peer_recv)
        })
        .await
        .unwrap();
        let live = sample();
        assert_eq!(live.quic_bytes, baseline.quic_bytes + 2048);
        assert!(live.tasks > baseline.tasks);
        println!("cycle={cycle} state=quic_live {live:?}");
        drop(server);
        timeout(CLEANUP, server_conn.closed()).await.unwrap();
        assert!(peer_send.write_all(b"closed").await.is_err());
        assert!(peer_recv.read(&mut [0]).await.is_err());
        assert_eq!(
            sample().quic_bytes,
            baseline.quic_bytes + 2048,
            "application handles still own their reservation"
        );
        assert_eq!(
            released.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        drop((server_conn, peer_send, peer_recv));
        assert!(timeout(CLEANUP, released).await.unwrap().is_err());
        assert_eq!(sample().quic_bytes, baseline.quic_bytes + 1024);
        drop(std::net::UdpSocket::bind(bound).unwrap());
        client.close(0u32.into(), b"done");
        drop((client_conn, send, recv, client));
        restored("quic_owner_destroyed", baseline).await;
    }
}
