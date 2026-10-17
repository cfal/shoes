use super::*;

#[cfg(unix)]
async fn reload(peer: &Peer, config: &Value) {
    let ready = peer.logs().matches("Servers ready").count();
    let path = peer.directory.path().join("config.json");
    std::fs::write(path, serde_json::to_vec(config).unwrap()).unwrap();
    assert_eq!(
        unsafe { libc::kill(peer.process.id() as i32, libc::SIGHUP) },
        0
    );
    timeout(LIMIT, async {
        while peer.logs().matches("Servers ready").count() == ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|e| panic!("reload: {e}\n{}", peer.logs()));
}

async fn roundtrip(stream: &mut TcpStream, payload: &[u8]) {
    timeout(LIMIT, async {
        stream.write_all(payload).await.unwrap();
        let mut reply = vec![0; payload.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn live_reload_resets_tickets_preserves_active_streams_and_rotates_keys() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for mode in ["native", "xorpub", "random"] {
            let (encryption, decryption, _) = credentials(mode, &["x25519"]);
            let (target, count, mut target_task) = echo().await;
            let port = free_port().await;
            let mut config = server_config(Kind::Shoes, port, &decryption, false);
            let server = start(Kind::Shoes, port, config.clone()).await;
            let client_port = free_port().await;
            let client = start(
                peer,
                client_port,
                client_config(peer, client_port, port, &encryption, false),
            )
            .await;
            let mut active = socks_connect(client_port, target).await.unwrap();
            roundtrip(&mut active, b"old generation").await;
            exchange(client_port, target, b"warm").await.unwrap();
            server.assert_handshakes(&["fresh", "resumed"]);

            config[0]["protocol"]["decryption"] = json!(decryption.replace(".600s.", ".0s."));
            reload(&server, &config).await;
            roundtrip(&mut active, b"still live after reload").await;
            assert!(
                exchange(client_port, target, b"stale must not arrive")
                    .await
                    .is_err()
            );
            assert_eq!(count.load(Ordering::SeqCst), 2);
            for _ in 0..2 {
                exchange(client_port, target, b"fresh-only recovery")
                    .await
                    .unwrap();
            }
            server.assert_handshakes(&["fresh", "resumed", "fresh", "fresh"]);

            let (next_encryption, next_decryption, _) = credentials(mode, &["x25519"]);
            config[0]["protocol"]["decryption"] = json!(next_decryption);
            reload(&server, &config).await;
            roundtrip(&mut active, b"old stream survives key rotation").await;
            assert!(
                exchange(client_port, target, b"old key must fail")
                    .await
                    .is_err()
            );
            assert_eq!(count.load(Ordering::SeqCst), 4);
            drop(client);
            let client = start(
                peer,
                client_port,
                client_config(peer, client_port, port, &next_encryption, false),
            )
            .await;
            for _ in 0..2 {
                exchange(client_port, target, b"new key").await.unwrap();
            }
            server.assert_handshakes(&["fresh", "resumed", "fresh", "fresh", "fresh", "resumed"]);
            drop((active, client, server));
            target_task.stop().await;
        }
    }
}

#[tokio::test]
async fn expired_tickets_use_a_fresh_handshake_without_losing_the_request() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for peer_client in [false, true] {
            let (server_kind, client_kind) = peer_roles(peer, peer_client);
            let (encryption, decryption, _) = credentials("random", &["x25519"]);
            let decryption = decryption.replace(".600s.", ".5-5s.");
            let (target, count, mut task) = echo().await;
            let port = free_port().await;
            let server = start(
                server_kind,
                port,
                server_config(server_kind, port, &decryption, false),
            )
            .await;
            let proxy = free_port().await;
            let client = start(
                client_kind,
                proxy,
                client_config(client_kind, proxy, port, &encryption, false),
            )
            .await;
            for _ in 0..2 {
                exchange(proxy, target, b"warm before expiry")
                    .await
                    .unwrap();
            }
            let shoes = if peer_client { &server } else { &client };
            shoes.assert_handshakes(&["fresh", "resumed"]);
            tokio::time::sleep(Duration::from_millis(5200)).await;
            exchange(proxy, target, b"fresh after expiry")
                .await
                .unwrap();
            shoes.assert_handshakes(&["fresh", "resumed", "fresh"]);
            assert_eq!(count.load(Ordering::SeqCst), 3);
            drop((client, server));
            task.stop().await;
        }
    }
}

#[tokio::test]
async fn shoes_client_rejects_stale_peer_ticket_without_replaying_application_data() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for mode in ["native", "xorpub", "random"] {
            let (encryption, decryption, _) = credentials(mode, &["x25519"]);
            let (target, count, mut task) = echo().await;
            let port = free_port().await;
            let config = server_config(peer, port, &decryption, false);
            let server = start(peer, port, config.clone()).await;
            let proxy = free_port().await;
            let client = start(
                Kind::Shoes,
                proxy,
                client_config(Kind::Shoes, proxy, port, &encryption, false),
            )
            .await;
            for _ in 0..2 {
                exchange(proxy, target, b"warm").await.unwrap();
            }
            client.assert_handshakes(&["fresh", "resumed"]);
            drop(server);
            let server = start(peer, port, config).await;
            assert!(
                exchange(proxy, target, b"do not retry this request")
                    .await
                    .is_err()
            );
            assert_eq!(count.load(Ordering::SeqCst), 2);
            exchange(proxy, target, b"independent recovery")
                .await
                .unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 3);
            client.assert_handshakes(&["fresh", "resumed", "resumed", "fresh"]);
            drop((client, server));
            task.stop().await;
        }
    }
}

#[tokio::test]
async fn live_chacha_peer_clients_complete_fresh_and_resumed_handshakes() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for mode in ["native", "random"] {
            let (encryption, decryption, _) = credentials(mode, &["mlkem768"]);
            let (target, _, mut task) = echo().await;
            let port = free_port().await;
            let server = start(
                Kind::Shoes,
                port,
                server_config(Kind::Shoes, port, &decryption, false),
            )
            .await;
            let proxy = free_port().await;
            let client = start_options(
                peer,
                proxy,
                client_config(peer, proxy, port, &encryption, false),
                peer.binary(),
                Some("cpu.aes=off,cpu.pclmulqdq=off"),
            )
            .await;
            for _ in 0..2 {
                exchange(proxy, target, &vec![42; 32768]).await.unwrap();
            }
            server.assert_handshakes(&["fresh", "resumed"]);
            assert_eq!(
                server
                    .logs()
                    .matches("VLESS encryption server cipher: ChaCha20Poly1305")
                    .count(),
                2,
                "{}",
                server.logs()
            );
            drop((client, server));
            task.stop().await;
        }
    }
}
