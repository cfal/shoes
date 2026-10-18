use super::*;

#[tokio::test]
async fn tls_and_anytls_consumers_survive_backpressure_and_cancelled_streams() {
    let with_padding_gap = |setting: String| {
        let gapped = setting.replace(".100-35-35.", ".100-35-35.100-25-25.100-35-35.");
        assert_ne!(gapped, setting, "fixture padding token was not found");
        gapped
    };
    for mode in ["native", "xorpub", "random"] {
        for vision in [false, true] {
            for anytls in [false, true] {
                eprintln!("chained: {mode}, vision={vision}, anytls={anytls}");
                let (encryption, decryption, _) = credentials(mode, &["x25519"]);
                let encryption = with_padding_gap(encryption);
                let decryption = with_padding_gap(decryption);
                let carrier_port = free_port().await;
                let carrier = start(
                    Kind::Shoes,
                    carrier_port,
                    server_config(Kind::Shoes, carrier_port, &decryption, vision),
                )
                .await;
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let hop_port = free_port().await;
                let hop_protocol = if anytls {
                    json!({"type":"anytls","users":[{"name":"test","password":"test-password"}]})
                } else {
                    json!({"type":"socks"})
                };
                let hop_config = json!([{
                    "address":format!("0.0.0.0:{hop_port}"),
                    "protocol":{"type":"tls","default_target":{
                        "cert":cert.cert.pem(),"key":cert.signing_key.serialize_pem(),"protocol":hop_protocol
                    }}
                }]);
                let hop = start(Kind::Shoes, hop_port, hop_config).await;
                let proxy = free_port().await;
                let mut config =
                    client_config(Kind::Shoes, proxy, carrier_port, &encryption, vision);
                let vless_hop = config[0]["rules"][0]["client_chain"].take();
                let hop_client_protocol = if anytls {
                    json!({"type":"anytls","password":"test-password"})
                } else {
                    json!({"type":"socks"})
                };
                config[0]["rules"][0]["client_chain"] = json!([vless_hop, {
                    "address":format!("127.0.0.1:{hop_port}"),
                    "protocol":{"type":"tls","sni_hostname":"localhost","verify":false,"protocol":hop_client_protocol}
                }]);
                let client = start(Kind::Shoes, proxy, config).await;
                let (target, _, mut target_task) = echo().await;
                let result = timeout(Duration::from_secs(30), async {
                    // Keep one stream alive while abandoning a different stream with unread data.
                    let mut survivor = socks_connect(proxy, target).await?;
                    let mut cancelled = socks_connect(proxy, target).await?;
                    cancelled.write_all(&vec![31; 128 * 1024]).await?;
                    drop(cancelled);
                    let payload: Vec<_> =
                        (0..2 * 1024 * 1024 + 17).map(|n| (n % 251) as u8).collect();
                    let (mut read, mut write) = survivor.split();
                    tokio::try_join!(
                        async {
                            for chunk in payload.chunks(16384) {
                                write.write_all(chunk).await?;
                            }
                            write.flush().await
                        },
                        async {
                            let mut received = vec![0; payload.len()];
                            for chunk in received.chunks_mut(4096) {
                                read.read_exact(chunk).await?;
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            assert_eq!(received, payload);
                            Ok::<_, io::Error>(())
                        }
                    )?;
                    drop(survivor);
                    exchange(proxy, target, b"new stream after cancellation").await
                })
                .await;
                assert!(
                    matches!(result, Ok(Ok(()))),
                    "{result:?}\n{}\nhop: {}",
                    pair_logs(&client, &carrier),
                    hop.logs()
                );
                assert!(
                    carrier
                        .logs()
                        .contains("VLESS encryption server: fresh handshake")
                );
                drop((client, hop, carrier));
                target_task.stop().await;
            }
        }
    }
}
