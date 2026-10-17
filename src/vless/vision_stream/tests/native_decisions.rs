use super::decisions::{
    APPLICATION, TLS13_VERSION, assert_decision, client_hello, server_hello, transfer,
};
use super::*;
use crate::vless::encryption::{
    ClientEncryption, EncryptionStream, ServerEncryption, tests::fixture_pair,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    time::{Duration, timeout},
};

type NativeVision = VisionStream<EncryptionStream<DuplexStream>>;

async fn pair(
    client: &ClientEncryption,
    server: &ServerEncryption,
    resumed: bool,
) -> (NativeVision, NativeVision) {
    let (a, b) = tokio::io::duplex(65536);
    let (a, b) = timeout(Duration::from_secs(3), async {
        tokio::join!(
            async {
                let mut stream = client.handshake(a).await?;
                stream.flush().await?;
                Ok::<_, io::Error>(stream)
            },
            server.handshake(b)
        )
    })
    .await
    .unwrap();
    let a = a.unwrap();
    assert_eq!(a.is_resumed(), resumed);
    (
        VisionStream::new_client(a, [7; 16])
            .unwrap()
            .with_write_error_policy(VisionWriteErrorPolicy::AcknowledgeAccepted),
        VisionStream::new_server(b.unwrap(), [7; 16], b"")
            .unwrap()
            .with_write_error_policy(VisionWriteErrorPolicy::AcknowledgeAccepted),
    )
}

#[tokio::test]
async fn native_fresh_and_resumed_direct_decisions_preserve_both_directions() {
    timeout(Duration::from_secs(60), async {
        for mode in ["native", "xorpub", "random"] {
            for cipher in [
                0x1301, 0x1302, 0x1303, 0x1304, 0x1305, 0x1306, 0xc02f, 0x0a0a,
            ] {
                for extensions in [TLS13_VERSION, b"".as_slice()] {
                    for server_first in [false, true] {
                        let (client, server) = fixture_pair(mode, true, &[32]);
                        for resumed in [false, true] {
                            let (mut c, mut s) = pair(&client, &server, resumed).await;
                            transfer(&mut c, &mut s, &client_hello()).await;
                            transfer(&mut s, &mut c, &server_hello(cipher, 32, extensions)).await;
                            assert_decision(
                                &mut c,
                                &mut s,
                                (0x1301..=0x1304).contains(&cipher) && !extensions.is_empty(),
                                server_first,
                            )
                            .await;
                            c.shutdown().await.unwrap();
                            assert_eq!(s.read(&mut [0]).await.unwrap(), 0);
                            s.write_all(b"after half-close").await.unwrap();
                            s.flush().await.unwrap();
                            let mut reply = [0; 16];
                            c.read_exact(&mut reply).await.unwrap();
                            assert_eq!(&reply, b"after half-close");
                            s.shutdown().await.unwrap();
                            assert_eq!(c.read(&mut [0]).await.unwrap(), 0);
                        }
                    }
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_fragmented_records_preserve_direct_decisions_and_coalesced_tails() {
    timeout(Duration::from_secs(60), async {
        for mode in ["native", "xorpub", "random"] {
            for cipher in [0x1301, 0x1305] {
                let hello = server_hello(cipher, 32, TLS13_VERSION);
                for split in 1..hello.len() {
                    let (client, server) = fixture_pair(mode, true, &[32]);
                    for resumed in [false, true] {
                        let (mut c, mut s) = pair(&client, &server, resumed).await;
                        transfer(&mut c, &mut s, &client_hello()).await;
                        s.write_all(&hello[..split]).await.unwrap();
                        s.flush().await.unwrap();
                        assert!(!s.filter.supports_xtls());
                        s.write_all(&hello[split..]).await.unwrap();
                        s.flush().await.unwrap();
                        let mut received = vec![0; hello.len()];
                        c.read_exact(&mut received).await.unwrap();
                        assert_eq!(received, hello);
                        assert_decision(&mut c, &mut s, cipher == 0x1301, split % 2 == 0).await;
                    }
                }
                for split in 1..APPLICATION.len() {
                    let (client, server) = fixture_pair(mode, true, &[32]);
                    let (mut c, mut s) = pair(&client, &server, false).await;
                    transfer(&mut c, &mut s, &client_hello()).await;
                    transfer(&mut s, &mut c, &hello).await;
                    s.write_all(&APPLICATION[..split]).await.unwrap();
                    s.flush().await.unwrap();
                    let tail = [APPLICATION[split..].to_vec(), b"coalesced tail".to_vec()].concat();
                    s.write_all(&tail).await.unwrap();
                    s.flush().await.unwrap();
                    let expected = [APPLICATION, b"coalesced tail"].concat();
                    let mut received = vec![0; expected.len()];
                    c.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, expected);
                    assert_eq!(
                        c.read_mode,
                        if cipher == 0x1301 {
                            VisionMode::Direct
                        } else {
                            VisionMode::Tls
                        }
                    );
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_malformed_hello_and_non_tls_never_enable_direct() {
    timeout(Duration::from_secs(60), async {
        let mut short = server_hello(0x1301, 32, TLS13_VERSION);
        short[6..9].copy_from_slice(&[0, 0, 2]);
        let mut long = short.clone();
        long[6..9].copy_from_slice(&[0, 1, 0]);
        let cases = [
            short,
            long,
            server_hello(0x1301, 33, TLS13_VERSION),
            server_hello(0x1301, 0, b"\x00\x2b\x00\x01\x03"),
        ];
        for mode in ["native", "xorpub", "random"] {
            for hello in &cases {
                let (client, server) = fixture_pair(mode, true, &[32]);
                for resumed in [false, true] {
                    let (mut c, mut s) = pair(&client, &server, resumed).await;
                    transfer(&mut c, &mut s, &client_hello()).await;
                    transfer(&mut s, &mut c, hello).await;
                    assert_decision(&mut c, &mut s, false, false).await;
                }
            }
            let (client, server) = fixture_pair(mode, true, &[32]);
            for resumed in [false, true] {
                let (mut c, mut s) = pair(&client, &server, resumed).await;
                transfer(&mut c, &mut s, b"GET / HTTP/1.1\r\n\r\n").await;
                transfer(&mut s, &mut c, b"HTTP/1.1 200 OK\r\n\r\n").await;
                // Exhaust the shared read/write inspection budget, then commit END.
                for _ in 0..10 {
                    transfer(&mut c, &mut s, &[b'x'; 256]).await;
                    transfer(&mut s, &mut c, &[b'y'; 256]).await;
                }
                assert_eq!(c.write_mode, VisionMode::Tls);
                assert_eq!(s.read_mode, VisionMode::Tls);
                assert!(!c.filter.supports_xtls());
                assert!(!s.filter.supports_xtls());
            }
        }
    })
    .await
    .unwrap();
}
