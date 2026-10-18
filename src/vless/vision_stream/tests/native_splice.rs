use super::decisions::{APPLICATION, TLS13_VERSION, client_hello, server_hello};
use super::*;
use crate::{copy_bidirectional::copy_bidirectional, vless::encryption::tests::fixture_pair};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(("127.0.0.1", listener.local_addr().unwrap().port())),
        listener.accept()
    );
    let client = client.unwrap();
    let server = server.unwrap().0;
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server)
}

async fn transfer(
    sender: &mut (impl AsyncStream + ?Sized),
    receiver: &mut (impl AsyncStream + ?Sized),
    bytes: &[u8],
) {
    let mut received = vec![0; bytes.len()];
    let (sent, read) = tokio::join!(
        async {
            sender.write_all(bytes).await?;
            sender.flush().await
        },
        receiver.read_exact(&mut received)
    );
    sent.unwrap();
    read.unwrap();
    assert_eq!(received, bytes);
}

#[tokio::test]
async fn native_direct_splices_only_unmasked_tcp_and_preserves_half_close() {
    timeout(Duration::from_secs(60), async {
        for mode in ["native", "xorpub", "random"] {
            for server_relay in [false, true] {
                for hide_tcp in [false, true] {
                    let (client, server) = fixture_pair(mode, true, &[32]);
                    for resumed in [false, true] {
                        let (a, b) = tcp_pair().await;
                        let wrap = |socket| -> Box<dyn AsyncStream> {
                            if hide_tcp {
                                Box::new(crate::prepend_stream::PrependStream::new(socket, None))
                            } else {
                                Box::new(socket)
                            }
                        };
                        let (a, b) = tokio::join!(
                            async {
                                let mut a = client.handshake(wrap(a)).await.unwrap();
                                assert_eq!(a.is_resumed(), resumed);
                                a.flush().await.unwrap();
                                a
                            },
                            server.handshake(wrap(b))
                        );
                        let c = VisionStream::new_client(a, [7; 16])
                            .unwrap()
                            .with_write_error_policy(VisionWriteErrorPolicy::AcknowledgeAccepted);
                        let s = VisionStream::new_server(b.unwrap(), [7; 16], b"")
                            .unwrap()
                            .with_write_error_policy(VisionWriteErrorPolicy::AcknowledgeAccepted);
                        let (mut peer, mut relay_io) = if server_relay { (c, s) } else { (s, c) };
                        let (mut remote, mut target) = tcp_pair().await;
                        let relay = tokio::spawn(async move {
                            copy_bidirectional(&mut relay_io, &mut remote, false, false).await
                        });
                        let hello = client_hello();
                        let flight = [
                            server_hello(0x1301, 32, TLS13_VERSION),
                            APPLICATION.to_vec(),
                        ]
                        .concat();
                        if server_relay {
                            transfer(&mut peer, &mut target, &hello).await;
                            transfer(&mut target, &mut peer, &flight).await;
                            assert!(peer.plain_tcp().is_none());
                            transfer(&mut peer, &mut target, APPLICATION).await;
                        } else {
                            transfer(&mut target, &mut peer, &hello).await;
                            transfer(&mut peer, &mut target, &flight).await;
                            assert!(peer.plain_tcp().is_none());
                            transfer(&mut target, &mut peer, APPLICATION).await;
                        }
                        let expect_splice = mode != "random" && !hide_tcp;
                        assert_eq!(peer.plain_tcp().is_some(), expect_splice);
                        let payload: Vec<_> =
                            (0..1024 * 1024 + 37).map(|n| (n % 251) as u8).collect();
                        for upload in [true, false] {
                            let before = crate::splice::TEST_SPLICED_BYTES.get();
                            if upload {
                                transfer(&mut peer, &mut target, &payload).await;
                            } else {
                                transfer(&mut target, &mut peer, &payload).await;
                            }
                            let copied = crate::splice::TEST_SPLICED_BYTES.get() - before;
                            assert_eq!(
                                copied > 0,
                                expect_splice,
                                "{mode}, server={server_relay}, hidden={hide_tcp}, resumed={resumed}, upload={upload}"
                            );
                        }
                        peer.shutdown().await.unwrap();
                        assert_eq!(target.read(&mut [0]).await.unwrap(), 0);
                        transfer(&mut target, &mut peer, b"response after EOF").await;
                        target.shutdown().await.unwrap();
                        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                        relay.await.unwrap().unwrap();
                    }
                }
            }
        }
    })
    .await
    .unwrap();
}
