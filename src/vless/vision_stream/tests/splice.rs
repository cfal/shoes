use super::*;
use crate::copy_bidirectional::{copy_bidirectional, copy_bidirectional_with_sizes};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);
const APPLICATION_DATA: &[u8] = b"\x17\x03\x03\x00\x04data";
type Vision = VisionStream<Box<dyn AsyncStream>>;

fn inner_client_hello() -> Vec<u8> {
    let (mut client, _) = new_connections(Backend::Tls13);
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    hello
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let client = client.unwrap();
    let server = server.unwrap().0;
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server)
}

async fn vision_pair(backend: Backend, hide_tcp: bool) -> (Vision, Vision) {
    let (client, server) = connection_pair(backend);
    let (a, b) = tcp_pair().await;
    let wrap = |socket| -> Box<dyn AsyncStream> {
        if hide_tcp {
            Box::new(crate::prepend_stream::PrependStream::new(socket, None))
        } else {
            Box::new(socket)
        }
    };
    let client = CryptoTlsStream::new(wrap(a), client, Some(TlsDeframer::new()));
    let server = CryptoTlsStream::new(wrap(b), server, Some(TlsDeframer::new()));
    (
        VisionStream::new_client(client, [7; 16]).unwrap(),
        VisionStream::new_server(server, [7; 16], b"").unwrap(),
    )
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

struct HandoffWitness {
    stream: Vision,
    handed_off: Arc<AtomicBool>,
    ready: Arc<tokio::sync::Notify>,
}

impl HandoffWitness {
    fn check_buffered(&self) {
        assert!(
            !self.handed_off.load(Ordering::Relaxed),
            "wrapper I/O after handoff"
        );
    }
}

impl AsyncRead for HandoffWitness {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_buffered();
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for HandoffWitness {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_buffered();
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_buffered();
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_buffered();
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for HandoffWitness {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        panic!("unexpected ping")
    }
}

impl AsyncStream for HandoffWitness {
    fn plain_tcp(&self) -> Option<&TcpStream> {
        let socket = self.stream.plain_tcp()?;
        if !self.handed_off.swap(true, Ordering::Relaxed) {
            self.ready.notify_one();
        }
        Some(socket)
    }
}

async fn direct_relay(backend: Backend, server: bool, buffered: bool, hide_tcp: bool) {
    let (client, inbound) = vision_pair(backend, hide_tcp).await;
    let (mut peer, stream) = if server {
        (client, inbound)
    } else {
        (inbound, client)
    };
    let (mut remote, mut destination) = tcp_pair().await;
    let handed_off = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(tokio::sync::Notify::new());
    let mut witness = HandoffWitness {
        stream,
        handed_off: handed_off.clone(),
        ready: ready.clone(),
    };
    let relay = tokio::spawn(async move {
        if buffered {
            copy_bidirectional_with_sizes(&mut witness, &mut remote, false, false, 16384, 16384)
                .await
        } else {
            copy_bidirectional(&mut witness, &mut remote, false, false).await
        }
    });

    let hello = inner_client_hello();
    if server {
        transfer(&mut peer, &mut destination, &hello).await;
    } else {
        transfer(&mut destination, &mut peer, &hello).await;
    }
    let flight = [inner_server_hello().as_ref(), APPLICATION_DATA].concat();
    if server {
        transfer(&mut destination, &mut peer, &flight).await;
    } else {
        transfer(&mut peer, &mut destination, &flight).await;
    }
    assert!(peer.plain_tcp().is_none(), "only one direction is DIRECT");
    assert!(!handed_off.load(Ordering::Relaxed));
    if server {
        transfer(&mut peer, &mut destination, APPLICATION_DATA).await;
    } else {
        transfer(&mut destination, &mut peer, APPLICATION_DATA).await;
    }
    let expect_handoff = !buffered && !hide_tcp;
    if expect_handoff {
        // No more request traffic is needed to enter the raw relay.
        ready.notified().await;
    }

    let spliced_before = crate::splice::TEST_SPLICED_BYTES.get();
    let payload: Vec<u8> = (0..4 * 1024 * 1024 + 37)
        .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
        .collect();
    if server {
        transfer(&mut destination, &mut peer, &payload).await;
    } else {
        transfer(&mut peer, &mut destination, &payload).await;
    }
    assert_eq!(handed_off.load(Ordering::Relaxed), expect_handoff);
    let spliced = crate::splice::TEST_SPLICED_BYTES.get() - spliced_before;
    if expect_handoff {
        assert!(spliced > 0, "bulk DIRECT traffic must actually use splice");
    } else {
        assert_eq!(spliced, 0);
    }

    // A half-close must leave the reverse direction alive for a delayed reply.
    peer.shutdown().await.unwrap();
    assert_eq!(destination.read(&mut [0; 1]).await.unwrap(), 0);
    transfer(&mut destination, &mut peer, b"response after EOF").await;
    destination.shutdown().await.unwrap();
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    relay.await.unwrap().unwrap();
}

#[tokio::test]
async fn direct_download_hands_off_client_and_server_without_more_upload() {
    timeout(DEADLINE, async {
        for backend in BACKENDS {
            for server in [false, true] {
                direct_relay(backend, server, false, false).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_buffered_and_hidden_tcp_paths_never_handoff() {
    timeout(DEADLINE, async {
        direct_relay(Backend::Tls13, true, true, false).await;
        direct_relay(Backend::Tls13, false, false, true).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn capability_waits_for_pending_plaintext_and_transition_flush() {
    timeout(DEADLINE, async {
        for backend in BACKENDS {
            let (mut client, mut server) = vision_pair(backend, false).await;
            transfer(&mut client, &mut server, &inner_client_hello()).await;
            transfer(&mut server, &mut client, &inner_server_hello()).await;
            transfer(&mut client, &mut server, APPLICATION_DATA).await;
            assert!(server.plain_tcp().is_none());

            server.write_all(APPLICATION_DATA).await.unwrap();
            // Even an empty frozen prefix requires the final transport flush.
            assert!(server.plain_tcp().is_none());
            server.flush().await.unwrap();
            assert!(server.plain_tcp().is_some());

            let mut first = [0; 1];
            client.read_exact(&mut first).await.unwrap();
            assert_eq!(first[0], APPLICATION_DATA[0]);
            assert!(client.plain_tcp().is_none());
            let mut rest = [0; APPLICATION_DATA.len() - 1];
            client.read_exact(&mut rest).await.unwrap();
            assert_eq!(rest, &APPLICATION_DATA[1..]);
            assert!(client.plain_tcp().is_some());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_direct_read_hands_off_even_when_read_returns_pending() {
    timeout(DEADLINE, async {
        let (mut client, mut server) = vision_pair(Backend::Tls13, false).await;
        let flight = [inner_server_hello().as_ref(), APPLICATION_DATA].concat();
        transfer(&mut server, &mut client, &flight).await;
        assert!(server.plain_tcp().is_none());

        let (mut remote, _destination) = tcp_pair().await;
        let ready = Arc::new(tokio::sync::Notify::new());
        let mut witness = HandoffWitness {
            stream: server,
            handed_off: Arc::new(AtomicBool::new(false)),
            ready: ready.clone(),
        };
        let relay = tokio::spawn(async move {
            copy_bidirectional(&mut witness, &mut remote, false, false).await
        });

        let mut empty_direct = vec![7; 16];
        empty_direct.extend_from_slice(&[COMMAND_DIRECT, 0, 0, 0, 0]);
        client.queue_padded_write(&empty_direct);
        client.switch_write_to_direct_mode().unwrap();
        client.flush().await.unwrap();
        ready.notified().await;
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn half_close_before_second_direct_transition_stays_buffered() {
    timeout(DEADLINE, async {
        let (mut client, server) = vision_pair(Backend::Tls13, false).await;
        let (mut remote, mut destination) = tcp_pair().await;
        let handed_off = Arc::new(AtomicBool::new(false));
        let mut witness = HandoffWitness {
            stream: server,
            handed_off: handed_off.clone(),
            ready: Arc::new(tokio::sync::Notify::new()),
        };
        let relay = tokio::spawn(async move {
            copy_bidirectional(&mut witness, &mut remote, false, false).await
        });
        transfer(&mut client, &mut destination, &inner_client_hello()).await;
        transfer(&mut destination, &mut client, &inner_server_hello()).await;
        transfer(&mut client, &mut destination, APPLICATION_DATA).await;
        client.shutdown().await.unwrap();
        assert_eq!(destination.read(&mut [0; 1]).await.unwrap(), 0);

        let response = [APPLICATION_DATA, &vec![43; 128 * 1024]].concat();
        transfer(&mut destination, &mut client, &response).await;
        destination.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        relay.await.unwrap().unwrap();
        assert!(!handed_off.load(Ordering::Relaxed));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn end_and_inner_tls12_never_expose_tcp() {
    timeout(DEADLINE, async {
        for tls12 in [false, true] {
            let (mut client, mut server) = vision_pair(Backend::Tls13, false).await;
            transfer(&mut client, &mut server, &inner_client_hello()).await;
            let hello = if tls12 {
                let (mut inner_client, mut inner_server) = new_connections(Backend::Tls12);
                transfer_tls(&mut inner_client, &mut inner_server);
                let mut flight = Vec::new();
                inner_server.write_tls(&mut flight).unwrap();
                flight
            } else {
                // Non-TLS exhausts the filter and selects END rather than DIRECT.
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
            };
            transfer(&mut server, &mut client, &hello).await;
            for _ in 0..10 {
                transfer(&mut client, &mut server, APPLICATION_DATA).await;
                transfer(&mut server, &mut client, APPLICATION_DATA).await;
            }
            assert!(client.plain_tcp().is_none());
            assert!(server.plain_tcp().is_none());
            assert_eq!(client.read_mode, VisionMode::Tls);
            assert_eq!(server.write_mode, VisionMode::Tls);
        }
    })
    .await
    .unwrap();
}
