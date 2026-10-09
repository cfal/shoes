use super::*;
use crate::copy_bidirectional::{copy_bidirectional, copy_bidirectional_with_sizes};
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);
const APPLICATION_DATA: &[u8] = b"\x17\x03\x03\x00\x04data";
type Vision = VisionStream<Box<dyn AsyncStream>>;

#[derive(Clone, Copy)]
enum RelayMode {
    Adaptive,
    Buffered,
    Wrapped,
}

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
    let (a, b) = tcp_pair().await;
    let wrap = |socket| -> Box<dyn AsyncStream> {
        if hide_tcp {
            Box::new(crate::prepend_stream::PrependStream::new(socket, None))
        } else {
            Box::new(socket)
        }
    };
    wrap_vision_pair(backend, wrap(a), wrap(b))
}

fn wrap_vision_pair(
    backend: Backend,
    client_io: Box<dyn AsyncStream>,
    server_io: Box<dyn AsyncStream>,
) -> (Vision, Vision) {
    let (client, server) = connection_pair(backend);
    let client = CryptoTlsStream::new(client_io, client, Some(TlsDeframer::new()));
    let server = CryptoTlsStream::new(server_io, server, Some(TlsDeframer::new()));
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
    fn new(stream: Vision) -> Self {
        Self {
            stream,
            handed_off: Arc::new(AtomicBool::new(false)),
            ready: Arc::new(tokio::sync::Notify::new()),
        }
    }

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

#[derive(Default)]
struct OutputState {
    bytes_before_block: usize,
    write_release: Option<oneshot::Receiver<()>>,
    flush_release: Option<oneshot::Receiver<()>>,
}

#[derive(Default)]
struct OutputGate {
    state: Mutex<OutputState>,
    write_blocked: Notify,
    flush_blocked: Notify,
}

impl OutputGate {
    fn block(&self) -> (oneshot::Sender<()>, oneshot::Sender<()>) {
        let (write, write_release) = oneshot::channel();
        let (flush, flush_release) = oneshot::channel();
        *self.state.lock().unwrap() = OutputState {
            bytes_before_block: 7,
            write_release: Some(write_release),
            flush_release: Some(flush_release),
        };
        (write, flush)
    }
}

struct GatedTcp {
    socket: TcpStream,
    output: Arc<OutputGate>,
}

impl AsyncRead for GatedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for GatedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut state = this.output.state.lock().unwrap();
        if state.bytes_before_block == 0
            && let Some(release) = &mut state.write_release
        {
            match Pin::new(release).poll(cx) {
                Poll::Pending => {
                    this.output.write_blocked.notify_one();
                    return Poll::Pending;
                }
                Poll::Ready(result) => result.unwrap(),
            }
            state.write_release = None;
        }
        let len = if state.write_release.is_some() {
            buf.len().min(state.bytes_before_block)
        } else {
            buf.len()
        };
        let written = ready!(Pin::new(&mut this.socket).poll_write(cx, &buf[..len]))?;
        state.bytes_before_block = state.bytes_before_block.saturating_sub(written);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.output.state.lock().unwrap();
        if let Some(release) = &mut state.flush_release {
            match Pin::new(release).poll(cx) {
                Poll::Pending => {
                    if state.write_release.is_none() {
                        this.output.flush_blocked.notify_one();
                    }
                    return Poll::Pending;
                }
                Poll::Ready(result) => result.unwrap(),
            }
            state.flush_release = None;
        }
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl AsyncPing for GatedTcp {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        panic!("unexpected ping")
    }
}

impl AsyncStream for GatedTcp {
    fn plain_tcp(&self) -> Option<&TcpStream> {
        let state = self.output.state.lock().unwrap();
        assert!(state.write_release.is_none(), "handoff with blocked writes");
        assert!(state.flush_release.is_none(), "handoff with blocked flush");
        Some(&self.socket)
    }
}

#[tokio::test]
async fn two_vision_endpoints_drain_bidirectional_backpressure_before_handoff() {
    timeout(DEADLINE, async {
        for backend in BACKENDS {
            let (client_io, inbound_io) = tcp_pair().await;
            let (outbound_io, server_io) = tcp_pair().await;
            let inbound_gate = Arc::new(OutputGate::default());
            let outbound_gate = Arc::new(OutputGate::default());
            let (mut client, mut inbound) = wrap_vision_pair(
                backend,
                Box::new(client_io),
                Box::new(GatedTcp {
                    socket: inbound_io,
                    output: inbound_gate.clone(),
                }),
            );
            let (outbound, mut server) = wrap_vision_pair(
                backend,
                Box::new(GatedTcp {
                    socket: outbound_io,
                    output: outbound_gate.clone(),
                }),
                Box::new(server_io),
            );
            // The second endpoint is probed only after both relay buffers and
            // the first endpoint are eligible, so this witnesses the joint handoff.
            let mut outbound = HandoffWitness::new(outbound);
            let handed_off = outbound.handed_off.clone();
            let ready = outbound.ready.clone();
            let relay = tokio::spawn(async move {
                copy_bidirectional(&mut inbound, &mut outbound, false, false).await
            });
            transfer(&mut client, &mut server, &inner_client_hello()).await;
            transfer(&mut server, &mut client, &inner_server_hello()).await;

            let (inbound_write, inbound_flush) = inbound_gate.block();
            let (outbound_write, outbound_flush) = outbound_gate.block();
            let tail: Vec<u8> = (0..32 * 1024 + 37).map(|i| (i ^ (i >> 8)) as u8).collect();
            let uploaded = [APPLICATION_DATA, tail.as_slice()].concat();
            let downloaded = [APPLICATION_DATA, &tail[..tail.len() - 18]].concat();
            let spliced_before = crate::splice::TEST_SPLICED_BYTES.get();
            tokio::try_join!(
                async {
                    client.write_all(&uploaded).await?;
                    client.flush().await
                },
                async {
                    server.write_all(&downloaded).await?;
                    server.flush().await
                }
            )
            .unwrap();
            inbound_gate.write_blocked.notified().await;
            outbound_gate.write_blocked.notified().await;
            assert!(!handed_off.load(Ordering::Relaxed));
            assert_eq!(crate::splice::TEST_SPLICED_BYTES.get(), spliced_before);

            inbound_write.send(()).unwrap();
            inbound_gate.flush_blocked.notified().await;
            outbound_write.send(()).unwrap();
            outbound_gate.flush_blocked.notified().await;
            assert!(!handed_off.load(Ordering::Relaxed));
            assert_eq!(crate::splice::TEST_SPLICED_BYTES.get(), spliced_before);

            inbound_flush.send(()).unwrap();
            let mut received = vec![0; downloaded.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, downloaded);
            assert!(!handed_off.load(Ordering::Relaxed));
            assert_eq!(crate::splice::TEST_SPLICED_BYTES.get(), spliced_before);

            outbound_flush.send(()).unwrap();
            let mut received = vec![0; uploaded.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, uploaded);
            // Releasing the final flush must wake the handoff without another write.
            ready.notified().await;
            assert!(client.plain_tcp().is_some());
            assert!(server.plain_tcp().is_some());

            let payload = crate::copy_bidirectional::tests::quota_test_payload();
            let before_upload = crate::splice::TEST_SPLICED_BYTES.get();
            transfer(&mut client, &mut server, &payload).await;
            let after_upload = crate::splice::TEST_SPLICED_BYTES.get();
            assert!(after_upload > before_upload, "upload must use splice");
            transfer(&mut server, &mut client, &payload).await;
            assert!(
                crate::splice::TEST_SPLICED_BYTES.get() > after_upload,
                "download must use splice"
            );

            client.shutdown().await.unwrap();
            assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0);
            transfer(&mut server, &mut client, b"response after EOF").await;
            server.shutdown().await.unwrap();
            assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
            relay.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

async fn direct_relay(backend: Backend, is_server: bool, mode: RelayMode) {
    let (client, inbound) = vision_pair(backend, matches!(mode, RelayMode::Wrapped)).await;
    let (mut peer, stream) = if is_server {
        (client, inbound)
    } else {
        (inbound, client)
    };
    let (mut remote, mut destination) = tcp_pair().await;
    let mut witness = HandoffWitness::new(stream);
    let handed_off = witness.handed_off.clone();
    let ready = witness.ready.clone();
    let relay = tokio::spawn(async move {
        match mode {
            RelayMode::Buffered => {
                copy_bidirectional_with_sizes(&mut witness, &mut remote, false, false, 16384, 16384)
                    .await
            }
            RelayMode::Adaptive | RelayMode::Wrapped => {
                copy_bidirectional(&mut witness, &mut remote, false, false).await
            }
        }
    });

    let hello = inner_client_hello();
    if is_server {
        transfer(&mut peer, &mut destination, &hello).await;
    } else {
        transfer(&mut destination, &mut peer, &hello).await;
    }
    let flight = [inner_server_hello().as_ref(), APPLICATION_DATA].concat();
    if is_server {
        transfer(&mut destination, &mut peer, &flight).await;
    } else {
        transfer(&mut peer, &mut destination, &flight).await;
    }
    assert!(peer.plain_tcp().is_none(), "only one direction is DIRECT");
    assert!(!handed_off.load(Ordering::Relaxed));
    if is_server {
        transfer(&mut peer, &mut destination, APPLICATION_DATA).await;
    } else {
        transfer(&mut destination, &mut peer, APPLICATION_DATA).await;
    }
    let expect_handoff = matches!(mode, RelayMode::Adaptive);
    if expect_handoff {
        // No more request traffic is needed to enter the raw relay.
        ready.notified().await;
    }

    let spliced_before = crate::splice::TEST_SPLICED_BYTES.get();
    let payload: Vec<u8> = (0..4 * 1024 * 1024 + 37)
        .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
        .collect();
    if is_server {
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
            for is_server in [false, true] {
                direct_relay(backend, is_server, RelayMode::Adaptive).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_buffered_and_hidden_tcp_paths_never_handoff() {
    timeout(DEADLINE, async {
        direct_relay(Backend::Tls13, true, RelayMode::Buffered).await;
        direct_relay(Backend::Tls13, false, RelayMode::Wrapped).await;
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
        let mut witness = HandoffWitness::new(server);
        let ready = witness.ready.clone();
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
        let mut witness = HandoffWitness::new(server);
        let handed_off = witness.handed_off.clone();
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
