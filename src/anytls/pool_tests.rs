use super::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec};
use super::{AnyTlsClientHandler, PaddingFactory, PoolOptions};
use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncShutdownMessageExt, AsyncStream},
    tcp::{
        carrier_dialer::{CarrierDialer, RouteKey},
        tcp_handler::{ClientTransport, TcpClientHandler},
    },
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    sync::mpsc,
};

mod xhttp;

#[derive(Debug)]
struct Dialer {
    key: RouteKey,
    calls: AtomicUsize,
    peers: mpsc::UnboundedSender<tokio::io::DuplexStream>,
}

#[async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let (client, peer) = tokio::io::duplex(4096);
        self.peers.send(peer).map_err(io::Error::other)?;
        Ok(Box::new(client))
    }
}

fn dialer(
    id: usize,
) -> (
    Arc<Dialer>,
    mpsc::UnboundedReceiver<tokio::io::DuplexStream>,
) {
    let (peers, rx) = mpsc::unbounded_channel();
    (
        Arc::new(Dialer {
            key: RouteKey(vec![id]),
            calls: AtomicUsize::new(0),
            peers,
        }),
        rx,
    )
}

fn transport<D: CarrierDialer + 'static>(dialer: &Arc<D>) -> ClientTransport<'static> {
    let route = dialer.clone();
    let dialer = dialer.clone();
    ClientTransport {
        route,
        open: Box::pin(async move { dialer.open_stream().await }),
    }
}

fn handler(options: PoolOptions) -> AnyTlsClientHandler {
    AnyTlsClientHandler::with_options(
        "test".into(),
        Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap()),
        true,
        options,
    )
}

fn configured_handler(config: serde_json::Value) -> Box<dyn TcpClientHandler> {
    crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
        serde_json::from_value(config).unwrap(),
        &NetLocation::from_str("127.0.0.1:443", None).unwrap(),
        Arc::new(crate::resolver::NativeResolver::new()),
    )
    .unwrap()
}

fn target() -> ResolvedLocation {
    NetLocation::from_str("127.0.0.1:12345", None)
        .unwrap()
        .into()
}

async fn connect<D: CarrierDialer + 'static>(
    handler: &dyn TcpClientHandler,
    dialer: &Arc<D>,
) -> Box<dyn AsyncStream> {
    handler
        .connect_client_tcp(transport(dialer), target())
        .await
        .unwrap()
        .client_stream
}

struct Peer<T = tokio::io::DuplexStream> {
    io: T,
    buffer: BytesMut,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Peer<T> {
    async fn new(mut io: T) -> Self {
        let mut auth = [0; 34];
        io.read_exact(&mut auth).await.unwrap();
        let padding = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        io.read_exact(&mut vec![0; padding]).await.unwrap();
        Self {
            io,
            buffer: BytesMut::new(),
        }
    }
    async fn frame(&mut self) -> Frame {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(frame) = FrameCodec::decode(&mut self.buffer).unwrap() {
                    return frame;
                }
                assert_ne!(self.io.read_buf(&mut self.buffer).await.unwrap(), 0);
            }
        })
        .await
        .unwrap()
    }
    async fn send(&mut self, cmd: Command, id: u32, data: &[u8]) {
        let mut buffer = BytesMut::new();
        Frame::with_data(cmd, id, Bytes::copy_from_slice(data))
            .encode_into(&mut buffer)
            .unwrap();
        self.io.write_all(&buffer).await.unwrap();
        self.io.flush().await.unwrap();
    }
    async fn opened(&mut self, id: u32) {
        if id == 1 {
            assert_eq!(self.frame().await.cmd, Command::Settings);
        }
        let syn = self.frame().await;
        assert_eq!((syn.cmd, syn.stream_id), (Command::Syn, id));
        assert_eq!(self.frame().await.cmd, Command::Psh);
    }
}

async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

async fn warm_v2_second_lease(
    handler: &AnyTlsClientHandler,
    dialer: &Arc<Dialer>,
    peers: &mut mpsc::UnboundedReceiver<tokio::io::DuplexStream>,
) -> (Box<dyn AsyncStream>, Peer) {
    let stream = connect(handler, dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::ServerSettings, 0, b"v=2").await;
    settle().await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let stream = connect(handler, dialer).await;
    peer.opened(2).await;
    (stream, peer)
}

async fn assert_message_echo(
    stream: &mut dyn AsyncMessageStream,
    payload: &[u8],
    buffer: &mut [u8],
) {
    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload))
        .await
        .unwrap();
    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
        .await
        .unwrap();
    let mut response = ReadBuf::new(buffer);
    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut response))
        .await
        .unwrap();
    assert_eq!(response.filled(), payload);
}

#[tokio::test]
async fn transport_wrappers_run_in_order_only_on_pool_miss() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let order = parking_lot::Mutex::new(Vec::new());
    let wrapped_transport = || {
        transport(&dialer)
            .wrap(|stream| async {
                order.lock().push(1);
                Ok(stream)
            })
            .wrap(|stream| async {
                order.lock().push(2);
                Ok(stream)
            })
    };
    let transport = wrapped_transport();
    assert!(order.lock().is_empty());
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 0);
    let stream = handler
        .connect_client_tcp(transport, target())
        .await
        .unwrap();
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    assert_eq!(*order.lock(), [1, 2]);
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let _next = handler
        .connect_client_tcp(wrapped_transport(), target())
        .await
        .unwrap();
    peer.opened(2).await;
    assert_eq!(*order.lock(), [1, 2]);
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn invalid_destination_does_not_consume_an_idle_session() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let invalid: ResolvedLocation =
        NetLocation::new(crate::address::Address::Hostname("x".repeat(256)), 443).into();
    let tcp_error = handler
        .connect_client_tcp(transport(&dialer), invalid.clone())
        .await
        .err()
        .unwrap();
    let udp_error = handler
        .connect_client_udp(transport(&dialer), invalid)
        .await
        .err()
        .unwrap();
    for error in [tcp_error, udp_error] {
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "AnyTLS destination hostname exceeds 255 bytes"
        );
    }
    let _next = connect(&handler, &dialer).await;
    peer.opened(2).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn attachment_after_writer_disposal_returns_exactly_one_lease() {
    use super::{anytls_client_pool::SessionPool, anytls_client_session::AnyTlsClientSession};

    tokio::time::timeout(Duration::from_secs(2), async {
        let pool = SessionPool::new(PoolOptions::default());
        let (dialer, mut peers) = dialer(1);
        let session = AnyTlsClientSession::new(
            dialer.open_stream().await.unwrap(),
            "test",
            Arc::new(parking_lot::RwLock::new(Arc::new(
                PaddingFactory::new(b"stop=1\n0=0-0").unwrap(),
            ))),
        )
        .await
        .unwrap();
        let mut stream = session.open_stream(target().into_location()).await.unwrap();
        let mut peer = Peer::new(peers.recv().await.unwrap()).await;
        peer.opened(1).await;
        stream.shutdown().await.unwrap();
        assert_eq!(peer.frame().await.cmd, Command::Fin);
        assert!(pool.take(dialer.route_key()).is_none());
        stream.attach_pool(&pool, dialer.clone());
        let reused = pool
            .take(dialer.route_key())
            .expect("late attachment lost the session");
        assert!(Arc::ptr_eq(&session, &reused));
        assert!(pool.take(dialer.route_key()).is_none());
        let mut next = reused.open_stream(target().into_location()).await.unwrap();
        peer.opened(2).await;
        drop(stream);
        assert!(pool.take(dialer.route_key()).is_none());
        next.write_all(b"live").await.unwrap();
        let frame = peer.frame().await;
        assert_eq!(
            (frame.cmd, frame.stream_id, frame.data.as_ref()),
            (Command::Psh, 2, &b"live"[..])
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn retained_terminal_streams_release_cancelled_write_reservations() {
    use std::task::{Context, Poll, Waker};

    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    let mut retained = Vec::new();
    for id in 1..=17 {
        peer.opened(id).await;
        stream.write_all(&[7; 32000]).await.unwrap();
        settle().await;
        let mut queued = 0;
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            match Pin::new(&mut *stream).poll_write(&mut cx, b"queued") {
                Poll::Ready(Ok(_)) => queued += 1,
                Poll::Pending => break,
                result => panic!("unexpected write result: {result:?}"),
            }
            assert!(queued <= super::anytls_stream::STREAM_CHANNEL_BUFFER);
        }
        peer.send(Command::Psh, id, b"buffered").await;
        peer.send(Command::Fin, id, b"").await;
        settle().await;
        // Cancel the write and retain the handle for unread response bytes.
        // No terminal write-side poll or Drop may be needed to free its permit.
        retained.push(stream);
        for _ in 0..=queued {
            assert_eq!(peer.frame().await.cmd, Command::Psh);
        }
        stream = tokio::time::timeout(Duration::from_secs(1), connect(&handler, &dialer))
            .await
            .expect("completed handles exhausted the shared queue permits");
    }
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
    for mut old in retained {
        let mut response = Vec::new();
        old.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"buffered");
    }
}

#[tokio::test]
async fn handoff_retains_session_when_completion_wakes_stream_drop() {
    use std::task::{Context, Waker};

    struct DropOnWake(parking_lot::Mutex<Option<Box<dyn AsyncStream>>>);
    impl std::task::Wake for DropOnWake {
        fn wake(self: Arc<Self>) {
            let stream = self.0.lock().take();
            drop(stream);
        }
    }

    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    stream.write_all(&[7; 32000]).await.unwrap();
    settle().await;
    let on_wake = Arc::new(DropOnWake(parking_lot::Mutex::new(None)));
    let waker = Waker::from(on_wake.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut *stream).poll_flush(&mut cx).is_pending());
    *on_wake.0.lock() = Some(stream);
    peer.send(Command::Fin, 1, b"").await;
    settle().await;
    assert!(on_wake.0.lock().is_none());
    let _next = connect(&handler, &dialer).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
    assert_eq!(peer.frame().await.cmd, Command::Psh);
    peer.opened(2).await;
}

#[test]
fn terminal_completion_disposes_stale_waker_outside_lifecycle_lock() {
    use super::{
        anytls_client_pool::SessionPool, anytls_client_session::AnyTlsClientSession,
        anytls_stream::AnyTlsStream,
    };
    use std::task::{Context, Poll, Waker};
    use tokio::io::AsyncWrite;

    struct StaleWaker {
        stream: parking_lot::Mutex<Option<AnyTlsStream>>,
        pool: Arc<SessionPool>,
        dialer: Arc<Dialer>,
        late_attach: bool,
    }
    #[allow(
        clippy::manual_noop_waker,
        reason = "The regression needs waker-owned state destroyed with the waker"
    )]
    impl std::task::Wake for StaleWaker {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for StaleWaker {
        fn drop(&mut self) {
            if self.late_attach {
                self.stream
                    .get_mut()
                    .as_ref()
                    .unwrap()
                    .attach_pool(&self.pool, self.dialer.clone());
            }
            assert!(
                self.pool.take(self.dialer.route_key()).is_none(),
                "published before disposal completed"
            );
        }
    }

    // A synchronous mutex deadlock cannot be bounded by a Tokio timer on the
    // same runtime. Keep the regression's wall-clock guard on another thread.
    let (done, completed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for late_attach in [false, true] {
                    let pool = SessionPool::new(PoolOptions::default());
                    let (dialer, mut peers) = dialer(1);
                    let session = AnyTlsClientSession::new(
                        dialer.open_stream().await.unwrap(),
                        "test",
                        Arc::new(parking_lot::RwLock::new(Arc::new(
                            PaddingFactory::new(b"stop=1\n0=0-0").unwrap(),
                        ))),
                    )
                    .await
                    .unwrap();
                    let mut stream = session.open_stream(target().into_location()).await.unwrap();
                    if !late_attach {
                        stream.attach_pool(&pool, dialer.clone());
                    }
                    let session_id = Arc::downgrade(&session);
                    drop(session);
                    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
                    peer.opened(1).await;
                    stream.write_all(&[7; 32000]).await.unwrap();
                    settle().await;
                    let owner = Arc::new(StaleWaker {
                        stream: parking_lot::Mutex::new(None),
                        pool: pool.clone(),
                        dialer: dialer.clone(),
                        late_attach,
                    });
                    let waker = Waker::from(owner.clone());
                    assert!(
                        Pin::new(&mut stream)
                            .poll_flush(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                    assert!(matches!(
                        Pin::new(&mut stream)
                            .poll_write(&mut Context::from_waker(Waker::noop()), b""),
                        Poll::Ready(Ok(0))
                    ));
                    *owner.stream.lock() = Some(stream);
                    drop(waker);
                    drop(owner);
                    // Only the obsolete flush waker now owns the stream. Dropping
                    // that waker during completion synchronously drops the stream.
                    peer.send(Command::Fin, 1, b"").await;
                    settle().await;
                    let session = pool
                        .take(dialer.route_key())
                        .expect("carrier lost during disposal");
                    assert!(session_id.ptr_eq(&Arc::downgrade(&session)));
                    let _next = session.open_stream(target().into_location()).await.unwrap();
                    assert_eq!(peer.frame().await.cmd, Command::Psh);
                    peer.opened(2).await;
                }
            });
        done.send(()).unwrap();
    });
    assert!(
        !matches!(
            completed.recv_timeout(Duration::from_secs(5)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "stale flush waker disposal re-entered the lifecycle lock"
    );
    worker.join().unwrap();
}

#[tokio::test(start_paused = true)]
async fn watchdog_excludes_previous_lease_backlog() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::ServerSettings, 0, b"v=2").await;
    settle().await;
    stream.write_all(&[7; 32000]).await.unwrap();
    settle().await;
    for _ in 0..4 {
        stream.write_all(b"queued").await.unwrap();
    }
    peer.send(Command::Fin, 1, b"").await;
    settle().await;
    let mut next = connect(&handler, &dialer).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    next.write_all(b"live")
        .await
        .expect("watchdog timed the previous lease's backlog");
    for _ in 0..5 {
        assert_eq!(peer.frame().await.cmd, Command::Psh);
    }
    peer.opened(2).await;
    assert_eq!(&peer.frame().await.data[..], b"live");
    peer.send(Command::Psh, 2, b"ok").await;
    next.read_exact(&mut [0; 2]).await.unwrap();
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    next.write_all(b"still live").await.unwrap();
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn peer_fin_wakes_pending_write_flush_and_shutdown() {
    use std::task::{Context, Poll, Waker};

    for operation in ["write", "flush", "shutdown"] {
        let handler = handler(PoolOptions::default());
        let (dialer, mut peers) = dialer(1);
        let mut stream = connect(&handler, &dialer).await;
        let mut peer = Peer::new(peers.recv().await.unwrap()).await;
        peer.opened(1).await;
        stream.write_all(&[7; 32000]).await.unwrap();
        settle().await;

        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut poll_operation = |cx: &mut Context<'_>| match operation {
            "write" => Pin::new(&mut *stream)
                .poll_write(cx, b"blocked")
                .map_ok(|_| ()),
            "flush" => Pin::new(&mut *stream).poll_flush(cx),
            _ => Pin::new(&mut *stream).poll_shutdown(cx),
        };
        // A write must fill the outgoing queue as well as the carrier buffer.
        if operation == "write" {
            for _ in 0..super::anytls_stream::STREAM_CHANNEL_BUFFER {
                assert!(matches!(poll_operation(&mut cx), Poll::Ready(Ok(()))));
            }
        }
        assert!(poll_operation(&mut cx).is_pending(), "{operation}");
        settle().await;
        count.0.store(0, Ordering::Relaxed);
        peer.send(Command::Fin, 1, b"").await;
        settle().await;
        assert!(count.0.load(Ordering::Relaxed) > 0, "{operation} not woken");
        assert!(
            matches!(poll_operation(&mut cx), Poll::Ready(Ok(()))),
            "terminal {operation}"
        );
        if operation == "shutdown" {
            assert!(stream.write_all(b"after local shutdown").await.is_err());
        }
        assert_eq!(peer.frame().await.cmd, Command::Psh);
        if operation == "write" {
            for _ in 0..super::anytls_stream::STREAM_CHANNEL_BUFFER {
                let frame = peer.frame().await;
                assert_eq!((frame.cmd, frame.stream_id), (Command::Psh, 1));
                assert_eq!(frame.data.as_ref(), b"blocked");
            }
        } else if operation == "shutdown" {
            assert_eq!(peer.frame().await.cmd, Command::Fin);
        }
        let _next = connect(&handler, &dialer).await;
        peer.opened(2).await;
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn terminal_uot_shutdown_does_not_flush_a_new_lease() {
    use crate::vless::VlessMessageStream;

    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::Fin, 1, b"").await;
    settle().await;
    let mut next = connect(&handler, &dialer).await;
    peer.opened(2).await;
    next.write_all(&[7; 32000]).await.unwrap();
    settle().await;
    let mut udp = VlessMessageStream::new(stream);
    tokio::time::timeout(Duration::from_secs(1), udp.shutdown_message())
        .await
        .expect("terminal UoT shutdown waited on a different lease")
        .unwrap();
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn peer_fin_preserves_buffered_response_during_a_relay_upload() {
    use std::future::Future;
    use std::task::{Context, Waker};

    tokio::time::timeout(Duration::from_secs(3), async {
        let handler = handler(PoolOptions::default());
        let (dialer, mut peers) = dialer(1);
        let mut stream = connect(&handler, &dialer).await;
        let mut peer = Peer::new(peers.recv().await.unwrap()).await;
        peer.opened(1).await;
        let response = vec![42; 32000];
        peer.send(Command::Psh, 1, &response).await;
        peer.send(Command::Fin, 1, b"").await;
        // The heartbeat response proves FIN was processed without draining stream 1.
        peer.send(Command::HeartRequest, 0, b"").await;
        assert_eq!(peer.frame().await.cmd, Command::HeartResponse);
        let mut next = connect(&handler, &dialer).await;
        peer.opened(2).await;

        let (mut client, mut inbound) = tokio::io::duplex(64);
        client.write_all(b"upload still arriving").await.unwrap();
        client.shutdown().await.unwrap();
        let mut relay = Box::pin(crate::copy_bidirectional::copy_bidirectional(
            &mut inbound,
            &mut *stream,
            false,
            false,
        ));
        assert!(
            relay
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "upload after peer FIN must not abort the backpressured response"
        );
        let mut received = Vec::new();
        let (copied, read) = tokio::join!(relay, client.read_to_end(&mut received));
        copied.unwrap();
        read.unwrap();
        assert_eq!(received, response);
        assert!(stream.write_all(b"after local shutdown").await.is_err());
        drop(stream);
        next.write_all(b"next lease").await.unwrap();
        let frame = peer.frame().await;
        assert_eq!(
            (frame.cmd, frame.stream_id, frame.data.as_ref()),
            (Command::Psh, 2, &b"next lease"[..])
        );
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sequential_shutdown_drop_and_peer_fin_reuse_exactly_once() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::ServerSettings, 0, b"v=2").await;
    for id in 1..=16 {
        if id > 1 {
            peer.opened(id).await;
        }
        peer.send(Command::Psh, id, b"response").await;
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        stream.shutdown().await.unwrap();
        assert_eq!(peer.frame().await.cmd, Command::Fin);
        // Drop after another checkout must not return the old lease again.
        let next = connect(&handler, &dialer).await;
        drop(stream);
        stream = next;
    }
    peer.opened(17).await;
    peer.send(Command::Psh, 17, b"buffered").await;
    peer.send(Command::Fin, 17, b"").await;
    settle().await;
    let mut next = connect(&handler, &dialer).await;
    peer.opened(18).await;
    stream.write_all(b"late").await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"buffered");
    drop(stream);
    next.write_all(b"after").await.unwrap();
    let frame = peer.frame().await;
    assert_eq!(
        (frame.cmd, frame.stream_id, frame.data.as_ref()),
        (Command::Psh, 18, &b"after"[..])
    );
    let concurrent = connect(&handler, &dialer).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    drop((next, concurrent));
}

#[tokio::test]
async fn concurrent_leases_mru_and_route_isolation() {
    let handler = handler(PoolOptions::default());
    let (mut a, mut peers) = dialer(1);
    Arc::get_mut(&mut a).unwrap().key = RouteKey(vec![1, 11]);
    let first = connect(&handler, &a).await;
    let mut peer1 = Peer::new(peers.recv().await.unwrap()).await;
    peer1.opened(1).await;
    let second = connect(&handler, &a).await;
    let mut peer2 = Peer::new(peers.recv().await.unwrap()).await;
    peer2.opened(1).await;
    drop(first);
    drop(second);
    assert_eq!(peer1.frame().await.cmd, Command::Fin);
    assert_eq!(peer2.frame().await.cmd, Command::Fin);
    let third = connect(&handler, &a).await;
    peer2.opened(2).await;
    let fourth = connect(&handler, &a).await;
    peer1.opened(2).await;
    assert_eq!(a.calls.load(Ordering::Relaxed), 2);
    drop(third);
    let (mut b, _peers_b) = dialer(2);
    Arc::get_mut(&mut b).unwrap().key = RouteKey(vec![1, 12]);
    let other_route = connect(&handler, &b).await;
    assert_eq!(b.calls.load(Ordering::Relaxed), 1);
    drop((fourth, other_route));
}

#[tokio::test]
async fn warm_v2_uot_header_precedes_ack_and_pool_is_shared_with_tcp() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::ServerSettings, 0, b"v=2").await;
    settle().await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let mut udp = tokio::time::timeout(
        Duration::from_secs(1),
        handler.connect_client_udp(transport(&dialer), target()),
    )
    .await
    .unwrap()
    .unwrap();
    peer.opened(2).await;
    let mut header = Vec::new();
    while header.len() < 8 {
        header.extend_from_slice(&peer.frame().await.data);
    }
    assert_eq!(header, [1, 1, 127, 0, 0, 1, 0x30, 0x39]);
    peer.send(Command::SynAck, 2, b"").await;
    futures::future::poll_fn(|cx| Pin::new(&mut *udp).poll_write_message(cx, b"dns"))
        .await
        .unwrap();
    futures::future::poll_fn(|cx| Pin::new(&mut *udp).poll_flush_message(cx))
        .await
        .unwrap();
    assert_eq!(&peer.frame().await.data[..], b"\0\x03dns");
    peer.send(Command::Psh, 2, b"\0\x03dns").await;
    let mut response = [0; 8];
    let mut read = ReadBuf::new(&mut response);
    futures::future::poll_fn(|cx| Pin::new(&mut *udp).poll_read_message(cx, &mut read))
        .await
        .unwrap();
    assert_eq!(read.filled(), b"dns");
    let _busy = connect(&handler, &dialer).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    drop(udp);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let _tcp = connect(&handler, &dialer).await;
    peer.opened(3).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn version_one_warm_opens_have_no_watchdog() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let mut stream = connect(&handler, &dialer).await;
    peer.opened(2).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    stream.write_all(b"live").await.unwrap();
    assert_eq!(peer.frame().await.data.as_ref(), b"live");
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn watchdog_disarms_on_a_non_stream_control_header() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::ServerSettings, 0, b"v=2").await;
    peer.send(Command::Psh, 1, b"ready").await;
    stream.read_exact(&mut [0; 5]).await.unwrap();
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let mut stream = connect(&handler, &dialer).await;
    peer.opened(2).await;
    peer.send(Command::HeartResponse, 0, b"").await;
    settle().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    stream.write_all(b"live").await.unwrap();
    assert_eq!(peer.frame().await.data.as_ref(), b"live");
}

#[tokio::test(start_paused = true)]
async fn watchdog_accepts_data_without_ack_and_retires_silent_carriers() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let (mut stream, mut peer) = warm_v2_second_lease(&handler, &dialer, &mut peers).await;
    peer.send(Command::Psh, 2, b"x").await;
    stream.read_exact(&mut [0; 1]).await.unwrap();
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    stream.write_all(b"still live").await.unwrap();
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Psh);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let mut stream = connect(&handler, &dialer).await;
    peer.opened(3).await;
    tokio::time::advance(Duration::from_millis(2999)).await;
    settle().await;
    stream.write_all(b"before deadline").await.unwrap();
    assert_eq!(peer.frame().await.data.as_ref(), b"before deadline");
    tokio::time::advance(Duration::from_millis(2)).await;
    settle().await;
    assert!(stream.write_all(b"closed").await.is_err());
    drop(stream);
    let _replacement = connect(&handler, &dialer).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn watchdog_disarms_before_a_slow_response_payload_arrives() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let (mut stream, mut peer) = warm_v2_second_lease(&handler, &dialer, &mut peers).await;

    let payload = vec![42; u16::MAX as usize];
    let frame = Frame::with_data(Command::Psh, 2, Bytes::copy_from_slice(&payload)).encode();
    peer.io
        .write_all(&frame[..FRAME_HEADER_SIZE])
        .await
        .unwrap();
    settle().await;
    for chunk in frame[FRAME_HEADER_SIZE..].chunks(4096) {
        tokio::time::advance(Duration::from_millis(500)).await;
        settle().await;
        stream.write_all(b"live").await.unwrap();
        assert_eq!(&peer.frame().await.data[..], b"live");
        peer.io.write_all(chunk).await.unwrap();
        settle().await;
    }
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let _next = connect(&handler, &dialer).await;
    peer.opened(3).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn watchdog_does_not_disarm_on_an_incomplete_header() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let (mut stream, mut peer) = warm_v2_second_lease(&handler, &dialer, &mut peers).await;

    let frame = Frame::with_data(Command::Psh, 2, Bytes::from_static(b"response")).encode();
    peer.io
        .write_all(&frame[..FRAME_HEADER_SIZE - 1])
        .await
        .unwrap();
    settle().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    assert!(stream.write_all(b"closed").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn watchdog_does_not_reuse_an_old_header_for_the_next_lease() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let (stream, mut peer) = warm_v2_second_lease(&handler, &dialer, &mut peers).await;

    let frame = Frame::with_data(Command::Psh, 2, Bytes::from_static(b"response")).encode();
    peer.io
        .write_all(&frame[..FRAME_HEADER_SIZE])
        .await
        .unwrap();
    settle().await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let mut stream = connect(&handler, &dialer).await;
    peer.opened(3).await;
    peer.io
        .write_all(&frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 1])
        .await
        .unwrap();
    settle().await;
    peer.io
        .write_all(&frame[FRAME_HEADER_SIZE + 1..])
        .await
        .unwrap();
    settle().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    settle().await;
    assert!(stream.write_all(b"closed").await.is_err());
}

#[tokio::test(start_paused = true)]
async fn local_completion_does_not_disarm_the_warm_open_watchdog() {
    for shutdown in [false, true] {
        let handler = handler(PoolOptions::default());
        let (dialer, mut peers) = dialer(1);
        let (mut stream, mut peer) = warm_v2_second_lease(&handler, &dialer, &mut peers).await;
        if shutdown {
            stream.shutdown().await.unwrap();
        }
        drop(stream);
        assert_eq!(peer.frame().await.cmd, Command::Fin);
        tokio::time::advance(Duration::from_secs(4)).await;
        settle().await;
        let _next = connect(&handler, &dialer).await;
        assert_eq!(
            dialer.calls.load(Ordering::Relaxed),
            2,
            "shutdown={shutdown}"
        );
    }
}

#[tokio::test]
async fn negative_ack_surfaces_error_without_poisoning_carrier() {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    peer.send(Command::SynAck, 1, b"refused").await;
    assert_eq!(
        stream.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    assert!(stream.write_all(b"late").await.is_err());
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let _next = connect(&handler, &dialer).await;
    peer.opened(2).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn expiry_minimum_dead_idle_and_handler_drop() {
    let handler = configured_handler(serde_json::json!({
        "type": "anytls",
        "password": "test",
        "padding_scheme": ["stop=1", "0=0-0"],
        "idle_session_check_interval_secs": 6,
        "idle_session_timeout_secs": 6,
        "min_idle_session": 1
    }));
    let (dialer, mut peers) = dialer(1);
    let a = connect(&*handler, &dialer).await;
    let mut peer_a = Peer::new(peers.recv().await.unwrap()).await;
    peer_a.opened(1).await;
    let b = connect(&*handler, &dialer).await;
    let mut peer_b = Peer::new(peers.recv().await.unwrap()).await;
    peer_b.opened(1).await;
    let dead = connect(&*handler, &dialer).await;
    let mut dead_peer = Peer::new(peers.recv().await.unwrap()).await;
    dead_peer.opened(1).await;
    drop(a);
    drop(b);
    drop(dead);
    drop(dead_peer);
    peer_a.frame().await;
    peer_b.frame().await;
    settle().await;
    tokio::time::advance(Duration::from_secs(13)).await;
    settle().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer_a.io.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let mut active = connect(&*handler, &dialer).await;
    peer_b.opened(2).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 3);
    drop(handler);
    peer_b.send(Command::Psh, 2, b"drain").await;
    let mut response = [0; 5];
    active.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"drain");
    drop(active);
    let mut remaining = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        peer_b.io.read_to_end(&mut remaining),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn configured_short_intervals_are_normalized_and_reaper_restarts() {
    let cases = [(5, 13, 29, 2), (6, 5, 29, 8), (6, 13, 14, 5)];
    for (check, idle, survives, expires_within) in cases {
        let handler = configured_handler(serde_json::json!({
            "type": "anytls",
            "password": "test",
            "padding_scheme": ["stop=1", "0=0-0"],
            "idle_session_check_interval_secs": check,
            "idle_session_timeout_secs": idle,
            "min_idle_session": 0,
            "disable_reuse": false
        }));
        let (dialer, mut peers) = dialer(1);
        for dials in 1..=2 {
            let stream = connect(&*handler, &dialer).await;
            let mut peer = Peer::new(peers.recv().await.unwrap()).await;
            peer.opened(1).await;
            drop(stream);
            assert_eq!(peer.frame().await.cmd, Command::Fin);
            assert!(
                tokio::time::timeout(Duration::from_secs(survives), peer.io.read(&mut [0; 1]))
                    .await
                    .is_err()
            );
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(expires_within),
                    peer.io.read(&mut [0; 1])
                )
                .await
                .unwrap()
                .unwrap(),
                0
            );
            assert_eq!(dialer.calls.load(Ordering::Relaxed), dials);
        }
    }
}

#[tokio::test]
async fn disable_reuse_and_closed_idle_require_fresh_dials() {
    for disabled in [false, true] {
        let handler = configured_handler(serde_json::json!({
            "type": "anytls",
            "password": "test",
            "padding_scheme": ["stop=1", "0=0-0"],
            "disable_reuse": disabled
        }));
        let (dialer, mut peers) = dialer(1);
        let stream = connect(&*handler, &dialer).await;
        let mut peer = peers.recv().await.unwrap();
        drop(stream);
        if disabled {
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut Vec::new()))
                .await
                .expect("disabled reuse must close a live carrier")
                .unwrap();
        }
        drop(peer);
        settle().await;
        let _next = connect(&*handler, &dialer).await;
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn configuration_defaults_and_offline_construction() {
    let config: crate::config::ClientProxyConfig = serde_json::from_value(serde_json::json!({
        "type": "anytls",
        "password": "test"
    }))
    .unwrap();
    let crate::config::ClientProxyConfig::Anytls {
        idle_session_check_interval_secs,
        idle_session_timeout_secs,
        min_idle_session,
        disable_reuse,
        ..
    } = config
    else {
        panic!()
    };
    assert_eq!(
        (
            idle_session_check_interval_secs,
            idle_session_timeout_secs,
            min_idle_session,
            disable_reuse
        ),
        (30, 30, 0, false)
    );
    drop(handler(PoolOptions::default()));
}

#[async_trait]
impl crate::tcp::socket_connector::SocketConnector for Dialer {
    async fn connect(
        &self,
        _: &Arc<dyn crate::resolver::Resolver>,
        _: &ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        self.open_stream().await
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn crate::resolver::Resolver>,
        _: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[tokio::test]
async fn chains_reuse_tls_once_per_selected_prefix_for_tcp_and_udp() {
    use crate::{
        client_proxy_chain::{ClientProxyChain, InitialHopEntry},
        tcp::proxy_connector_impl::ProxyConnectorImpl,
    };
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap(),
    );
    for chained in [false, true] {
        let (a, peers_a) = dialer(1);
        let (b, peers_b) = dialer(2);
        let handshakes = Arc::new(AtomicUsize::new(0));
        let mut servers = Vec::new();
        for mut peers in [peers_a, peers_b] {
            let config = server_config.clone();
            let handshakes = handshakes.clone();
            servers.push(tokio::spawn(async move {
                let mut sessions = tokio::task::JoinSet::new();
                while let Some(io) = peers.recv().await {
                    let config = config.clone();
                    let handshakes = handshakes.clone();
                    sessions.spawn(async move {
                        let tls = tokio_rustls::TlsAcceptor::from(config)
                            .accept(io)
                            .await
                            .unwrap();
                        handshakes.fetch_add(1, Ordering::Relaxed);
                        let mut peer = Peer::new(tls).await;
                        assert_eq!(peer.frame().await.cmd, Command::Settings);
                        peer.send(Command::ServerSettings, 0, b"v=2").await;
                        let mut destination = false;
                        let mut uot_header = false;
                        loop {
                            let frame = peer.frame().await;
                            match frame.cmd {
                                Command::Syn => destination = true,
                                Command::Psh if destination => {
                                    destination = false;
                                    uot_header = frame
                                        .data
                                        .windows(crate::uot::UOT_V2_MAGIC_ADDRESS.len())
                                        .any(|bytes| {
                                            bytes == crate::uot::UOT_V2_MAGIC_ADDRESS.as_bytes()
                                        });
                                    if !uot_header {
                                        peer.send(Command::SynAck, frame.stream_id, b"").await;
                                    }
                                }
                                Command::Psh if uot_header => {
                                    // The current client writes connect flag and destination separately.
                                    if frame.data.len() > 1 {
                                        uot_header = false;
                                        peer.send(Command::SynAck, frame.stream_id, b"").await;
                                    }
                                }
                                Command::Psh => {
                                    peer.send(Command::Psh, frame.stream_id, &frame.data).await
                                }
                                _ => {}
                            }
                        }
                    });
                }
            }));
        }
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        let proxy = || {
            let config = serde_json::from_value(serde_json::json!({
                "address": "localhost:443",
                "protocol": {
                    "type": "tls",
                    "sni_hostname": "localhost",
                    "verify": false,
                    "protocol": {
                        "type": "anytls",
                        "password": "test",
                        "padding_scheme": ["stop=1", "0=0-0"]
                    }
                }
            }))
            .unwrap();
            ProxyConnectorImpl::from_config(config, resolver.clone())
                .unwrap()
                .unwrap()
        };
        let chain = if chained {
            ClientProxyChain::new(
                vec![
                    InitialHopEntry::Direct(a.clone()),
                    InitialHopEntry::Direct(b.clone()),
                ],
                vec![vec![Box::new(proxy())]],
            )
        } else {
            ClientProxyChain::new(
                vec![InitialHopEntry::Proxy {
                    socket: a.clone(),
                    proxy: Box::new(proxy()),
                }],
                vec![],
            )
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..4 {
                let mut stream = chain
                    .connect_tcp(target(), &resolver)
                    .await
                    .unwrap()
                    .client_stream;
                stream.write_all(b"tcp").await.unwrap();
                let mut response = [0; 3];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"tcp");
                stream.shutdown().await.unwrap();
                drop(stream);
            }
            for _ in 0..4 {
                let mut udp = chain
                    .connect_udp_bidirectional(&resolver, target())
                    .await
                    .unwrap();
                let mut response = [0; 3];
                assert_message_echo(&mut *udp, b"udp", &mut response).await;
                udp.shutdown_message().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(a.calls.load(Ordering::Relaxed), 1);
        assert_eq!(b.calls.load(Ordering::Relaxed), usize::from(chained));
        assert_eq!(
            handshakes.load(Ordering::Relaxed),
            if chained { 2 } else { 1 }
        );
        for server in servers {
            server.abort();
            let _ = server.await;
        }
    }
}

#[tokio::test]
async fn dropping_chained_idle_pools_closes_every_carrier() {
    use crate::{
        address::NetLocationMask,
        client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry},
        client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule},
        tcp::{
            proxy_connector_impl::ProxyConnectorImpl,
            tcp_handler::{TcpServerHandler, TcpServerSetupResult},
        },
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        for two_hops in [false, true] {
            let resolver: Arc<dyn crate::resolver::Resolver> =
                Arc::new(crate::resolver::NativeResolver::new());
            let (socket, mut sockets) = dialer(1);
            let (inner, inner_peers) = dialer(2);
            let (mut peers, server) = if two_hops {
                let chain =
                    ClientProxyChain::new(vec![InitialHopEntry::Direct(inner.clone())], vec![]);
                let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                    vec![NetLocationMask::ANY],
                    ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
                )]));
                let handler = super::AnyTlsServerHandler::new(
                    vec![("test".into(), "test".into())],
                    Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap()),
                    resolver.clone(),
                    selector,
                    false,
                    None,
                );
                let task = tokio::spawn(async move {
                    let io = sockets.recv().await.unwrap();
                    let TcpServerSetupResult::Session(run) =
                        handler.setup_server_stream(Box::new(io)).await.unwrap()
                    else {
                        panic!()
                    };
                    run.await;
                });
                (inner_peers, Some(task))
            } else {
                (sockets, None)
            };
            let proxy = || {
                let config = serde_json::from_value(serde_json::json!({
                    "address": "127.0.0.1:443",
                    "protocol": {
                        "type": "anytls",
                        "password": "test",
                        "padding_scheme": ["stop=1", "0=0-0"],
                        "min_idle_session": 1
                    }
                }))
                .unwrap();
                ProxyConnectorImpl::from_config(config, resolver.clone())
                    .unwrap()
                    .unwrap()
            };
            let initial = if two_hops {
                InitialHopEntry::Proxy {
                    socket: socket.clone(),
                    proxy: Box::new(proxy()),
                }
            } else {
                InitialHopEntry::Direct(socket.clone())
            };
            let chain = ClientProxyChain::new(vec![initial], vec![vec![Box::new(proxy())]]);
            let mut stream = chain
                .connect_tcp(target(), &resolver)
                .await
                .unwrap()
                .client_stream;
            let mut peer = Peer::new(peers.recv().await.unwrap()).await;
            for id in 1..=4 {
                peer.opened(id).await;
                peer.send(Command::Psh, id, b"ok").await;
                stream.read_exact(&mut [0; 2]).await.unwrap();
                stream.shutdown().await.unwrap();
                assert_eq!(peer.frame().await.cmd, Command::Fin);
                if id < 4 {
                    stream = chain
                        .connect_tcp(target(), &resolver)
                        .await
                        .unwrap()
                        .client_stream;
                }
            }
            drop(stream);
            assert_eq!(socket.calls.load(Ordering::Relaxed), 1);
            assert_eq!(inner.calls.load(Ordering::Relaxed), usize::from(two_hops));
            drop(chain);
            assert_eq!(peer.io.read(&mut [0; 1]).await.unwrap(), 0);
            if let Some(server) = server {
                server.await.unwrap();
            }
        }
    })
    .await
    .expect("idle chain retained a carrier after drop");
}

#[tokio::test]
async fn negotiated_padding_is_shared_with_new_sessions_and_invalid_updates_are_ignored() {
    for stop in ["3", "-1"] {
        check_negotiated_padding(stop).await;
    }
}

async fn check_negotiated_padding(stop: &str) {
    let handler = handler(PoolOptions::default());
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    let scheme = format!("stop={stop}\n0=41-41\n1=70000-70000");
    peer.send(Command::UpdatePaddingScheme, 0, scheme.as_bytes())
        .await;
    peer.send(Command::UpdatePaddingScheme, 0, b"stop=invalid")
        .await;
    peer.send(Command::Psh, 1, b"ready").await;
    stream.read_exact(&mut [0; 5]).await.unwrap();
    let next = connect(&handler, &dialer).await;
    let mut io = peers.recv().await.unwrap();
    let mut auth = [0; 34];
    io.read_exact(&mut auth).await.unwrap();
    assert_eq!(u16::from_be_bytes([auth[32], auth[33]]), 41);
    io.read_exact(&mut [0; 41]).await.unwrap();
    let mut peer = Peer {
        io,
        buffer: BytesMut::new(),
    };
    let settings = peer.frame().await;
    assert_eq!(settings.cmd, Command::Settings);
    assert!(
        std::str::from_utf8(&settings.data)
            .unwrap()
            .contains(PaddingFactory::new(scheme.as_bytes()).unwrap().md5())
    );
    assert_eq!(peer.frame().await.cmd, Command::Syn);
    assert_eq!(peer.frame().await.cmd, Command::Psh);
    assert_eq!(peer.frame().await.data.len(), 65535);
    let remainder = peer.frame().await;
    assert_eq!(remainder.cmd, Command::Waste);
    assert!(remainder.data.len() > 1000);
    drop((stream, next));
}

#[tokio::test]
async fn negotiated_padding_updates_live_writers_without_resetting_counters() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let handler = AnyTlsClientHandler::with_options(
            "test".into(),
            Arc::new(PaddingFactory::new(b"stop=100\n0=0-0").unwrap()),
            true,
            PoolOptions::default(),
        );
        let (dialer, mut peers) = dialer(1);
        let mut first = connect(&handler, &dialer).await;
        let mut a = Peer::new(peers.recv().await.unwrap()).await;
        a.opened(1).await;
        let mut second = connect(&handler, &dialer).await;
        let mut b = Peer::new(peers.recv().await.unwrap()).await;
        b.opened(1).await;
        second.write_all(b"packet two").await.unwrap();
        second.flush().await.unwrap();
        assert_eq!(b.frame().await.data.as_ref(), b"packet two");

        a.send(
            Command::UpdatePaddingScheme,
            0,
            b"stop=100\n2=128-128\n3=256-256\n4=512-512",
        )
        .await;
        a.send(Command::Psh, 1, b"ready").await;
        first.read_exact(&mut [0; 5]).await.unwrap();
        for (stream, peer, wire_size) in [(&mut first, &mut a, 128), (&mut second, &mut b, 256)] {
            stream.write_all(b"live").await.unwrap();
            stream.flush().await.unwrap();
            let data = peer.frame().await;
            assert_eq!((data.cmd, data.data.as_ref()), (Command::Psh, &b"live"[..]));
            let waste = peer.frame().await;
            assert_eq!(waste.cmd, Command::Waste);
            assert_eq!(
                data.data.len() + waste.data.len() + 2 * FRAME_HEADER_SIZE,
                wire_size
            );
        }

        a.send(Command::UpdatePaddingScheme, 0, b"stop=2").await;
        a.send(Command::Psh, 1, b"ready").await;
        first.read_exact(&mut [0; 5]).await.unwrap();
        first.write_all(b"stop").await.unwrap();
        first.flush().await.unwrap();
        assert_eq!(a.frame().await.data.as_ref(), b"stop");
        a.send(
            Command::UpdatePaddingScheme,
            0,
            b"stop=100\n3=256-256\n4=512-512\n5=1024-1024",
        )
        .await;
        a.send(Command::Psh, 1, b"ready").await;
        first.read_exact(&mut [0; 5]).await.unwrap();
        for payload in [b"stopped one", b"stopped two"] {
            first.write_all(payload).await.unwrap();
            first.flush().await.unwrap();
            let frame = a.frame().await;
            assert_eq!(
                (frame.cmd, frame.data.as_ref()),
                (Command::Psh, &payload[..])
            );
        }
        first.shutdown().await.unwrap();
        assert_eq!(a.frame().await.cmd, Command::Fin);
        second.write_all(b"still padded").await.unwrap();
        second.flush().await.unwrap();
        assert_eq!(b.frame().await.data.as_ref(), b"still padded");
        let waste = b.frame().await;
        assert_eq!(waste.cmd, Command::Waste);
        assert_eq!(waste.data.len() + 12 + 2 * FRAME_HEADER_SIZE, 512);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_or_failed_warm_uot_setup_retires_without_replay() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for cancel in [false, true] {
            check_failed_warm_open(cancel).await;
        }
    })
    .await
    .unwrap();
}

async fn check_failed_warm_open(cancel: bool) {
    let handler = AnyTlsClientHandler::with_options(
        "test".into(),
        Arc::new(PaddingFactory::new(b"stop=100\n0=0-0").unwrap()),
        true,
        PoolOptions::default(),
    );
    let (dialer, mut peers) = dialer(1);
    let mut stream = connect(&handler, &dialer).await;
    let mut peer = Peer::new(peers.recv().await.unwrap()).await;
    peer.opened(1).await;
    // Force the warm writer to block before its flush barrier completes.
    peer.send(
        Command::UpdatePaddingScheme,
        0,
        b"stop=100\n0=0-0\n2=1048576-1048576\n3=1048576-1048576\n4=1048576-1048576",
    )
    .await;
    peer.send(Command::Fin, 1, b"").await;
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    // Retain the terminal handle so last-owner Drop cannot substitute for retirement.
    let mut opening = Box::pin(handler.connect_client_udp(transport(&dialer), target()));
    tokio::select! {
        result = &mut opening => {
            panic!("warm UoT open completed before its blocked flush: {:?}", result.err());
        }
        frame = peer.frame() => {
            assert_eq!((frame.cmd, frame.stream_id), (Command::Syn, 2));
        }
    }
    if !cancel {
        peer.io.shutdown().await.unwrap();
        assert!(opening.as_mut().await.is_err());
    }
    drop(opening);
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
    peer.io.read_to_end(&mut Vec::new()).await.unwrap();
    let _next = connect(&handler, &dialer).await;
    assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    drop(stream);
}

#[derive(Debug)]
struct NetworkDialer {
    address: String,
    calls: AtomicUsize,
    key: RouteKey,
}

#[async_trait]
impl CarrierDialer for NetworkDialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(
            tokio::net::TcpStream::connect(&self.address).await?,
        ))
    }
}

#[tokio::test]
#[ignore = "requires ANYTLS_REFERENCE_PEER pointing to the pinned Go echo peer"]
async fn reference_peer_tcp_uot_and_concurrent_session_reuse() {
    use tokio::io::AsyncBufReadExt;
    let executable = std::env::var("ANYTLS_REFERENCE_PEER").expect("ANYTLS_REFERENCE_PEER");
    let mut child = tokio::process::Command::new(executable)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut port = String::new();
    assert_ne!(
        tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut port))
            .await
            .expect("reference peer did not announce its port")
            .unwrap(),
        0
    );
    let dialer = Arc::new(NetworkDialer {
        address: format!("127.0.0.1:{}", port.trim()),
        calls: AtomicUsize::new(0),
        key: RouteKey(vec![1]),
    });
    let handler = handler(PoolOptions::default());
    tokio::time::timeout(Duration::from_secs(15), async {
        for _ in 0..16 {
            let mut stream = connect(&handler, &dialer).await;
            stream.write_all(b"reference tcp").await.unwrap();
            let mut response = [0; 13];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"reference tcp");
            stream.shutdown().await.unwrap();
        }
        let mut udp = handler
            .connect_client_udp(transport(&dialer), target())
            .await
            .unwrap();
        for _ in 0..4 {
            let mut bytes = [0; 13];
            assert_message_echo(&mut *udp, b"reference udp", &mut bytes).await;
        }
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
        // A live UoT association must not be shared with a concurrent TCP request.
        let mut tcp = connect(&handler, &dialer).await;
        tcp.write_all(b"parallel").await.unwrap();
        let mut response = [0; 8];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"parallel");
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
        tcp.shutdown().await.unwrap();
        drop(udp);
        let mut tcp = connect(&handler, &dialer).await;
        tcp.write_all(b"reuse").await.unwrap();
        let mut response = [0; 5];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reuse");
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
