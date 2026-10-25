use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::TransportErrors;
use crate::async_stream::{AsyncPing, AsyncStream};

struct ErrorIo {
    error: fn() -> io::Error,
    calls: Vec<&'static str>,
    closed: bool,
    interrupt_preface: bool,
}

impl ErrorIo {
    fn new(error: fn() -> io::Error) -> Self {
        Self {
            error,
            calls: Vec::new(),
            closed: false,
            interrupt_preface: false,
        }
    }
}

impl AsyncRead for ErrorIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.push("read");
        if self.closed || buf.remaining() == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err((self.error)()))
        }
    }
}

impl AsyncWrite for ErrorIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls.push("write");
        if self.interrupt_preface {
            self.interrupt_preface = false;
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        if self.closed || buf.is_empty() {
            Poll::Ready(Ok(0))
        } else {
            Poll::Ready(Err((self.error)()))
        }
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.calls.push("vectored");
        Poll::Ready(Err((self.error)()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.push("flush");
        Poll::Ready(Err((self.error)()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.push("shutdown");
        Poll::Ready(Err((self.error)()))
    }
}

async fn h2_copy(error: &io::Error) -> h2::Error {
    struct PrefaceError(Option<io::Error>);
    impl AsyncRead for PrefaceError {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            unreachable!()
        }
    }
    impl AsyncWrite for PrefaceError {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.0.take().unwrap()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            unreachable!()
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            unreachable!()
        }
    }
    let copy = match error.get_ref() {
        Some(inner) => io::Error::new(error.kind(), inner.to_string()),
        None => io::Error::from(error.kind()),
    };
    h2::client::handshake(PrefaceError(Some(copy)))
        .await
        .err()
        .unwrap()
}

#[tokio::test]
async fn observer_delegates_and_recovers_causes_without_changing_h2_messages() {
    for (make_error, local) in cases() {
        for operation in ["read", "write", "vectored", "flush", "shutdown"] {
            let errors = TransportErrors::default();
            errors.start_driver();
            let mut stream = errors.wrap(ErrorIo::new(make_error));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut bytes = [0; 1];
            assert!(stream.is_write_vectored());
            let result = match operation {
                "read" => Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
                "write" => Pin::new(&mut stream)
                    .poll_write(&mut cx, b"x")
                    .map_ok(|_| ()),
                "vectored" => Pin::new(&mut stream)
                    .poll_write_vectored(&mut cx, &[io::IoSlice::new(b"x")])
                    .map_ok(|_| ()),
                "flush" => Pin::new(&mut stream).poll_flush(&mut cx),
                "shutdown" => Pin::new(&mut stream).poll_shutdown(&mut cx),
                _ => unreachable!(),
            };
            let Poll::Ready(Err(returned)) = result else {
                panic!("missing error")
            };
            let original = make_error();
            assert_eq!(returned.kind(), original.kind());
            assert_eq!(returned.raw_os_error(), original.raw_os_error());
            assert_eq!(returned.to_string(), original.to_string());
            assert_eq!(stream.inner.calls, [operation]);
            for label in [None, Some("H2 recv error")] {
                let h2_error = h2_copy(&returned).await;
                let display = match label {
                    Some(label) => format!("{label}: {h2_error}"),
                    None => h2_error.to_string(),
                };
                let mapped = match label {
                    Some(label) => errors.map_with(label, h2_error),
                    None => errors.map(h2_error),
                };
                assert_eq!(mapped.kind(), io::ErrorKind::Other);
                assert_eq!(mapped.to_string(), display);
                assert_eq!(
                    crate::clash_api::probes::local_failure(&mapped),
                    local,
                    "{mapped:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn first_terminal_event_wins_and_recovery_is_connection_scoped() {
    for (make_error, local) in cases() {
        let errors = TransportErrors::default();
        errors.start_driver();
        let first = errors.record(make_error());
        let _ = errors.record(io::ErrorKind::OutOfMemory.into());
        for _ in 0..2 {
            let mapped = errors.map(h2_copy(&first).await);
            assert_eq!(crate::clash_api::probes::local_failure(&mapped), local);
        }
        let closed = errors.map(h2_copy(&io::ErrorKind::BrokenPipe.into()).await);
        assert_eq!(crate::clash_api::probes::local_failure(&closed), local);
        let reset = errors.map(h2::Reason::REFUSED_STREAM.into());
        assert!(reset.get_ref().unwrap().is::<h2::Error>());
        assert!(!crate::clash_api::probes::local_failure(&reset));
        let mismatched =
            errors.map(h2_copy(&io::Error::other("unrelated transport failure")).await);
        assert!(mismatched.get_ref().unwrap().is::<h2::Error>());
        let fresh = TransportErrors::default().map(h2_copy(&first).await);
        assert!(fresh.get_ref().unwrap().is::<h2::Error>());
    }
}

#[tokio::test]
async fn empty_buffers_do_not_close_observation_but_eof_and_write_zero_do() {
    for read in [false, true] {
        for empty in [false, true] {
            let errors = TransportErrors::default();
            errors.start_driver();
            let mut inner = ErrorIo::new(crate::resources::exhausted);
            inner.closed = true;
            let mut stream = errors.wrap(inner);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut bytes = vec![0; usize::from(!empty)];
            if read {
                assert!(
                    Pin::new(&mut stream)
                        .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                        .is_ready()
                );
            } else {
                assert!(Pin::new(&mut stream).poll_write(&mut cx, &bytes).is_ready());
            }
            let returned = errors.record(crate::resources::exhausted());
            let mapped = errors.map(h2_copy(&returned).await);
            assert_eq!(crate::clash_api::probes::local_failure(&mapped), empty);
        }
    }
}

#[tokio::test]
async fn handshake_errors_keep_sources_without_recording_retried_interruptions() {
    for (make_error, local) in cases() {
        let errors = TransportErrors::default();
        let mut inner = ErrorIo::new(make_error);
        inner.interrupt_preface = true;
        let error = h2::client::handshake(errors.wrap(inner))
            .await
            .err()
            .unwrap();
        assert!(errors.0.terminal.get().is_none());
        let mapped = errors.map_with("H2 client handshake failed", error);
        assert_eq!(
            crate::clash_api::probes::local_failure(&mapped),
            local,
            "{mapped:?}"
        );
        errors.start_driver();
        let returned = errors.record(io::ErrorKind::ConnectionReset.into());
        assert!(!crate::clash_api::probes::local_failure(
            &errors.map(h2_copy(&returned).await)
        ));
    }
}

#[derive(Clone)]
pub(crate) struct Fault {
    failed: Arc<AtomicBool>,
    waker: Arc<AtomicWaker>,
    error: fn() -> io::Error,
}

impl Fault {
    pub(crate) fn new(error: fn() -> io::Error) -> Self {
        Self {
            failed: Arc::new(AtomicBool::new(false)),
            waker: Arc::new(AtomicWaker::new()),
            error,
        }
    }

    pub(crate) fn inject(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    pub(crate) fn wrap<T>(&self, inner: T) -> FaultIo<T> {
        FaultIo {
            inner,
            fault: self.clone(),
        }
    }
}

pub(crate) struct FaultIo<T> {
    inner: T,
    fault: Fault,
}

impl<T: AsyncRead + Unpin> AsyncRead for FaultIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.fault.waker.register(cx.waker());
        if self.fault.failed.load(Ordering::SeqCst) {
            Poll::Ready(Err((self.fault.error)()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FaultIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncStream> AsyncPing for FaultIo<T> {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<T: AsyncStream> AsyncStream for FaultIo<T> {}

pub(crate) fn peer(
    error: fn() -> io::Error,
) -> (
    FaultIo<tokio::io::DuplexStream>,
    Fault,
    tokio::sync::mpsc::UnboundedReceiver<h2::SendStream<Bytes>>,
    tokio::task::JoinHandle<()>,
) {
    let fault = Fault::new(error);
    let (client, peer) = tokio::io::duplex(8192);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        let mut bodies = tokio::task::JoinSet::new();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(Bytes::from_static(b"x"), false).unwrap();
            // Retain the request body so dropping it cannot reset a live CONNECT.
            bodies.spawn(async move {
                let mut body = request.into_body();
                while let Some(Ok(data)) = body.data().await {
                    let _ = body.flow_control().release_capacity(data.len());
                }
            });
            if tx.send(send).is_err() {
                break;
            }
        }
    });
    (fault.wrap(client), fault, rx, driver)
}

pub(crate) fn cases() -> Vec<(fn() -> io::Error, bool)> {
    vec![
        (crate::resources::exhausted, true),
        #[cfg(unix)]
        (|| io::Error::from_raw_os_error(libc::EMFILE), true),
        (|| io::ErrorKind::ConnectionReset.into(), false),
    ]
}

#[tokio::test]
async fn established_streams_share_transport_cause_but_not_remote_resets() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for (make_error, local) in cases() {
            let (client, fault, mut sends, driver) = peer(make_error);
            let mut session = crate::http2::client::H2ClientSession::new(Box::new(client))
                .await
                .unwrap();
            let mut streams = Vec::new();
            let mut peers = Vec::new();
            for _ in 0..3 {
                let request = http::Request::builder()
                    .method("CONNECT")
                    .uri("example.com:80")
                    .body(())
                    .unwrap();
                let (_, mut stream) = session.open(request).await.unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), b'x');
                streams.push(stream);
                peers.push(sends.recv().await.unwrap());
            }
            peers[0].send_reset(h2::Reason::REFUSED_STREAM);
            let reset = streams[0].read_u8().await.unwrap_err();
            assert!(!crate::clash_api::probes::local_failure(&reset));
            assert!(reset.get_ref().unwrap().is::<h2::Error>());
            fault.inject();
            for stream in &mut streams[1..] {
                let error = stream.read_u8().await.unwrap_err();
                assert_eq!(
                    crate::clash_api::probes::local_failure(&error),
                    local,
                    "{error:?}"
                );
            }
            assert!(!crate::clash_api::probes::local_failure(&reset));
            drop(streams);
            drop(session);
            driver.abort();
            let _ = driver.await;
        }
    })
    .await
    .unwrap();
}
