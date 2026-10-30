use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::{
    Prepared, Role,
    codec::{Decoder, Encoder},
};

const WIRE_CAPACITY: usize = 32 * 1024;
const READ_BUDGET: usize = 64 * 1024;

struct Failure {
    kind: io::ErrorKind,
    message: String,
}

impl Failure {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

/// Writes may buffer output; callers must flush before waiting for a response.
/// Reads only drive input.
pub(crate) struct SudokuStream {
    inner: Box<dyn AsyncStream>,
    encoder: Encoder,
    decoder: Decoder,
    read_wire: Box<[u8]>,
    read_start: usize,
    read_end: usize,
    read_error: Option<Failure>,
    eof: bool,
    write_wire: Box<[u8]>,
    write_start: usize,
    write_end: usize,
    write_error: Option<Failure>,
    shutdown: bool,
}

impl SudokuStream {
    pub fn new(inner: Box<dyn AsyncStream>, config: Arc<Prepared>, role: Role) -> Self {
        Self {
            inner,
            encoder: Encoder::new(config.clone(), role),
            decoder: Decoder::new(config, role),
            read_wire: vec![0; WIRE_CAPACITY].into_boxed_slice(),
            read_start: 0,
            read_end: 0,
            read_error: None,
            eof: false,
            write_wire: vec![0; WIRE_CAPACITY].into_boxed_slice(),
            write_start: 0,
            write_end: 0,
            write_error: None,
            shutdown: false,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = &self.write_error {
            return Poll::Ready(Err(error.error()));
        }
        while self.write_start < self.write_end {
            match ready!(
                Pin::new(&mut self.inner)
                    .poll_write(cx, &self.write_wire[self.write_start..self.write_end])
            ) {
                Ok(0) => {
                    self.write_error = Some(Failure::new(io::ErrorKind::WriteZero.into()));
                    break;
                }
                Ok(n) => self.write_start += n,
                Err(error) => {
                    self.write_error = Some(Failure::new(error));
                    break;
                }
            }
        }
        if let Some(error) = &self.write_error {
            return Poll::Ready(Err(error.error()));
        }
        self.write_start = 0;
        self.write_end = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SudokuStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let initial = output.filled().len();
        let mut work = 0;
        loop {
            while this.read_start < this.read_end && output.remaining() != 0 && work < READ_BUDGET {
                let end = this.read_end.min(this.read_start + READ_BUDGET - work);
                let input = &this.read_wire[this.read_start..end];
                let capacity = output.remaining().min(input.len());
                let decoded = this
                    .decoder
                    .decode(input, output.initialize_unfilled_to(capacity));
                this.read_start += decoded.consumed;
                work += decoded.consumed;
                output.advance(decoded.written);
                if let Some(error) = decoded.error {
                    this.read_error = Some(Failure::new(error));
                    this.read_start = this.read_end;
                    break;
                }
            }
            if output.filled().len() != initial {
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = &this.read_error {
                return Poll::Ready(Err(error.error()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if work >= READ_BUDGET {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut input = ReadBuf::new(&mut this.read_wire);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input)) {
                Ok(()) => {
                    this.read_end = input.filled().len();
                    this.read_start = 0;
                    if this.read_end == 0 {
                        this.eof = true;
                    }
                }
                Err(error) => this.read_error = Some(Failure::new(error)),
            }
        }
    }
}

impl AsyncWrite for SudokuStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.poll_drain(cx))?;
        let accepted = input.len().min(this.encoder.max_input(WIRE_CAPACITY));
        if accepted == 0 {
            return Poll::Ready(Ok(0));
        }
        this.write_end = this
            .encoder
            .encode(&input[..accepted], &mut this.write_wire);
        // Acceptance belongs to this call even if the transport blocks or fails now.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        match ready!(Pin::new(&mut this.inner).poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(this.write_error.insert(Failure::new(error)).error())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for SudokuStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for SudokuStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn flow(&self) -> Option<&Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        // Vision DIRECT may bypass encryption, never this wire transform.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct WakeCounter(AtomicUsize);
    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    enum Read {
        Bytes(Vec<u8>),
        Pending,
        Error,
        Eof,
    }
    enum Write {
        Count(usize),
        Pending,
        Error,
    }
    #[derive(Default)]
    struct State {
        reads: VecDeque<Read>,
        writes: VecDeque<Write>,
        read_waker: Option<std::task::Waker>,
        write_waker: Option<std::task::Waker>,
        read_polls: usize,
        write_polls: usize,
        flush_blocked: bool,
        shutdown_blocked: bool,
        ping_blocked: bool,
        sent: Vec<u8>,
        events: Vec<&'static str>,
    }
    struct Script(Arc<Mutex<State>>);
    impl AsyncRead for Script {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut state = self.0.lock().unwrap();
            state.read_polls += 1;
            match state.reads.pop_front().unwrap_or(Read::Pending) {
                Read::Bytes(bytes) => {
                    let n = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        state.reads.push_front(Read::Bytes(bytes[n..].to_vec()));
                    }
                    Poll::Ready(Ok(()))
                }
                Read::Pending => {
                    state.read_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Read::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                Read::Eof => Poll::Ready(Ok(())),
            }
        }
    }
    impl AsyncWrite for Script {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            state.write_polls += 1;
            match state.writes.pop_front().unwrap_or(Write::Count(usize::MAX)) {
                Write::Count(n) => {
                    let n = n.min(buf.len());
                    state.sent.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
                Write::Pending => {
                    state.write_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Write::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.0.lock().unwrap();
            state.events.push("flush");
            if state.flush_blocked {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.0.lock().unwrap();
            state.events.push("shutdown");
            if state.shutdown_blocked {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncPing for Script {
        fn supports_ping(&self) -> bool {
            true
        }
        fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            let mut state = self.0.lock().unwrap();
            state.events.push("ping");
            if state.ping_blocked {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(true))
        }
    }
    impl AsyncStream for Script {}

    fn scripted(role: Role) -> (SudokuStream, Arc<Mutex<State>>) {
        let state = Arc::new(Mutex::new(State::default()));
        (
            SudokuStream::new(
                Box::new(Script(state.clone())),
                super::super::tests::config(json!({})),
                role,
            ),
            state,
        )
    }
    fn wire(data: &[u8], role: Role) -> Vec<u8> {
        let mut encoder = Encoder::new(super::super::tests::config(json!({})), role);
        let mut out = vec![0; data.len() * 9 + 8];
        let n = encoder.encode(data, &mut out);
        out.truncate(n);
        out
    }

    fn decode_wire(wire: &[u8], role: Role) -> Vec<u8> {
        let mut decoder = Decoder::new(super::super::tests::config(json!({})), role);
        wire.iter()
            .filter_map(|byte| decoder.decode_byte(*byte).transpose())
            .collect::<io::Result<_>>()
            .unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Write,
        WriteVectored,
        Flush,
        Shutdown,
        Ping,
    }

    impl Operation {
        fn poll(self, stream: &mut SudokuStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self {
                Self::Write => Pin::new(stream)
                    .poll_write(cx, b"next")
                    .map(|r| r.map(|_| ())),
                Self::WriteVectored => Pin::new(stream)
                    .poll_write_vectored(cx, &[io::IoSlice::new(b""), io::IoSlice::new(b"next")])
                    .map(|r| r.map(|_| ())),
                Self::Flush => Pin::new(stream).poll_flush(cx),
                Self::Shutdown => Pin::new(stream).poll_shutdown(cx),
                Self::Ping => Pin::new(stream).poll_write_ping(cx).map(|r| r.map(|_| ())),
            }
        }
    }

    #[test]
    fn reads_leave_buffered_output_and_writer_readiness_untouched() {
        for operation in [
            Operation::Write,
            Operation::WriteVectored,
            Operation::Flush,
            Operation::Shutdown,
            Operation::Ping,
        ] {
            for (role, peer_role) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                for output_ready in [false, true] {
                    let (mut stream, state) = scripted(role);
                    state.lock().unwrap().writes.extend([
                        Write::Count(1),
                        Write::Pending,
                        Write::Pending,
                    ]);
                    let writer = Arc::new(WakeCounter(AtomicUsize::new(0)));
                    let reader = Arc::new(WakeCounter(AtomicUsize::new(0)));
                    let (write_waker, read_waker) = (writer.clone().into(), reader.clone().into());
                    let mut write_cx = Context::from_waker(&write_waker);
                    let mut read_cx = Context::from_waker(&read_waker);
                    assert!(matches!(
                        Pin::new(&mut stream).poll_write(&mut write_cx, b"one"),
                        Poll::Ready(Ok(3))
                    ));
                    assert!(operation.poll(&mut stream, &mut write_cx).is_pending());
                    assert_eq!(writer.0.load(Ordering::Relaxed), 0);
                    let (sent, polls, events, read_polls) = {
                        let mut state = state.lock().unwrap();
                        if !output_ready {
                            state.writes.push_back(Write::Pending);
                        }
                        state
                            .reads
                            .push_back(Read::Bytes(wire(b"incoming", peer_role)));
                        (
                            state.sent.clone(),
                            state.write_polls,
                            state.events.clone(),
                            state.read_polls,
                        )
                    };
                    assert!(matches!(
                        Pin::new(&mut stream).poll_read(&mut read_cx, &mut ReadBuf::new(&mut [])),
                        Poll::Ready(Ok(()))
                    ));
                    assert_eq!(state.lock().unwrap().read_polls, read_polls);
                    let mut bytes = [0; 8];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut stream).poll_read(&mut read_cx, &mut buf),
                        Poll::Ready(Ok(()))
                    ));
                    assert_eq!(buf.filled(), b"incoming");
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(&mut read_cx, &mut ReadBuf::new(&mut [0]))
                            .is_pending()
                    );
                    let readiness = {
                        let mut state = state.lock().unwrap();
                        assert_eq!(
                            (&state.sent, state.write_polls, &state.events),
                            (&sent, polls, &events)
                        );
                        state.writes.clear();
                        state.write_waker.take().unwrap()
                    };
                    assert_eq!(writer.0.load(Ordering::Relaxed), 0);
                    assert!(readiness.will_wake(&write_waker));
                    // Abandon the reader; write readiness must reach only the writer.
                    readiness.wake();
                    assert_eq!(writer.0.load(Ordering::Relaxed), 1);
                    assert_eq!(reader.0.load(Ordering::Relaxed), 0);
                    assert!(matches!(
                        operation.poll(&mut stream, &mut write_cx),
                        Poll::Ready(Ok(()))
                    ));
                    assert_eq!(writer.0.load(Ordering::Relaxed), 1);
                    let readiness = state.lock().unwrap().read_waker.take().unwrap();
                    assert!(readiness.will_wake(&read_waker));
                    readiness.wake();
                    assert_eq!(reader.0.load(Ordering::Relaxed), 1);
                    assert_eq!(writer.0.load(Ordering::Relaxed), 1);
                    let decoded = decode_wire(&state.lock().unwrap().sent, peer_role);
                    assert_eq!(
                        decoded,
                        if matches!(operation, Operation::Write | Operation::WriteVectored) {
                            b"onenext".as_slice()
                        } else {
                            b"one"
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn reads_leave_transport_control_readiness_untouched() {
        for operation in [Operation::Flush, Operation::Shutdown, Operation::Ping] {
            let (mut stream, state) = scripted(Role::Client);
            {
                let mut state = state.lock().unwrap();
                state.flush_blocked = matches!(operation, Operation::Flush);
                state.shutdown_blocked = matches!(operation, Operation::Shutdown);
                state.ping_blocked = matches!(operation, Operation::Ping);
            }
            let writer = Arc::new(WakeCounter(AtomicUsize::new(0)));
            let reader = Arc::new(WakeCounter(AtomicUsize::new(0)));
            let waker = writer.clone().into();
            let read_waker = reader.clone().into();
            let mut write_cx = Context::from_waker(&waker);
            let mut read_cx = Context::from_waker(&read_waker);
            assert!(operation.poll(&mut stream, &mut write_cx).is_pending());
            let events = state.lock().unwrap().events.clone();
            assert!(
                Pin::new(&mut stream)
                    .poll_read(&mut read_cx, &mut ReadBuf::new(&mut [0]))
                    .is_pending()
            );
            let readiness = {
                let mut state = state.lock().unwrap();
                assert_eq!(state.events, events);
                assert_eq!(state.write_polls, 0);
                state.flush_blocked = false;
                state.shutdown_blocked = false;
                state.ping_blocked = false;
                state.write_waker.take().unwrap()
            };
            assert_eq!(writer.0.load(Ordering::Relaxed), 0);
            assert!(readiness.will_wake(&waker));
            readiness.wake();
            assert_eq!(writer.0.load(Ordering::Relaxed), 1);
            assert_eq!(reader.0.load(Ordering::Relaxed), 0);
            assert!(matches!(
                operation.poll(&mut stream, &mut write_cx),
                Poll::Ready(Ok(()))
            ));
        }
    }

    #[test]
    fn pending_write_acceptance_cancellation_and_control_drains() {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let (mut stream, state) = scripted(Role::Client);
        state
            .lock()
            .unwrap()
            .writes
            .extend([Write::Count(1), Write::Pending, Write::Pending]);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"one"),
            Poll::Ready(Ok(3))
        ));
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"two"),
            Poll::Ready(Ok(3))
        ));
        state.lock().unwrap().writes.push_back(Write::Pending);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"three"),
            Poll::Ready(Ok(5))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write_ping(&mut cx),
            Poll::Ready(Ok(true))
        ));
        state.lock().unwrap().writes.push_back(Write::Pending);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"four"),
            Poll::Ready(Ok(4))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"five"),
            Poll::Ready(Err(_))
        ));
        let state = state.lock().unwrap();
        assert_eq!(decode_wire(&state.sent, Role::Server), b"onetwothreefour");
        assert_eq!(state.events, ["ping", "flush", "shutdown"]);
        assert_eq!(
            (stream.read_wire.len(), stream.write_wire.len()),
            (32768, 32768)
        );
    }

    #[test]
    fn write_errors_are_deferred_after_acceptance_and_sticky() {
        for failure in [Write::Count(0), Write::Error] {
            let (mut stream, state) = scripted(Role::Client);
            state.lock().unwrap().writes.push_back(failure);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"x"),
                Poll::Ready(Ok(1))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"y"),
                Poll::Ready(Err(_))
            ));
            assert!(state.lock().unwrap().sent.is_empty());
        }
    }

    #[test]
    fn read_and_write_failures_remain_independent() {
        for failure in [Write::Count(0), Write::Error] {
            let (mut stream, state) = scripted(Role::Client);
            state
                .lock()
                .unwrap()
                .writes
                .extend([Write::Pending, failure]);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"one"),
                Poll::Ready(Ok(3))
            ));
            // Neither a pending write error nor a recorded one may prevent input progress.
            for failed in [false, true] {
                state
                    .lock()
                    .unwrap()
                    .reads
                    .push_back(Read::Bytes(wire(b"ok", Role::Server)));
                let mut bytes = [0; 2];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(buf.filled(), b"ok");
                assert_eq!(stream.write_error.is_some(), failed);
                assert!(matches!(
                    Pin::new(&mut stream).poll_flush(&mut cx),
                    Poll::Ready(Err(_))
                ));
            }
            assert_eq!(state.lock().unwrap().write_polls, 2);
        }

        for input in [Read::Error, Read::Bytes(vec![0; 4]), Read::Eof] {
            let eof = matches!(input, Read::Eof);
            let (mut stream, state) = scripted(Role::Server);
            state.lock().unwrap().writes.push_back(Write::Pending);
            state.lock().unwrap().reads.push_back(input);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"one"),
                Poll::Ready(Ok(3))
            ));
            for _ in 0..2 {
                let result = Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut [0]));
                assert!(if eof {
                    matches!(result, Poll::Ready(Ok(())))
                } else {
                    matches!(result, Poll::Ready(Err(_)))
                });
                assert_eq!(state.lock().unwrap().write_polls, 1);
            }
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            let state = state.lock().unwrap();
            assert_eq!(decode_wire(&state.sent, Role::Client), b"one");
        }
    }

    #[test]
    fn decoded_prefix_precedes_errors_and_pending_with_prefilled_output() {
        for tail in [Read::Pending, Read::Error, Read::Eof] {
            let (mut stream, state) = scripted(Role::Server);
            state
                .lock()
                .unwrap()
                .reads
                .extend([Read::Bytes(wire(b"ok", Role::Client)), tail]);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut bytes = [0; 8];
            let mut buf = ReadBuf::new(&mut bytes);
            buf.put_slice(b"pre");
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled(), b"preok");
        }
        let (mut stream, state) = scripted(Role::Server);
        let mut encoded = wire(b"ok", Role::Client);
        encoded.extend([0, 0, 0, 0]);
        state.lock().unwrap().reads.push_back(Read::Bytes(encoded));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"ok");
        for _ in 0..2 {
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
                Poll::Ready(Err(_))
            ));
        }
    }

    #[test]
    fn padding_only_yields_without_false_eof_and_truncated_tail_is_discarded() {
        let (mut stream, state) = scripted(Role::Server);
        state.lock().unwrap().writes.push_back(Write::Pending);
        let writer = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let write_waker = writer.clone().into();
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut Context::from_waker(&write_waker), b"pending"),
            Poll::Ready(Ok(7))
        ));
        state.lock().unwrap().reads.extend([
            Read::Bytes(vec![0xff; READ_BUDGET + 1]),
            Read::Bytes(vec![0; 3]),
            Read::Eof,
        ]);
        let wakes = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = wakes.clone().into();
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 1];
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(writer.0.load(Ordering::Relaxed), 0);
        assert_eq!(state.lock().unwrap().write_polls, 1);
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(buf.filled().is_empty());
        assert_eq!(state.lock().unwrap().write_polls, 1);
    }

    #[tokio::test]
    async fn tiny_reads_fragmentation_and_half_close_preserve_both_directions() {
        for size in [1, 5, 4096] {
            let config = super::super::tests::config(
                json!({"padding_min":100,"custom_tables":["","xpxvvpvv"]}),
            );
            let (client, server) = tokio::io::duplex(17);
            let mut client = SudokuStream::new(Box::new(client), config.clone(), Role::Client);
            let mut server = SudokuStream::new(Box::new(server), config, Role::Server);
            let data: Vec<u8> = (0..1025).map(|n| n as u8).collect();
            let expected = data.clone();
            let send = async move {
                client.write_all(&data).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, data);
            };
            let echo = async move {
                let mut data = Vec::new();
                let mut buf = vec![0; size];
                loop {
                    let n = server.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n]);
                }
                assert_eq!(data, expected);
                server.write_all(&data).await.unwrap();
                server.shutdown().await.unwrap();
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(send, echo);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn explicit_flush_before_read_drains_stacked_masks_and_buffered_transports() {
        for layers in [1, 2] {
            for buffered in [false, true] {
                let (a, b) = tokio::io::duplex(1);
                let (mut client, mut server): (Box<dyn AsyncStream>, Box<dyn AsyncStream>) =
                    if buffered {
                        use crate::async_stream::test_streams::FlushGatedStream;
                        (
                            Box::new(FlushGatedStream::new(a)),
                            Box::new(FlushGatedStream::new(b)),
                        )
                    } else {
                        (Box::new(a), Box::new(b))
                    };
                for layer in 0..layers {
                    let config = super::super::tests::config(
                        json!({"ascii":"ascii", "password":format!("layer-{layer}")}),
                    );
                    client = Box::new(SudokuStream::new(client, config.clone(), Role::Client));
                    server = Box::new(SudokuStream::new(server, config, Role::Server));
                }
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    tokio::join!(
                        async {
                            client.write_all(b"question").await.unwrap();
                            client.flush().await.unwrap();
                            let mut reply = [0; 6];
                            client.read_exact(&mut reply).await.unwrap();
                            assert_eq!(&reply, b"answer");
                        },
                        async {
                            let mut request = [0; 8];
                            server.read_exact(&mut request).await.unwrap();
                            assert_eq!(&request, b"question");
                            server.write_all(b"answer").await.unwrap();
                            server.flush().await.unwrap();
                        }
                    );
                })
                .await
                .unwrap();
            }
        }
    }

    #[test]
    fn empty_reads_do_not_consume_wire_and_read_pending_does_not_invent_eof() {
        let (mut stream, state) = scripted(Role::Server);
        let encoded = wire(b"x", Role::Client);
        state.lock().unwrap().reads.extend([
            Read::Bytes(encoded[..1].to_vec()),
            Read::Pending,
            Read::Bytes(encoded[1..].to_vec()),
        ]);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut [])),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(state.lock().unwrap().reads.len(), 3);
        let mut bytes = [0; 1];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        assert!(buf.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"x");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn never_exposes_the_underlying_tcp_socket_for_splice() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let client = tokio::net::TcpStream::connect((
            std::net::Ipv4Addr::LOCALHOST,
            listener.local_addr().unwrap().port(),
        ))
        .await
        .unwrap();
        assert!(client.plain_tcp().is_some());
        let stream = SudokuStream::new(
            Box::new(client),
            super::super::tests::config(json!({})),
            Role::Client,
        );
        assert!(stream.plain_tcp().is_none());
        assert!(stream.peer_addr().is_some());
    }
}
