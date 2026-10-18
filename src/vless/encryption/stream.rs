use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{
    ready,
    task::{ArcWake, AtomicWaker, waker_ref},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use zeroize::Zeroizing;

use super::{
    crypto::{Aead, HEADER_LEN, WRITE_PLAINTEXT_MAX, invalid, record_length},
    mask::HeaderMask,
    session::{ClientSession, ClientSessionCache, ResumeGuard},
};
use crate::{
    async_stream::{AsyncPing, AsyncStream},
    vless::vision_transport::VisionTransport,
};

const PROGRESS_BUDGET: usize = 32;

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl Failure {
    fn new(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string().into(),
        }
    }

    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

#[derive(Default)]
struct PaddingWake {
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl ArcWake for PaddingWake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.reader.wake();
        this.writer.wake();
    }
}

pub(super) struct FreshPadding {
    pub(super) ciphertext: Vec<u8>,
    pub(super) filled: usize,
    pub(super) ticket: Option<(Arc<ClientSessionCache>, Arc<ClientSession>)>,
    deadline: Pin<Box<Sleep>>,
    wake: Arc<PaddingWake>,
}

impl FreshPadding {
    pub(super) fn new(
        ciphertext: Vec<u8>,
        filled: usize,
        ticket: Option<(Arc<ClientSessionCache>, Arc<ClientSession>)>,
        deadline: Instant,
    ) -> Self {
        Self {
            ciphertext,
            filled,
            ticket,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            wake: Arc::default(),
        }
    }
}

pub(super) enum InitialRead {
    Records,
    Fresh(FreshPadding),
    Resumed { random: [u8; 16], filled: usize },
}

pub(crate) struct EncryptionStream<S> {
    inner: S,
    client: bool,
    united: Zeroizing<[u8; 96]>,
    write_aead: Aead,
    read_aead: Option<Aead>,
    write_mask: Option<HeaderMask>,
    read_mask: Option<HeaderMask>,
    random_mode: bool,
    initial: InitialRead,
    resume: Option<ResumeGuard>,
    server_random: Option<[u8; 16]>,
    output: BytesMut,
    prefix_unattached: bool,
    header: [u8; HEADER_LEN],
    header_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    plaintext: BytesMut,
    read_raw: bool,
    write_raw: bool,
    read_eof: bool,
    write_closed: bool,
    need_flush: bool,
    output_error: Option<Failure>,
    shared_error: Option<Failure>,
}

pub(super) struct StreamKeys {
    pub(super) united: Zeroizing<[u8; 96]>,
    pub(super) write_aead: Aead,
    pub(super) read_aead: Option<Aead>,
    pub(super) write_mask: Option<HeaderMask>,
    pub(super) read_mask: Option<HeaderMask>,
    pub(super) random_mode: bool,
}

impl<S: AsyncStream> EncryptionStream<S> {
    #[cfg(test)]
    pub(crate) fn is_resumed(&self) -> bool {
        self.resume.is_some()
    }
    pub(super) fn new(inner: S, client: bool, keys: StreamKeys, initial: InitialRead) -> Self {
        Self {
            inner,
            client,
            united: keys.united,
            write_aead: keys.write_aead,
            read_aead: keys.read_aead,
            write_mask: keys.write_mask,
            read_mask: keys.read_mask,
            random_mode: keys.random_mode,
            initial,
            resume: None,
            server_random: None,
            output: BytesMut::new(),
            prefix_unattached: false,
            header: [0; HEADER_LEN],
            header_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            plaintext: BytesMut::new(),
            read_raw: false,
            write_raw: false,
            read_eof: false,
            write_closed: false,
            need_flush: false,
            output_error: None,
            shared_error: None,
        }
    }

    pub(super) fn set_client_prefix(
        &mut self,
        mut prefix: Vec<u8>,
        guard: ResumeGuard,
    ) -> io::Result<()> {
        if let Some(mask) = &mut self.write_mask {
            mask.apply_write(&mut prefix)?;
        }
        self.output.extend_from_slice(&prefix);
        self.prefix_unattached = true;
        self.resume = Some(guard);
        self.need_flush = true;
        Ok(())
    }

    pub(super) fn set_server_random(&mut self, random: [u8; 16]) {
        self.server_random = Some(random);
    }

    fn wake(&self) -> Option<Arc<PaddingWake>> {
        match &self.initial {
            InitialRead::Fresh(p) => Some(p.wake.clone()),
            _ => None,
        }
    }

    fn register(&self, cx: &Context<'_>, writing: bool) {
        // Exclusive borrows (including Tokio split's mutex) ensure one registrant
        // per direction. Helpers must never register the dispatcher's own waker.
        if let Some(wake) = self.wake() {
            if writing {
                wake.writer.register(cx.waker());
            } else {
                wake.reader.register(cx.waker());
            }
        }
    }

    fn with_context<T>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut Self, &mut Context<'_>) -> T,
    ) -> T {
        if let Some(wake) = self.wake() {
            let waker = waker_ref(&wake);
            f(self, &mut Context::from_waker(&waker))
        } else {
            f(self, cx)
        }
    }

    fn invalidate_resume(&mut self) {
        if let Some(guard) = self.resume.take() {
            guard.invalidate();
        }
    }

    fn fail_output(&mut self, error: io::Error) -> io::Error {
        self.invalidate_resume();
        self.output_error = Some(Failure::new(&error));
        error
    }

    fn fail_shared(&mut self, error: io::Error) -> io::Error {
        self.invalidate_resume();
        self.shared_error = Some(Failure::new(&error));
        if let Some(wake) = self.wake() {
            PaddingWake::wake_by_ref(&wake);
        }
        // Discard any pending ticket without publishing it.
        self.initial = InitialRead::Records;
        error
    }

    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> bool {
        self.with_context(cx, |this, cx| match &mut this.initial {
            InitialRead::Fresh(padding) => padding.deadline.as_mut().poll(cx).is_ready(),
            _ => false,
        })
    }

    fn poll_initial(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Poll<io::Result<()>> {
        loop {
            if matches!(self.initial, InitialRead::Records) {
                return Poll::Ready(Ok(()));
            }
            if *budget == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let progress = self.with_context(cx, |this, cx| match &mut this.initial {
                InitialRead::Fresh(p) => poll_field(
                    &mut this.inner,
                    &mut this.read_mask,
                    cx,
                    &mut p.ciphertext,
                    &mut p.filled,
                ),
                InitialRead::Resumed { random, filled } => {
                    poll_field(&mut this.inner, &mut this.read_mask, cx, random, filled)
                }
                InitialRead::Records => unreachable!(),
            });
            match progress {
                Poll::Pending => {
                    if self.poll_deadline(cx) {
                        return Poll::Ready(Err(self.fail_shared(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "VLESS fresh padding timed out",
                        ))));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail_shared(error))),
                Poll::Ready(Ok(false)) => {
                    *budget -= 1;
                }
                Poll::Ready(Ok(true)) => {
                    let initial = std::mem::replace(&mut self.initial, InitialRead::Records);
                    match initial {
                        InitialRead::Fresh(mut padding) => {
                            let result = self
                                .read_aead
                                .as_mut()
                                .expect("fresh read AEAD")
                                .open(&mut padding.ciphertext, &[]);
                            PaddingWake::wake_by_ref(&padding.wake);
                            if let Err(error) = result {
                                return Poll::Ready(Err(self.fail_shared(error)));
                            }
                            if let Some((cache, ticket)) = padding.ticket {
                                cache.publish(ticket, Instant::now());
                            }
                        }
                        InitialRead::Resumed { random, .. } => {
                            let result =
                                Aead::new(&random, self.united.as_ref(), self.write_aead.cipher);
                            self.read_aead = Some(result.map_err(|error| self.fail_shared(error))?);
                            if self.random_mode {
                                self.read_mask = Some(
                                    HeaderMask::new(self.united.as_ref(), &random, 0)
                                        .map_err(|error| self.fail_shared(error))?,
                                );
                            }
                        }
                        InitialRead::Records => unreachable!(),
                    }
                }
            }
        }
    }

    fn output_entry(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Poll<io::Result<()>> {
        self.register(cx, true);
        if let Some(error) = self.shared_error.as_ref().or(self.output_error.as_ref()) {
            return Poll::Ready(Err(error.error()));
        }
        if self.poll_deadline(cx) {
            // Available padding wins over expiry; budget yields accept no output.
            ready!(self.poll_initial(cx, budget))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_output<T>(
        &mut self,
        cx: &mut Context<'_>,
        budget: &mut usize,
        mut operation: impl FnMut(&mut Self, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        loop {
            match self.with_context(cx, &mut operation) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail_output(error))),
                Poll::Ready(Ok(result)) => return Poll::Ready(Ok(result)),
                Poll::Pending if matches!(self.initial, InitialRead::Fresh(_)) => {
                    ready!(self.poll_initial(cx, budget))?;
                    // with_context now restores the original caller in this poll.
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Poll<io::Result<()>> {
        // An explicit drain commits an unattached prefix even if the write stalls.
        self.prefix_unattached = false;
        self.poll_output(cx, budget, |this, cx| {
            while !this.output.is_empty() {
                let written = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.output))?;
                if written == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                this.output.advance(written);
            }
            Poll::Ready(Ok(()))
        })
    }

    fn queue_record(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let record = self
            .write_aead
            .seal_record(plaintext, self.united.as_ref())?;
        let mut output = Vec::with_capacity(record.len() + self.server_random.map_or(0, |_| 16));
        if let Some(random) = self.server_random.take() {
            output.extend_from_slice(&random);
        }
        output.extend_from_slice(&record);
        if let Some(mask) = &mut self.write_mask {
            mask.apply_write(&mut output)?;
        }
        self.output.extend_from_slice(&output);
        self.prefix_unattached = false;
        self.need_flush = true;
        Ok(())
    }

    fn copy_plaintext(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.plaintext.is_empty() {
            return false;
        }
        let n = self.plaintext.len().min(buf.remaining());
        buf.put_slice(&self.plaintext[..n]);
        self.plaintext.advance(n);
        true
    }

    fn poll_read_record(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.header_filled < HEADER_LEN {
            let mut input = ReadBuf::new(&mut self.header[self.header_filled..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut input) {
                Poll::Ready(Ok(())) if input.filled().is_empty() && self.header_filled == 0 => {
                    self.read_eof = true;
                    self.invalidate_resume();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail_shared(error))),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    if input.filled().is_empty() {
                        return Poll::Ready(Err(
                            self.fail_shared(io::ErrorKind::UnexpectedEof.into())
                        ));
                    }
                    if let Some(mask) = &mut self.read_mask
                        && let Err(error) = mask.apply_read(input.filled_mut())
                    {
                        return Poll::Ready(Err(self.fail_shared(error)));
                    }
                    self.header_filled += input.filled().len();
                }
            }
        }
        if self.body.is_empty() {
            let length = record_length(&self.header).map_err(|error| self.fail_shared(error))?;
            self.body.resize(length, 0);
        }
        while self.body_filled < self.body.len() {
            ready!(poll_field(
                &mut self.inner,
                &mut self.read_mask,
                cx,
                &mut self.body,
                &mut self.body_filled
            ))
            .map_err(|error| self.fail_shared(error))?;
        }
        let plaintext = self
            .read_aead
            .as_mut()
            .expect("record read AEAD")
            .open_record(&self.header, &mut self.body, self.united.as_ref());
        match plaintext {
            Ok(plaintext) => {
                let n = plaintext.len().min(buf.remaining());
                buf.put_slice(&plaintext[..n]);
                self.plaintext.extend_from_slice(&plaintext[n..]);
            }
            Err(error) => return Poll::Ready(Err(self.fail_shared(error))),
        }
        self.resume = None;
        self.header_filled = 0;
        self.body_filled = 0;
        self.body.clear();
        Poll::Ready(Ok(()))
    }
}

fn poll_field<S: AsyncStream>(
    inner: &mut S,
    mask: &mut Option<HeaderMask>,
    cx: &mut Context<'_>,
    bytes: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<bool>> {
    if *filled == bytes.len() {
        return Poll::Ready(Ok(true));
    }
    let mut buf = ReadBuf::new(&mut bytes[*filled..]);
    ready!(Pin::new(inner).poll_read(cx, &mut buf))?;
    if buf.filled().is_empty() {
        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
    }
    if let Some(mask) = mask {
        mask.apply_read(buf.filled_mut())?;
    }
    *filled += buf.filled().len();
    Poll::Ready(Ok(*filled == bytes.len()))
}

impl<S: AsyncStream> AsyncRead for EncryptionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.register(cx, false);
        if let Some(error) = &this.shared_error {
            return Poll::Ready(Err(error.error()));
        }
        let mut budget = PROGRESS_BUDGET;
        ready!(this.poll_initial(cx, &mut budget))?;
        if this.copy_plaintext(buf) || this.read_eof {
            return Poll::Ready(Ok(()));
        }
        if !this.read_raw {
            return this.poll_read_record(cx, buf);
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))
            .map_err(|error| this.fail_shared(error))?;
        if let Some(mask) = &mut this.read_mask {
            mask.apply_read(&mut buf.filled_mut()[before..])
                .map_err(|error| this.fail_shared(error))?;
        }
        this.read_eof = before == buf.filled().len();
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncWrite for EncryptionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut budget = PROGRESS_BUDGET;
        ready!(this.output_entry(cx, &mut budget))?;
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // Attach the first record before submitting a resumed prefix to the transport.
        if !this.prefix_unattached {
            ready!(this.poll_drain(cx, &mut budget))?;
        }
        let n = buf.len().min(WRITE_PLAINTEXT_MAX);
        if this.write_raw {
            let mut output = buf[..n].to_vec();
            if let Some(mask) = &mut this.write_mask {
                mask.apply_write(&mut output)
                    .map_err(|error| this.fail_shared(error))?;
            }
            this.output.extend_from_slice(&output);
            this.need_flush = true;
        } else {
            this.queue_record(&buf[..n])
                .map_err(|error| this.fail_shared(error))?;
        }
        // Once encoded, these bytes belong to the stream, even if draining fails.
        let _ = this.poll_drain(cx, &mut budget);
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(
            cx,
            bufs.iter()
                .find(|buf| !buf.is_empty())
                .map_or(&[], |buf| &**buf),
        )
    }

    fn is_write_vectored(&self) -> bool {
        false
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut budget = PROGRESS_BUDGET;
        ready!(this.output_entry(cx, &mut budget))?;
        ready!(this.poll_drain(cx, &mut budget))?;
        ready!(this.poll_output(cx, &mut budget, |this, cx| {
            Pin::new(&mut this.inner).poll_flush(cx)
        }))?;
        this.need_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        let mut budget = PROGRESS_BUDGET;
        ready!(this.output_entry(cx, &mut budget))?;
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_output(cx, &mut budget, |this, cx| {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }))?;
        this.server_random = None;
        this.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncPing for EncryptionStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        let mut budget = PROGRESS_BUDGET;
        ready!(this.output_entry(cx, &mut budget))?;
        ready!(this.poll_drain(cx, &mut budget))?;
        let written = ready!(this.poll_output(cx, &mut budget, |this, cx| {
            Pin::new(&mut this.inner).poll_write_ping(cx)
        }))?;
        this.need_flush |= written;
        Poll::Ready(Ok(written))
    }
}

impl<S: AsyncStream> AsyncStream for EncryptionStream<S> {
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if !self.read_raw
            || !self.write_raw
            || self.random_mode
            || self.need_flush
            || self.read_eof
            || self.write_closed
            || self.shared_error.is_some()
            || self.output_error.is_some()
            || !self.output.is_empty()
            || !self.plaintext.is_empty()
            || self.header_filled != 0
            || !self.body.is_empty()
            || self.server_random.is_some()
            || !matches!(self.initial, InitialRead::Records)
        {
            return None;
        }
        self.inner.plain_tcp()
    }

    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        std::num::NonZeroUsize::new(WRITE_PLAINTEXT_MAX)
    }
}

impl<S: AsyncStream> VisionTransport for EncryptionStream<S> {
    fn is_client(&self) -> bool {
        self.client
    }
    fn is_server(&self) -> bool {
        !self.client
    }
    fn require_record_framing(&self) -> io::Result<()> {
        Ok(())
    }
    fn allow_streaming_reads(&mut self) {}

    fn start_raw_read(&mut self) -> io::Result<()> {
        if !matches!(self.initial, InitialRead::Records) || self.header_filled != 0 || self.read_raw
        {
            return Err(invalid(
                "VLESS DIRECT requires an authenticated record boundary",
            ));
        }
        self.read_raw = true;
        Ok(())
    }

    fn start_raw_write(&mut self, final_plaintext: &[u8]) -> io::Result<()> {
        if let Some(error) = self.shared_error.as_ref().or(self.output_error.as_ref()) {
            return Err(error.error());
        }
        if self.write_raw || self.write_closed || final_plaintext.len() > 65535 {
            return Err(invalid("invalid VLESS DIRECT write transition"));
        }
        if final_plaintext.is_empty() && self.server_random.is_some() {
            return Err(invalid(
                "VLESS resumed server DIRECT requires a final record",
            ));
        }
        for chunk in final_plaintext.chunks(WRITE_PLAINTEXT_MAX) {
            self.queue_record(chunk)
                .map_err(|error| self.fail_shared(error))?;
        }
        self.write_raw = true;
        self.need_flush = true;
        Ok(())
    }

    fn poll_drain_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut budget = PROGRESS_BUDGET;
        ready!(self.output_entry(cx, &mut budget))?;
        self.poll_drain(cx, &mut budget)
    }
}

#[cfg(test)]
mod tests;
