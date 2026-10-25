use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(test)]
#[path = "transport_tests.rs"]
pub(crate) mod tests;

/// h2 copies transport errors as kind and text, discarding errno and typed causes.
#[derive(Clone, Debug, Default)]
pub(crate) struct TransportErrors(Arc<State>);

#[derive(Debug, Default)]
struct State {
    running: AtomicBool,
    terminal: OnceLock<Option<Arc<io::Error>>>,
}

impl TransportErrors {
    pub(crate) fn wrap<T>(&self, inner: T) -> ObservedIo<T> {
        ObservedIo {
            inner,
            errors: self.clone(),
        }
    }

    pub(crate) fn start_driver(&self) {
        // The preface write retries Interrupted; only driver errors are terminal.
        self.0.running.store(true, Ordering::Relaxed);
    }

    fn record(&self, error: io::Error) -> io::Error {
        if !self.0.running.load(Ordering::Relaxed) || self.0.terminal.get().is_some() {
            return error;
        }
        let copy = match (error.raw_os_error(), error.get_ref()) {
            (Some(code), _) => io::Error::from_raw_os_error(code),
            (None, Some(inner)) => io::Error::new(error.kind(), inner.to_string()),
            (None, None) => error.kind().into(),
        };
        let _ = self.0.terminal.set(Some(Arc::new(error)));
        copy
    }

    fn closed(&self) {
        if self.0.running.load(Ordering::Relaxed) {
            let _ = self.0.terminal.set(None);
        }
    }

    pub(crate) fn cause(&self, error: &h2::Error) -> Option<Arc<io::Error>> {
        let reported = error.get_io()?;
        let original = self.0.terminal.get()?.as_ref()?;
        let text = match original.get_ref() {
            Some(inner) => inner.to_string(),
            None => io::Error::from(original.kind()).to_string(),
        };
        let matches = reported.kind() == original.kind() && reported.to_string() == text;
        // h2's PING handle reports a bare BrokenPipe when the failed driver exits.
        let closed = reported.kind() == io::ErrorKind::BrokenPipe && reported.get_ref().is_none();
        if matches || closed {
            Some(original.clone())
        } else {
            None
        }
    }

    pub(crate) fn map(&self, error: h2::Error) -> io::Error {
        let cause = self.cause(&error);
        Self::map_captured(error, cause)
    }

    pub(crate) fn map_captured(error: h2::Error, cause: Option<Arc<io::Error>>) -> io::Error {
        match cause {
            Some(cause) => io::Error::other(RecoveredError {
                error,
                cause: Some(cause),
                label: None,
            }),
            None => io::Error::other(error),
        }
    }

    pub(crate) fn map_with(&self, label: &'static str, error: h2::Error) -> io::Error {
        if !error.is_io() {
            return io::Error::other(format!("{label}: {error}"));
        }
        io::Error::other(RecoveredError {
            cause: self.cause(&error),
            error,
            label: Some(label),
        })
    }
}

#[derive(Debug)]
pub(crate) struct RecoveredError {
    pub(crate) error: h2::Error,
    cause: Option<Arc<io::Error>>,
    label: Option<&'static str>,
}

impl fmt::Display for RecoveredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(label) = self.label {
            write!(f, "{label}: ")?;
        }
        self.error.fmt(f)
    }
}

impl Error for RecoveredError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => self.error.get_io().map(|error| error as &dyn Error),
        }
    }
}

pub(crate) struct ObservedIo<T> {
    inner: T,
    errors: TransportErrors,
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let remaining = buf.remaining();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && remaining > 0 && buf.filled().len() == filled {
            this.errors.closed();
        }
        result.map_err(|error| this.errors.record(error))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(0))) && !buf.is_empty() {
            this.errors.closed();
        }
        result.map_err(|error| this.errors.record(error))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(0))) && bufs.iter().any(|buf| !buf.is_empty()) {
            this.errors.closed();
        }
        result.map_err(|error| this.errors.record(error))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(|error| this.errors.record(error))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_shutdown(cx)
            .map_err(|error| this.errors.record(error))
    }
}
