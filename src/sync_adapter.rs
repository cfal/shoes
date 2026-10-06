/// Sync adapters for bridging async I/O with rustls's synchronous API
///
/// These adapters allow rustls's synchronous `read_tls()` and `write_tls()` methods
/// to work with Tokio's async I/O primitives.
///
/// Adapted from tokio-rustls:
/// https://github.com/rustls/tokio-rustls/blob/ba767aeb51611107e7cb6aa756f10a2f49e70926/src/common/mod.rs#L403
use std::io::{self, IoSlice, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Adapter to bridge async read to synchronous read for rustls
///
/// This allows rustls's `read_tls()` method to read from async TCP sockets.
/// When the async socket would block (Poll::Pending), this returns WouldBlock error.
pub struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> std::io::Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Adapter to bridge async write to synchronous write for rustls
///
/// This allows rustls's `write_tls()` method to write to async TCP sockets.
/// When the async socket would block (Poll::Pending), this returns WouldBlock error.
pub struct SyncWriteAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn vectors_survive_transparent_wrappers_and_partial_writes() {
        let (writer, mut reader) = tokio::io::duplex(4);
        let mut writer = crate::prepend_stream::PrependStream::new(writer, None);
        assert!(writer.is_write_vectored());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut adapter = SyncWriteAdapter {
            io: &mut writer,
            cx: &mut cx,
        };
        let slices = [
            IoSlice::new(b""),
            IoSlice::new(b"abc"),
            IoSlice::new(b"def"),
        ];
        assert_eq!(adapter.write_vectored(&slices).unwrap(), 4);
        assert_eq!(
            adapter.write_vectored(&slices).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut received = [0; 4];
        reader.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"abcd");
        assert_eq!(adapter.write_vectored(&[IoSlice::new(b"")]).unwrap(), 0);
        assert_eq!(adapter.write_vectored(&[IoSlice::new(b"ef")]).unwrap(), 2);
        drop(reader);
        assert_eq!(
            adapter.write_vectored(&slices).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
