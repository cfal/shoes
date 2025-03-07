use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Assume these traits are defined in your M-bM-^@M-^\async_streamM-bM-^@M-^] module.
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

pub struct VlessMessageStream {
    stream: Box<dyn AsyncStream>,
    read_buf: [u8; 65537],
    read_end_index: usize,
    pending_write: Vec<u8>,
    write_offset: usize,
    is_eof: bool,
}

impl VlessMessageStream {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            read_buf: [0u8; 65537],
            read_end_index: 0,
            pending_write: Vec::with_capacity(65537),
            write_offset: 0,
            is_eof: false,
        }
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > self.read_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "feed_initial_read_data called with too much data",
            ));
        }
        self.read_buf[0..data.len()].copy_from_slice(data);
        self.read_end_index = data.len();
        Ok(())
    }
}

impl AsyncReadMessage for VlessMessageStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.read_end_index >= 2 {
                let payload_len = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]) as usize;
                let total_len = 2 + payload_len;
                if this.read_end_index >= total_len {
                    if out_buf.remaining() < payload_len {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::Other,
                            "out_buf is too small to hold the message",
                        )));
                    }
                    out_buf.put_slice(&this.read_buf[2..total_len]);
                    if this.read_end_index > total_len {
                        this.read_buf.copy_within(total_len..this.read_end_index, 0);
                        this.read_end_index -= total_len;
                    } else {
                        // this.read_end_index == total_len
                        this.read_end_index = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            let read_buf_slice = &mut this.read_buf[this.read_end_index..];
            // this is impossible because our buffer size is u16::MAX + 2, so there should always
            // be space for a full message.
            assert!(!read_buf_slice.is_empty());
            let mut tmp = ReadBuf::new(read_buf_slice);
            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let n = tmp.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        if this.read_end_index == 0 {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "EOF reached in the middle of a message",
                            )));
                        }
                    }
                    this.read_end_index += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWriteMessage for VlessMessageStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<()>> {
        let mut this = self.get_mut();

        if !this.pending_write.is_empty() {
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            // previously this checked this.write_offset < this.pending_write.len(), but
            // we want to make sure the message was flushed in the underlying stream.
            if !this.pending_write.is_empty() {
                return Poll::Pending;
            }
        }

        if buf.len() > 65535 {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "message size too large",
            )));
        }

        this.pending_write
            .extend_from_slice(&(buf.len() as u16).to_be_bytes());
        this.pending_write.extend_from_slice(buf);
        this.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for VlessMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        while this.write_offset < this.pending_write.len() {
            let chunk = &this.pending_write[this.write_offset..];
            match Pin::new(&mut this.stream).poll_write(cx, chunk) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::WriteZero,
                            "failed to write message",
                        )));
                    }
                    this.write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Once complete, flush the underlying stream.
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_offset = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for VlessMessageStream {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        match <Self as AsyncFlushMessage>::poll_flush_message(Pin::new(this), cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for VlessMessageStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for VlessMessageStream {}
