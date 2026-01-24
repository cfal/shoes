//! H2MUX Padding Layer
//!
//! Wraps a connection to pad the first 16 read/write operations.
//! This is applied BEFORE the HTTP/2 layer, directly on the raw stream.
//!
//! Frame format (for first 16 operations):
//! ```text
//! +------------------+-----------------+-------------+-------------+
//! | Original Length  | Padding Length  | Data        | Padding     |
//! | (2 bytes BE)     | (2 bytes BE)    | (variable)  | (256-767 B) |
//! +------------------+-----------------+-------------+-------------+
//! ```

use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::h2mux_protocol::{MAX_PADDING, MIN_PADDING};

const FIRST_PADDINGS: usize = 16;
const HEADER_SIZE: usize = 4;
const MAX_PAYLOAD_SIZE: usize = 65535;
const SKIP_BUF_SIZE: usize = 1024;

/// Read state machine for padding layer.
#[derive(Debug, Clone, Copy)]
enum ReadState {
    /// Reading 4-byte frame header
    Header { pos: usize },
    /// Delivering frame data to caller
    Data {
        remaining: usize,
        padding_after: usize,
    },
    /// Skipping padding bytes after data
    SkipPadding { remaining: usize },
    /// Direct passthrough (padding phase complete)
    Passthrough,
}

/// Write state machine for padding layer.
#[derive(Debug, Clone, Copy)]
enum WriteState {
    /// Ready to accept new write
    Ready,
    /// Frame built, write returned Pending, need to flush then report Ok
    Pending { pos: usize, payload_len: usize },
    /// Frame partially written, already reported Ok, need to flush before next write
    Partial { pos: usize },
    /// Direct passthrough (padding phase complete)
    Passthrough,
}

/// Stream wrapper that pads the first 16 read/write operations.
pub struct H2MuxPaddingStream<S> {
    inner: S,
    // Read state
    read_state: ReadState,
    read_count: usize,
    read_header: [u8; HEADER_SIZE],
    skip_buf: [u8; SKIP_BUF_SIZE],
    // Write state
    write_state: WriteState,
    write_count: usize,
    write_buffer: BytesMut,
}

impl<S> H2MuxPaddingStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_state: ReadState::Header { pos: 0 },
            read_count: 0,
            read_header: [0u8; HEADER_SIZE],
            skip_buf: [0u8; SKIP_BUF_SIZE],
            write_state: WriteState::Ready,
            write_count: 0,
            write_buffer: BytesMut::with_capacity(
                HEADER_SIZE + MAX_PAYLOAD_SIZE + MAX_PADDING as usize,
            ),
        }
    }

    /// Transitions write state after buffer is fully flushed.
    fn finish_write_flush(&mut self) {
        self.write_buffer.clear();
        self.write_count += 1;
        if self.write_count >= FIRST_PADDINGS {
            let _ = mem::take(&mut self.write_buffer);
            self.write_state = WriteState::Passthrough;
        } else {
            self.write_state = WriteState::Ready;
        }
    }
}

impl<S: Unpin> Unpin for H2MuxPaddingStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for H2MuxPaddingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ReadState::Passthrough => {
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                ReadState::Header { mut pos } => {
                    while pos < HEADER_SIZE {
                        let mut temp_buf = ReadBuf::new(&mut this.read_header[pos..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    if pos == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "EOF while reading padding frame header",
                                    )));
                                }
                                pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.read_state = ReadState::Header { pos };
                                return Poll::Pending;
                            }
                        }
                    }

                    // Header complete, parse it
                    let data_len =
                        u16::from_be_bytes([this.read_header[0], this.read_header[1]]) as usize;
                    let padding_len =
                        u16::from_be_bytes([this.read_header[2], this.read_header[3]]) as usize;
                    this.read_count += 1;

                    if data_len == 0 {
                        this.read_state = ReadState::SkipPadding {
                            remaining: padding_len,
                        };
                    } else {
                        this.read_state = ReadState::Data {
                            remaining: data_len,
                            padding_after: padding_len,
                        };
                    }
                }

                ReadState::Data {
                    remaining,
                    padding_after,
                } => {
                    let to_read = remaining.min(buf.remaining());
                    let mut temp_buf = ReadBuf::new(buf.initialize_unfilled_to(to_read));
                    match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = temp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF while reading padding frame data",
                                )));
                            }
                            buf.advance(n);
                            let new_remaining = remaining - n;
                            if new_remaining == 0 {
                                this.read_state = ReadState::SkipPadding {
                                    remaining: padding_after,
                                };
                            } else {
                                this.read_state = ReadState::Data {
                                    remaining: new_remaining,
                                    padding_after,
                                };
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                ReadState::SkipPadding { mut remaining } => {
                    while remaining > 0 {
                        let skip_len = remaining.min(SKIP_BUF_SIZE);
                        let mut temp_buf = ReadBuf::new(&mut this.skip_buf[..skip_len]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    this.read_state = ReadState::SkipPadding { remaining };
                                    return Poll::Ready(Ok(()));
                                }
                                remaining -= n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.read_state = ReadState::SkipPadding { remaining };
                                return Poll::Pending;
                            }
                        }
                    }

                    // Padding complete, transition to next state
                    if this.read_count >= FIRST_PADDINGS {
                        let _ = mem::take(&mut this.write_buffer);
                        this.read_state = ReadState::Passthrough;
                    } else {
                        this.read_state = ReadState::Header { pos: 0 };
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for H2MuxPaddingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        loop {
            match this.write_state {
                WriteState::Passthrough => {
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                }

                WriteState::Pending {
                    mut pos,
                    payload_len,
                } => {
                    // Flush buffer, then return Ok(payload_len)
                    while pos < this.write_buffer.len() {
                        let remaining = &this.write_buffer[pos..];
                        match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                            Poll::Ready(Ok(n)) => pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.write_state = WriteState::Pending { pos, payload_len };
                                return Poll::Pending;
                            }
                        }
                    }
                    this.finish_write_flush();
                    return Poll::Ready(Ok(payload_len));
                }

                WriteState::Partial { mut pos } => {
                    // Flush buffer, then continue to Ready state
                    while pos < this.write_buffer.len() {
                        let remaining = &this.write_buffer[pos..];
                        match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                            Poll::Ready(Ok(n)) => pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.write_state = WriteState::Partial { pos };
                                return Poll::Pending;
                            }
                        }
                    }
                    this.finish_write_flush();
                    // Continue loop to handle new data in Ready state
                }

                WriteState::Ready => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    // Build padded frame
                    let payload_len = buf.len().min(MAX_PAYLOAD_SIZE);
                    let payload = &buf[..payload_len];
                    let padding_len = rand::rng().random_range(MIN_PADDING..=MAX_PADDING) as usize;

                    this.write_buffer.clear();
                    this.write_buffer.put_u16(payload_len as u16);
                    this.write_buffer.put_u16(padding_len as u16);
                    this.write_buffer.put_slice(payload);
                    this.write_buffer
                        .resize(HEADER_SIZE + payload_len + padding_len, 0);

                    match Pin::new(&mut this.inner).poll_write(cx, &this.write_buffer) {
                        Poll::Ready(Ok(n)) => {
                            if n == this.write_buffer.len() {
                                this.finish_write_flush();
                            } else {
                                this.write_state = WriteState::Partial { pos: n };
                            }
                            return Poll::Ready(Ok(payload_len));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = WriteState::Pending {
                                pos: 0,
                                payload_len,
                            };
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any pending buffer first
        match this.write_state {
            WriteState::Passthrough | WriteState::Ready => {}
            WriteState::Pending {
                mut pos,
                payload_len,
            } => {
                while pos < this.write_buffer.len() {
                    let remaining = &this.write_buffer[pos..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = WriteState::Pending { pos, payload_len };
                            return Poll::Pending;
                        }
                    }
                }
                this.finish_write_flush();
            }
            WriteState::Partial { mut pos } => {
                while pos < this.write_buffer.len() {
                    let remaining = &this.write_buffer[pos..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = WriteState::Partial { pos };
                            return Poll::Pending;
                        }
                    }
                }
                this.finish_write_flush();
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any pending buffer first
        match this.write_state {
            WriteState::Passthrough | WriteState::Ready => {}
            WriteState::Pending { mut pos, .. } => {
                while pos < this.write_buffer.len() {
                    let remaining = &this.write_buffer[pos..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = WriteState::Pending {
                                pos,
                                payload_len: 0, // doesn't matter during shutdown
                            };
                            return Poll::Pending;
                        }
                    }
                }
                this.write_buffer.clear();
                this.write_state = WriteState::Ready;
            }
            WriteState::Partial { mut pos } => {
                while pos < this.write_buffer.len() {
                    let remaining = &this.write_buffer[pos..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = WriteState::Partial { pos };
                            return Poll::Pending;
                        }
                    }
                }
                this.write_buffer.clear();
                this.write_state = WriteState::Ready;
            }
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for H2MuxPaddingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for H2MuxPaddingStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_padding_write_read_roundtrip() {
        let (client, server) = duplex(65536);

        let mut client_stream = H2MuxPaddingStream::new(client);
        let mut server_stream = H2MuxPaddingStream::new(server);

        // Write data from client
        let data = b"Hello, World!";
        client_stream.write_all(data).await.unwrap();
        client_stream.flush().await.unwrap();

        // Read data on server
        let mut buf = vec![0u8; 100];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[tokio::test]
    async fn test_padding_multiple_frames() {
        let (client, server) = duplex(65536);

        let mut client_stream = H2MuxPaddingStream::new(client);
        let mut server_stream = H2MuxPaddingStream::new(server);

        // Write multiple frames
        for i in 0..5 {
            let data = format!("Message {}", i);
            client_stream.write_all(data.as_bytes()).await.unwrap();
        }
        client_stream.flush().await.unwrap();

        // Read all messages
        let mut buf = vec![0u8; 1024];
        let mut total = String::new();
        for _ in 0..5 {
            let n = server_stream.read(&mut buf).await.unwrap();
            total.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        assert!(total.contains("Message 0"));
        assert!(total.contains("Message 4"));
    }

    #[tokio::test]
    async fn test_padding_transition_after_16_operations() {
        let (client, server) = duplex(65536);

        let mut client_stream = H2MuxPaddingStream::new(client);
        let mut server_stream = H2MuxPaddingStream::new(server);

        // Write 16 padded frames
        for i in 0..16 {
            let data = format!("Padded {}", i);
            client_stream.write_all(data.as_bytes()).await.unwrap();
        }

        // Write 17th frame (should be raw)
        let raw_data = b"Raw data after padding";
        client_stream.write_all(raw_data).await.unwrap();
        client_stream.flush().await.unwrap();

        // Read all 17 messages
        let mut buf = vec![0u8; 100];
        for i in 0..16 {
            let n = server_stream.read(&mut buf).await.unwrap();
            let expected = format!("Padded {}", i);
            assert_eq!(&buf[..n], expected.as_bytes());
        }

        // Read raw message
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], raw_data);
    }

    #[tokio::test]
    async fn test_padding_large_write_fragmentation() {
        let (client, server) = duplex(256 * 1024);

        let mut client_stream = H2MuxPaddingStream::new(client);
        let mut server_stream = H2MuxPaddingStream::new(server);

        // Write data larger than MAX_PAYLOAD_SIZE (65535)
        let large_data = vec![0xABu8; 70000];
        let written = client_stream.write(&large_data).await.unwrap();

        // Should only write up to MAX_PAYLOAD_SIZE in one call
        assert!(written <= MAX_PAYLOAD_SIZE);

        client_stream.flush().await.unwrap();

        // Read should get the fragmented data
        let mut buf = vec![0u8; 70000];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, written);
        assert_eq!(&buf[..n], &large_data[..written]);
    }

    #[tokio::test]
    async fn test_padding_bidirectional() {
        let (client, server) = duplex(65536);

        let mut client_stream = H2MuxPaddingStream::new(client);
        let mut server_stream = H2MuxPaddingStream::new(server);

        // Client sends
        client_stream.write_all(b"Request").await.unwrap();
        client_stream.flush().await.unwrap();

        // Server receives and responds
        let mut buf = vec![0u8; 100];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Request");

        server_stream.write_all(b"Response").await.unwrap();
        server_stream.flush().await.unwrap();

        // Client receives response
        let n = client_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Response");
    }

    #[tokio::test]
    async fn test_padding_empty_write() {
        let (client, _server) = duplex(65536);
        let mut client_stream = H2MuxPaddingStream::new(client);

        // Empty write should return 0
        let n = client_stream.write(&[]).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_padding_constants() {
        // Verify padding range
        assert!(MIN_PADDING <= MAX_PADDING);
        assert_eq!(MIN_PADDING, 256);
        assert_eq!(MAX_PADDING, 767);
        assert_eq!(FIRST_PADDINGS, 16);
    }
}
