use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::shadow_tls_hmac::ShadowTlsHmac;
use crate::util::allocate_vec;

// see comment in shadow_tls_handler.rs
const TLS_FRAME_MAX_LEN: usize = 5 + 65535;

pub struct ShadowTlsStream {
    stream: Box<dyn AsyncStream>,
    hmac_client_data: ShadowTlsHmac,
    hmac_server_data: ShadowTlsHmac,

    read_buf: Box<[u8]>,
    read_buf_pos: usize,
    read_buf_end: usize,

    write_buf: Box<[u8]>,
    write_buf_pos: usize,
    write_buf_end: usize,
}

impl ShadowTlsStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        initial_client_data: &[u8],
        hmac_client_data: ShadowTlsHmac,
        hmac_server_data: ShadowTlsHmac,
    ) -> std::io::Result<Self> {
        let mut read_buf = allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice();
        if initial_client_data.len() > read_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "initial client data too large for read buffer",
            ));
        }
        read_buf[..initial_client_data.len()].copy_from_slice(initial_client_data);
        Ok(Self {
            stream,
            hmac_client_data,
            hmac_server_data,
            read_buf,
            read_buf_pos: 0,
            read_buf_end: initial_client_data.len(),
            write_buf: allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice(),
            write_buf_pos: 0,
            write_buf_end: 0,
        })
    }
}

impl AsyncRead for ShadowTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If there's buffered data, serve it first
        if this.read_buf_pos < this.read_buf_end {
            let available = this.read_buf_end - this.read_buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_buf_pos..this.read_buf_pos + to_copy]);
            this.read_buf_pos += to_copy;
            if this.read_buf_pos == this.read_buf_end {
                this.read_buf_pos = 0;
                this.read_buf_end = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read enough data to get a full TLS record header (5 bytes)
        while this.read_buf_end < 5 {
            let mut temp = ReadBuf::new(&mut this.read_buf[this.read_buf_end..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let n = temp.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.read_buf_end += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        // Parse the header
        let header = &this.read_buf[0..5];
        if header[0] != 0x17 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid record type",
            )));
        }

        let frame_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if frame_len < 4 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame length too short",
            )));
        }

        // Read the rest of the record
        let total_len = 5 + frame_len;
        if total_len > this.read_buf.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame too large: {} bytes", total_len),
            )));
        }

        while this.read_buf_end < total_len {
            let mut temp = ReadBuf::new(&mut this.read_buf[this.read_buf_end..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let n = temp.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF mid-frame",
                        )));
                    }
                    this.read_buf_end += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        // Process the frame
        let frame_body = &this.read_buf[5..total_len];
        let received_digest = &frame_body[..4];
        let payload = &frame_body[4..];
        this.hmac_client_data.update(payload);
        let expected_digest = this.hmac_client_data.digest();
        if received_digest != expected_digest {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HMAC verification failed",
            )));
        }
        this.hmac_client_data.update(&expected_digest);

        // Copy payload to user buffer
        let to_copy = payload.len().min(buf.remaining());
        buf.put_slice(&payload[..to_copy]);

        // Store any remaining payload data
        if to_copy < payload.len() {
            // Move the remaining data to the start
            let remaining = payload.len() - to_copy;
            this.read_buf.copy_within(5 + 4 + to_copy..total_len, 0);
            this.read_buf_pos = 0;
            this.read_buf_end = remaining;
        } else {
            // Check if there's more data after this frame
            if this.read_buf_end > total_len {
                this.read_buf.copy_within(total_len..this.read_buf_end, 0);
                this.read_buf_end -= total_len;
                this.read_buf_pos = 0;
            } else {
                this.read_buf_pos = 0;
                this.read_buf_end = 0;
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ShadowTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Flush any pending write buffer first.
        while this.write_buf_pos < this.write_buf_end {
            let remaining = &this.write_buf[this.write_buf_pos..this.write_buf_end];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Failed to write pending data",
                        )));
                    }
                    this.write_buf_pos += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        // Reset buffer positions
        this.write_buf_pos = 0;
        this.write_buf_end = 0;

        // Construct TLS frame in our preallocated buffer
        let frame_len = buf.len() + 4; // HMAC(4) + payload

        if frame_len > 0xFFFF {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Payload too large for TLS record",
            )));
        }

        if 5 + frame_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Payload too large for TLS header",
            )));
        }

        // Write TLS header
        this.write_buf[0] = 0x17; // APPLICATION_DATA
        this.write_buf[1] = 0x03; // TLS_MAJOR
        this.write_buf[2] = 0x03; // TLS_MINOR
        this.write_buf[3..5].copy_from_slice(&(frame_len as u16).to_be_bytes());

        // Calculate and write HMAC
        this.hmac_server_data.update(buf);
        let digest = this.hmac_server_data.digest();
        this.hmac_server_data.update(&digest);

        this.write_buf[5..9].copy_from_slice(&digest);

        // Write payload
        this.write_buf[9..9 + buf.len()].copy_from_slice(buf);

        // Set end position
        this.write_buf_end = 5 + frame_len;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        // If we have pending data to write, write it first
        while this.write_buf_pos < this.write_buf_end {
            let remaining = &this.write_buf[this.write_buf_pos..this.write_buf_end];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Failed to flush pending data",
                        )));
                    }
                    this.write_buf_pos += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        // Reset buffer positions
        this.write_buf_pos = 0;
        this.write_buf_end = 0;

        // Flush the underlying stream
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let this = self.as_mut().get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for ShadowTlsStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for ShadowTlsStream {}
