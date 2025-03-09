use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::shadow_tls_hmac::ShadowTlsHmac;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;

// see comment in shadow_tls_handler.rs
const TLS_FRAME_MAX_LEN: usize = 5 + 65535;

const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub struct ShadowTlsStream {
    stream: Box<dyn AsyncStream>,
    hmac_client_data: ShadowTlsHmac,
    hmac_server_data: ShadowTlsHmac,

    is_eof: bool,

    unprocessed_buf: Box<[u8]>,
    unprocessed_end_offset: usize,

    processed_buf: Box<[u8]>,
    processed_start_offset: usize,
    processed_end_offset: usize,

    write_buf: Box<[u8]>,
    write_buf_pos: usize,
    write_buf_end: usize,
}

impl ShadowTlsStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        initial_processed_data: &[u8],
        hmac_client_data: ShadowTlsHmac,
        hmac_server_data: ShadowTlsHmac,
    ) -> std::io::Result<Self> {
        let mut processed_buf = allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice();
        if initial_processed_data.len() > processed_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "initial processed data too large for read buffer",
            ));
        }
        processed_buf[..initial_processed_data.len()].copy_from_slice(initial_processed_data);

        Ok(Self {
            stream,
            hmac_client_data,
            hmac_server_data,
            is_eof: false,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: initial_processed_data.len(),
            unprocessed_buf: allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice(),
            unprocessed_end_offset: 0,
            write_buf: allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice(),
            write_buf_pos: 0,
            write_buf_end: 0,
        })
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        assert!(self.unprocessed_end_offset == 0);

        if data.len() > self.unprocessed_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "feed_initial_read_data called with too much data",
            ));
        }

        self.unprocessed_buf[0..data.len()].copy_from_slice(data);
        self.unprocessed_end_offset = data.len();

        Ok(())
    }

    #[inline]
    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) {
        assert!(
            self.processed_end_offset > 0,
            "called without any processed data"
        );

        let available_len = self.processed_end_offset - self.processed_start_offset;

        let unfilled_len = buf.remaining();

        let write_amount = std::cmp::min(unfilled_len, available_len);
        assert!(
            write_amount > 0,
            "no data to write (available_len = {}, unfilled_len = {})",
            available_len,
            unfilled_len,
        );

        buf.put_slice(
            &self.processed_buf
                [self.processed_start_offset..self.processed_start_offset + write_amount],
        );

        let new_processed_start_offset = self.processed_start_offset + write_amount;
        if new_processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    #[inline]
    fn try_deframe(&mut self) -> std::io::Result<DeframeState> {
        // We should only deframe when there is no readily available processed data.
        assert!(self.processed_end_offset == 0);

        // Need at least 5 bytes for a TLS header
        if self.unprocessed_end_offset < 5 {
            return Ok(DeframeState::NeedData);
        }

        let header = &self.unprocessed_buf[0..5];
        let content_type = header[0];
        if content_type == CONTENT_TYPE_ALERT {
            self.is_eof = true;
            return Ok(DeframeState::ReceivedAlert);
        }
        if content_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid record type",
            ));
        }

        let frame_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if frame_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame length too short",
            ));
        }

        let total_len = 5 + frame_len;
        if self.unprocessed_end_offset < total_len {
            return Ok(DeframeState::NeedData);
        }

        // Compute the payload length (frame_len includes 4 bytes for HMAC)
        let payload_len = frame_len - 4;

        // Ensure there is space in the processed buffer (compact if needed)
        if payload_len > self.processed_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Payload too large for processed buffer",
            ));
        }

        // Process the TLS frame: the frame_body consists of a 4-byte HMAC followed by the payload.
        let frame_body = &self.unprocessed_buf[5..total_len];
        let received_digest = &frame_body[0..4];
        let payload = &frame_body[4..];
        self.hmac_client_data.update(payload);
        let expected_digest = self.hmac_client_data.digest();
        if received_digest != expected_digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }
        self.hmac_client_data.update(&expected_digest);

        // Append payload into the processed buffer
        self.processed_buf[0..payload_len].copy_from_slice(payload);
        self.processed_end_offset = payload_len;

        // Advance the unprocessed buffer pointer
        if total_len < self.unprocessed_end_offset {
            self.unprocessed_buf
                .copy_within(total_len..self.unprocessed_end_offset, 0);
            self.unprocessed_end_offset -= total_len;
        } else {
            self.unprocessed_end_offset = 0;
        }

        Ok(DeframeState::Success)
    }
}

enum DeframeState {
    NeedData,
    Success,
    ReceivedAlert,
}

impl AsyncRead for ShadowTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        }
        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        if this.unprocessed_end_offset > 0 {
            // Deframe any complete TLS frames available.
            match this.try_deframe()? {
                DeframeState::Success => {
                    this.read_processed(buf);
                    return Poll::Ready(Ok(()));
                }
                DeframeState::NeedData => {}
                DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
            }

            // If the unprocessed buffer is full, return an error.
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unprocessed buffer full",
                )));
            }
        }

        // Read more TLS data from the underlying stream.
        loop {
            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.unprocessed_end_offset += n;

                    match this.try_deframe()? {
                        DeframeState::Success => {
                            this.read_processed(buf);
                            return Poll::Ready(Ok(()));
                        }
                        DeframeState::NeedData => {}
                        DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
                    }
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
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
        this.write_buf[0] = CONTENT_TYPE_APPLICATION_DATA;
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
