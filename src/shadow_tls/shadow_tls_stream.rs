use std::pin::Pin;
use std::task::{Context, Poll, ready};
use subtle::ConstantTimeEq;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::shadow_tls_hmac::ShadowTlsHmac;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;

// see comment in shadow_tls_server_handler.rs
// TODO: remove duplicated consts
const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65535;

// the max size allowed for a payload ie. `buf` in poll_write.
// 2^14 - 4 (HMAC) = 16380
const MAX_WRITE_PAYLOAD_LEN: usize = 16380;
// 2^14 + 5 (header) = 16385
const WRITE_BUF_LEN: usize = 16389;

const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub struct ShadowTlsStream {
    stream: Box<dyn AsyncStream>,
    read_hmac: ShadowTlsHmac,
    write_hmac: ShadowTlsHmac,

    // the HMAC_ServerRandom used client-side to verify handshake app data frames.
    handshake_hmac: Option<ShadowTlsHmac>,

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
        read_hmac: ShadowTlsHmac,
        write_hmac: ShadowTlsHmac,
        handshake_hmac: Option<ShadowTlsHmac>,
    ) -> std::io::Result<Self> {
        let mut processed_buf = allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice();
        if initial_processed_data.len() > processed_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "initial processed data too large for read buffer",
            ));
        }
        processed_buf[..initial_processed_data.len()].copy_from_slice(initial_processed_data);

        let mut write_buf = allocate_vec(WRITE_BUF_LEN).into_boxed_slice();
        // set partial frame header that never changes
        write_buf[0] = CONTENT_TYPE_APPLICATION_DATA;
        write_buf[1] = 0x03; // TLS_MAJOR
        write_buf[2] = 0x03; // TLS_MINOR

        Ok(Self {
            stream,
            read_hmac,
            write_hmac,
            handshake_hmac,
            is_eof: false,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: initial_processed_data.len(),
            unprocessed_buf: allocate_vec(TLS_FRAME_MAX_LEN).into_boxed_slice(),
            unprocessed_end_offset: 0,
            write_buf,
            write_buf_pos: 0,
            write_buf_end: 0,
        })
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        assert!(self.unprocessed_end_offset == 0);

        if data.len() > self.unprocessed_buf.len() {
            return Err(std::io::Error::other(
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
            "no data to write (available_len = {available_len}, unfilled_len = {unfilled_len})",
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
        // we should only deframe when there is no readily available processed data.
        assert!(self.processed_end_offset == 0);

        if self.unprocessed_end_offset < TLS_HEADER_LEN {
            return Ok(DeframeState::NeedData);
        }

        let header = &self.unprocessed_buf[0..TLS_HEADER_LEN];
        let content_type = header[0];
        if content_type == CONTENT_TYPE_ALERT {
            self.is_eof = true;
            return Ok(DeframeState::ReceivedAlert);
        }

        let frame_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if frame_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame length too short",
            ));
        }

        let total_len = TLS_HEADER_LEN + frame_len;
        if self.unprocessed_end_offset < total_len {
            return Ok(DeframeState::NeedData);
        }

        if content_type != CONTENT_TYPE_APPLICATION_DATA {
            if self.handshake_hmac.is_some() {
                // Allow any other frame type while we haven't completed
                // the handshake, ie. we haven't received non-forwarded app
                // data.
                if total_len < self.unprocessed_end_offset {
                    self.unprocessed_buf
                        .copy_within(total_len..self.unprocessed_end_offset, 0);
                    self.unprocessed_end_offset -= total_len;
                    return Ok(DeframeState::HandshakeFrame);
                } else {
                    self.unprocessed_end_offset = 0;
                    return Ok(DeframeState::NeedData);
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid record type",
            ));
        }

        // frame length minus HMAC
        let payload_len = frame_len - 4;

        if payload_len > self.processed_buf.len() {
            return Err(std::io::Error::other(
                "Payload too large for processed buffer",
            ));
        }

        let frame_body = &self.unprocessed_buf[TLS_HEADER_LEN..total_len];
        let received_digest = &frame_body[0..4];
        let payload = &frame_body[4..];

        if let Some(ref mut handshake_hmac) = self.handshake_hmac {
            handshake_hmac.update(payload);
            let expected_digest = handshake_hmac.digest();
            if bool::from(received_digest.ct_eq(&expected_digest)) {
                if total_len < self.unprocessed_end_offset {
                    self.unprocessed_buf
                        .copy_within(total_len..self.unprocessed_end_offset, 0);
                    self.unprocessed_end_offset -= total_len;
                    return Ok(DeframeState::HandshakeFrame);
                } else {
                    self.unprocessed_end_offset = 0;
                    return Ok(DeframeState::NeedData);
                }
            }
            // this must be the first non-handshake server data frame, or else
            // this is malformed and we error out in the follow hmac check.
            self.handshake_hmac = None;
        }

        self.read_hmac.update(payload);
        let expected_digest = self.read_hmac.digest();
        if !bool::from(received_digest.ct_eq(&expected_digest)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }
        self.read_hmac.update(&expected_digest);

        self.processed_buf[0..payload_len].copy_from_slice(payload);
        self.processed_end_offset = payload_len;

        if total_len < self.unprocessed_end_offset {
            self.unprocessed_buf
                .copy_within(total_len..self.unprocessed_end_offset, 0);
            self.unprocessed_end_offset -= total_len;
        } else {
            self.unprocessed_end_offset = 0;
        }

        Ok(DeframeState::Success)
    }

    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_buf_pos < self.write_buf_end {
            let remaining = &self.write_buf[self.write_buf_pos..self.write_buf_end];
            let n = ready!(Pin::new(&mut self.stream).poll_write(cx, remaining))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Failed to write pending data",
                )));
            }
            self.write_buf_pos += n;
        }

        self.write_buf_pos = 0;
        self.write_buf_end = 0;
        Poll::Ready(Ok(()))
    }
}

enum DeframeState {
    NeedData,
    Success,
    ReceivedAlert,
    HandshakeFrame,
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
            loop {
                match this.try_deframe()? {
                    DeframeState::Success => {
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DeframeState::NeedData => break,
                    DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
                    DeframeState::HandshakeFrame => {}
                }
            }

            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                return Poll::Ready(Err(std::io::Error::other("Unprocessed buffer full")));
            }
        }

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

                    loop {
                        match this.try_deframe()? {
                            DeframeState::Success => {
                                this.read_processed(buf);
                                return Poll::Ready(Ok(()));
                            }
                            DeframeState::NeedData => break,
                            DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
                            DeframeState::HandshakeFrame => {}
                        }
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
        // A record without payload would be sent at once, and readers panic on it.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        ready!(this.poll_drain_write_buf(cx))?;

        let consumed_buf_len = std::cmp::min(buf.len(), MAX_WRITE_PAYLOAD_LEN);
        let consumed_buf = &buf[0..consumed_buf_len];

        let frame_len = consumed_buf_len + 4; // HMAC(4) + payload

        // write_buf[0..2] never changes and is set in the constructor.
        this.write_buf[3..5].copy_from_slice(&(frame_len as u16).to_be_bytes());

        this.write_hmac.update(consumed_buf);
        let digest = this.write_hmac.digest();
        this.write_hmac.update(&digest);

        this.write_buf[5..9].copy_from_slice(&digest);

        this.write_buf[9..9 + consumed_buf_len].copy_from_slice(consumed_buf);

        this.write_buf_end = TLS_HEADER_LEN + frame_len;

        // Sends the frame now rather than on the next write or flush, matching the other
        // transports, so peers waiting for it are not stalled. The frame is already part of
        // the HMAC chain, so the bytes count as written even if sending stalls or fails here;
        // the next write, flush, or shutdown sends the rest or reports the error.
        let _ = this.poll_drain_write_buf(cx);

        Poll::Ready(Ok(consumed_buf_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buf(cx))?;
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
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncStream for ShadowTlsStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn hmac(label: &[u8]) -> ShadowTlsHmac {
        let key =
            aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, b"test");
        let mut hmac = ShadowTlsHmac::new(&key);
        hmac.update(label);
        hmac
    }

    fn client_stream(io: DuplexStream) -> ShadowTlsStream {
        ShadowTlsStream::new(Box::new(io), &[], hmac(b"S"), hmac(b"C"), None).unwrap()
    }

    fn server_stream(io: DuplexStream) -> ShadowTlsStream {
        ShadowTlsStream::new(Box::new(io), &[], hmac(b"C"), hmac(b"S"), None).unwrap()
    }

    fn stream_pair(pipe_capacity: usize) -> (ShadowTlsStream, ShadowTlsStream) {
        let (client_io, server_io) = tokio::io::duplex(pipe_capacity);
        (client_stream(client_io), server_stream(server_io))
    }

    #[tokio::test]
    async fn written_frame_is_sent_without_flush() {
        let (mut client, mut server) = stream_pair(1024);
        client.write_all(b"hello").await.unwrap();

        let mut received = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut received))
            .await
            .expect("frame was not sent")
            .unwrap();
        assert_eq!(&received, b"hello");
    }

    #[tokio::test]
    async fn large_writes_survive_partial_inner_writes() {
        // A pipe smaller than one frame forces partial and pending inner writes.
        let (mut client, mut server) = stream_pair(1000);
        let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let expected = data.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&data).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut received))
            .await
            .expect("transfer stalled")
            .unwrap();
        assert_eq!(received, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn empty_write_sends_no_record() {
        let (client_io, mut peer) = tokio::io::duplex(1024);
        let mut client = client_stream(client_io);
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        client.flush().await.unwrap();

        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut byte)).await;
        assert!(read.is_err(), "empty write produced a record");
    }

    #[tokio::test]
    async fn send_error_after_framing_surfaces_on_flush() {
        let (client_io, peer) = tokio::io::duplex(1024);
        drop(peer);
        let mut client = client_stream(client_io);
        assert_eq!(client.write(b"hello").await.unwrap(), 5);
        assert_eq!(
            client.flush().await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }
}
