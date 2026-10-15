//! H2MUX Client Stream
//!
//! Unified client stream that handles:
//! - Lazy response resolution (matches sing-mux's lateHTTPConn pattern)
//! - StreamRequest prepended to first write
//! - Status response read on first read

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, Bytes, BytesMut};
use h2::client::ResponseFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};

use super::h2mux_client_session::H2MuxClientSession;
use super::h2mux_protocol::{
    MAX_ERROR_RESPONSE_LEN, STATUS_ERROR, STATUS_SUCCESS, StreamRequest, decode_error_length,
};

/// Client stream that wraps h2 streams with sing-mux protocol handling.
///
/// Combines lazy response resolution with protocol framing:
/// - Stream returns immediately after CONNECT request (lazy pattern)
/// - StreamRequest is prepended to first write
/// - Status response is read on first read
pub struct H2MuxClientStream {
    send: h2::SendStream<Bytes>,
    /// Resolved RecvStream (set after first read resolves recv_pending)
    recv: Option<h2::RecvStream>,
    /// Pending receiver for lazy response resolution
    recv_pending: Option<ResponseFuture>,
    /// Buffered received data
    recv_buf: Bytes,
    /// Whether we've sent END_STREAM
    shutdown_sent: bool,
    /// Encoded stream request bytes to prepend on first write (None after written)
    request_bytes: Option<Bytes>,
    /// Pending write data from partial send (combined_buffer, user_data_len, bytes_sent)
    pending_write: Option<(Bytes, usize, usize)>,
    /// Destination for logging
    destination: NetLocation,
    /// Whether we've read the status response
    response_read: bool,
    session: H2MuxClientSession,
}

impl Drop for H2MuxClientStream {
    fn drop(&mut self) {
        self.session.release_stream();
    }
}

impl H2MuxClientStream {
    /// Create a new client stream with lazy response resolution.
    ///
    /// The caller can write immediately; RecvStream is resolved on first read.
    pub fn new(
        send: h2::SendStream<Bytes>,
        response_future: ResponseFuture,
        destination: NetLocation,
        is_tcp: bool,
        session: H2MuxClientSession,
    ) -> io::Result<Self> {
        let request = if is_tcp {
            StreamRequest::tcp(destination.clone())
        } else {
            StreamRequest::udp(destination.clone(), false)
        };
        let request_bytes = Bytes::from(request.encode()?);

        Ok(Self {
            send,
            recv: None,
            recv_pending: Some(response_future),
            recv_buf: Bytes::new(),
            shutdown_sent: false,
            request_bytes: Some(request_bytes),
            pending_write: None,
            destination,
            response_read: false,
            session,
        })
    }

    /// Resolve the pending receiver into a RecvStream.
    fn poll_resolve_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.recv_pending.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(response)) => {
                    self.recv_pending = None;
                    if response.status() != http::StatusCode::OK {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "CONNECT failed with status: {}",
                            response.status()
                        ))));
                    }
                    self.recv = Some(response.into_body());
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    self.recv_pending = None;
                    Poll::Ready(Err(io::Error::other(format!(
                        "CONNECT response error: {e}"
                    ))))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "No receiver available",
            )))
        }
    }

    /// Read and validate the status response from buffered data.
    fn read_status_response(&mut self) -> io::Result<()> {
        if self.recv_buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for status",
            ));
        }

        let status = self.recv_buf[0];

        match status {
            STATUS_SUCCESS => {
                self.recv_buf = self.recv_buf.slice(1..);
                self.response_read = true;
                log::debug!(
                    "H2MuxClientStream: stream to {} opened successfully",
                    self.destination
                );
                Ok(())
            }
            STATUS_ERROR => {
                // Parse varint-length-prefixed error message
                let error_msg = self.read_error_message()?;
                Err(io::Error::other(format!(
                    "Stream to {} rejected: {}",
                    self.destination, error_msg
                )))
            }
            _ => {
                self.recv_buf = self.recv_buf.slice(1..);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid status byte: {}", status),
                ))
            }
        }
    }

    /// Read error message with varint length prefix from recv_buf.
    /// Returns WouldBlock if more data is needed.
    fn read_error_message(&mut self) -> io::Result<String> {
        // Need at least status byte + 1 byte for varint
        if self.recv_buf.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for error message",
            ));
        }

        let (len, prefix_len) = decode_error_length(&self.recv_buf[1..])?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "need more data for error length")
        })?;
        let pos = 1 + prefix_len;

        // Check if we have the full message
        let total_len = pos.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "h2mux error length overflow")
        })?;
        if self.recv_buf.len() < total_len {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "need more data for error message body",
            ));
        }

        // Extract message
        let msg_bytes = &self.recv_buf[pos..total_len];
        let message = String::from_utf8_lossy(msg_bytes).to_string();

        // Consume the bytes
        self.recv_buf = self.recv_buf.slice(total_len..);

        Ok(message)
    }

    /// Poll the h2 stream directly for new data, bypassing recv_buf.
    /// Returns Ok(None) on EOF.
    fn poll_h2_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        let recv = self.recv.as_mut().expect("recv should be resolved");
        match Pin::new(recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let len = data.len();
                let _ = self
                    .recv
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(len);
                Poll::Ready(Ok(Some(data)))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("H2 recv error: {e}"))))
            }
            Poll::Ready(None) => Poll::Ready(Ok(None)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll for data from the h2 RecvStream, returning buffered data first.
    fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return buffered data first
        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        match self.poll_h2_stream(cx) {
            Poll::Ready(Ok(Some(data))) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.recv_buf = data.slice(to_copy..);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Internal poll_write for data after request is written.
    fn poll_send_data(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let current_capacity = self.send.capacity();
        if current_capacity < buf.len() {
            self.send.reserve_capacity(buf.len());
        }

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let to_send = buf.len().min(capacity);
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..to_send]), false)
                    .map_err(|e| io::Error::other(format!("H2 send_data failed: {e}")))?;
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(format!(
                "H2 poll_capacity error: {e}"
            )))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for H2MuxClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, resolve the recv stream if not yet done
        if self.recv.is_none() {
            match self.poll_resolve_recv(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Read and validate status response on first read
        if !self.response_read {
            // Try from buffered data first
            if !self.recv_buf.is_empty() {
                match self.read_status_response() {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            // Poll h2 stream directly for NEW data in a loop until we have enough
            // or get Pending. We use poll_h2_stream (not poll_recv_data) because
            // poll_recv_data returns recv_buf contents first, which would cause an
            // infinite loop when recv_buf has partial status data.
            while !self.response_read {
                match self.poll_h2_stream(cx) {
                    Poll::Ready(Ok(Some(data))) => {
                        // Skip empty data frames to avoid infinite loop
                        if data.is_empty() {
                            continue;
                        }

                        let total_len =
                            self.recv_buf.len().checked_add(data.len()).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "h2mux response length overflow",
                                )
                            })?;
                        let status = self.recv_buf.first().or_else(|| data.first());
                        if status == Some(&STATUS_ERROR) && total_len > MAX_ERROR_RESPONSE_LEN {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "h2mux error response exceeds limit",
                            )));
                        }
                        if self.recv_buf.is_empty() {
                            self.recv_buf = data;
                        } else {
                            let mut new_buf = BytesMut::with_capacity(total_len);
                            new_buf.put_slice(&self.recv_buf);
                            new_buf.put_slice(&data);
                            self.recv_buf = new_buf.freeze();
                        }

                        match self.read_status_response() {
                            Ok(()) => break,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    Poll::Ready(Ok(None)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading stream response",
                        )));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        self.poll_recv_data(cx, buf)
    }
}

impl AsyncWrite for H2MuxClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First, flush any pending partial write
        if let Some((pending_data, user_len, sent)) = self.pending_write.take() {
            let remaining = &pending_data[sent..];
            let current_capacity = self.send.capacity();
            if current_capacity < remaining.len() {
                self.send.reserve_capacity(remaining.len());
            }

            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => {
                    let to_send = remaining.len().min(capacity);
                    self.send
                        .send_data(pending_data.slice(sent..sent + to_send), false)
                        .map_err(|e| io::Error::other(format!("H2 send_data failed: {e}")))?;

                    let new_sent = sent + to_send;
                    if new_sent < pending_data.len() {
                        // Still more to send
                        self.pending_write = Some((pending_data, user_len, new_sent));
                        return Poll::Pending;
                    }
                    // Pending write complete, return original user data length
                    return Poll::Ready(Ok(user_len));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "H2 poll_capacity error: {e}"
                    ))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream closed",
                    )));
                }
                Poll::Pending => {
                    self.pending_write = Some((pending_data, user_len, sent));
                    return Poll::Pending;
                }
            }
        }

        // Prepend StreamRequest on first write
        if let Some(request_bytes) = self.request_bytes.take() {
            let request_len = request_bytes.len();
            let mut combined = BytesMut::with_capacity(request_len + buf.len());
            combined.put_slice(&request_bytes);
            combined.put_slice(buf);
            let combined = combined.freeze();

            let current_capacity = self.send.capacity();
            if current_capacity < combined.len() {
                self.send.reserve_capacity(combined.len());
            }

            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => {
                    let to_send = combined.len().min(capacity);
                    self.send
                        .send_data(combined.slice(..to_send), false)
                        .map_err(|e| io::Error::other(format!("H2 send_data failed: {e}")))?;

                    if to_send < combined.len() {
                        // Partial write - track remaining data
                        let user_written = to_send.saturating_sub(request_len).min(buf.len());
                        self.pending_write = Some((combined, user_written, to_send));
                        Poll::Pending
                    } else {
                        // Full write complete
                        Poll::Ready(Ok(buf.len()))
                    }
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(format!(
                    "H2 poll_capacity error: {e}"
                )))),
                Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "H2 stream closed",
                ))),
                Poll::Pending => {
                    // No data sent yet - restore original request bytes only
                    self.request_bytes = Some(request_bytes);
                    Poll::Pending
                }
            }
        } else {
            self.poll_send_data(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            match self.send.send_data(Bytes::new(), true) {
                Ok(()) => self.shutdown_sent = true,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "H2 send END_STREAM failed: {e}"
                    ))));
                }
            }
        }

        match self.send.poll_reset(cx) {
            Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncPing for H2MuxClientStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MuxClientStream {}

impl AsyncStream for H2MuxClientStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2mux::H2MuxOptions;
    use crate::h2mux::h2mux_protocol::{SessionRequest, StreamResponse};
    use tokio::io::AsyncReadExt;

    async fn read_response(frames: Vec<Bytes>) -> io::Result<Vec<u8>> {
        let (client, mut peer) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            SessionRequest::decode(&mut peer).await.unwrap();
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (_request, mut response) = connection.accept().await.unwrap().unwrap();
            let mut send = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            for frame in frames {
                send.send_data(frame, false).unwrap();
            }
            send.send_data(Bytes::new(), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut session = H2MuxClientSession::new(client, &H2MuxOptions::default())
                .await
                .unwrap();
            let destination = NetLocation::from_str("example.com:443", None).unwrap();
            let mut stream = session.open_tcp(&destination).await.unwrap();
            let mut result = Vec::new();
            stream.read_to_end(&mut result).await?;
            Ok(result)
        })
        .await;
        peer.abort();
        let _ = peer.await;
        result.expect("response parsing stalled")
    }

    #[tokio::test]
    async fn peer_error_lengths_do_not_panic_or_wait_for_oversized_bodies() {
        for payload in [
            vec![STATUS_ERROR, 0x81, 0x20],
            vec![STATUS_ERROR, 0x80, 0x80, 0],
            vec![STATUS_ERROR, 0xff, 0xff, 0xff, 0xff, 0x0f],
            vec![
                STATUS_ERROR,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                1,
            ],
        ] {
            for frames in [
                vec![Bytes::from(payload.clone())],
                payload
                    .iter()
                    .map(|b| Bytes::copy_from_slice(&[*b]))
                    .collect(),
            ] {
                assert_eq!(
                    read_response(frames).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
        let mut oversized = vec![STATUS_ERROR, 0x80, 0x20];
        oversized.extend(vec![b'x'; MAX_ERROR_RESPONSE_LEN]);
        assert_eq!(
            read_response(vec![oversized.into()])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn valid_and_truncated_responses_work_across_frames() {
        for len in [0, 127, 128, 4096] {
            let encoded = StreamResponse::error("x".repeat(len)).encode().freeze();
            let frames = encoded.chunks(1).map(Bytes::copy_from_slice).collect();
            assert_eq!(
                read_response(frames).await.unwrap_err().kind(),
                io::ErrorKind::Other
            );
        }
        for payload in [
            vec![STATUS_ERROR],
            vec![STATUS_ERROR, 0x80],
            vec![STATUS_ERROR, 3, b'x'],
        ] {
            assert_eq!(
                read_response(vec![payload.into()])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let mut success = vec![STATUS_SUCCESS];
        success.extend(vec![b'x'; 8192]);
        assert_eq!(
            read_response(vec![success.into()]).await.unwrap(),
            vec![b'x'; 8192]
        );
    }
}
