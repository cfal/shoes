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
use tokio::sync::oneshot;

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};

use super::h2mux_protocol::{STATUS_ERROR, STATUS_SUCCESS, StreamRequest};

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
    recv_pending: Option<oneshot::Receiver<io::Result<h2::RecvStream>>>,
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
}

impl H2MuxClientStream {
    /// Create a new client stream with lazy response resolution.
    ///
    /// Spawns a task to await the HTTP response asynchronously.
    /// The caller can write immediately; RecvStream is resolved on first read.
    pub fn new(
        send: h2::SendStream<Bytes>,
        response_future: ResponseFuture,
        destination: NetLocation,
        is_tcp: bool,
    ) -> io::Result<Self> {
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match response_future.await {
                Ok(response) => {
                    if response.status() == http::StatusCode::OK {
                        let _ = tx.send(Ok(response.into_body()));
                    } else {
                        let _ = tx.send(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("CONNECT failed with status: {}", response.status()),
                        )));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("CONNECT response error: {}", e),
                    )));
                }
            }
        });

        let request = if is_tcp {
            StreamRequest::tcp(destination.clone())
        } else {
            StreamRequest::udp(destination.clone(), false)
        };
        let request_bytes = Bytes::from(request.encode()?);

        Ok(Self {
            send,
            recv: None,
            recv_pending: Some(rx),
            recv_buf: Bytes::new(),
            shutdown_sent: false,
            request_bytes: Some(request_bytes),
            pending_write: None,
            destination,
            response_read: false,
        })
    }

    /// Resolve the pending receiver into a RecvStream.
    fn poll_resolve_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.recv_pending.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(Ok(recv))) => {
                    self.recv = Some(recv);
                    self.recv_pending = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.recv_pending = None;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.recv_pending = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Response channel closed",
                    )))
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
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Stream to {} rejected: {}", self.destination, error_msg),
                ))
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

        // Parse varint starting after status byte
        let mut pos = 1;
        let mut len: usize = 0;
        let mut shift = 0;

        loop {
            if pos >= self.recv_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "need more data for varint",
                ));
            }

            let byte = self.recv_buf[pos];
            pos += 1;
            len |= ((byte & 0x7F) as usize) << shift;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "varint too large",
                ));
            }
        }

        // Check if we have the full message
        let total_len = pos + len;
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
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
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
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
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

                        // Append new data to recv_buf
                        let mut new_buf =
                            BytesMut::with_capacity(self.recv_buf.len() + data.len());
                        new_buf.put_slice(&self.recv_buf);
                        new_buf.put_slice(&data);
                        self.recv_buf = new_buf.freeze();

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
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
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
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
                Poll::Ready(Some(Err(e))) => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
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
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
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
