//! H2MUX Server Stream
//!
//! Wraps H2MuxStream with sing-mux server protocol handling:
//! - Status response is prepended to first write (like sing-mux serverConn)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::write_all;

use super::h2mux_protocol::{STATUS_SUCCESS, StreamResponse};
use super::h2mux_stream::H2MuxStream;

/// Server stream wrapper that prepends status response to first write.
///
/// This matches sing-mux's serverConn behavior where the status byte
/// is sent with the first data write rather than immediately.
pub struct H2MuxServerStream {
    inner: H2MuxStream,
    /// Whether we've written the status response
    response_written: bool,
}

impl H2MuxServerStream {
    /// Create a new server stream wrapper.
    pub fn new(inner: H2MuxStream) -> Self {
        Self {
            inner,
            response_written: false,
        }
    }

    /// Get reference to inner stream.
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut H2MuxStream {
        &mut self.inner
    }

    /// Send an error response to the client before closing.
    ///
    /// This should be called when rejecting a stream (e.g., UDP disabled).
    /// After calling this, the stream should be shut down.
    /// Returns error if response was already written.
    pub async fn write_error_response(&mut self, message: &str) -> io::Result<()> {
        if self.response_written {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Response already written",
            ));
        }

        let response = StreamResponse::error(message);
        let encoded = response.encode();
        write_all(&mut self.inner, &encoded).await?;
        self.response_written = true;
        Ok(())
    }
}

impl AsyncRead for H2MuxServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2MuxServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First write prepends the status response
        if !self.response_written {
            // Create combined buffer: status + data
            let mut combined = BytesMut::with_capacity(1 + buf.len());
            combined.put_u8(STATUS_SUCCESS);
            combined.put_slice(buf);

            match Pin::new(&mut self.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write h2mux response status",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.response_written = true;
                    if written > 1 || buf.is_empty() {
                        return Poll::Ready(Ok(written - 1));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Status-only progress must wait for payload credit, not report a zero-length write.
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for H2MuxServerStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MuxServerStream {}

impl AsyncStream for H2MuxServerStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::oneshot;
    use tokio::task::JoinSet;
    use tokio::time::{Duration, timeout};

    async fn stream_pair(
        receive_window: u32,
        drivers: &mut JoinSet<()>,
    ) -> (H2MuxServerStream, h2::RecvStream, h2::SendStream<Bytes>) {
        let (client, server) = tokio::io::duplex(65536);
        let (mut sender, connection) = h2::client::Builder::new()
            .initial_window_size(receive_window)
            .handshake(client)
            .await
            .unwrap();
        drivers.spawn(async move {
            connection.await.unwrap();
        });
        let (stream_tx, stream_rx) = oneshot::channel();
        drivers.spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            let send = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            let stream = H2MuxServerStream::new(H2MuxStream::new(send, request.into_body()));
            assert!(stream_tx.send(stream).is_ok());
            assert!(connection.accept().await.is_none());
        });
        let (response, request) = sender
            .send_request(
                http::Request::builder()
                    .uri("https://localhost/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        (
            stream_rx.await.unwrap(),
            response.await.unwrap().into_body(),
            request,
        )
    }

    async fn read_response_body(response: &mut h2::RecvStream) -> Vec<u8> {
        let mut body = Vec::new();
        while let Some(chunk) = response.data().await {
            let chunk = chunk.unwrap();
            response
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            body.extend_from_slice(&chunk);
        }
        body
    }

    #[tokio::test]
    async fn status_only_write_waits_for_payload_credit() {
        timeout(Duration::from_secs(5), async {
            let mut drivers = JoinSet::new();
            let (mut stream, mut response, _request) = stream_pair(1, &mut drivers).await;
            let payload = b"first response";
            assert!(futures::poll!(std::pin::pin!(stream.write(payload))).is_pending());
            let status = response.data().await.unwrap().unwrap();
            assert_eq!(&status[..], &[STATUS_SUCCESS]);
            assert!(stream.response_written);
            assert!(futures::poll!(std::pin::pin!(stream.write(payload))).is_pending());

            let send = async {
                stream.write_all(payload).await.unwrap();
                stream.write_all(b"second response").await.unwrap();
                stream.shutdown().await.unwrap();
            };
            let receive = async {
                response.flow_control().release_capacity(1).unwrap();
                let body = read_response_body(&mut response).await;
                assert_eq!(body, b"first responsesecond response");
            };
            tokio::join!(send, receive);
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reset_while_waiting_for_response_credit_is_an_error() {
        timeout(Duration::from_secs(5), async {
            let mut drivers = JoinSet::new();
            let (mut stream, mut response, mut request) = stream_pair(1, &mut drivers).await;
            assert!(futures::poll!(std::pin::pin!(stream.write(b"payload"))).is_pending());
            assert_eq!(
                &response.data().await.unwrap().unwrap()[..],
                &[STATUS_SUCCESS]
            );
            request.send_reset(h2::Reason::CANCEL);
            assert!(stream.write_all(b"payload").await.is_err());
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn zero_credit_does_not_mark_response_written() {
        timeout(Duration::from_secs(5), async {
            let mut drivers = JoinSet::new();
            let (mut stream, _response, mut request) = stream_pair(0, &mut drivers).await;
            assert!(futures::poll!(std::pin::pin!(stream.write(b"payload"))).is_pending());
            assert!(!stream.response_written);
            request.send_reset(h2::Reason::CANCEL);
            assert!(stream.write_all(b"payload").await.is_err());
            assert!(!stream.response_written);
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn empty_first_write_sends_only_status() {
        timeout(Duration::from_secs(5), async {
            let mut drivers = JoinSet::new();
            let (mut stream, mut response, _request) = stream_pair(1, &mut drivers).await;
            assert_eq!(stream.write(&[]).await.unwrap(), 0);
            assert!(stream.response_written);
            stream.shutdown().await.unwrap();
            assert_eq!(
                &response.data().await.unwrap().unwrap()[..],
                &[STATUS_SUCCESS]
            );
            while let Some(chunk) = response.data().await {
                assert!(chunk.unwrap().is_empty());
            }
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn first_response_preserves_payload_with_partial_and_full_credit() {
        timeout(Duration::from_secs(5), async {
            for window in [2, 65535] {
                let mut drivers = JoinSet::new();
                let (mut stream, mut response, _request) = stream_pair(window, &mut drivers).await;
                let send = async {
                    stream.write_all(b"first").await.unwrap();
                    stream.write_all(b"second").await.unwrap();
                    stream.shutdown().await.unwrap();
                };
                let receive = async {
                    let body = read_response_body(&mut response).await;
                    assert_eq!(body, b"\0firstsecond");
                };
                tokio::join!(send, receive);
                drivers.shutdown().await;
            }
        })
        .await
        .unwrap();
    }
}
