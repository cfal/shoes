//! H2MultiStream - H2 stream for multiplexed connections

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// H2 stream for multiplexed connections.
/// The connection driver is managed by NaiveServerSession and stays alive
/// as long as any stream is active.
pub struct H2MultiStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Buffered received data
    recv_buf: Bytes,
    /// Whether we've sent END_STREAM
    shutdown_sent: bool,
    session_owner: Option<super::naive_client_session::NaiveClientSession>,
}

impl H2MultiStream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
            session_owner: None,
        }
    }

    pub fn set_session_owner(&mut self, session: super::naive_client_session::NaiveClientSession) {
        self.session_owner = Some(session);
    }
}

impl AsyncRead for H2MultiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Release capacity so sender can continue
                let _ = self.recv.flow_control().release_capacity(data.len());

                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.recv_buf = data.slice(to_copy..);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("H2 recv error: {e}"))))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2MultiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        self.send.reserve_capacity(buf.len());
        loop {
            // poll_capacity reports increases, not readiness of already assigned credit.
            let capacity = self.send.capacity();
            if capacity > 0 {
                let to_send = buf.len().min(capacity);
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..to_send]), false)
                    .map_err(|e| io::Error::other(format!("H2 send_data failed: {e}")))?;
                return Poll::Ready(Ok(to_send));
            }
            match std::task::ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "H2 poll_capacity error: {e}"
                    ))));
                }
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream closed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 has no per-stream flush; the connection driver handles transmission
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

        // Don't wait for peer ACK; the connection driver transmits END_STREAM reliably
        match self.send.poll_reset(cx) {
            Poll::Ready(_) | Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncPing for H2MultiStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MultiStream {}

impl AsyncStream for H2MultiStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_writes_do_not_strand_credit_on_multiplexed_streams() {
        use tokio::io::AsyncWriteExt;
        use tokio::sync::{mpsc, oneshot};
        use tokio::task::JoinSet;
        use tokio::time::{Duration, timeout};

        timeout(Duration::from_secs(5), async {
            let (client, server) = tokio::io::duplex(8192);
            let (accepted_tx, mut accepted_rx) = mpsc::channel(3);
            let (release_tx, release_rx) = oneshot::channel();
            let (updated_tx, updated_rx) = oneshot::channel();
            let mut drivers = JoinSet::new();
            drivers.spawn(async move {
                let mut connection = h2::server::Builder::new()
                    .initial_window_size(0)
                    .handshake::<_, Bytes>(server)
                    .await
                    .unwrap();
                for _ in 0..3 {
                    let (request, mut response) = connection.accept().await.unwrap().unwrap();
                    let send = response
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    accepted_tx.send((send, request.into_body())).await.unwrap();
                }
                tokio::select! {
                    result = release_rx => result.unwrap(),
                    _ = connection.accept() => panic!("unexpected stream"),
                }
                connection.set_initial_window_size(64).unwrap();
                updated_tx.send(()).unwrap();
                while connection.accept().await.is_some() {}
            });
            let (mut request, mut connection) = h2::client::handshake(client).await.unwrap();
            let mut ping = connection.ping_pong().unwrap();
            drivers.spawn(async move { connection.await.unwrap() });
            let mut streams = Vec::new();
            let mut peers = Vec::new();
            for _ in 0..3 {
                request = request.ready().await.unwrap();
                let (response, send) = request
                    .send_request(
                        http::Request::builder()
                            .method("CONNECT")
                            .uri("example.com:443")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                let recv = response.await.unwrap().into_body();
                peers.push(accepted_rx.recv().await.unwrap());
                let mut stream = H2MultiStream::new(send, recv);
                std::future::poll_fn(|cx| {
                    assert!(Pin::new(&mut stream).poll_write(cx, &[42; 64]).is_pending());
                    Poll::Ready(())
                })
                .await;
                streams.push(stream);
            }

            release_tx.send(()).unwrap();
            updated_rx.await.unwrap();
            // The PING reply fences the server's window update before smaller retries.
            ping.ping(h2::Ping::opaque()).await.unwrap();
            for stream in &mut streams {
                assert_eq!(stream.send.capacity(), 64);
                stream.write_all(b"a").await.unwrap();
                assert_eq!(stream.send.capacity(), 0, "surplus credit was not returned");
                timeout(Duration::from_secs(1), stream.write_all(b"b"))
                    .await
                    .expect("write stalled despite unused capacity")
                    .unwrap();
                assert_eq!(stream.write(&[]).await.unwrap(), 0);
                stream.shutdown().await.unwrap();
                assert_eq!(
                    stream.write(b"after shutdown").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
            }
            for (_send, mut recv) in peers {
                let mut received = Vec::new();
                while let Some(data) = recv.data().await {
                    let data = data.unwrap();
                    received.extend_from_slice(&data);
                    recv.flow_control().release_capacity(data.len()).unwrap();
                }
                assert_eq!(received, b"ab");
            }
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn test_h2_multi_stream_is_async_stream() {
        fn assert_async_stream<T: AsyncStream>() {}
        assert_async_stream::<H2MultiStream>();
    }

    #[test]
    fn test_h2_multi_stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<H2MultiStream>();
    }

    #[test]
    fn test_h2_multi_stream_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<H2MultiStream>();
        assert_sync::<H2MultiStream>();
    }
}
