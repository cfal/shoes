//! H2MultiStream - H2 stream for multiplexed connections

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// H2 stream for multiplexed connections.
/// Client streams retain the connection driver independently of the session slot.
pub struct H2MultiStream {
    send: Arc<parking_lot::Mutex<h2::SendStream<Bytes>>>,
    recv: h2::RecvStream,
    /// Buffered received data
    recv_buf: Bytes,
    /// Whether we've sent END_STREAM
    shutdown_sent: bool,
    reservation: Option<super::client::StreamReservation>,
}

impl H2MultiStream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send: Arc::new(parking_lot::Mutex::new(send)),
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
            reservation: None,
        }
    }

    pub fn set_reservation(&mut self, reservation: super::client::StreamReservation) {
        self.reservation = Some(reservation);
    }

    // A relay blocked on its upstream must still observe a peer reset.
    pub fn reset(&self) -> impl Future<Output = Result<h2::Reason, h2::Error>> + use<> {
        let send = self.send.clone();
        std::future::poll_fn(move |cx| send.lock().poll_reset(cx))
    }
}

impl AsyncRead for H2MultiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Empty DATA is not EOF. Bound work per poll even for a padding-only peer.
        for _ in 0..32 {
            if !self.recv_buf.is_empty() {
                let count = self.recv_buf.len().min(buf.remaining());
                buf.put_slice(&self.recv_buf.split_to(count));
                self.recv
                    .flow_control()
                    .release_capacity(count)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.recv_buf = data,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for H2MultiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let wanted = buf.len().min(16 * 1024);
        let mut send = self.send.lock();
        send.reserve_capacity(wanted);
        loop {
            let capacity = send.capacity();
            if capacity != 0 {
                let count = wanted.min(capacity);
                send.send_data(Bytes::copy_from_slice(&buf[..count]), false)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(count));
            }
            match std::task::ready!(send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 has no per-stream flush; the connection driver handles transmission
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            let result = self.send.lock().send_data(Bytes::new(), true);
            match result {
                Ok(()) => self.shutdown_sent = true,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "H2 send END_STREAM failed: {e}"
                    ))));
                }
            }
        }

        // Don't wait for peer ACK; the connection driver transmits END_STREAM reliably
        Poll::Ready(Ok(()))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (H2MultiStream, H2MultiStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(8192);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tx.send(H2MultiStream::new(send, request.into_body()))
                .ok()
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut session = super::super::client::H2ClientSession::new(Box::new(client))
            .await
            .unwrap();
        let (_, client) = session
            .open(
                http::Request::builder()
                    .method("CONNECT")
                    .uri("example.com:443")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        (client, rx.await.unwrap(), driver)
    }

    #[tokio::test]
    async fn empty_data_small_reads_and_half_close() {
        let (mut client, mut server, driver) = pair().await;
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        assert_eq!(client.read(&mut []).await.unwrap(), 0);
        for _ in 0..64 {
            server.send.lock().send_data(Bytes::new(), false).unwrap();
        }
        server
            .send
            .lock()
            .send_data(Bytes::from_static(b"hello"), true)
            .unwrap();
        let mut first = [0; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_exact(&mut first),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&first, b"h");
        assert_eq!(client.recv_buf.len(), 4);
        assert_eq!(client.recv.flow_control().used_capacity(), 4);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"ello");
        assert_eq!(client.recv.flow_control().used_capacity(), 0);
        client.write_all(b"tail").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            client.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut tail = Vec::new();
        server.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail");
        driver.abort();
        let _ = driver.await;
    }

    #[tokio::test]
    async fn flow_control_blocks_until_consumption_and_writes_are_bounded() {
        let (mut client, mut server, driver) = pair().await;
        let data = vec![42; 1024 * 1024];
        let count = client.write(&data).await.unwrap();
        assert!(count > 0 && count <= 16 * 1024);
        let write = async {
            client.write_all(&data[count..]).await.unwrap();
            client.shutdown().await.unwrap();
        };
        tokio::pin!(write);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut write)
                .await
                .is_err()
        );
        let read = async {
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, data);
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(&mut write, read);
        })
        .await
        .unwrap();
        driver.abort();
        let _ = driver.await;
    }

    #[tokio::test]
    async fn abandoned_stream_resets_peer() {
        let (client, server, driver) = pair().await;
        drop(client);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server.reset())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, h2::Reason::CANCEL);
        driver.abort();
        let _ = driver.await;
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
