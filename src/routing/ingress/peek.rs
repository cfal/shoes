use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::poll_fn;
use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

pub(crate) struct PeekMessageStream<S> {
    inner: S,
    packet: Option<Box<[u8]>>,
}

impl<S: AsyncMessageStream> PeekMessageStream<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            packet: None,
        }
    }

    pub(crate) async fn peek(&mut self) -> io::Result<Option<crate::rules::Protocol>> {
        let mut packet = crate::util::allocate_vec(65535);
        let mut buffer = ReadBuf::new(&mut packet);
        let read = poll_fn(|cx| Pin::new(&mut self.inner).poll_read_message(cx, &mut buffer));
        match tokio::time::timeout(crate::sniff::SNIFF_TIMEOUT, read).await {
            Err(_) => Ok(None),
            Ok(result) => {
                result?;
                let len = buffer.filled().len();
                if len == 0 && self.inner.read_message_eof_on_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "UDP stream closed before first datagram",
                    ));
                }
                packet.truncate(len);
                let protocol = crate::sniff::udp::classify(&packet);
                self.packet = Some(packet.into_boxed_slice());
                Ok(protocol)
            }
        }
    }
}

impl<S: AsyncMessageStream> AsyncReadMessage for PeekMessageStream<S> {
    fn read_message_eof_on_empty(&self) -> bool {
        self.inner.read_message_eof_on_empty()
    }

    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(packet) = &this.packet {
            if packet.len() > buf.remaining() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for captured UDP datagram",
                )));
            }
            buf.put_slice(packet);
            this.packet = None;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.inner).poll_read_message(cx, buf)
        }
    }
}

impl<S: AsyncMessageStream> AsyncWriteMessage for PeekMessageStream<S> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_write_message(cx, buf)
    }
}

impl<S: AsyncMessageStream> AsyncFlushMessage for PeekMessageStream<S> {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}

impl<S: AsyncMessageStream> AsyncShutdownMessage for PeekMessageStream<S> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}

impl<S: AsyncMessageStream> AsyncPing for PeekMessageStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncMessageStream> AsyncMessageStream for PeekMessageStream<S> {
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Protocol;
    use crate::vless::VlessMessageStream;
    use tokio::io::AsyncWriteExt;

    async fn read<S: AsyncMessageStream>(stream: &mut S) -> Vec<u8> {
        let mut bytes = vec![0; 65535];
        let mut buffer = ReadBuf::new(&mut bytes);
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut buffer))
            .await
            .unwrap();
        let len = buffer.filled().len();
        bytes.truncate(len);
        bytes
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_preserves_partial_framing_and_coalesced_packets() {
        let packet = crate::sniff::udp::tests::stun_packet();
        let mut wire = (packet.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&packet);
        wire.extend_from_slice(&[0, 3, 1, 2, 3]);
        for split in [0, 1, 2, 5, 21] {
            let (mut peer, server) = tokio::io::duplex(1024);
            let mut stream = PeekMessageStream::new(VlessMessageStream::new(server));
            peer.write_all(&wire[..split]).await.unwrap();
            let started = tokio::time::Instant::now();
            assert_eq!(stream.peek().await.unwrap(), None);
            assert_eq!(started.elapsed(), std::time::Duration::from_millis(300));
            peer.write_all(&wire[split..]).await.unwrap();
            assert_eq!(read(&mut stream).await, packet);
            assert_eq!(read(&mut stream).await, [1, 2, 3]);
        }
    }

    #[tokio::test]
    async fn capture_replays_exactly_once_and_small_buffer_can_retry() {
        for (packet, protocol) in [
            (
                crate::sniff::udp::tests::stun_packet(),
                Some(Protocol::Stun),
            ),
            (
                crate::sniff::udp::tests::dtls_packet(),
                Some(Protocol::Dtls),
            ),
            (b"unknown".to_vec(), None),
            (vec![42; 65535], None),
        ] {
            let (mut peer, server) = tokio::io::duplex(131072);
            let mut stream = PeekMessageStream::new(VlessMessageStream::new(server));
            peer.write_all(&(packet.len() as u16).to_be_bytes())
                .await
                .unwrap();
            peer.write_all(&packet).await.unwrap();
            peer.write_all(&[0, 1, 42]).await.unwrap();
            assert_eq!(stream.peek().await.unwrap(), protocol);
            let mut tiny = [0; 1];
            assert!(
                poll_fn(
                    |cx| Pin::new(&mut stream).poll_read_message(cx, &mut ReadBuf::new(&mut tiny))
                )
                .await
                .is_err()
            );
            assert_eq!(read(&mut stream).await, packet);
            assert_eq!(read(&mut stream).await, [42]);
        }
    }

    #[tokio::test]
    async fn empty_datagram_is_preserved_but_framed_eof_is_an_error() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&[], server.local_addr().unwrap())
            .await
            .unwrap();
        let mut stream = PeekMessageStream::new(server);
        assert_eq!(stream.peek().await.unwrap(), None);
        assert!(!stream.read_message_eof_on_empty());
        assert!(read(&mut stream).await.is_empty());
        for prefix in [vec![], vec![0], vec![0, 5, 1]] {
            let (mut peer, server) = tokio::io::duplex(1024);
            peer.write_all(&prefix).await.unwrap();
            drop(peer);
            let mut stream = PeekMessageStream::new(VlessMessageStream::new(server));
            assert!(stream.read_message_eof_on_empty());
            assert_eq!(
                stream.peek().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}
