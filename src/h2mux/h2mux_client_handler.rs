//! H2MUX Client Handler
//!
//! Wraps an inner TcpClientHandler to multiplex multiple streams over h2mux.
//! Each supplied transport belongs to its returned stream; idle sessions are not retained.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

use super::h2mux_client_session::H2MuxClientSession;
use super::{H2MuxOptions, MUX_DESTINATION_HOST, MUX_DESTINATION_PORT};

/// H2MUX client handler that multiplexes streams over HTTP/2.
///
/// This handler wraps an inner protocol handler (e.g., Shadowsocks, VLESS)
/// and establishes h2mux on the transport supplied by the proxy chain.
#[derive(Debug)]
pub struct H2MuxClientHandler {
    /// Inner protocol handler used to establish connections to the proxy server
    inner: Arc<dyn TcpClientHandler>,
    /// H2MUX configuration options
    options: H2MuxOptions,
}

impl H2MuxClientHandler {
    /// Create a new H2MUX client handler wrapping the given inner handler.
    pub fn new(inner: Arc<dyn TcpClientHandler>, options: H2MuxOptions) -> Self {
        Self { inner, options }
    }

    async fn create_session(&self, stream: Box<dyn AsyncStream>) -> io::Result<H2MuxClientSession> {
        let magic_location = ResolvedLocation::new(NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.to_string()),
            MUX_DESTINATION_PORT,
        ));
        let inner_result = self
            .inner
            .setup_client_tcp_stream(stream, magic_location)
            .await?;

        debug!("H2MuxClientHandler: creating session from stream");

        // Session handles padding internally: sends request header on raw stream,
        // then applies padding layer before HTTP/2 handshake.
        H2MuxClientSession::new(inner_result.client_stream, &self.options).await
    }
}

#[async_trait]
impl TcpClientHandler for H2MuxClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let mut session = self.create_session(client_stream).await?;
        let location = remote_location.into_location();
        let stream = session.open_tcp(&location).await?;

        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let mut session = self.create_session(client_stream).await?;
        let location = target.into_location();
        let stream = session.open_udp(&location, false).await?;

        Ok(Box::new(H2MuxUdpMessageStream::new(stream)))
    }
}

/// Wrapper that adapts an H2MuxStream for UDP to AsyncMessageStream.
///
/// H2MUX UDP uses length-prefixed packets: [length:2][data]
struct H2MuxUdpMessageStream {
    stream: Box<dyn AsyncStream>,
    // Read state machine
    read_state: ReadState,
    read_header: [u8; 2],
    read_header_pos: usize,
    read_data_remaining: usize,
    read_buffer: Vec<u8>,
    // Write buffer for assembling length-prefixed messages
    write_buffer: BytesMut,
    write_pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Header,
    Data,
}

impl H2MuxUdpMessageStream {
    fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            read_state: ReadState::Header,
            read_header: [0u8; 2],
            read_header_pos: 0,
            read_data_remaining: 0,
            read_buffer: Vec::new(),
            write_buffer: BytesMut::with_capacity(65537),
            write_pos: 0,
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buffer.len() {
            let n = std::task::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.write_buffer[self.write_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_buffer.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for H2MuxUdpMessageStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2MuxUdpMessageStream").finish()
    }
}

impl Unpin for H2MuxUdpMessageStream {}

impl AsyncReadMessage for H2MuxUdpMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            match this.read_state {
                ReadState::Header => {
                    while this.read_header_pos < 2 {
                        let mut temp_buf =
                            ReadBuf::new(&mut this.read_header[this.read_header_pos..]);
                        std::task::ready!(Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf))?;
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            if this.read_header_pos == 0 {
                                // EOF at message boundary - return empty
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading message header",
                            )));
                        }
                        this.read_header_pos += n;
                    }

                    let len = u16::from_be_bytes(this.read_header) as usize;
                    this.read_header_pos = 0;
                    this.read_data_remaining = len;
                    this.read_buffer.resize(len, 0);
                    this.read_state = ReadState::Data;

                    if len == 0 {
                        // Empty message
                        this.read_state = ReadState::Header;
                        return Poll::Ready(Ok(()));
                    }

                    if len > buf.remaining() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("UDP packet too large: {} > {}", len, buf.remaining()),
                        )));
                    }
                }
                ReadState::Data => {
                    let offset = this.read_buffer.len() - this.read_data_remaining;
                    let mut temp_buf = ReadBuf::new(&mut this.read_buffer[offset..]);
                    std::task::ready!(Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf))?;
                    let n = temp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading message data",
                        )));
                    }
                    this.read_data_remaining -= n;

                    if this.read_data_remaining == 0 {
                        this.read_state = ReadState::Header;
                        if this.read_buffer.len() > buf.remaining() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "UDP receive buffer too small",
                            )));
                        }
                        buf.put_slice(&this.read_buffer);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl AsyncWriteMessage for H2MuxUdpMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        use bytes::BufMut;

        if buf.len() > 65535 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP packet too large",
            )));
        }
        std::task::ready!(self.poll_drain_write(cx))?;
        self.write_buffer.put_u16(buf.len() as u16);
        self.write_buffer.put_slice(buf);
        // Accept exactly once; subsequent writes and flush drain this bounded buffer.
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for H2MuxUdpMessageStream {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_drain_write(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for H2MuxUdpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for H2MuxUdpMessageStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for H2MuxUdpMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_message_read_preserves_payload_across_polls() {
        let packet = b"\0\x03abc";
        for split in 1..packet.len() {
            let (stream, mut peer) = tokio::io::duplex(1024);
            let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
            peer.write_all(&packet[..split]).await.unwrap();
            let waker = futures::task::noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut storage = [0; 32];
            let mut first = ReadBuf::new(&mut storage);
            assert!(
                Pin::new(&mut stream)
                    .poll_read_message(&mut cx, &mut first)
                    .is_pending()
            );
            assert!(first.filled().is_empty());
            peer.write_all(&packet[split..]).await.unwrap();
            let mut next = ReadBuf::new(&mut storage);
            assert!(matches!(
                Pin::new(&mut stream).poll_read_message(&mut cx, &mut next),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(next.filled(), b"abc");
        }
    }

    #[tokio::test]
    async fn message_read_distinguishes_eof_from_truncated_frames() {
        for (packet, expected_error) in [
            (b"".as_slice(), None),
            (b"\0".as_slice(), Some("EOF while reading message header")),
            (
                b"\0\x03a".as_slice(),
                Some("EOF while reading message data"),
            ),
        ] {
            let (stream, mut peer) = tokio::io::duplex(1024);
            let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
            peer.write_all(packet).await.unwrap();
            peer.shutdown().await.unwrap();

            let mut storage = [0; 32];
            let mut buffer = ReadBuf::new(&mut storage);
            let result = futures::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_message(cx, &mut buffer)
            })
            .await;
            if let Some(message) = expected_error {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                assert_eq!(error.to_string(), message);
            } else {
                result.unwrap();
            }
            assert!(buffer.filled().is_empty());
        }
    }

    #[tokio::test]
    async fn pending_write_and_shutdown_preserve_packet_boundaries() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut stream = H2MuxUdpMessageStream::new(Box::new(stream));
        let writer = tokio::spawn(async move {
            for payload in [b"abc".as_slice(), b"defg".as_slice()] {
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_write_message(cx, payload)
                })
                .await
                .unwrap();
            }
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .unwrap();
        });
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer.read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();
        assert_eq!(&bytes, b"\0\x03abc\0\x04defg");
    }
}
