//! H2MUX Client Handler
//!
//! Wraps an inner TcpClientHandler to multiplex multiple streams over h2mux.
//! Maintains a pool of H2MuxClientSession connections with session selection logic.
//!
//! TODO: Session pooling is not yet working. Currently each call to setup_client_tcp_stream
//! creates a new session because the caller provides the transport stream. To enable true
//! multiplexing, setup_client_tcp_stream and the proxy chain group need significant changes
//! to allow the handler to manage its own transport connections.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, ReadBuf};

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
/// and uses h2mux to multiplex multiple logical streams over pooled connections.
#[derive(Debug)]
pub struct H2MuxClientHandler {
    /// Inner protocol handler used to establish connections to the proxy server
    inner: Arc<dyn TcpClientHandler>,
    /// H2MUX configuration options
    options: H2MuxOptions,
    /// Pool of active sessions
    sessions: Arc<Mutex<Vec<SessionEntry>>>,
}

/// Entry in the session pool, tracking session state
#[derive(Debug)]
struct SessionEntry {
    session: H2MuxClientSession,
    /// Estimated number of active streams (may be stale)
    estimated_streams: u32,
}

impl H2MuxClientHandler {
    /// Create a new H2MUX client handler wrapping the given inner handler.
    pub fn new(inner: Arc<dyn TcpClientHandler>, options: H2MuxOptions) -> Self {
        Self {
            inner,
            options,
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get an existing session or create a new one.
    /// Reserved for future session pooling.
    #[allow(dead_code)]
    async fn get_or_create_session(&self) -> io::Result<H2MuxClientSession> {
        // First try to find an existing session
        {
            let mut sessions = self.sessions.lock();

            // Remove closed sessions
            sessions.retain(|entry| entry.session.is_ready());

            // Find best session (fewest streams that can take new request)
            let best_idx = sessions
                .iter()
                .enumerate()
                .filter(|(_, e)| e.session.is_ready())
                .min_by_key(|(_, e)| e.estimated_streams)
                .map(|(idx, _)| idx);

            if let Some(idx) = best_idx {
                let num_sessions = sessions.len();
                let num_streams = sessions[idx].estimated_streams;

                // Use this session if it has no streams (idle)
                if num_streams == 0 {
                    sessions[idx].estimated_streams += 1;
                    return Ok(sessions[idx].session.clone());
                }

                // Check if we should use existing vs create new
                let should_use_existing = if self.options.max_connections > 0 {
                    // Have connection limit: use existing if at limit or below min_streams
                    num_sessions >= self.options.max_connections as usize
                        || num_streams < self.options.min_streams
                } else if self.options.max_streams > 0 {
                    // No connection limit but have stream limit: use if below max
                    num_streams < self.options.max_streams
                } else {
                    // No limits: always reuse
                    true
                };

                if should_use_existing {
                    sessions[idx].estimated_streams += 1;
                    return Ok(sessions[idx].session.clone());
                }
            }
        }

        // Create new session
        self.create_session().await
    }

    /// Create a new h2mux session by connecting through the inner handler.
    /// Reserved for future session pooling.
    #[allow(dead_code)]
    async fn create_session(&self) -> io::Result<H2MuxClientSession> {
        debug!("H2MuxClientHandler: creating new session");

        // Connect to the proxy server using the inner handler with magic destination
        let _magic_location = NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.to_string()),
            MUX_DESTINATION_PORT,
        );

        // We need a raw connection to the proxy server first.
        // The inner handler will connect to the server and send the magic destination.
        // We'll get back the wrapped stream.

        // Note: We need a transport stream first. The caller should provide this
        // via setup_client_tcp_stream. For connection pooling to work properly,
        // we need access to the connection factory.
        //
        // For now, we implement a simpler model where each call to setup_client_tcp_stream
        // that needs a new session will create one on-demand. The caller must provide
        // the transport stream.

        Err(io::Error::other(
            "H2MuxClientHandler requires transport stream to be provided",
        ))
    }

    /// Create a session from an existing transport stream.
    ///
    /// The session will handle padding internally if enabled in options.
    async fn create_session_from_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<H2MuxClientSession> {
        debug!("H2MuxClientHandler: creating session from stream");

        // Session handles padding internally: sends request header on raw stream,
        // then applies padding layer before HTTP/2 handshake.
        let session = H2MuxClientSession::new(stream, &self.options).await?;

        // Add to pool
        {
            let mut sessions = self.sessions.lock();
            sessions.push(SessionEntry {
                session: session.clone(),
                estimated_streams: 0,
            });
        }

        Ok(session)
    }
}

#[async_trait]
impl TcpClientHandler for H2MuxClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        // First, connect through the inner handler to the magic destination.
        // This establishes the protocol layer (e.g., Shadowsocks, VLESS).
        let magic_location = ResolvedLocation::new(NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.to_string()),
            MUX_DESTINATION_PORT,
        ));

        let inner_result = self
            .inner
            .setup_client_tcp_stream(client_stream, magic_location)
            .await?;

        // Now we have a stream connected to the magic destination
        // Create an h2mux session over it
        let mut session = self
            .create_session_from_stream(inner_result.client_stream)
            .await?;

        // Open a stream to the actual destination
        let location = remote_location.into_location();
        let stream = session.open_tcp(&location).await?;

        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        // H2MUX supports UDP through its own stream protocol
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        // First, connect through the inner handler to the magic destination
        let magic_location = ResolvedLocation::new(NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.to_string()),
            MUX_DESTINATION_PORT,
        ));

        let inner_result = self
            .inner
            .setup_client_tcp_stream(client_stream, magic_location)
            .await?;

        // Create an h2mux session over it
        let mut session = self
            .create_session_from_stream(inner_result.client_stream)
            .await?;

        // Open a UDP stream to the target
        let location = target.into_location();
        let stream = session.open_udp(&location, false).await?;

        // Wrap the stream as a message stream
        // The H2MuxStream already handles length-prefixed UDP packets
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
            write_buffer: BytesMut::with_capacity(65537),
            write_pos: 0,
        }
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
                    // Read the 2-byte length header
                    while this.read_header_pos < 2 {
                        let mut temp_buf =
                            ReadBuf::new(&mut this.read_header[this.read_header_pos..]);
                        match Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
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
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Parse header
                    let len = u16::from_be_bytes(this.read_header) as usize;
                    this.read_header_pos = 0;
                    this.read_data_remaining = len;
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
                    // Read the message data
                    let to_read = this.read_data_remaining.min(buf.remaining());
                    let mut temp_buf = ReadBuf::new(buf.initialize_unfilled_to(to_read));
                    match Pin::new(&mut this.stream).poll_read(cx, &mut temp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = temp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF while reading message data",
                                )));
                            }
                            buf.advance(n);
                            this.read_data_remaining -= n;

                            if this.read_data_remaining == 0 {
                                // Message complete
                                this.read_state = ReadState::Header;
                                return Poll::Ready(Ok(()));
                            }
                            // Continue reading
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
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
        use tokio::io::AsyncWrite;

        let this = &mut *self;

        // Flush any pending data first
        while this.write_pos < this.write_buffer.len() {
            let remaining = &this.write_buffer[this.write_pos..];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Clear buffer after fully written
        this.write_buffer.clear();
        this.write_pos = 0;

        if buf.len() > 65535 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP packet too large",
            )));
        }

        // Build message: length prefix + data
        this.write_buffer.put_u16(buf.len() as u16);
        this.write_buffer.put_slice(buf);

        // Write the message
        while this.write_pos < this.write_buffer.len() {
            let remaining = &this.write_buffer[this.write_pos..];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buffer.clear();
        this.write_pos = 0;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for H2MuxUdpMessageStream {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;

        let this = &mut *self;

        // Flush any pending data first
        while this.write_pos < this.write_buffer.len() {
            let remaining = &this.write_buffer[this.write_pos..];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buffer.clear();
        this.write_pos = 0;

        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for H2MuxUdpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;
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
