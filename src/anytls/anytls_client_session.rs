//! AnyTLS Client Implementation
//!
//! Provides AnyTLS client support for outbound connections.
//! Creates multiplexed streams over a single TLS connection.

use aws_lc_rs::digest::{SHA256, digest};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::AsyncStream;
use crate::socks_handler::write_location_to_vec;

/// Outgoing message types for the unified writer channel
enum OutgoingMessage {
    /// Buffered frames (Settings + SYN + destination) - sent as single TLS record
    /// This is used for the first stream to avoid fingerprinting
    Buffered { data: Bytes },
    /// Control frame (Settings, SYN, etc.) - encoded in writer loop
    Control {
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    },
    /// Data frame for a stream (PSH) - encoded in writer loop
    Data { stream_id: u32, data: Bytes },
    /// FIN frame for a stream - encoded in writer loop
    Fin { stream_id: u32 },
}

/// AnyTLS client session - manages multiplexed streams over a connection
///
/// Each session handles:
/// - Authentication with the server
/// - Protocol version negotiation
/// - Stream multiplexing (multiple logical streams over one connection)
/// - Frame-based communication
pub struct AnyTlsClientSession {
    /// Stream management
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,
    stream_id_counter: AtomicU32,

    /// Unified channel for all outgoing messages (control frames and data)
    /// Using a single channel ensures proper ordering of SYN/data frames
    outgoing_tx: mpsc::UnboundedSender<OutgoingMessage>,

    /// Session state
    is_closed: Arc<AtomicBool>,

    /// Padding configuration
    padding: Arc<PaddingFactory>,

    /// Protocol version negotiation
    peer_version: AtomicU8,

    /// Pending stream opens (stream_id -> completion sender)
    pending_opens: Mutex<HashMap<u32, oneshot::Sender<Result<(), String>>>>,

    /// Padding state (client only) - true until stop packets sent
    send_padding: AtomicBool,
    /// Packet counter for padding
    pkt_counter: AtomicU32,

    /// Initial buffer for coalescing Settings + first SYN + first destination
    /// This ensures they are sent as a single TLS record to avoid fingerprinting.
    /// Once taken (by first open_stream), this is None and subsequent streams
    /// are sent normally through the channel.
    initial_buffer: std::sync::Mutex<Option<BytesMut>>,
}

impl std::fmt::Debug for AnyTlsClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientSession")
            .field("is_closed", &self.is_closed.load(Ordering::Relaxed))
            .field("peer_version", &self.peer_version.load(Ordering::Relaxed))
            .finish()
    }
}

impl AnyTlsClientSession {
    /// Create a new client session on the given transport.
    ///
    /// This performs:
    /// 1. Send authentication frame (password_hash + padding)
    /// 2. Buffer client Settings frame (sent with first stream's SYN + destination)
    /// 3. Start reader/writer tasks
    ///
    /// The Settings frame is NOT sent immediately - it's buffered and will be
    /// sent together with the first stream's SYN and destination address as a
    /// single TLS record to avoid fingerprinting.
    ///
    /// Returns the session wrapped in Arc for shared ownership.
    pub async fn new(
        mut transport: Box<dyn AsyncStream>,
        password: &str,
        padding: Arc<PaddingFactory>,
    ) -> io::Result<Arc<Self>> {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(hash_result.as_ref());

        // Send authentication (this is packet 0, sent separately)
        Self::send_auth(&mut transport, &password_hash, &padding).await?;

        // Create unified channel for all outgoing messages
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();

        // Pre-encode Settings frame into initial buffer
        // This will be sent together with first SYN + destination as one TLS record
        let initial_buffer = Self::create_initial_buffer(&padding);

        let session = Arc::new(Self {
            streams: RwLock::new(HashMap::new()),
            stream_id_counter: AtomicU32::new(0),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding: Arc::clone(&padding),
            peer_version: AtomicU8::new(1), // Assume v1 until server confirms v2
            pending_opens: Mutex::new(HashMap::new()),
            send_padding: AtomicBool::new(true),
            pkt_counter: AtomicU32::new(0), // Start at 0, incremented before use
            initial_buffer: std::sync::Mutex::new(Some(initial_buffer)),
        });

        // NOTE: Settings is NOT sent here - it's in initial_buffer and will be
        // sent with the first stream's SYN + destination

        // Spawn background tasks
        let (read_half, write_half) = tokio::io::split(transport);
        Self::spawn_tasks(Arc::clone(&session), read_half, write_half, outgoing_rx);

        Ok(session)
    }

    /// Create initial buffer with Settings frame pre-encoded
    fn create_initial_buffer(padding: &PaddingFactory) -> BytesMut {
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "shoes-anytls/1.0");
        settings.insert("padding-md5", padding.md5());

        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));

        // Allocate buffer with room for Settings + SYN + typical destination
        let mut buffer = BytesMut::with_capacity(256);
        settings_frame.encode_into(&mut buffer);
        buffer
    }

    /// Send authentication frame
    async fn send_auth(
        transport: &mut Box<dyn AsyncStream>,
        password_hash: &[u8; 32],
        padding: &PaddingFactory,
    ) -> io::Result<()> {
        // Calculate padding for packet 0
        let padding_sizes = padding.generate_record_payload_sizes(0);
        let padding_len = padding_sizes.first().copied().unwrap_or(0).max(0) as u16;

        // Build auth frame: SHA256(password) + padding_len(u16) + padding
        let mut auth_frame = Vec::with_capacity(34 + padding_len as usize);
        auth_frame.extend_from_slice(password_hash);
        auth_frame.extend_from_slice(&padding_len.to_be_bytes());
        if padding_len > 0 {
            auth_frame.resize(34 + padding_len as usize, 0);
        }

        transport.write_all(&auth_frame).await?;
        transport.flush().await?;

        Ok(())
    }

    /// Send a control frame through the writer channel (zero-copy)
    fn send_control_frame(&self, cmd: Command, stream_id: u32, data: Bytes) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Control {
                cmd,
                stream_id,
                data,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed"))
    }

    /// Send buffered frames (Settings + SYN + destination) as single message
    fn send_buffered(&self, data: Bytes) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Buffered { data })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed"))
    }

    /// Spawn reader and writer tasks
    fn spawn_tasks<R, W>(
        session: Arc<Self>,
        reader: R,
        writer: W,
        outgoing_rx: mpsc::UnboundedReceiver<OutgoingMessage>,
    ) where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // Writer task - handles all outgoing messages (control and data)
        let session_writer = Arc::clone(&session);
        tokio::spawn(async move {
            if let Err(e) = Self::writer_loop(session_writer, writer, outgoing_rx).await {
                log::debug!("AnyTLS client writer ended: {}", e);
            }
        });

        // Reader task
        let session_reader = Arc::clone(&session);
        tokio::spawn(async move {
            if let Err(e) = Self::reader_loop(session_reader, reader).await {
                log::debug!("AnyTLS client reader ended: {}", e);
            }
        });
    }

    /// Writer loop - sends frames to the transport with padding
    ///
    /// Uses reusable buffers to minimize allocations in the hot path:
    /// - write_buf: for encoding frames
    /// - padding_buf: for constructing payload + padding in single writes
    ///
    /// Key optimizations:
    /// - Buffered messages (Settings + SYN + destination) sent as single TLS record
    /// - Padding frames concatenated with payload before write (single syscall)
    /// - Zero-allocation padding using put_bytes()
    async fn writer_loop<W>(
        session: Arc<Self>,
        mut writer: W,
        mut outgoing_rx: mpsc::UnboundedReceiver<OutgoingMessage>,
    ) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Send + Unpin,
    {
        log::debug!("AnyTLS client writer loop started");

        // Pre-allocate write buffer for max frame size (64KB payload + header + margin)
        // This buffer is reused for all frames to avoid per-frame allocations
        let mut write_buf = BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64);

        // Pre-allocate padding buffer for combining payload + WASTE frames
        // Used to ensure single write() call per padding segment
        let mut padding_buf = BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE * 2 + 64);

        while let Some(msg) = outgoing_rx.recv().await {
            if session.is_closed.load(Ordering::Relaxed) {
                break;
            }

            // Clear and reuse buffer for each frame
            write_buf.clear();

            match msg {
                OutgoingMessage::Buffered { data } => {
                    // Send buffered frames as single TLS record to avoid fingerprinting
                    log::debug!("AnyTLS client writer: buffered frames {} bytes", data.len());
                    Self::write_with_padding(&session, &mut writer, &data, &mut padding_buf)
                        .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Control {
                    cmd,
                    stream_id,
                    data,
                } => {
                    Frame::with_data(cmd, stream_id, data).encode_into(&mut write_buf);
                    log::debug!(
                        "AnyTLS client writer: control frame {} bytes",
                        write_buf.len()
                    );
                    Self::write_with_padding(&session, &mut writer, &write_buf, &mut padding_buf)
                        .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Data { stream_id, data } => {
                    Frame::data(stream_id, data).encode_into(&mut write_buf);
                    log::debug!(
                        "AnyTLS client writer: stream {} data {} bytes",
                        stream_id,
                        write_buf.len()
                    );
                    Self::write_with_padding(&session, &mut writer, &write_buf, &mut padding_buf)
                        .await?;
                    writer.flush().await?;
                }
                OutgoingMessage::Fin { stream_id } => {
                    Frame::control(Command::Fin, stream_id).encode_into(&mut write_buf);
                    log::debug!("AnyTLS client writer: stream {} FIN", stream_id);
                    Self::write_with_padding(&session, &mut writer, &write_buf, &mut padding_buf)
                        .await?;
                    writer.flush().await?;

                    let mut streams = session.streams.write().await;
                    streams.remove(&stream_id);
                }
            }
        }
        log::debug!("AnyTLS client writer loop: channel closed, exiting");
        Ok(())
    }

    /// Write data with padding applied (client-side padding)
    ///
    /// Key optimizations for protocol conformance and performance:
    /// 1. Payload + padding are concatenated BEFORE write (single TLS record)
    /// 2. Uses put_bytes() for zero-fill (no Vec allocation)
    /// 3. Reuses padding_buf across calls
    ///
    /// This matches the reference Go implementation which uses slices.Concat()
    /// to combine payload and padding before writing.
    async fn write_with_padding<W>(
        session: &Arc<Self>,
        writer: &mut W,
        data: &[u8],
        padding_buf: &mut BytesMut,
    ) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Send + Unpin,
    {
        use crate::anytls::anytls_padding::CHECK_MARK;

        if !session.send_padding.load(Ordering::Relaxed) {
            // Padding disabled, write directly
            return writer.write_all(data).await;
        }

        // Increment packet counter and check if we should still pad
        let pkt = session.pkt_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let stop = session.padding.stop();

        if pkt >= stop {
            session.send_padding.store(false, Ordering::Relaxed);
            return writer.write_all(data).await;
        }

        // Get padding sizes for this packet
        let pkt_sizes = session.padding.generate_record_payload_sizes(pkt);
        if pkt_sizes.is_empty() {
            return writer.write_all(data).await;
        }

        let mut remaining = data;

        for size in pkt_sizes {
            if size == CHECK_MARK {
                // Check mark: stop if no more payload
                if remaining.is_empty() {
                    break;
                }
                continue;
            }

            let l = size as usize;
            let remain_len = remaining.len();

            if remain_len > l {
                // This segment is all payload, no padding needed
                writer.write_all(&remaining[..l]).await?;
                remaining = &remaining[l..];
            } else if remain_len > 0 {
                // This segment contains payload + padding
                // We need to combine them into single write for correct TLS record
                let padding_len = l.saturating_sub(remain_len + FRAME_HEADER_SIZE);
                if padding_len > 0 {
                    // Combine payload + WASTE frame into single buffer
                    padding_buf.clear();
                    padding_buf.reserve(remain_len + FRAME_HEADER_SIZE + padding_len);

                    // Add payload
                    padding_buf.extend_from_slice(remaining);

                    // Add WASTE frame header (7 bytes) - NO Vec ALLOCATION
                    padding_buf.put_u8(Command::Waste as u8);
                    padding_buf.put_u32(0); // stream_id = 0 for padding
                    padding_buf.put_u16(padding_len as u16);

                    // Add padding zeros - put_bytes does NOT allocate Vec!
                    padding_buf.put_bytes(0, padding_len);

                    // Single write for payload + padding (one TLS record)
                    writer.write_all(padding_buf).await?;
                } else {
                    // Padding would be negative/zero, just write payload
                    writer.write_all(remaining).await?;
                }
                remaining = &[];
            } else {
                // This segment is pure padding (no payload left)
                // Build WASTE frame directly in padding_buf - NO Vec ALLOCATION
                padding_buf.clear();
                padding_buf.reserve(FRAME_HEADER_SIZE + l);

                // WASTE frame header
                padding_buf.put_u8(Command::Waste as u8);
                padding_buf.put_u32(0); // stream_id = 0
                padding_buf.put_u16(l as u16);

                // Padding zeros - put_bytes does NOT allocate Vec!
                padding_buf.put_bytes(0, l);

                writer.write_all(padding_buf).await?;
            }
        }

        // Write any remaining payload after padding scheme exhausted
        if !remaining.is_empty() {
            writer.write_all(remaining).await?;
        }

        Ok(())
    }

    /// Reader loop - receives frames from the transport
    async fn reader_loop<R>(session: Arc<Self>, mut reader: R) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin,
    {
        log::debug!("AnyTLS client reader loop started");
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            if session.is_closed.load(Ordering::Relaxed) {
                log::debug!("AnyTLS client reader loop: session closed, exiting");
                return Ok(());
            }

            // Decode any frames already in buffer
            while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                log::debug!(
                    "AnyTLS client received frame: {:?} stream={} len={}",
                    frame.cmd,
                    frame.stream_id,
                    frame.data.len()
                );
                if let Err(e) = session.handle_frame(frame).await {
                    log::warn!("AnyTLS client error handling frame: {}", e);
                    return Err(e);
                }
            }

            // Read more data
            let n = reader.read_buf(&mut buffer).await?;
            if n == 0 {
                log::debug!("AnyTLS client reader loop: connection closed (EOF)");
                return Ok(()); // Connection closed
            }
            log::debug!("AnyTLS client reader: read {} bytes", n);
        }
    }

    /// Handle a received frame
    async fn handle_frame(&self, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                // Data for a stream
                if frame.data.is_empty() {
                    return Ok(());
                }

                let tx = {
                    let streams = self.streams.read().await;
                    streams.get(&frame.stream_id).cloned()
                };

                if let Some(tx) = tx {
                    if tx.send(frame.data).await.is_err() {
                        log::trace!("Stream {} channel closed", frame.stream_id);
                    }
                } else {
                    log::trace!("Data for unknown stream {}", frame.stream_id);
                }
            }

            Command::Fin => {
                // Stream closed by server
                let tx = {
                    let mut streams = self.streams.write().await;
                    streams.remove(&frame.stream_id)
                };

                // Signal EOF
                if let Some(tx) = tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::SynAck => {
                // Stream open acknowledged (v2)
                let mut pending = self.pending_opens.lock().await;
                if let Some(sender) = pending.remove(&frame.stream_id) {
                    if frame.data.is_empty() {
                        let _ = sender.send(Ok(()));
                    } else {
                        let error = String::from_utf8_lossy(&frame.data).to_string();
                        let _ = sender.send(Err(error));
                    }
                }
            }

            Command::ServerSettings => {
                // Server settings response (v2)
                let settings = StringMap::from_bytes(&frame.data);
                if let Some(v) = settings.get("v").and_then(|s| s.parse::<u8>().ok()) {
                    self.peer_version.store(v, Ordering::Relaxed);
                    log::debug!("AnyTLS server version: {}", v);
                }
            }

            Command::UpdatePaddingScheme => {
                // Server sent new padding scheme for censorship resistance.
                // Per protocol: "subsequent new sessions must use the server's padding scheme"
                //
                // TODO: Implement UpdatePaddingScheme support:
                // 1. Change AnyTlsClientHandler.padding from Arc<PaddingFactory> to
                //    Arc<arc_swap::ArcSwap<PaddingFactory>> (or similar atomic wrapper)
                // 2. Pass a reference to that atomic into AnyTlsClientSession
                // 3. Here, parse frame.data as raw padding scheme bytes and call:
                //    if let Ok(new_factory) = PaddingFactory::new(&frame.data) {
                //        shared_padding.store(Arc::new(new_factory));
                //        log::info!("AnyTLS padding scheme updated: {}", new_factory.md5());
                //    }
                // 4. New sessions created by the handler will automatically use the updated scheme
                //
                // Reference: anytls-go/proxy/session/session.go:319-332
                // Reference: sing-anytls/session/session.go:314-327
                log::debug!(
                    "AnyTLS received padding scheme update ({} bytes) - not yet implemented",
                    frame.data.len()
                );
            }

            Command::Alert => {
                // Server alert - fatal
                let msg = String::from_utf8_lossy(&frame.data);
                log::warn!("AnyTLS server alert: {}", msg);
                self.is_closed.store(true, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("Server alert: {}", msg),
                ));
            }

            Command::HeartRequest => {
                // Respond to heartbeat
                let _ =
                    self.send_control_frame(Command::HeartResponse, frame.stream_id, Bytes::new());
            }

            Command::HeartResponse => {
                // Heartbeat response - acknowledge
                log::trace!("AnyTLS heartbeat response received");
            }

            Command::Waste => {
                // Padding - discard
            }

            _ => {
                log::debug!("Unexpected command: {:?}", frame.cmd);
            }
        }

        Ok(())
    }

    /// Open a new stream to the given destination
    ///
    /// Takes `self: &Arc<Self>` to allow the stream to hold a reference
    /// to the session, keeping it alive for the stream's lifetime.
    ///
    /// For the FIRST stream opened on a session, Settings + SYN + destination
    /// are sent together as a single TLS record to avoid fingerprinting.
    /// Subsequent streams use normal frame-by-frame transmission.
    pub async fn open_stream(
        self: &Arc<Self>,
        destination: NetLocation,
    ) -> io::Result<AnyTlsStream> {
        if self.is_closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Session is closed",
            ));
        }

        // Allocate stream ID (sequential starting from 1, matching Go implementation)
        // fetch_add returns old value, so +1 gives us 1, 2, 3, ...
        let stream_id = self.stream_id_counter.fetch_add(1, Ordering::Relaxed) + 1;

        // Create stream channels
        let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);

        // Register stream
        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, data_tx);
        }

        // Set up SYNACK receiver if v2
        let synack_rx = if self.peer_version.load(Ordering::Relaxed) >= 2 {
            let (tx, rx) = oneshot::channel();
            let mut pending = self.pending_opens.lock().await;
            pending.insert(stream_id, tx);
            Some(rx)
        } else {
            None
        };

        // Encode destination address
        let dest_data = write_location_to_vec(&destination);

        // Try to take the initial buffer (only first stream gets it)
        // If present, we send Settings + SYN + destination as single message
        let buffered_data = {
            let mut buf_guard = self.initial_buffer.lock().unwrap();
            if let Some(ref mut buf) = *buf_guard {
                // First stream - add SYN and destination to buffer
                // This creates: [Settings frame][SYN frame][PSH frame with destination]
                Frame::control(Command::Syn, stream_id).encode_into(buf);
                Frame::data(stream_id, Bytes::from(dest_data.clone())).encode_into(buf);

                // Take the buffer (subsequent streams won't have it)
                buf_guard.take().map(|b| b.freeze())
            } else {
                None
            }
        };

        if let Some(data) = buffered_data {
            // First stream: send buffered Settings + SYN + destination as one message
            // This ensures they go out as a single TLS record
            log::debug!(
                "AnyTLS client: sending buffered frames ({} bytes) for first stream {}",
                data.len(),
                stream_id
            );
            self.send_buffered(data)?;
        } else {
            // Subsequent streams: send SYN and destination normally
            self.send_control_frame(Command::Syn, stream_id, Bytes::new())?;
            self.send_control_frame(Command::Psh, stream_id, Bytes::from(dest_data))?;
        }

        // Wait for SYNACK if v2
        if let Some(synack_rx) = synack_rx {
            // 3-second timeout matches Go implementation's deadline watcher
            match tokio::time::timeout(std::time::Duration::from_secs(3), synack_rx).await {
                Ok(Ok(Ok(()))) => {
                    log::debug!("AnyTLS stream {} opened", stream_id);
                }
                Ok(Ok(Err(error))) => {
                    // Remove stream on error
                    let mut streams = self.streams.write().await;
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("Stream open failed: {}", error),
                    ));
                }
                Ok(Err(_)) => {
                    // Sender dropped
                    let mut streams = self.streams.write().await;
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Stream open cancelled",
                    ));
                }
                Err(_) => {
                    // Timeout - remove from pending and streams
                    {
                        let mut pending = self.pending_opens.lock().await;
                        pending.remove(&stream_id);
                    }
                    let mut streams = self.streams.write().await;
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Stream open timeout",
                    ));
                }
            }
        }

        // Create bounded channel for the stream's write path
        // This provides backpressure while keeping proper ordering via the unified channel
        let (stream_write_tx, mut stream_write_rx) =
            mpsc::channel::<(u32, Bytes)>(STREAM_CHANNEL_BUFFER);

        // Spawn forwarding task: bounded channel -> unified channel
        // Converts stream writes to OutgoingMessage variants
        let outgoing_tx = self.outgoing_tx.clone();
        let is_closed = Arc::clone(&self.is_closed);
        tokio::spawn(async move {
            while let Some((sid, data)) = stream_write_rx.recv().await {
                if is_closed.load(Ordering::Relaxed) {
                    break;
                }
                // Empty data signals FIN, non-empty is PSH data
                let msg = if data.is_empty() {
                    OutgoingMessage::Fin { stream_id: sid }
                } else {
                    OutgoingMessage::Data {
                        stream_id: sid,
                        data,
                    }
                };
                if outgoing_tx.send(msg).is_err() {
                    break;
                }
            }
        });

        // Create stream wrapper with session keepalive reference
        let stream = AnyTlsStream::with_keepalive(
            stream_id,
            data_rx,
            stream_write_tx,
            Arc::clone(&self.is_closed),
            Arc::clone(self),
        );

        Ok(stream)
    }
}
