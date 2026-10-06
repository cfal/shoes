//! AnyTLS Client Implementation
//!
//! Provides AnyTLS client support for outbound connections.
//! Creates multiplexed streams over a single TLS connection.

use aws_lc_rs::digest::{SHA256, digest};
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::AsyncStream;
use crate::socks_handler::write_location_to_vec;

/// Outgoing message types for the unified writer channel
pub(super) enum OutgoingMessage {
    /// Buffered frames (Settings + SYN + destination) - sent as single TLS record
    /// This is used for the first stream to avoid fingerprinting
    Buffered {
        data: Bytes,
    },
    /// Control frame (Settings, SYN, etc.) - encoded in writer loop
    Control {
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    },
    /// Data frame for a stream (PSH) - encoded in writer loop
    Data {
        stream_id: u32,
        data: Bytes,
    },
    /// FIN frame for a stream - encoded in writer loop
    Fin {
        stream_id: u32,
    },
    Flush {
        done: oneshot::Sender<()>,
    },
}

/// AnyTLS client session - manages multiplexed streams over a connection
///
/// Each session handles:
/// - Authentication with the server
/// - Protocol version negotiation
/// - Stream multiplexing (multiple logical streams over one connection)
/// - Frame-based communication
pub struct AnyTlsClientSession {
    state: Arc<ClientSessionState>,
    tasks: Vec<tokio::task::AbortHandle>,
}

struct ClientSessionState {
    /// Stream management
    streams: Mutex<HashMap<u32, mpsc::Sender<Bytes>>>,
    stream_id_counter: AtomicU32,

    /// Unified channel for all outgoing messages (control frames and data)
    /// Using a single channel ensures proper ordering of SYN/data frames
    outgoing_tx: mpsc::Sender<OutgoingMessage>,

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

    /// Notify to break reader/writer loops when session is dropped
    close_notify: CancellationToken,
}

struct StreamRegistration {
    state: Arc<ClientSessionState>,
    stream_id: u32,
    armed: bool,
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        if self.armed {
            self.state.streams.lock().remove(&self.stream_id);
            self.state.pending_opens.lock().remove(&self.stream_id);
            if self
                .state
                .outgoing_tx
                .try_send(OutgoingMessage::Fin {
                    stream_id: self.stream_id,
                })
                .is_err()
            {
                self.state.close();
            }
        }
    }
}

impl std::fmt::Debug for AnyTlsClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientSession")
            .field("is_closed", &self.state.is_closed.load(Ordering::Relaxed))
            .field(
                "peer_version",
                &self.state.peer_version.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl Drop for AnyTlsClientSession {
    fn drop(&mut self) {
        self.state.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl AnyTlsClientSession {
    pub async fn new(
        transport: Box<dyn AsyncStream>,
        password: &str,
        padding: Arc<PaddingFactory>,
    ) -> io::Result<Arc<Self>> {
        let (state, tasks) = ClientSessionState::new(transport, password, padding).await?;
        Ok(Arc::new(Self { state, tasks }))
    }

    pub async fn open_stream(
        self: &Arc<Self>,
        destination: NetLocation,
    ) -> io::Result<AnyTlsStream> {
        self.state.open_stream(destination, Arc::clone(self)).await
    }

    pub(super) fn remove_stream(&self, stream_id: u32) {
        self.state.streams.lock().remove(&stream_id);
        self.state.pending_opens.lock().remove(&stream_id);
    }

    pub(super) fn close(&self) {
        self.state.close();
    }
}

impl ClientSessionState {
    fn close(&self) {
        self.is_closed.store(true, Ordering::Relaxed);
        self.close_notify.cancel();
        self.streams.lock().clear();
        self.pending_opens.lock().clear();
    }

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
    ) -> io::Result<(Arc<Self>, Vec<tokio::task::AbortHandle>)> {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(hash_result.as_ref());

        // Send authentication (this is packet 0, sent separately)
        Self::send_auth(&mut transport, &password_hash, &padding).await?;

        // Create unified channel for all outgoing messages
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);

        // Pre-encode Settings frame into initial buffer
        // This will be sent together with first SYN + destination as one TLS record
        let initial_buffer = Self::create_initial_buffer(&padding);

        let session = Arc::new(Self {
            streams: Mutex::new(HashMap::new()),
            stream_id_counter: AtomicU32::new(0),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding: Arc::clone(&padding),
            peer_version: AtomicU8::new(1), // Assume v1 until server confirms v2
            pending_opens: Mutex::new(HashMap::new()),
            send_padding: AtomicBool::new(true),
            pkt_counter: AtomicU32::new(0), // Start at 0, incremented before use
            initial_buffer: std::sync::Mutex::new(Some(initial_buffer)),
            close_notify: CancellationToken::new(),
        });

        // NOTE: Settings is NOT sent here - it's in initial_buffer and will be
        // sent with the first stream's SYN + destination

        // Spawn background tasks
        let (read_half, write_half) = tokio::io::split(transport);
        let tasks = Self::spawn_tasks(Arc::clone(&session), read_half, write_half, outgoing_rx);

        Ok((session, tasks))
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
    async fn send_control_frame(
        &self,
        cmd: Command,
        stream_id: u32,
        data: Bytes,
    ) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Control {
                cmd,
                stream_id,
                data,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed"))
    }

    /// Send buffered frames (Settings + SYN + destination) as single message
    async fn send_buffered(&self, data: Bytes) -> io::Result<()> {
        self.outgoing_tx
            .send(OutgoingMessage::Buffered { data })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Session writer closed"))
    }

    fn spawn_tasks<R, W>(
        session: Arc<Self>,
        reader: R,
        writer: W,
        outgoing_rx: mpsc::Receiver<OutgoingMessage>,
    ) -> Vec<tokio::task::AbortHandle>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let writer_state = Arc::clone(&session);
        let writer_task = tokio::spawn(async move {
            tokio::select! {
                result = Self::writer_loop(
                    Arc::downgrade(&writer_state), writer, outgoing_rx,
                    writer_state.close_notify.clone(),
                ) => {
                    if let Err(e) = result {
                        log::debug!("AnyTLS client writer ended: {e}");
                    }
                }
                _ = writer_state.close_notify.cancelled() => {}
            }
            writer_state.close();
        });
        let reader_task = tokio::spawn(async move {
            tokio::select! {
                result = Self::reader_loop(
                    Arc::downgrade(&session), reader, session.close_notify.clone(),
                ) => {
                    if let Err(e) = result {
                        log::debug!("AnyTLS client reader ended: {e}");
                    }
                }
                _ = session.close_notify.cancelled() => {}
            }
            session.close();
        });
        vec![writer_task.abort_handle(), reader_task.abort_handle()]
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
        session_weak: std::sync::Weak<Self>,
        mut writer: W,
        mut outgoing_rx: mpsc::Receiver<OutgoingMessage>,
        close_notify: CancellationToken,
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
        let mut unflushed_bytes = 0;
        const FLUSH_BATCH_BYTES: usize = 256 * 1024;

        loop {
            let msg = tokio::select! {
                m = outgoing_rx.recv() => m,
                _ = close_notify.cancelled() => {
                    log::debug!("AnyTLS client writer loop: close_notify triggered");
                    break;
                }
            };

            let msg = match msg {
                Some(m) => m,
                None => break,
            };

            let session = match session_weak.upgrade() {
                Some(s) => s,
                None => {
                    log::debug!("AnyTLS client writer loop: session dropped, exiting");
                    break;
                }
            };

            if session.is_closed.load(Ordering::Relaxed) {
                break;
            }

            // Clear and reuse buffer for each frame
            write_buf.clear();

            match msg {
                OutgoingMessage::Flush { done } => {
                    writer.flush().await?;
                    unflushed_bytes = 0;
                    let _ = done.send(());
                }
                OutgoingMessage::Buffered { data } => {
                    // Send buffered frames as single TLS record to avoid fingerprinting
                    log::debug!("AnyTLS client writer: buffered frames {} bytes", data.len());
                    Self::write_with_padding(&session, &mut writer, &data, &mut padding_buf)
                        .await?;
                    writer.flush().await?;
                    unflushed_bytes = 0;
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
                    unflushed_bytes = 0;
                }
                OutgoingMessage::Data { stream_id, data } => {
                    let padding_active = session.send_padding.load(Ordering::Relaxed);
                    Frame::data(stream_id, data).encode_into(&mut write_buf);
                    log::debug!(
                        "AnyTLS client writer: stream {} data {} bytes",
                        stream_id,
                        write_buf.len()
                    );
                    Self::write_with_padding(&session, &mut writer, &write_buf, &mut padding_buf)
                        .await?;
                    unflushed_bytes += write_buf.len();
                    let quota_reached = unflushed_bytes >= FLUSH_BATCH_BYTES;
                    if padding_active || outgoing_rx.is_empty() || quota_reached {
                        writer.flush().await?;
                        unflushed_bytes = 0;
                    }
                    if quota_reached {
                        tokio::task::yield_now().await;
                    }
                }
                OutgoingMessage::Fin { stream_id } => {
                    Frame::control(Command::Fin, stream_id).encode_into(&mut write_buf);
                    log::debug!("AnyTLS client writer: stream {} FIN", stream_id);
                    Self::write_with_padding(&session, &mut writer, &write_buf, &mut padding_buf)
                        .await?;
                    writer.flush().await?;
                    unflushed_bytes = 0;

                    let mut streams = session.streams.lock();
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
    async fn reader_loop<R>(
        session_weak: std::sync::Weak<Self>,
        mut reader: R,
        close_notify: CancellationToken,
    ) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin,
    {
        log::debug!("AnyTLS client reader loop started");
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            // Scope for the strong reference to session
            let has_closed = {
                let session = match session_weak.upgrade() {
                    Some(s) => s,
                    None => {
                        log::debug!("AnyTLS client reader loop: session dropped, exiting");
                        return Ok(());
                    }
                };

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

                false
            };

            if has_closed {
                return Ok(());
            }

            // DO NOT hold `session` (strong Arc) across `reader.read_buf().await`.
            // Because if we hold the Arc, the Drop impl will never be called when the stream disconnects!
            // Wait for new data or close_notify
            let read_result = tokio::select! {
                res = reader.read_buf(&mut buffer) => res,
                _ = close_notify.cancelled() => {
                    log::debug!("AnyTLS client reader loop: close_notify triggered");
                    return Ok(());
                }
            };

            let n = read_result?;
            if n == 0 {
                log::debug!("AnyTLS client reader loop: connection closed (EOF)");
                // Once reader gets EOF from upstream, TLS connection is dead.
                // Re-upgrade to signal writer loop
                if let Some(session) = session_weak.upgrade() {
                    session.is_closed.store(true, Ordering::Relaxed);
                    session.close_notify.cancel();
                }
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
                    let streams = self.streams.lock();
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
                    let mut streams = self.streams.lock();
                    streams.remove(&frame.stream_id)
                };

                // Signal EOF
                if let Some(tx) = tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::SynAck => {
                // Stream open acknowledged (v2)
                let mut pending = self.pending_opens.lock();
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
                let _ = self
                    .send_control_frame(Command::HeartResponse, frame.stream_id, Bytes::new())
                    .await;
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
        owner: Arc<AnyTlsClientSession>,
    ) -> io::Result<AnyTlsStream> {
        if self.is_closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Session is closed",
            ));
        }

        // Allocate stream ID (sequential starting from 1, matching Go implementation)
        // fetch_add returns old value, so +1 gives us 1, 2, 3, ...
        let stream_id = self
            .stream_id_counter
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .ok_or_else(|| {
                self.close();
                io::Error::other("AnyTLS stream IDs exhausted")
            })?;

        // Create stream channels
        let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);

        // Register stream
        {
            let mut streams = self.streams.lock();
            if self.is_closed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::NotConnected.into());
            }
            streams.insert(stream_id, data_tx);
        }
        let mut registration = StreamRegistration {
            state: Arc::clone(self),
            stream_id,
            armed: true,
        };

        // Set up SYNACK receiver if v2
        let synack_rx = if self.peer_version.load(Ordering::Relaxed) >= 2 {
            let (tx, rx) = oneshot::channel();
            let mut pending = self.pending_opens.lock();
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
            self.send_buffered(data).await?;
        } else {
            // Subsequent streams: send SYN and destination normally
            self.send_control_frame(Command::Syn, stream_id, Bytes::new())
                .await?;
            self.send_control_frame(Command::Psh, stream_id, Bytes::from(dest_data))
                .await?;
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
                    let mut streams = self.streams.lock();
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("Stream open failed: {}", error),
                    ));
                }
                Ok(Err(_)) => {
                    // Sender dropped
                    let mut streams = self.streams.lock();
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Stream open cancelled",
                    ));
                }
                Err(_) => {
                    // Timeout - remove from pending and streams
                    {
                        let mut pending = self.pending_opens.lock();
                        pending.remove(&stream_id);
                    }
                    let mut streams = self.streams.lock();
                    streams.remove(&stream_id);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Stream open timeout",
                    ));
                }
            }
        }

        let stream = AnyTlsStream::with_keepalive(
            stream_id,
            data_rx,
            self.outgoing_tx.clone(),
            Arc::clone(&self.is_closed),
            owner,
        );
        registration.armed = false;

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    #[derive(Default)]
    struct WriteLog {
        pending: Vec<u8>,
        flushed: Vec<Vec<u8>>,
    }

    struct RecordingWriter(Arc<Mutex<WriteLog>>);

    impl tokio::io::AsyncWrite for RecordingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().pending.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut log = self.0.lock();
            let bytes = std::mem::take(&mut log.pending);
            log.flushed.push(bytes);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn writer_state() -> (Arc<ClientSessionState>, mpsc::Receiver<OutgoingMessage>) {
        let (outgoing_tx, rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let state = Arc::new(ClientSessionState {
            streams: Mutex::new(HashMap::new()),
            stream_id_counter: AtomicU32::new(1),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding: Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap()),
            peer_version: AtomicU8::new(1),
            pending_opens: Mutex::new(HashMap::new()),
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            initial_buffer: std::sync::Mutex::new(None),
            close_notify: CancellationToken::new(),
        });
        (state, rx)
    }

    #[tokio::test]
    async fn writer_batches_ready_data_but_preserves_flush_and_fin_barriers() {
        for (count, size, expected_flushes) in [(3, 64, 2), (5, 65535, 3)] {
            let (state, rx) = writer_state();
            for i in 0..count {
                state
                    .outgoing_tx
                    .try_send(OutgoingMessage::Data {
                        stream_id: 1,
                        data: Bytes::from(vec![i as u8; size]),
                    })
                    .unwrap();
            }
            let (done, mut barrier) = oneshot::channel();
            state
                .outgoing_tx
                .try_send(OutgoingMessage::Flush { done })
                .unwrap();
            state
                .outgoing_tx
                .try_send(OutgoingMessage::Fin { stream_id: 1 })
                .unwrap();
            let log = Arc::new(Mutex::new(WriteLog::default()));
            let mut writer = Box::pin(ClientSessionState::writer_loop(
                Arc::downgrade(&state),
                RecordingWriter(log.clone()),
                rx,
                state.close_notify.clone(),
            ));
            // A quota can yield before the barrier; repeated polls must eventually reach it.
            for _ in 0..4 {
                assert!(
                    writer
                        .as_mut()
                        .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                        .is_pending()
                );
                if barrier.try_recv().is_ok() {
                    break;
                }
            }
            let log = log.lock();
            assert!(log.pending.is_empty());
            assert_eq!(log.flushed.len(), expected_flushes);
            let mut bytes = BytesMut::from(log.flushed.concat().as_slice());
            for i in 0..count {
                let frame = FrameCodec::decode(&mut bytes).unwrap().unwrap();
                assert_eq!(frame.cmd, Command::Psh);
                assert_eq!(frame.data.as_ref(), vec![i as u8; size]);
            }
            assert_eq!(
                FrameCodec::decode(&mut bytes).unwrap().unwrap().cmd,
                Command::Fin
            );
            assert!(bytes.is_empty());
        }
    }

    #[tokio::test]
    async fn writer_flushes_sparse_data_without_an_explicit_barrier() {
        let (state, rx) = writer_state();
        state
            .outgoing_tx
            .try_send(OutgoingMessage::Data {
                stream_id: 1,
                data: Bytes::from_static(b"request"),
            })
            .unwrap();
        let log = Arc::new(Mutex::new(WriteLog::default()));
        let mut writer = Box::pin(ClientSessionState::writer_loop(
            Arc::downgrade(&state),
            RecordingWriter(log.clone()),
            rx,
            state.close_notify.clone(),
        ));
        assert!(
            writer
                .as_mut()
                .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                .is_pending()
        );
        assert!(log.lock().pending.is_empty());
        assert_eq!(log.lock().flushed.len(), 1);
    }

    #[tokio::test]
    async fn padding_transition_preserves_data_under_transport_backpressure() {
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut state, rx) = writer_state();
            Arc::get_mut(&mut state).unwrap().padding =
                Arc::new(PaddingFactory::new(b"stop=3\n0=0-0\n1=128-128\n2=128-128").unwrap());
            state.send_padding.store(true, Ordering::Relaxed);
            for index in 0..5 {
                state
                    .outgoing_tx
                    .try_send(OutgoingMessage::Data {
                        stream_id: 1,
                        data: Bytes::from(vec![index; 64]),
                    })
                    .unwrap();
            }
            state
                .outgoing_tx
                .try_send(OutgoingMessage::Fin { stream_id: 1 })
                .unwrap();
            let (done, barrier) = oneshot::channel();
            state
                .outgoing_tx
                .try_send(OutgoingMessage::Flush { done })
                .unwrap();
            let (writer, mut reader) = tokio::io::duplex(7);
            let writing = tokio::spawn(ClientSessionState::writer_loop(
                Arc::downgrade(&state),
                writer,
                rx,
                state.close_notify.clone(),
            ));
            let reading = tokio::spawn(async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await.unwrap();
                BytesMut::from(received.as_slice())
            });
            barrier.await.unwrap();
            assert!(!state.send_padding.load(Ordering::Relaxed));
            state.close();
            writing.await.unwrap().unwrap();
            let mut received = reading.await.unwrap();
            for index in 0..5 {
                let frame = FrameCodec::decode(&mut received).unwrap().unwrap();
                assert_eq!(frame.cmd, Command::Psh);
                assert_eq!(frame.data.as_ref(), [index; 64]);
                if index < 2 {
                    let padding = FrameCodec::decode(&mut received).unwrap().unwrap();
                    assert_eq!(padding.cmd, Command::Waste);
                }
            }
            assert_eq!(
                FrameCodec::decode(&mut received).unwrap().unwrap().cmd,
                Command::Fin
            );
            assert!(received.is_empty());
        })
        .await
        .unwrap();
    }

    async fn open() -> (
        Arc<AnyTlsClientSession>,
        AnyTlsStream,
        tokio::io::DuplexStream,
    ) {
        let (transport, peer) = tokio::io::duplex(128);
        let session = AnyTlsClientSession::new(
            Box::new(transport),
            "test",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        let stream = session
            .open_stream(NetLocation::from_str("127.0.0.1:12345", None).unwrap())
            .await
            .unwrap();
        (session, stream, peer)
    }

    #[tokio::test]
    async fn stalled_transport_backpressures_all_streams() {
        let (session, mut stream, peer) = open().await;
        let bytes = vec![1; 2 * 1024 * 1024];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.write_all(&bytes))
                .await
                .is_err()
        );
        assert!(session.state.outgoing_tx.capacity() <= STREAM_CHANNEL_BUFFER);
        drop(peer);
    }

    #[tokio::test]
    async fn transport_eof_wakes_parked_reader() {
        let (session, mut stream, mut peer) = open().await;
        peer.shutdown().await.unwrap();
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .unwrap();
        assert_eq!(result.unwrap(), 0);
        assert!(session.state.streams.lock().is_empty());
    }

    #[tokio::test]
    async fn dropping_last_owner_cancels_stalled_io() {
        let (session, mut stream, _peer) = open().await;
        stream.write_all(b"payload").await.unwrap();
        tokio::task::yield_now().await;
        let state = Arc::downgrade(&session.state);
        let tasks = session.tasks.clone();
        drop(session);
        drop(stream);
        tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.iter().any(|task| !task.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.upgrade().is_none());
    }

    #[tokio::test]
    async fn cancelled_stream_open_releases_registration() {
        let (session, stream, _peer) = open().await;
        session.state.peer_version.store(2, Ordering::Relaxed);
        let destination = NetLocation::from_str("127.0.0.1:12345", None).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), session.open_stream(destination))
                .await
                .is_err()
        );
        assert_eq!(session.state.streams.lock().len(), 1);
        assert!(session.state.pending_opens.lock().is_empty());
        drop(stream);
        assert!(session.state.streams.lock().is_empty());
    }

    #[tokio::test]
    async fn shutdown_drains_data_after_a_cancelled_flush() {
        let (transport, mut peer) = tokio::io::duplex(64);
        let padding = Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap());
        let session = AnyTlsClientSession::new(Box::new(transport), "test", padding)
            .await
            .unwrap();
        let mut stream = session
            .open_stream(NetLocation::from_str("127.0.0.1:12345", None).unwrap())
            .await
            .unwrap();
        stream.write_all(b"first").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.flush())
                .await
                .is_err()
        );
        let reader = tokio::spawn(async move {
            let mut auth = [0; 34];
            peer.read_exact(&mut auth).await.unwrap();
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await.unwrap();
            let mut buffer = BytesMut::from(bytes.as_slice());
            let mut payloads = Vec::new();
            let mut fin = false;
            while let Some(frame) = FrameCodec::decode(&mut buffer).unwrap() {
                if frame.cmd == Command::Psh {
                    assert!(!fin);
                    payloads.push(frame.data);
                }
                if frame.cmd == Command::Fin {
                    fin = true;
                }
            }
            assert!(fin);
            assert_eq!(
                &payloads[1..],
                &[Bytes::from_static(b"first"), Bytes::from_static(b"second")]
            );
        });
        stream.write_all(b"second").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
    }
}
