//! AnyTLS Client Implementation
//!
//! Provides AnyTLS client support for outbound connections.
//! Creates multiplexed streams over a single TLS connection.

use aws_lc_rs::digest::{SHA256, digest};
use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::{PaddingFactory, SharedPadding, append_padding};
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER, StreamLifecycle};
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

struct StreamEntry {
    sender: mpsc::Sender<Bytes>,
    lifecycle: Arc<StreamLifecycle>,
}

struct ClientSessionState {
    /// Stream management
    streams: Mutex<HashMap<u32, StreamEntry>>,
    stream_id_counter: AtomicU32,

    /// Unified channel for all outgoing messages (control frames and data)
    /// Using a single channel ensures proper ordering of SYN/data frames
    outgoing_tx: mpsc::Sender<OutgoingMessage>,

    /// Session state
    is_closed: Arc<AtomicBool>,

    /// Padding configuration
    padding: SharedPadding,

    /// Protocol version negotiation
    peer_version: AtomicU8,

    open_deadline: Mutex<Option<tokio::time::Instant>>,
    deadline_changed: Notify,

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
    armed: bool,
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        if self.armed {
            // Settings or SYN may already be consumed/queued. Never recycle a
            // transport whose cancelled open has an ambiguous wire boundary.
            self.state.close();
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
        padding: SharedPadding,
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
    }

    pub(super) fn is_reusable(&self) -> bool {
        !self.state.is_closed.load(Ordering::Relaxed)
            && self.state.stream_id_counter.load(Ordering::Relaxed) < u32::MAX
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
        *self.open_deadline.lock() = None;
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
        padding: SharedPadding,
    ) -> io::Result<(Arc<Self>, Vec<tokio::task::AbortHandle>)> {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(hash_result.as_ref());

        // Send authentication (this is packet 0, sent separately)
        let initial_padding = padding.read().clone();
        Self::send_auth(&mut transport, &password_hash, &initial_padding).await?;

        // Create unified channel for all outgoing messages
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);

        // Pre-encode Settings frame into initial buffer
        // This will be sent together with first SYN + destination as one TLS record
        let initial_buffer = Self::create_initial_buffer(&initial_padding);

        let session = Arc::new(Self {
            streams: Mutex::new(HashMap::new()),
            stream_id_counter: AtomicU32::new(0),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding: Arc::clone(&padding),
            peer_version: AtomicU8::new(1), // Assume v1 until server confirms v2
            open_deadline: Mutex::new(None),
            deadline_changed: Notify::new(),
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
        settings_frame
            .encode_into(&mut buffer)
            .expect("fixed settings fit a control frame");
        buffer
    }

    /// Send authentication frame
    async fn send_auth(
        transport: &mut Box<dyn AsyncStream>,
        password_hash: &[u8; 32],
        padding: &PaddingFactory,
    ) -> io::Result<()> {
        // Authentication has one u16 length, unlike framed padding which can span records.
        let padding_sizes = padding.generate_record_payload_sizes(0);
        let padding_len = padding_sizes
            .first()
            .copied()
            .unwrap_or(0)
            .clamp(0, u16::MAX as i32) as u16;

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
        let watchdog_task = tokio::spawn(Self::watchdog_loop(Arc::clone(&session)));
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
        vec![
            writer_task.abort_handle(),
            reader_task.abort_handle(),
            watchdog_task.abort_handle(),
        ]
    }

    async fn watchdog_loop(session: Arc<Self>) {
        loop {
            let changed = session.deadline_changed.notified();
            let deadline = *session.open_deadline.lock();
            tokio::select! {
                _ = session.close_notify.cancelled() => return,
                _ = changed => {},
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let expired = {
                        let deadline = session.open_deadline.lock();
                        let expired = deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now());
                        if expired {
                            session.is_closed.store(true, Ordering::Relaxed);
                        }
                        expired
                    };
                    if expired {
                        session.close();
                        return;
                    }
                }
            }
        }
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
                    // Do not charge the previous lease's queued writes against
                    // the new stream's peer-response watchdog.
                    if cmd == Command::Syn
                        && stream_id >= 2
                        && session.peer_version.load(Ordering::Relaxed) >= 2
                    {
                        *session.open_deadline.lock() =
                            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(3));
                        session.deadline_changed.notify_one();
                    }
                    Frame::with_data(cmd, stream_id, data).encode_into(&mut write_buf)?;
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
                    Frame::data(stream_id, data).encode_into(&mut write_buf)?;
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
                    Frame::control(Command::Fin, stream_id).encode_into(&mut write_buf)?;
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
            return writer.write_all(data).await;
        }

        let pkt = session.pkt_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let padding = session.padding.read().clone();

        if pkt >= padding.stop() {
            session.send_padding.store(false, Ordering::Relaxed);
            return writer.write_all(data).await;
        }

        let pkt_sizes = padding.generate_record_payload_sizes(pkt);
        let mut remaining = data;

        for size in pkt_sizes {
            if size == CHECK_MARK {
                if remaining.is_empty() {
                    break;
                }
                continue;
            }

            let size = size as usize;
            let payload_len = remaining.len();

            if payload_len > size {
                writer.write_all(&remaining[..size]).await?;
                remaining = &remaining[size..];
            } else if payload_len > 0 {
                let padding_budget = size - payload_len;
                if padding_budget > FRAME_HEADER_SIZE {
                    // Payload and padding share one write to preserve TLS record boundaries.
                    padding_buf.clear();
                    padding_buf.reserve(size);
                    padding_buf.extend_from_slice(remaining);
                    append_padding(padding_buf, padding_budget, true);
                    writer.write_all(padding_buf).await?;
                } else {
                    writer.write_all(remaining).await?;
                }
                remaining = &[];
            } else {
                padding_buf.clear();
                padding_buf.reserve(FRAME_HEADER_SIZE + size);
                append_padding(padding_buf, size, false);
                writer.write_all(padding_buf).await?;
            }
        }

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
        let mut header_received = false;

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
                while buffer.len() >= FRAME_HEADER_SIZE {
                    if !header_received {
                        // A header proves liveness even if its payload arrives slowly.
                        // Count it only once: a later lease may re-arm during the payload.
                        *session.open_deadline.lock() = None;
                        header_received = true;
                    }
                    let Some(frame) = FrameCodec::decode(&mut buffer)? else {
                        break;
                    };
                    header_received = false;
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
                    streams
                        .get(&frame.stream_id)
                        .map(|entry| entry.sender.clone())
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
                let entry = {
                    let mut streams = self.streams.lock();
                    streams.remove(&frame.stream_id)
                };

                // Dropping the sender preserves queued data without blocking
                // the session reader on an EOF sentinel in a full channel.
                if let Some(entry) = entry {
                    entry.lifecycle.finish(None);
                }
            }

            Command::SynAck => {
                if !frame.data.is_empty() {
                    let entry = self.streams.lock().remove(&frame.stream_id);
                    if let Some(entry) = entry {
                        if self
                            .outgoing_tx
                            .try_send(OutgoingMessage::Fin {
                                stream_id: frame.stream_id,
                            })
                            .is_err()
                        {
                            self.close();
                        }
                        entry
                            .lifecycle
                            .finish(Some(String::from_utf8_lossy(&frame.data).into_owned()));
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

            Command::UpdatePaddingScheme => match PaddingFactory::new(&frame.data) {
                Ok(padding) => *self.padding.write() = Arc::new(padding),
                Err(error) => log::debug!("Ignoring invalid AnyTLS padding update: {error}"),
            },

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
        validate_destination(&destination)?;
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
        let lifecycle = Arc::new(StreamLifecycle::client(self.outgoing_tx.clone()));

        // Register stream
        {
            let mut streams = self.streams.lock();
            if self.is_closed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::NotConnected.into());
            }
            streams.insert(
                stream_id,
                StreamEntry {
                    sender: data_tx,
                    lifecycle: lifecycle.clone(),
                },
            );
        }
        let mut registration = StreamRegistration {
            state: Arc::clone(self),
            armed: true,
        };

        // Encode destination address
        let dest_data = write_location_to_vec(&destination)?;

        // Try to take the initial buffer (only first stream gets it)
        // If present, we send Settings + SYN + destination as single message
        let buffered_data = {
            let mut buf_guard = self.initial_buffer.lock().unwrap();
            if let Some(ref mut buf) = *buf_guard {
                // First stream - add SYN and destination to buffer
                // This creates: [Settings frame][SYN frame][PSH frame with destination]
                Frame::control(Command::Syn, stream_id).encode_into(buf)?;
                Frame::data(stream_id, Bytes::from(dest_data.clone())).encode_into(buf)?;

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

        let stream = AnyTlsStream::with_keepalive(
            stream_id,
            data_rx,
            Arc::clone(&self.is_closed),
            owner,
            lifecycle,
        );
        registration.armed = false;

        Ok(stream)
    }
}

pub(super) fn validate_destination(destination: &NetLocation) -> io::Result<()> {
    if destination
        .address()
        .hostname()
        .is_some_and(|host| host.len() > 255)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AnyTLS destination hostname exceeds 255 bytes",
        ));
    }
    Ok(())
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
        writes: Vec<Vec<u8>>,
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
            let mut log = self.0.lock();
            log.writes.push(data.to_vec());
            log.pending.extend_from_slice(data);
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
            padding: Arc::new(parking_lot::RwLock::new(Arc::new(
                PaddingFactory::new(b"stop=1\n0=0-0").unwrap(),
            ))),
            peer_version: AtomicU8::new(1),
            open_deadline: Mutex::new(None),
            deadline_changed: Notify::new(),
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            initial_buffer: std::sync::Mutex::new(None),
            close_notify: CancellationToken::new(),
        });
        (state, rx)
    }

    #[tokio::test]
    async fn padding_segments_preserve_write_boundaries_without_flushing() {
        for case in crate::anytls::anytls_padding::padding_write_cases() {
            let (state, _rx) = writer_state();
            *state.padding.write() = Arc::new(
                PaddingFactory::new(format!("stop=8\n1={}", case.sizes).as_bytes()).unwrap(),
            );
            state.send_padding.store(true, Ordering::Relaxed);
            let log = Arc::new(Mutex::new(WriteLog::default()));
            ClientSessionState::write_with_padding(
                &state,
                &mut RecordingWriter(log.clone()),
                &case.payload,
                &mut BytesMut::new(),
            )
            .await
            .unwrap();
            let log = log.lock();
            assert_eq!(log.writes, case.writes, "sizes={}", case.sizes);
            assert!(log.flushed.is_empty());
            assert_eq!(state.pkt_counter.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn padding_updates_propagate_without_resetting_sessions() {
        use tokio::io::AsyncReadExt;
        let (state, _rx) = writer_state();
        let (unrelated, _other_rx) = writer_state();
        state.send_padding.store(true, Ordering::Relaxed);
        state.pkt_counter.store(4, Ordering::Relaxed);
        let scheme = b"stop=10\n0=9-9\n5=1048576-1048576\n6=128-128";
        state
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(scheme),
            ))
            .await
            .unwrap();
        let expected = PaddingFactory::new(scheme).unwrap();
        assert_eq!(state.padding.read().md5(), expected.md5());
        assert_ne!(unrelated.padding.read().md5(), expected.md5());
        assert_eq!(state.pkt_counter.load(Ordering::Relaxed), 4);
        state
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(b"stop=invalid"),
            ))
            .await
            .unwrap();
        assert_eq!(state.padding.read().md5(), expected.md5());

        let log = Arc::new(Mutex::new(WriteLog::default()));
        let mut writer = RecordingWriter(log.clone());
        let payload = Frame::data(1, Bytes::from_static(b"payload")).encode();
        ClientSessionState::write_with_padding(&state, &mut writer, &payload, &mut BytesMut::new())
            .await
            .unwrap();
        let mut wire = BytesMut::from(log.lock().pending.as_slice());
        assert_eq!(wire.len(), 1 << 20);
        assert_eq!(
            FrameCodec::decode(&mut wire).unwrap().unwrap().data,
            b"payload"[..]
        );
        let mut frames = 0;
        while let Some(frame) = FrameCodec::decode(&mut wire).unwrap() {
            assert_eq!(frame.cmd, Command::Waste);
            frames += 1;
        }
        assert!(wire.is_empty());
        assert!(frames > 1);

        let (transport, mut peer) = tokio::io::duplex(1024);
        let session = AnyTlsClientSession::new(Box::new(transport), "test", state.padding.clone())
            .await
            .unwrap();
        let mut auth = [0; 43];
        peer.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth[32..34], &[0, 9]);
        let mut settings = session
            .state
            .initial_buffer
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        let settings = FrameCodec::decode(&mut settings).unwrap().unwrap();
        assert_eq!(
            StringMap::from_bytes(&settings.data)
                .get("padding-md5")
                .unwrap(),
            expected.md5()
        );
        drop(session);

        state.send_padding.store(false, Ordering::Relaxed);
        state
            .handle_frame(Frame::with_data(
                Command::UpdatePaddingScheme,
                0,
                Bytes::from_static(b"stop=100\n6=256-256"),
            ))
            .await
            .unwrap();
        log.lock().pending.clear();
        ClientSessionState::write_with_padding(&state, &mut writer, &payload, &mut BytesMut::new())
            .await
            .unwrap();
        assert_eq!(log.lock().pending, payload);
        assert_eq!(state.pkt_counter.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn authentication_padding_length_matches_its_clamped_body() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (transport, mut peer) = tokio::io::duplex(31);
            let task = tokio::spawn(async move {
                let mut transport: Box<dyn AsyncStream> = Box::new(transport);
                let padding = PaddingFactory::new(b"stop=8\n0=1048576-1048576").unwrap();
                ClientSessionState::send_auth(&mut transport, &[42; 32], &padding)
                    .await
                    .unwrap();
            });
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await.unwrap();
            task.await.unwrap();
            assert_eq!(&bytes[..32], &[42; 32]);
            assert_eq!(&bytes[32..34], &[255, 255]);
            assert_eq!(bytes.len(), 34 + 65535);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn split_waste_respects_payload_record_wire_budget() {
        let payload = Frame::data(1, Bytes::from_static(b"payload")).encode();
        let frame_limit = u16::MAX as usize + FRAME_HEADER_SIZE;
        for budget in [
            8,
            frame_limit,
            frame_limit + 7,
            frame_limit + 8,
            70000,
            (1 << 20) - payload.len(),
        ] {
            let size = payload.len() + budget;
            let (state, _rx) = writer_state();
            *state.padding.write() = Arc::new(
                PaddingFactory::new(format!("stop=2\n1={size}-{size}").as_bytes()).unwrap(),
            );
            state.send_padding.store(true, Ordering::Relaxed);
            let log = Arc::new(Mutex::new(WriteLog::default()));
            ClientSessionState::write_with_padding(
                &state,
                &mut RecordingWriter(log.clone()),
                &payload,
                &mut BytesMut::new(),
            )
            .await
            .unwrap();
            let mut bytes = BytesMut::from(log.lock().pending.as_slice());
            let remainder = budget % frame_limit;
            let unused = if remainder <= FRAME_HEADER_SIZE {
                remainder
            } else {
                0
            };
            assert_eq!(bytes.len(), size - unused, "budget={budget}");
            assert_eq!(
                FrameCodec::decode(&mut bytes).unwrap().unwrap().cmd,
                Command::Psh
            );
            while !bytes.is_empty() {
                let waste = FrameCodec::decode(&mut bytes)
                    .unwrap()
                    .expect("complete WASTE frame");
                assert_eq!(waste.cmd, Command::Waste);
                assert!(waste.data.iter().all(|byte| *byte == 0));
            }
        }
    }

    #[tokio::test]
    async fn watchdog_arms_only_for_version_two_warm_syns() {
        for (version, id, command, armed) in [
            (1, 2, Command::Syn, false),
            (2, 1, Command::Syn, false),
            (2, 2, Command::Syn, true),
            (2, 2, Command::HeartRequest, false),
        ] {
            let (state, rx) = writer_state();
            state.peer_version.store(version, Ordering::Relaxed);
            state
                .outgoing_tx
                .try_send(OutgoingMessage::Control {
                    cmd: command,
                    stream_id: id,
                    data: Bytes::new(),
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
                    .poll(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            assert_eq!(log.lock().flushed.len(), 1);
            assert_eq!(
                state.open_deadline.lock().is_some(),
                armed,
                "v{version} stream {id} {command:?}"
            );
        }
    }

    #[tokio::test]
    async fn pure_padding_splits_at_the_frame_payload_limit() {
        let payload = Frame::data(1, Bytes::from_static(b"payload")).encode();
        let size = payload.len();
        let (state, _rx) = writer_state();
        *state.padding.write() = Arc::new(
            PaddingFactory::new(format!("stop=2\n1={size}-{size},70000-70000").as_bytes()).unwrap(),
        );
        state.send_padding.store(true, Ordering::Relaxed);
        let log = Arc::new(Mutex::new(WriteLog::default()));
        ClientSessionState::write_with_padding(
            &state,
            &mut RecordingWriter(log.clone()),
            &payload,
            &mut BytesMut::new(),
        )
        .await
        .unwrap();
        let mut bytes = BytesMut::from(log.lock().pending.as_slice());
        assert_eq!(bytes.len(), payload.len() + 70000 + 2 * FRAME_HEADER_SIZE);
        let data = FrameCodec::decode(&mut bytes).unwrap().unwrap();
        assert_eq!(
            (data.cmd, data.data.as_ref()),
            (Command::Psh, &b"payload"[..])
        );
        for size in [65535, 4465] {
            let waste = FrameCodec::decode(&mut bytes).unwrap().unwrap();
            assert_eq!((waste.cmd, waste.stream_id), (Command::Waste, 0));
            assert_eq!(waste.data.len(), size);
            assert!(waste.data.iter().all(|byte| *byte == 0));
        }
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn authentication_padding_is_clamped_to_its_wire_length() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (io, mut peer) = tokio::io::duplex(4096);
            let mut transport: Box<dyn AsyncStream> = Box::new(io);
            let padding = PaddingFactory::new(b"stop=2\n0=1048576-1048576").unwrap();
            let sending = async {
                ClientSessionState::send_auth(&mut transport, &[42; 32], &padding)
                    .await
                    .unwrap();
                transport.shutdown().await.unwrap();
            };
            let receiving = async {
                let mut auth = Vec::new();
                peer.read_to_end(&mut auth).await.unwrap();
                assert_eq!(&auth[..32], &[42; 32]);
                let length = u16::from_be_bytes([auth[32], auth[33]]);
                assert_eq!(length, u16::MAX);
                assert_eq!(auth.len(), 34 + usize::from(length));
                assert!(auth[34..].iter().all(|byte| *byte == 0));
            };
            tokio::join!(sending, receiving);
        })
        .await
        .unwrap();
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
            let mut acknowledged = false;
            for _ in 0..4 {
                assert!(
                    writer
                        .as_mut()
                        .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                        .is_pending()
                );
                if barrier.try_recv().is_ok() {
                    acknowledged = true;
                    break;
                }
            }
            assert!(acknowledged, "flush barrier was not acknowledged");
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
            let (state, rx) = writer_state();
            *state.padding.write() =
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
            Arc::new(parking_lot::RwLock::new(PaddingFactory::default_factory())),
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
    async fn local_completion_removes_registration_without_closing_the_session() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (session, mut stream, mut peer) = open().await;
            let exercise = async {
                assert_eq!(session.state.streams.lock().len(), 1);
                stream.shutdown().await.unwrap();
                assert!(session.state.streams.lock().is_empty());
                let next = session
                    .open_stream(NetLocation::from_str("127.0.0.1:12345", None).unwrap())
                    .await
                    .unwrap();
                assert_eq!(session.state.streams.lock().len(), 1);
                drop(next);
                assert!(session.state.streams.lock().is_empty());
                assert!(!session.state.is_closed.load(Ordering::Relaxed));
                session.close();
            };
            let drain = async {
                tokio::io::copy(&mut peer, &mut tokio::io::sink())
                    .await
                    .unwrap();
            };
            tokio::join!(exercise, drain);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_stream_open_retires_the_session() {
        let (session, mut stream, _peer) = open().await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                stream.write_all(&vec![0; 2 * 1024 * 1024])
            )
            .await
            .is_err()
        );
        let destination = NetLocation::from_str("127.0.0.1:12345", None).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), session.open_stream(destination))
                .await
                .is_err()
        );
        assert!(session.state.is_closed.load(Ordering::Relaxed));
        drop(stream);
    }

    #[tokio::test]
    async fn shutdown_drains_data_after_a_cancelled_flush() {
        let (transport, mut peer) = tokio::io::duplex(64);
        let padding = Arc::new(parking_lot::RwLock::new(Arc::new(
            PaddingFactory::new(b"stop=1\n0=0-0").unwrap(),
        )));
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
