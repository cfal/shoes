//! AnyTLS Session implementation
//!
//! A Session manages multiple Streams over a single TLS connection,
//! handling framing, multiplexing, padding, and stream routing.

use crate::address::{Address, NetLocation};
use crate::anytls::anytls_padding::{CHECK_MARK, PaddingFactory};
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::AsyncTargetedMessageStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream};
use crate::vless::VlessMessageStream;
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::{Mutex as SyncMutex, RwLock};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Timeout for control frame writes (matches reference implementation)
const CONTROL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

const STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

async fn cancelled_fin(stream: &mut AnyTlsStream) {
    let _ = tokio::time::timeout(Duration::from_millis(250), stream.shutdown()).await;
}

async fn setup_timeout<T>(
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(STREAM_SETUP_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS stream setup timed out"))?
}

struct SessionRunGuard<'a>(&'a AnyTlsSession);

impl Drop for SessionRunGuard<'_> {
    fn drop(&mut self) {
        self.0.close_state();
    }
}

/// AnyTLS Session manages multiplexed streams over a connection
pub struct AnyTlsSession {
    /// Underlying connection (split into reader/writer)
    reader: Mutex<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,

    /// Stream management (bounded channels for backpressure)
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,

    /// Active stream handler tasks (for cancellation on session close)
    stream_tasks: SyncMutex<HashMap<u32, JoinHandle<()>>>,

    /// Channel for receiving outgoing data from streams (bounded for backpressure)
    outgoing_rx: Mutex<mpsc::Receiver<(u32, Bytes)>>,
    outgoing_tx: mpsc::Sender<(u32, Bytes)>,

    /// Session state
    is_closed: Arc<AtomicBool>,
    cancel: CancellationToken,

    /// Padding configuration
    padding: Arc<PaddingFactory>,

    /// Client/Server mode
    is_client: bool,

    /// Padding state (client only)
    send_padding: AtomicBool,
    pkt_counter: AtomicU32,

    /// Buffering state (for initial settings+SYN coalescing)
    buffering: AtomicBool,
    buffer: Mutex<Vec<u8>>,

    /// Reusable write buffer to avoid allocations in hot path
    write_buf: Mutex<BytesMut>,

    /// Protocol version negotiation
    peer_version: AtomicU8,

    /// Server settings received
    received_client_settings: AtomicBool,

    // === Stream handling dependencies (server mode) ===
    /// Resolver for destination addresses (always required)
    resolver: Arc<dyn Resolver>,

    /// Proxy provider for routing decisions (always required - direct connect is dangerous)
    proxy_provider: Arc<ClientProxySelector>,

    /// UDP enabled for UoT support
    udp_enabled: bool,

    /// Authenticated user name for logging
    user_name: String,
    peer: Option<std::net::SocketAddr>,

    /// Initial data buffered during auth (to be prepended to first read)
    /// Uses std::sync::Mutex since it's only accessed once with no await points
    initial_data: std::sync::Mutex<Option<Box<[u8]>>>,
}

impl AnyTlsSession {
    /// Create a new server session with optional initial data that was buffered during auth.
    ///
    /// If `initial_data` is provided, it will be prepended to the first read in recv_loop.
    pub fn new_server_with_initial_data<IO>(
        conn: IO,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        user_name: String,
        initial_data: Option<Box<[u8]>>,
    ) -> Arc<Self>
    where
        IO: crate::async_stream::AsyncStream + 'static,
    {
        let peer = conn.peer_addr();
        let (reader, writer) = tokio::io::split(conn);
        // Use bounded channel for outgoing data to provide backpressure
        // Buffer size is per-session, shared across all streams
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        Arc::new(Self {
            peer,
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: SyncMutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
            padding,
            is_client: false,
            send_padding: AtomicBool::new(false), // Server doesn't pad by default
            pkt_counter: AtomicU32::new(0),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            // Pre-allocate write buffer for max frame size (64KB + header + some margin)
            write_buf: Mutex::new(BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64)),
            peer_version: AtomicU8::new(0),
            received_client_settings: AtomicBool::new(false),
            // Stream handling dependencies (always required)
            resolver,
            proxy_provider,
            udp_enabled,
            user_name,
            initial_data: std::sync::Mutex::new(initial_data),
        })
    }

    /// Create a minimal server session for testing protocol framing.
    ///
    /// Uses stub resolver/proxy_provider that panic if stream forwarding is attempted.
    /// Use this only for testing protocol framing, not end-to-end stream handling.
    #[cfg(test)]
    pub fn new_server_test<IO>(conn: IO, padding: Arc<PaddingFactory>) -> Arc<Self>
    where
        IO: crate::async_stream::AsyncStream + 'static,
    {
        use crate::client_proxy_selector::ConnectRule;
        use crate::resolver::NativeResolver;

        let (reader, writer) = tokio::io::split(conn);
        // Use bounded channel for outgoing data to provide backpressure
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        // Create a "block all" proxy selector - tests that need real routing should
        // use the full constructor with proper dependencies
        let proxy_provider = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![],
            crate::client_proxy_selector::ConnectAction::Block,
        )]));

        Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: SyncMutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
            padding,
            is_client: false,
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            write_buf: Mutex::new(BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64)),
            peer_version: AtomicU8::new(0),
            received_client_settings: AtomicBool::new(false),
            resolver: Arc::new(NativeResolver),
            proxy_provider,
            udp_enabled: false,
            user_name: String::new(),
            peer: None,
            initial_data: std::sync::Mutex::new(None),
        })
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    fn close_state(&self) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            // Abort all active stream handler tasks first
            // This prevents memory leaks from hung tasks holding Arc<Self>
            {
                let mut tasks = self.stream_tasks.lock();
                for (stream_id, handle) in tasks.drain() {
                    log::trace!("Aborting stream task {}", stream_id);
                    handle.abort();
                }
            }

            // Clear all streams (drops senders, signals EOF to any remaining receivers)
            self.streams.write().clear();
            self.cancel.cancel();
        }
    }

    /// Close the session and allow a bounded transport shutdown.
    pub async fn close(&self) {
        self.close_state();
        if let Ok(mut writer) = self.writer.try_lock() {
            let _ = tokio::time::timeout(CONTROL_FRAME_TIMEOUT, writer.shutdown()).await;
        }
    }

    /// Get the peer protocol version
    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Relaxed)
    }

    /// Run the session (blocking)
    ///
    /// This starts the receive loop and processes frames until the connection closes.
    /// New streams are handled internally using the configured resolver and proxy_provider.
    pub async fn run(self: &Arc<Self>) -> io::Result<()> {
        let _guard = SessionRunGuard(self);
        let result = tokio::select! {
            result = self.recv_loop() => result,
            _ = self.process_outgoing() => Ok(()),
            _ = self.cancel.cancelled() => Ok(()),
        };
        self.close().await;
        result
    }

    /// Process outgoing data from streams
    async fn process_outgoing(&self) {
        let mut rx = self.outgoing_rx.lock().await;

        while let Some((stream_id, data)) = rx.recv().await {
            if self.is_closed() {
                break;
            }

            // Check if this is a FIN signal (empty data)
            if data.is_empty() {
                // Send FIN frame
                let frame = Frame::control(Command::Fin, stream_id);
                if let Err(e) = self.write_frame(&frame).await {
                    log::debug!("Failed to send FIN for stream {}: {}", stream_id, e);
                }

                // Remove stream from map
                let mut streams = self.streams.write();
                streams.remove(&stream_id);
            } else {
                // Send data frame
                let frame = Frame::data(stream_id, data);
                if let Err(e) = self.write_frame(&frame).await {
                    log::debug!("Failed to send data for stream {}: {}", stream_id, e);
                    break;
                }
            }
        }
    }

    /// Main receive loop - reads frames and dispatches them
    async fn recv_loop(self: &Arc<Self>) -> io::Result<()> {
        let mut buffer = BytesMut::with_capacity(8192);

        // Prepend any initial data that was buffered during auth
        if let Some(initial) = self.initial_data.lock().unwrap().take() {
            buffer.extend_from_slice(&initial);
        }

        loop {
            if self.is_closed() {
                return Ok(());
            }

            // Decode and process any frames already in buffer (from initial data)
            while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                if let Err(e) = self.handle_frame(frame).await {
                    log::warn!("Error handling frame: {}", e);
                    return Err(e);
                }
            }

            // Read more data from connection
            let n = {
                let mut reader = self.reader.lock().await;
                match reader.read_buf(&mut buffer).await {
                    Ok(0) => return Ok(()), // Connection closed
                    Ok(n) => n,
                    Err(e) => return Err(e),
                }
            };

            log::trace!("Read {} bytes from connection", n);
        }
    }

    /// Handle a received frame
    async fn handle_frame(self: &Arc<Self>, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                // Skip zero-length PSH frames (matches reference implementation)
                if frame.data.is_empty() {
                    log::trace!("Ignoring zero-length PSH for stream {}", frame.stream_id);
                    return Ok(());
                }

                // Data frame - forward to stream
                // Clone sender and release lock before async send to avoid deadlock
                let tx = {
                    let streams = self.streams.read();
                    streams.get(&frame.stream_id).cloned()
                };
                if let Some(tx) = tx {
                    // Async send provides backpressure - blocks if stream channel is full
                    // This matches Go's channel behavior (head-of-line blocking)
                    if tx.send(frame.data).await.is_err() {
                        log::trace!("Stream {} channel closed", frame.stream_id);
                    }
                } else {
                    log::trace!("Data for unknown stream {}", frame.stream_id);
                }
            }

            Command::Syn => {
                // Stream open request (server side)
                if self.is_client {
                    log::warn!("Received SYN on client side");
                    return Ok(());
                }

                // Check if we've received client settings
                if !self.received_client_settings.load(Ordering::Relaxed) {
                    // Send alert - client must send settings first
                    let alert_frame = Frame::with_data(
                        Command::Alert,
                        0,
                        Bytes::from("client did not send its settings"),
                    );
                    self.write_control_frame(&alert_frame).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client did not send settings",
                    ));
                }

                let stream_id = frame.stream_id;
                if self.streams.read().contains_key(&stream_id) {
                    return Ok(());
                }
                let permit = if crate::resources::limits()
                    .max_streams_per_connection
                    .is_none_or(|limit| self.stream_tasks.lock().len() < limit)
                {
                    crate::resources::try_stream()
                } else {
                    None
                };
                let Some(permit) = permit else {
                    self.write_control_frame(&Frame::control(Command::Fin, stream_id))
                        .await?;
                    return Ok(());
                };
                // Hold task registration until spawn is recorded, so fast completion cannot
                // remove a missing handle and leave a completed task in the map.
                let mut tasks = self.stream_tasks.lock();
                if self.is_closed() || tasks.contains_key(&stream_id) {
                    return Ok(());
                }

                // Check if stream already exists and register atomically
                // This prevents race conditions with duplicate SYNs
                let stream_opt = {
                    let mut streams = self.streams.write();
                    use std::collections::hash_map::Entry;
                    match streams.entry(stream_id) {
                        Entry::Occupied(_) => {
                            log::warn!("Duplicate SYN for stream {}", stream_id);
                            None
                        }
                        Entry::Vacant(entry) => {
                            // Create new stream with bounded channel for backpressure
                            let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
                            let mut stream = AnyTlsStream::new(
                                stream_id,
                                data_rx,
                                self.outgoing_tx.clone(),
                                Arc::clone(&self.is_closed),
                            );
                            stream.peer = self.peer;
                            entry.insert(data_tx);
                            Some(stream)
                        }
                    }
                };

                if let Some(stream) = stream_opt {
                    let session = Arc::clone(self);
                    let handle = tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = session.handle_new_stream(stream).await {
                            log::debug!("AnyTLS stream {} error: {}", stream_id, e);
                        }
                        let mut tasks = session.stream_tasks.lock();
                        session.streams.write().remove(&stream_id);
                        tasks.remove(&stream_id);
                    });
                    tasks.insert(stream_id, handle);
                }
            }

            Command::SynAck => {
                // Server acknowledges stream (client side)
                if !self.is_client {
                    log::warn!("Received SYNACK on server side");
                    return Ok(());
                }

                // Handle SYNACK - for now just log
                if !frame.data.is_empty() {
                    let error_msg = String::from_utf8_lossy(&frame.data);
                    log::warn!(
                        "Stream {} error from server: {}",
                        frame.stream_id,
                        error_msg
                    );
                } else {
                    log::debug!("Stream {} acknowledged", frame.stream_id);
                }
            }

            Command::Fin => {
                // Stream close - remove from map first, then signal EOF
                // This matches reference implementation and prevents races where
                // new data arrives for a closing stream
                let stream_tx = {
                    let mut streams = self.streams.write();
                    streams.remove(&frame.stream_id)
                };

                // Signal EOF to stream (empty bytes)
                // Use async send for consistency, though FIN is typically not backpressured
                if let Some(tx) = stream_tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::Waste => {
                // Padding - just discard
                log::trace!("Received {} bytes of padding", frame.data.len());
            }

            Command::Settings => {
                // Client settings (server side)
                if self.is_client {
                    return Ok(());
                }

                self.received_client_settings.store(true, Ordering::Relaxed);

                let settings = StringMap::from_bytes(&frame.data);

                // Check padding-md5
                if settings
                    .get("padding-md5")
                    .is_some_and(|client_md5| client_md5 != self.padding.md5())
                {
                    // Send updated padding scheme
                    let update_frame = Frame::with_data(
                        Command::UpdatePaddingScheme,
                        0,
                        Bytes::copy_from_slice(self.padding.raw_scheme()),
                    );
                    self.write_control_frame(&update_frame).await?;
                }

                // Check client version
                if let Some(v) = settings
                    .get("v")
                    .and_then(|s| s.parse::<u8>().ok())
                    .filter(|&v| v >= 2)
                {
                    self.peer_version.store(v, Ordering::Relaxed);

                    // Send server settings
                    let mut server_settings = StringMap::new();
                    server_settings.insert("v", "2");
                    let settings_frame = Frame::with_data(
                        Command::ServerSettings,
                        0,
                        Bytes::from(server_settings.to_bytes()),
                    );
                    self.write_control_frame(&settings_frame).await?;
                }
            }

            Command::ServerSettings => {
                // Server settings (client side)
                if !self.is_client {
                    return Ok(());
                }

                let settings = StringMap::from_bytes(&frame.data);
                if let Some(v) = settings.get("v").and_then(|s| s.parse::<u8>().ok()) {
                    self.peer_version.store(v, Ordering::Relaxed);
                }
            }

            Command::UpdatePaddingScheme => {
                // Server updates padding scheme (client side)
                if !self.is_client {
                    return Ok(());
                }
                log::info!("Received padding scheme update from server");
                // Note: In a full implementation, we'd update the padding factory here
            }

            Command::Alert => {
                // Alert - fatal error
                let msg = String::from_utf8_lossy(&frame.data);
                log::error!("Received alert: {}", msg);
                return Err(io::Error::other(msg.to_string()));
            }

            Command::HeartRequest => {
                // Send heart response
                let response = Frame::control(Command::HeartResponse, frame.stream_id);
                self.write_control_frame(&response).await?;
            }

            Command::HeartResponse => {
                // Heartbeat response - just acknowledge
                log::trace!("Received heartbeat response");
            }
        }

        Ok(())
    }

    /// Write a frame to the connection with padding applied
    async fn write_frame(&self, frame: &Frame) -> io::Result<()> {
        // Use reusable write buffer to avoid allocation
        let mut write_buf = self.write_buf.lock().await;
        write_buf.clear();
        frame.encode_into(&mut write_buf);

        // Handle buffering
        if self.buffering.load(Ordering::Relaxed) {
            let mut buffer = self.buffer.lock().await;
            buffer.extend_from_slice(&write_buf);
            return Ok(());
        }

        // Flush any buffered data
        {
            let mut buffer = self.buffer.lock().await;
            if !buffer.is_empty() {
                // Prepend buffered data
                let mut combined = BytesMut::from(&buffer[..]);
                combined.extend_from_slice(&write_buf);
                write_buf.clear();
                write_buf.extend_from_slice(&combined);
                buffer.clear();
            }
        }

        // Apply padding if enabled
        if self.send_padding.load(Ordering::Relaxed) {
            // Use fetch_add + 1 to match Go's Add() semantics (returns new value)
            // This ensures packets 1-7 get padded (not 0-7), matching reference implementations
            let pkt = self.pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;

            if pkt < self.padding.stop() {
                // Need to take ownership for padding function
                let data = write_buf.split();
                return self.write_with_padding(data, pkt).await;
            } else {
                self.send_padding.store(false, Ordering::Relaxed);
            }
        }

        // Write directly
        let mut writer = self.writer.lock().await;
        writer.write_all(&write_buf).await?;
        writer.flush().await
    }

    /// Write data with padding applied according to scheme
    async fn write_with_padding(&self, mut data: BytesMut, pkt: u32) -> io::Result<()> {
        let pkt_sizes = self.padding.generate_record_payload_sizes(pkt);

        if pkt_sizes.is_empty() {
            let mut writer = self.writer.lock().await;
            writer.write_all(&data).await?;
            return writer.flush().await;
        }

        let mut writer = self.writer.lock().await;

        for size in pkt_sizes {
            let remain_payload_len = data.len();

            if size == CHECK_MARK {
                // Check mark: stop if no more data
                if remain_payload_len == 0 {
                    break;
                }
                continue;
            }

            let size = size as usize;

            if remain_payload_len > size {
                // This packet is all payload - send exactly `size` bytes
                writer.write_all(&data[..size]).await?;
                data = data.split_off(size);
            } else if remain_payload_len > 0 {
                // This packet contains payload + padding
                let padding_len = size.saturating_sub(remain_payload_len + FRAME_HEADER_SIZE);

                if padding_len > 0 {
                    // Append padding frame directly to data buffer (no intermediate allocation)
                    data.reserve(FRAME_HEADER_SIZE + padding_len);
                    data.put_u8(Command::Waste as u8);
                    data.put_u32(0); // stream_id = 0
                    data.put_u16(padding_len as u16);
                    data.put_bytes(0, padding_len); // Zero-fill without allocation
                }

                writer.write_all(&data).await?;
                data.clear();
            } else {
                // This packet is all padding - write directly without intermediate buffer
                // Use a small stack buffer for the header
                let header = [
                    Command::Waste as u8,
                    0,
                    0,
                    0,
                    0, // stream_id = 0
                    (size >> 8) as u8,
                    size as u8,
                ];
                writer.write_all(&header).await?;
                // Write zeros for padding body - use a static buffer for small sizes
                const ZERO_BUF: [u8; 1024] = [0u8; 1024];
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(ZERO_BUF.len());
                    writer.write_all(&ZERO_BUF[..chunk]).await?;
                    remaining -= chunk;
                }
            }
        }

        // Write any remaining payload
        if !data.is_empty() {
            writer.write_all(&data).await?;
        }

        writer.flush().await
    }

    /// Send SYNACK for a stream (server side, protocol v2)
    pub async fn send_synack(&self, stream_id: u32, error: Option<&str>) -> io::Result<()> {
        if self.peer_version() < 2 {
            return Ok(());
        }

        let frame = if let Some(err) = error {
            Frame::with_data(Command::SynAck, stream_id, Bytes::from(err.to_string()))
        } else {
            Frame::control(Command::SynAck, stream_id)
        };

        self.write_control_frame(&frame).await
    }

    /// Write a control frame with timeout
    ///
    /// Control frames (Settings, Alert, SYNACK, etc.) should complete quickly.
    /// If they timeout, the connection is likely dead and should be closed.
    async fn write_control_frame(&self, frame: &Frame) -> io::Result<()> {
        match tokio::time::timeout(CONTROL_FRAME_TIMEOUT, self.write_frame(frame)).await {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "Control frame write timed out after {:?}, closing session",
                    CONTROL_FRAME_TIMEOUT
                );
                self.close().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control frame write timed out",
                ))
            }
        }
    }

    /// Handle a new stream by reading destination and routing appropriately
    async fn handle_new_stream(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        // Read destination address (SOCKS5 address format)
        let destination = setup_timeout(read_location_direct(&mut stream)).await?;

        log::debug!(
            "AnyTLS stream {} (user: {}) -> {}",
            stream_id,
            self.user_name,
            destination
        );

        // Check for UoT magic addresses
        if let Address::Hostname(host) = destination.address() {
            if host == UOT_V2_MAGIC_ADDRESS {
                return self.handle_uot_v2(stream).await;
            } else if host == UOT_V1_MAGIC_ADDRESS {
                return self.handle_uot_v1(stream).await;
            }
        }

        // Regular TCP forwarding with proper routing
        self.handle_tcp_forward(stream, destination).await
    }

    /// Handle regular TCP forwarding with ClientProxySelector routing
    async fn handle_tcp_forward(
        &self,
        mut stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let prepared = match crate::tcp::ingress::PreparedTcp::new(
            &self.proxy_provider,
            destination.clone(),
            Vec::new(),
        ) {
            Ok(prepared) => prepared.with_source(self.peer),
            Err(error) => {
                let message = format!("connect failed: {error}");
                let _ = self.send_synack(stream_id, Some(&message)).await;
                let _ = tokio::time::timeout(CONTROL_FRAME_TIMEOUT, stream.shutdown()).await;
                return Err(error);
            }
        };
        let optimistic = prepared.needs_sniff_read();
        if optimistic {
            self.send_synack(stream_id, None).await?;
        }
        let setup = async {
            let route =
                setup_timeout(prepared.route(&mut stream, &self.proxy_provider, &self.resolver))
                    .await?;
            setup_timeout(route.connect(&self.resolver)).await
        };
        let routed = match setup.await {
            Ok(result) => result,
            Err(error) => {
                if !optimistic {
                    let message = format!("connect failed: {error}");
                    let _ = self.send_synack(stream_id, Some(&message)).await;
                }
                let _ = tokio::time::timeout(CONTROL_FRAME_TIMEOUT, stream.shutdown()).await;
                return Err(error);
            }
        };

        match routed.setup {
            Some(client_result) => {
                let mut client_stream = client_result.client_stream;
                let flow = client_stream.flow().cloned();

                if !optimistic {
                    let synack = self.send_synack(stream_id, None);
                    tokio::pin!(synack);
                    tokio::select! {
                        result = &mut synack => result?,
                        _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => {
                            drop(client_stream);
                            stream.close_read();
                            // Finish the bounded control write; truncating a shared frame corrupts siblings.
                            let _ = synack.await;
                            cancelled_fin(&mut stream).await;
                            return Err(crate::control::tracked_stream::cancelled());
                        }
                    }
                }
                if let Some(data) = client_result.early_data
                    && let Err(error) = crate::control::tracked_stream::during_flow(
                        flow.as_deref(),
                        setup_timeout(async {
                            stream.write_all(&data).await?;
                            stream.flush().await
                        }),
                    )
                    .await
                {
                    drop(client_stream);
                    stream.close_read();
                    if flow.as_ref().is_some_and(|flow| flow.cancel.is_cancelled()) {
                        cancelled_fin(&mut stream).await;
                    }
                    return Err(error);
                }
                if !routed.prefix.is_empty()
                    && let Err(error) = crate::control::tracked_stream::during_flow(
                        flow.as_deref(),
                        setup_timeout(async {
                            client_stream.write_all(&routed.prefix).await?;
                            client_stream.flush().await
                        }),
                    )
                    .await
                {
                    drop(client_stream);
                    stream.close_read();
                    if flow.as_ref().is_some_and(|flow| flow.cancel.is_cancelled()) {
                        cancelled_fin(&mut stream).await;
                    }
                    return Err(error);
                }

                drop(routed.prefix);
                log::debug!("AnyTLS stream {} connected to destination", stream_id);

                // Bidirectional copy
                let result =
                    copy_bidirectional(&mut stream, &mut *client_stream, false, false).await;

                let cancelled = tokio::select! {
                    biased;
                    _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => true,
                    _ = tokio::time::timeout(CONTROL_FRAME_TIMEOUT, async {
                        let _ = stream.shutdown().await;
                        let _ = client_stream.shutdown().await;
                    }) => false,
                };
                if cancelled {
                    drop(client_stream);
                    stream.close_read();
                    cancelled_fin(&mut stream).await;
                }

                if let Err(e) = &result {
                    log::debug!("AnyTLS stream {} ended: {}", stream_id, e);
                } else {
                    log::debug!("AnyTLS stream {} completed", stream_id);
                }

                result
            }
            None => {
                if !optimistic {
                    let error_msg = format!("blocked by rules: {}", destination);
                    let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                }

                log::debug!("AnyTLS stream {} blocked by rules", stream_id);
                let _ = tokio::time::timeout(CONTROL_FRAME_TIMEOUT, stream.shutdown()).await;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Connection to {} blocked by rules", destination),
                ))
            }
        }
    }

    /// Handle UoT V2 stream (sp.v2.udp-over-tcp.arpa)
    async fn handle_uot_v2(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        if !self.udp_enabled {
            log::debug!(
                "AnyTLS stream {} UoT V2 rejected: UDP not enabled",
                stream_id
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        // Read UoT V2 request header: isConnect(u8) + destination(SOCKS5 format)
        let (is_connect, destination) = setup_timeout(async {
            Ok((
                stream.read_u8().await?,
                read_location_direct(&mut stream).await?,
            ))
        })
        .await?;

        log::debug!(
            "AnyTLS stream {} UoT V2 (user: {}, connect={}) -> {}",
            stream_id,
            self.user_name,
            is_connect,
            destination
        );

        if is_connect == 1 {
            // V2 Connect Mode: Single destination, length-prefixed packets
            self.handle_uot_v2_connect(stream, destination).await
        } else {
            // V2 Non-Connect: Same as V1 (multi-destination)
            self.handle_uot_multi_destination(stream).await
        }
    }

    /// Handle UoT V1 stream (sp.udp-over-tcp.arpa) - multi-destination mode
    async fn handle_uot_v1(&self, stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        if !self.udp_enabled {
            log::debug!(
                "AnyTLS stream {} UoT V1 rejected: UDP not enabled",
                stream_id
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        log::debug!(
            "AnyTLS stream {} UoT V1 (user: {})",
            stream_id,
            self.user_name
        );

        self.handle_uot_multi_destination(stream).await
    }

    /// Handle UoT V2 Connect Mode (single destination)
    ///
    /// Uses connect_udp for proper proxy chaining support.
    async fn handle_uot_v2_connect(
        &self,
        mut stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let route = match setup_timeout(crate::routing::ingress::route_udp(
            &self.proxy_provider,
            destination,
            &self.resolver,
        ))
        .await
        {
            Ok(route) => route.with_source(self.peer),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                let _ = self
                    .send_synack(stream_id, Some("UDP blocked by rules"))
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "UDP blocked by rules",
                ));
            }
            Err(error) => {
                let _ = self
                    .send_synack(stream_id, Some(&format!("UDP connect failed: {error}")))
                    .await;
                return Err(error);
            }
        };
        let setup = match setup_timeout(route.connect(&self.resolver)).await {
            Ok(setup) => setup,
            Err(error) => {
                let _ = self
                    .send_synack(stream_id, Some(&format!("UDP connect failed: {error}")))
                    .await;
                return Err(error);
            }
        };
        let flow = setup.stream.flow().cloned();
        let synack = self.send_synack(stream_id, None);
        tokio::pin!(synack);
        tokio::select! {
            result = &mut synack => result?,
            _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => {
                drop(setup.stream);
                stream.close_read();
                // A partially written shared control frame must finish before FIN.
                let _ = synack.await;
                cancelled_fin(&mut stream).await;
                return Err(crate::control::tracked_stream::cancelled());
            }
        }
        let mut client_stream = setup.stream;
        let (result, cancelled) = {
            let mut server_stream = VlessMessageStream::new(&mut stream);
            let result = crate::control::tracked_stream::during_flow(
                flow.as_deref(),
                copy_bidirectional_message(&mut server_stream, &mut client_stream, false, false),
            )
            .await;
            let cancelled = tokio::select! {
                biased;
                _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => true,
                _ = async {
                    futures::join!(
                        crate::util::shutdown_message_stream(&mut server_stream),
                        crate::util::shutdown_message_stream(&mut client_stream),
                    );
                } => false,
            };
            (result, cancelled)
        };
        if cancelled {
            drop(client_stream);
            stream.close_read();
            cancelled_fin(&mut stream).await;
        }
        result
    }

    /// Handle UoT multi-destination mode (V1 and V2 non-connect)
    ///
    /// Uses connect_udp for proper proxy chaining support.
    async fn handle_uot_multi_destination(&self, stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        log::debug!(
            "AnyTLS stream {} UoT multi-dest: starting per-destination routing",
            stream_id
        );

        // Wrap AnyTlsStream as AsyncTargetedMessageStream (UotV1ServerStream)
        let server_stream: Box<dyn AsyncTargetedMessageStream> =
            Box::new(UotV1ServerStream::new_uot(stream));

        // Send successful SYNACK (protocol v2)
        let _ = self.send_synack(stream_id, None).await;

        // Run per-destination routing
        let result = run_udp_routing(
            ServerStream::Targeted(server_stream),
            self.proxy_provider.clone(),
            self.resolver.clone(),
            false, // no initial flush needed
        )
        .await;

        if let Err(e) = &result {
            log::debug!("AnyTLS stream {} UoT multi-dest ended: {}", stream_id, e);
        } else {
            log::debug!("AnyTLS stream {} UoT multi-dest completed", stream_id);
        }

        result
    }
}

#[cfg(test)]
mod tests;
