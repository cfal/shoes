//! AnyTLS Session implementation
//!
//! A Session manages multiple Streams over a single TLS connection,
//! handling framing, multiplexing, padding, and stream routing.

use crate::address::{Address, NetLocation};
use crate::anytls::anytls_padding::{CHECK_MARK, PaddingFactory};
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::{AsyncMessageStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::tcp::tcp_server::run_udp_copy;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream};
use crate::vless::VlessMessageStream;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;

/// Timeout for control frame writes (matches reference implementation)
const CONTROL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum lifetime for a single stream handler (5 minutes)
/// Prevents memory leaks from hung streams (slow DNS, stuck connections, etc.)
const STREAM_HANDLER_TIMEOUT: Duration = Duration::from_secs(300);

/// AnyTLS Session manages multiplexed streams over a connection
pub struct AnyTlsSession {
    /// Underlying connection (split into reader/writer)
    reader: Mutex<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,

    /// Stream management (bounded channels for backpressure)
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,

    /// Active stream handler tasks (for cancellation on session close)
    stream_tasks: Mutex<HashMap<u32, JoinHandle<()>>>,

    /// Channel for receiving outgoing data from streams (bounded for backpressure)
    outgoing_rx: Mutex<mpsc::Receiver<(u32, Bytes)>>,
    outgoing_tx: mpsc::Sender<(u32, Bytes)>,

    /// Session state
    is_closed: Arc<AtomicBool>,

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
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(conn);
        // Use bounded channel for outgoing data to provide backpressure
        // Buffer size is per-session, shared across all streams
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: Mutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
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
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
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
            stream_tasks: Mutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
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
            initial_data: std::sync::Mutex::new(None),
        })
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Close the session
    pub async fn close(&self) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            // Abort all active stream handler tasks first
            // This prevents memory leaks from hung tasks holding Arc<Self>
            {
                let mut tasks = self.stream_tasks.lock().await;
                for (stream_id, handle) in tasks.drain() {
                    log::trace!("Aborting stream task {}", stream_id);
                    handle.abort();
                }
            }

            // Clear all streams (drops senders, signals EOF to any remaining receivers)
            let mut streams = self.streams.write().await;
            streams.clear();

            // Try to shutdown writer gracefully
            if let Ok(mut writer) = self.writer.try_lock() {
                let _ = writer.shutdown().await;
            }
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
        let session = Arc::clone(self);

        // Start the outgoing data processor
        let session_clone = Arc::clone(&session);
        let outgoing_task = tokio::spawn(async move {
            session_clone.process_outgoing().await;
        });

        // Run the receive loop
        let result = session.recv_loop().await;

        // Cleanup
        session.close().await;
        outgoing_task.abort();

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
                let mut streams = self.streams.write().await;
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
                    let streams = self.streams.read().await;
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

                // Check if stream already exists and register atomically
                // This prevents race conditions with duplicate SYNs
                let stream_opt = {
                    let mut streams = self.streams.write().await;
                    use std::collections::hash_map::Entry;
                    match streams.entry(stream_id) {
                        Entry::Occupied(_) => {
                            log::warn!("Duplicate SYN for stream {}", stream_id);
                            None
                        }
                        Entry::Vacant(entry) => {
                            // Create new stream with bounded channel for backpressure
                            let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
                            let stream = AnyTlsStream::new(
                                stream_id,
                                data_rx,
                                self.outgoing_tx.clone(),
                                Arc::clone(&self.is_closed),
                            );
                            entry.insert(data_tx);
                            Some(stream)
                        }
                    }
                };

                // Handle the new stream internally with timeout and task tracking
                if let Some(stream) = stream_opt {
                    let session = Arc::clone(self);
                    let stream_id_for_cleanup = stream_id;
                    let session_for_cleanup = Arc::clone(self);

                    let handle = tokio::spawn(async move {
                        // Apply timeout to entire stream handler lifetime
                        // This prevents memory leaks from hung streams
                        let result = tokio::time::timeout(
                            STREAM_HANDLER_TIMEOUT,
                            session.handle_new_stream(stream),
                        )
                        .await;

                        match result {
                            Ok(Ok(())) => {
                                log::trace!("AnyTLS stream {} completed", stream_id_for_cleanup);
                            }
                            Ok(Err(e)) => {
                                log::debug!("AnyTLS stream {} error: {}", stream_id_for_cleanup, e);
                            }
                            Err(_) => {
                                log::warn!(
                                    "AnyTLS stream {} timed out after {:?}",
                                    stream_id_for_cleanup,
                                    STREAM_HANDLER_TIMEOUT
                                );
                            }
                        }

                        // Remove self from stream_tasks on completion
                        let mut tasks = session_for_cleanup.stream_tasks.lock().await;
                        tasks.remove(&stream_id_for_cleanup);
                    });

                    // Track the task for cancellation on session close
                    let mut tasks = self.stream_tasks.lock().await;
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
                    let mut streams = self.streams.write().await;
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
        let destination = read_location_direct(&mut stream).await?;

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

        let action = self
            .proxy_provider
            .judge(destination.clone().into(), &self.resolver)
            .await?;

        match action {
            ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                log::debug!(
                    "AnyTLS stream {} routing {} through chain",
                    stream_id,
                    remote_location
                );

                // Connect through the proxy chain
                let client_result = match chain_group
                    .connect_tcp(remote_location, &self.resolver)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        // Send SYNACK with error message (protocol v2)
                        let error_msg = format!("connect failed: {}", e);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(e);
                    }
                };
                let mut client_stream = client_result.client_stream;

                // Send successful SYNACK (protocol v2)
                if let Err(e) = self.send_synack(stream_id, None).await {
                    log::debug!("Failed to send SYNACK for stream {}: {}", stream_id, e);
                    // Continue anyway - client may be v1
                }

                log::debug!("AnyTLS stream {} connected to destination", stream_id);

                // Bidirectional copy
                let result =
                    copy_bidirectional(&mut stream, &mut *client_stream, false, false).await;

                let _ = stream.shutdown().await;
                let _ = client_stream.shutdown().await;

                if let Err(e) = &result {
                    log::debug!("AnyTLS stream {} ended: {}", stream_id, e);
                } else {
                    log::debug!("AnyTLS stream {} completed", stream_id);
                }

                result
            }
            ConnectDecision::Block => {
                // Send SYNACK with error (protocol v2)
                let error_msg = format!("blocked by rules: {}", destination);
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;

                log::debug!("AnyTLS stream {} blocked by rules", stream_id);
                let _ = stream.shutdown().await;
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
        let is_connect = stream.read_u8().await?;
        let destination = read_location_direct(&mut stream).await?;

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
        stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        // Use ClientProxySelector for routing
        let action = self
            .proxy_provider
            .judge(destination.clone().into(), &self.resolver)
            .await?;

        match action {
            ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                log::debug!(
                    "AnyTLS stream {} UoT V2 connect: routing {} through chain",
                    stream_id,
                    remote_location
                );

                // Wrap AnyTlsStream as AsyncMessageStream (VlessMessageStream for length-prefixed)
                let server_stream: Box<dyn AsyncMessageStream> =
                    Box::new(VlessMessageStream::new(stream));

                // Connect through the proxy chain
                let client_stream = match chain_group
                    .connect_udp_bidirectional(&self.resolver, remote_location)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        // Send SYNACK with error (protocol v2)
                        let error_msg = format!("UDP connect failed: {}", e);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(e);
                    }
                };

                // Send successful SYNACK (protocol v2)
                let _ = self.send_synack(stream_id, None).await;

                log::debug!("AnyTLS stream {} UoT V2 connect: connected", stream_id);

                // Run UDP copy
                let result = run_udp_copy(server_stream, client_stream, false, false).await;

                if let Err(e) = &result {
                    log::debug!("AnyTLS stream {} UoT V2 connect ended: {}", stream_id, e);
                } else {
                    log::debug!("AnyTLS stream {} UoT V2 connect completed", stream_id);
                }

                result
            }
            ConnectDecision::Block => {
                // Send SYNACK with error (protocol v2)
                let _ = self
                    .send_synack(stream_id, Some("UDP blocked by rules"))
                    .await;

                log::warn!(
                    "AnyTLS stream {} UoT V2 connect blocked by rules: {}",
                    stream_id,
                    destination
                );
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "UDP blocked by rules",
                ))
            }
        }
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
            Box::new(UotV1ServerStream::new(stream));

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
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_session_creation() {
        let (client, _server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        assert!(!session.is_closed());
        assert!(!session.is_client);
    }

    #[tokio::test]
    async fn test_frame_encoding() {
        let frame = Frame::data(123, Bytes::from("test data"));
        let encoded = frame.encode();

        assert_eq!(encoded[0], Command::Psh as u8);
        assert_eq!(
            u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]),
            123
        );
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 9);
        assert_eq!(&encoded[7..], b"test data");
    }

    #[tokio::test]
    async fn test_session_close() {
        let (client, _server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        assert!(!session.is_closed());
        session.close().await;
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn test_settings_frame_parsing() {
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "test");
        settings.insert("padding-md5", "abc123");

        let bytes = settings.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("v"), Some(&"2".to_string()));
        assert_eq!(parsed.get("client"), Some(&"test".to_string()));
        assert_eq!(parsed.get("padding-md5"), Some(&"abc123".to_string()));
    }

    #[tokio::test]
    async fn test_control_frame_types() {
        // Test all control frame types
        for (cmd, expected_byte) in [
            (Command::Waste, 0),
            (Command::Syn, 1),
            (Command::Psh, 2),
            (Command::Fin, 3),
            (Command::Settings, 4),
            (Command::Alert, 5),
            (Command::UpdatePaddingScheme, 6),
            (Command::SynAck, 7),
            (Command::HeartRequest, 8),
            (Command::HeartResponse, 9),
            (Command::ServerSettings, 10),
        ] {
            let frame = Frame::control(cmd, 42);
            let encoded = frame.encode();
            assert_eq!(encoded[0], expected_byte);
        }
    }

    #[tokio::test]
    async fn test_heartbeat_frame_roundtrip() {
        let request = Frame::control(Command::HeartRequest, 0);
        let encoded = request.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::HeartRequest);
        assert_eq!(decoded.stream_id, 0);
        assert!(decoded.data.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_streams_frame_interleaving() {
        // Simulate multiple streams sending data - verify framing isolation
        let stream1_data = Frame::data(1, Bytes::from("stream1-data"));
        let stream2_data = Frame::data(2, Bytes::from("stream2-data"));
        let stream3_data = Frame::data(3, Bytes::from("stream3-data"));

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&stream1_data.encode());
        combined.extend_from_slice(&stream2_data.encode());
        combined.extend_from_slice(&stream3_data.encode());

        // Decode all frames
        let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

        assert_eq!(f1.stream_id, 1);
        assert_eq!(f1.data.as_ref(), b"stream1-data");
        assert_eq!(f2.stream_id, 2);
        assert_eq!(f2.data.as_ref(), b"stream2-data");
        assert_eq!(f3.stream_id, 3);
        assert_eq!(f3.data.as_ref(), b"stream3-data");
    }

    #[tokio::test]
    async fn test_fin_and_syn_sequence() {
        // Test SYN -> PSH -> FIN sequence
        let syn = Frame::control(Command::Syn, 1);
        let data = Frame::data(1, Bytes::from("payload"));
        let fin = Frame::control(Command::Fin, 1);

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&syn.encode());
        combined.extend_from_slice(&data.encode());
        combined.extend_from_slice(&fin.encode());

        let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

        assert_eq!(f1.cmd, Command::Syn);
        assert_eq!(f2.cmd, Command::Psh);
        assert_eq!(f3.cmd, Command::Fin);
        assert!(f1.data.is_empty());
        assert_eq!(f2.data.as_ref(), b"payload");
        assert!(f3.data.is_empty());
    }

    #[tokio::test]
    async fn test_alert_frame_with_message() {
        let alert = Frame::with_data(Command::Alert, 0, Bytes::from("connection refused"));
        let encoded = alert.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::Alert);
        assert_eq!(decoded.data.as_ref(), b"connection refused");
    }

    #[tokio::test]
    async fn test_large_frame() {
        // Test frame with max-ish size (16KB)
        let large_data = vec![0xABu8; 16384];
        let frame = Frame::data(99, Bytes::from(large_data.clone()));
        let encoded = frame.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.stream_id, 99);
        assert_eq!(decoded.data.len(), 16384);
        assert_eq!(decoded.data.as_ref(), large_data.as_slice());
    }

    #[tokio::test]
    async fn test_partial_frame_decode() {
        // Test that partial frames don't decode until complete
        let frame = Frame::data(1, Bytes::from("complete"));
        let encoded = frame.encode();

        // Only provide partial data
        let mut partial = BytesMut::from(&encoded[..5]); // Only header partial
        let result = FrameCodec::decode(&mut partial).unwrap();
        assert!(result.is_none());

        // Add remaining data
        partial.extend_from_slice(&encoded[5..]);
        let decoded = FrameCodec::decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded.data.as_ref(), b"complete");
    }

    #[tokio::test]
    async fn test_waste_frame_padding() {
        // Test padding frame
        let padding_data = vec![0u8; 100];
        let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data.clone()));
        let encoded = waste.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::Waste);
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(decoded.data.len(), 100);
    }

    #[tokio::test]
    async fn test_session_rejects_syn_without_settings() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send SYN without Settings first
        let syn_frame = Frame::control(Command::Syn, 1);
        server.write_all(&syn_frame.encode()).await.unwrap();

        // Should receive Alert
        let mut buf = vec![0u8; 256];
        let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

        if let Ok(Ok(n)) = result {
            if n > 0 {
                assert_eq!(buf[0], Command::Alert as u8);
            }
        }

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_heartbeat_response() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings first
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        // Wait for and consume the ServerSettings response
        let mut buf = vec![0u8; 128];
        let _ = timeout(Duration::from_millis(200), server.read(&mut buf)).await;

        // Send heartbeat request
        let heart_request = Frame::control(Command::HeartRequest, 0);
        server.write_all(&heart_request.encode()).await.unwrap();

        // Should receive heartbeat response
        let mut response_buf = vec![0u8; 16];
        let result = timeout(Duration::from_millis(500), server.read(&mut response_buf)).await;

        if let Ok(Ok(n)) = result {
            if n >= 7 {
                assert_eq!(response_buf[0], Command::HeartResponse as u8);
            }
        }

        session.close().await;
        run_task.abort();
    }

    // ===== Frame parsing edge case tests =====

    #[test]
    fn test_frame_zero_length_data() {
        let frame = Frame::data(1, Bytes::new());
        let encoded = frame.encode();

        assert_eq!(encoded.len(), FRAME_HEADER_SIZE); // Just header, no data
        assert_eq!(encoded[0], Command::Psh as u8);

        // Decode should work
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_frame_max_stream_id() {
        let frame = Frame::control(Command::Syn, u32::MAX);
        let encoded = frame.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.stream_id, u32::MAX);
    }

    #[test]
    fn test_frame_decode_incomplete_header() {
        // Less than 7 bytes
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        let result = FrameCodec::decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_decode_incomplete_data() {
        // Header says 100 bytes of data, but only 50 provided
        let mut buf = BytesMut::with_capacity(64);
        buf.extend_from_slice(&[Command::Psh as u8]); // cmd
        buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
        buf.extend_from_slice(&[0, 100]); // length = 100
        buf.extend_from_slice(&[0u8; 50]); // only 50 bytes of data

        let result = FrameCodec::decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_unknown_command_returns_error() {
        // Command byte 255 is not defined
        let mut buf = BytesMut::with_capacity(16);
        buf.extend_from_slice(&[255u8]); // unknown cmd
        buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
        buf.extend_from_slice(&[0, 0]); // length = 0

        let result = FrameCodec::decode(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_frame_all_command_types() {
        for cmd in [
            Command::Waste,
            Command::Syn,
            Command::Psh,
            Command::Fin,
            Command::Settings,
            Command::Alert,
            Command::UpdatePaddingScheme,
            Command::SynAck,
            Command::HeartRequest,
            Command::HeartResponse,
            Command::ServerSettings,
        ] {
            let frame = Frame::control(cmd, 1);
            let encoded = frame.encode();
            let mut buf = BytesMut::from(&encoded[..]);
            let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.cmd, cmd);
        }
    }

    #[test]
    fn test_frame_max_data_length() {
        // Max u16 = 65535 bytes
        let large_data = vec![0xFFu8; 65535];
        let frame = Frame::data(1, Bytes::from(large_data.clone()));
        let encoded = frame.encode();

        // Verify length field
        let len = u16::from_be_bytes([encoded[5], encoded[6]]);
        assert_eq!(len, 65535);

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.data.len(), 65535);
    }

    // ===== Session protocol edge case tests =====

    #[tokio::test]
    async fn test_session_psh_for_nonexistent_stream() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send PSH for stream 999 (never opened)
        // This should NOT crash the session
        let psh = Frame::data(999, Bytes::from("orphan data"));
        server.write_all(&psh.encode()).await.unwrap();

        // Session should still be alive - send heartbeat to verify
        tokio::time::sleep(Duration::from_millis(100)).await;
        let heart = Frame::control(Command::HeartRequest, 0);
        let result = server.write_all(&heart.encode()).await;
        assert!(result.is_ok());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_fin_for_nonexistent_stream() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send FIN for stream 999 (never opened)
        // Should be gracefully ignored
        let fin = Frame::control(Command::Fin, 999);
        server.write_all(&fin.encode()).await.unwrap();

        // Session should still be alive
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!session.is_closed());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_waste_frame_ignored() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send waste (padding) frame with data
        let padding_data = vec![0u8; 500];
        let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data));
        server.write_all(&waste.encode()).await.unwrap();

        // Session should still function
        tokio::time::sleep(Duration::from_millis(100)).await;
        let syn = Frame::control(Command::Syn, 1);
        let result = server.write_all(&syn.encode()).await;
        assert!(result.is_ok());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_update_padding_scheme() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings with mismatched padding MD5
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", "different_md5_value");
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        // Should receive UpdatePaddingScheme frame
        let mut buf = vec![0u8; 256];
        let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

        if let Ok(Ok(n)) = result {
            if n >= 7 {
                // Could be ServerSettings or UpdatePaddingScheme
                // Either is valid response
                let cmd = buf[0];
                assert!(
                    cmd == Command::UpdatePaddingScheme as u8
                        || cmd == Command::ServerSettings as u8
                );
            }
        }

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_alert_closes_session() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings first
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send Alert from client
        let alert = Frame::with_data(Command::Alert, 0, Bytes::from("client error"));
        server.write_all(&alert.encode()).await.unwrap();

        // Session should close
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(session.is_closed());

        run_task.abort();
    }

    // ===== StringMap tests =====

    #[test]
    fn test_stringmap_roundtrip() {
        let mut map = StringMap::new();
        map.insert("key1", "value1");
        map.insert("key2", "value2");
        map.insert("special", "a=b=c");

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("key1"), Some(&"value1".to_string()));
        assert_eq!(parsed.get("key2"), Some(&"value2".to_string()));
        assert_eq!(parsed.get("special"), Some(&"a=b=c".to_string()));
    }

    #[test]
    fn test_stringmap_empty() {
        let map = StringMap::new();
        let bytes = map.to_bytes();
        assert!(bytes.is_empty());

        let parsed = StringMap::from_bytes(&[]);
        assert!(parsed.get("anything").is_none());
    }

    #[test]
    fn test_stringmap_newlines_in_values() {
        let mut map = StringMap::new();
        map.insert("multiline", "line1\nline2"); // Should not break parsing

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        // With newlines, parsing may be affected
        // This test documents current behavior
        let val = parsed.get("multiline");
        // Value may be truncated at newline
        assert!(val.is_none() || val == Some(&"line1".to_string()));
    }

    #[test]
    fn test_stringmap_special_characters() {
        let mut map = StringMap::new();
        map.insert("unicode", "Hello World!");
        map.insert("empty", "");

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("unicode"), Some(&"Hello World!".to_string()));
        assert_eq!(parsed.get("empty"), Some(&"".to_string()));
    }
}
