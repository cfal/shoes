// XUDP message stream - protocol-agnostic UDP session multiplexing
// Wraps any AsyncStream and provides XUDP frame encoding/decoding with session management
// Used by both VLESS and VMess protocols

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage, AsyncSessionMessageStream,
    AsyncShutdownMessage, AsyncStream, AsyncWriteSessionMessage,
};
use crate::resolver::{NativeResolver, ResolverCache};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};

pub struct XudpMessageStream {
    /// Underlying byte stream (VLESS VisionStream, VMess stream, or any TLS stream) that reads/writes raw XUDP frame bytes
    inner_stream: Box<dyn AsyncStream>,

    /// Read buffer for incoming XUDP frames
    read_buffer: BytesMut,

    /// Write buffer for outgoing XUDP frames
    write_buffer: BytesMut,

    /// Session ID counter (starts at 1, wraps at u16::MAX)
    next_session_id: u16,

    /// Active sessions: destination (RESOLVED IP) -> session_id
    /// Keys are always resolved IP addresses, never hostnames
    /// This ensures responses from UDP sockets (which give us IPs) can find the correct session
    destination_to_session: HashMap<NetLocation, u16>,

    /// Reverse mapping: session_id -> destination (RESOLVED IP)
    /// Used to remember which session_id maps to which destination
    session_to_destination: HashMap<u16, NetLocation>,

    /// Maps session_id -> ORIGINAL destination (before resolution)
    /// This preserves hostnames for encoding in response frames
    session_to_original_destination: HashMap<u16, NetLocation>,

    /// Resolver cache for hostname resolution
    /// Resolves hostnames to IPs before storing in session maps
    resolver_cache: ResolverCache,

    /// Buffered incoming message (if we read a complete frame)
    /// Stores: (data, original_destination, optional_resolved_destination)
    /// If resolved_destination is None, we still need to resolve it
    incoming_message: Option<(Vec<u8>, NetLocation, Option<NetLocation>)>,

    /// EOF flag
    is_eof: bool,
}

impl XudpMessageStream {
    pub fn new(inner_stream: Box<dyn AsyncStream>) -> Self {
        // Create resolver implicitly like UdpMessageStream does
        let resolver = Arc::new(NativeResolver::new());
        Self {
            inner_stream,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::with_capacity(65536),
            next_session_id: 1,
            destination_to_session: HashMap::new(),
            session_to_destination: HashMap::new(),
            session_to_original_destination: HashMap::new(),
            resolver_cache: ResolverCache::new(resolver),
            incoming_message: None,
            is_eof: false,
        }
    }

    /// Feed initial unparsed data into the read buffer
    /// Used when protocol header parsing (VLESS/VMess) consumed data that belongs to XUDP frames
    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        log::debug!(
            "[XUDP] Feeding {} bytes of initial data to read buffer",
            data.len()
        );
        self.read_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Allocate new session ID
    fn allocate_session_id(&mut self) -> u16 {
        loop {
            let id = self.next_session_id;
            self.next_session_id = self.next_session_id.wrapping_add(1);
            if self.next_session_id == 0 {
                self.next_session_id = 1; // Skip 0
            }

            // Check if ID is already in use (unlikely with u16 space)
            if !self.session_to_destination.contains_key(&id) {
                return id;
            }
        }
    }

    /// Get or create session ID for destination, preserving original address
    /// resolved_destination: IP address (used for reverse lookup from UDP responses)
    /// original_destination: Original address from XUDP frame (may be hostname, used in response frames)
    fn get_or_create_session(
        &mut self,
        resolved_destination: &NetLocation,
        original_destination: &NetLocation,
    ) -> (u16, bool) {
        if let Some(&session_id) = self.destination_to_session.get(resolved_destination) {
            log::debug!(
                "[XUDP] Found existing session {} for destination {}",
                session_id,
                resolved_destination
            );
            (session_id, false) // Existing session
        } else {
            let session_id = self.allocate_session_id();
            log::debug!(
                "[XUDP] Creating NEW session {} for resolved dest {} (original: {})",
                session_id,
                resolved_destination,
                original_destination
            );
            self.destination_to_session
                .insert(resolved_destination.clone(), session_id);
            self.session_to_destination
                .insert(session_id, resolved_destination.clone());
            // Store original destination for use in response frames
            self.session_to_original_destination
                .insert(session_id, original_destination.clone());
            log::debug!(
                "[XUDP] Session maps updated. Total sessions: {}",
                self.destination_to_session.len()
            );
            (session_id, true) // New session
        }
    }

    /// Try to decode one complete XUDP frame from the read buffer.
    ///
    /// This function must NOT consume any bytes from the buffer unless
    /// it successfully decodes a complete frame. Otherwise, partial frames would
    /// be lost when the function is called again with more data.
    ///
    /// Returns:
    ///   Ok(Some((data, destination))) - Successfully decoded a complete frame
    ///   Ok(None) - Buffer doesn't contain a complete frame yet (need more data)
    ///   Err(e) - Error during decoding
    fn try_decode_one_frame(&mut self) -> std::io::Result<Option<(Vec<u8>, NetLocation)>> {
        log::debug!(
            "[XUDP READ] Attempting to decode frame, buffer len: {}",
            self.read_buffer.len()
        );

        // First, peek at the buffer to determine total frame size WITHOUT consuming anything.
        // We need to check: metadata_len (2 bytes) + metadata + data_len (2 bytes) + data

        // Need at least 2 bytes for metadata length
        if self.read_buffer.len() < 2 {
            log::debug!("[XUDP READ] Buffer too short for metadata length field");
            return Ok(None);
        }

        let metadata_len = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

        // Check if we have complete metadata
        if self.read_buffer.len() < 2 + metadata_len {
            log::debug!("[XUDP READ] Buffer too short for complete metadata");
            return Ok(None);
        }

        // Peek at metadata to check if frame has data
        if metadata_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("metadata too short: {}", metadata_len),
            ));
        }

        // Peek at status and option bytes (at offset 2 + 2 + 1 = 5 for status, 6 for option)
        let status_byte = self.read_buffer[2 + 2]; // Skip metadata_len(2) + session_id(2)
        let option_byte = self.read_buffer[2 + 3]; // Skip metadata_len(2) + session_id(2) + status(1)

        let has_data = (option_byte & 0x01) != 0; // FrameOption::DATA = 0x01
        let is_end = status_byte == 0x03; // SessionStatus::End
        let is_keepalive = status_byte == 0x04; // SessionStatus::KeepAlive

        // For End or KeepAlive frames, or frames without data, we only need the metadata
        if is_end || is_keepalive || !has_data {
            // We have enough data to decode this frame - proceed with actual decode
            let metadata = FrameMetadata::decode(&mut self.read_buffer)?
                .expect("metadata decode should succeed after length check");

            log::debug!(
                "[XUDP READ] Decoded frame: session_id={}, status={:?}, has_data={}, target={:?}, network={:?}",
                metadata.session_id,
                metadata.status,
                metadata.option.has_data(),
                metadata.target,
                metadata.network
            );

            // Handle session mappings
            if let Some(ref target) = metadata.target {
                log::debug!(
                    "[XUDP READ] Updating session {} mapping to target {}",
                    metadata.session_id,
                    target
                );
                self.session_to_destination
                    .insert(metadata.session_id, target.clone());
                self.session_to_original_destination
                    .insert(metadata.session_id, target.clone());
            }

            if metadata.status == SessionStatus::End {
                if let Some(destination) = self.session_to_destination.remove(&metadata.session_id)
                {
                    self.destination_to_session.remove(&destination);
                }
                self.session_to_original_destination
                    .remove(&metadata.session_id);
                return self.try_decode_one_frame();
            }

            // No data, try to decode next frame
            return self.try_decode_one_frame();
        }

        // Frame has data - check if we have the data length and data
        let data_len_offset = 2 + metadata_len;
        if self.read_buffer.len() < data_len_offset + 2 {
            log::debug!("[XUDP READ] Buffer too short for data length field");
            return Ok(None);
        }

        let data_len = u16::from_be_bytes([
            self.read_buffer[data_len_offset],
            self.read_buffer[data_len_offset + 1],
        ]) as usize;

        // Check if we have all the data
        let total_frame_len = data_len_offset + 2 + data_len;
        if self.read_buffer.len() < total_frame_len {
            log::debug!(
                "[XUDP READ] Buffer too short for complete frame: have {}, need {}",
                self.read_buffer.len(),
                total_frame_len
            );
            return Ok(None);
        }

        // Now we know we have a complete frame - consume it all
        let metadata = FrameMetadata::decode(&mut self.read_buffer)?
            .expect("metadata decode should succeed after length check");

        log::debug!(
            "[XUDP READ] Decoded frame: session_id={}, status={:?}, has_data={}, target={:?}, network={:?}",
            metadata.session_id,
            metadata.status,
            metadata.option.has_data(),
            metadata.target,
            metadata.network
        );

        // Check for TCP destination - we don't support TCP over XUDP
        if let Some(TargetNetwork::Tcp) = metadata.network {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "XUDP with TCP destinations is not supported. Only UDP destinations are supported.",
            ));
        }

        // Check for ERROR option bit - remote side is signaling an error
        if metadata.option.has_error() {
            log::error!(
                "[XUDP READ] Received frame with ERROR option set for session {}",
                metadata.session_id
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "XUDP session closed by remote with error",
            ));
        }

        // Store/update session mapping for session_id → destination
        if let Some(ref target) = metadata.target {
            log::debug!(
                "[XUDP READ] Updating session {} mapping to target {}",
                metadata.session_id,
                target
            );
            self.session_to_destination
                .insert(metadata.session_id, target.clone());
            self.session_to_original_destination
                .insert(metadata.session_id, target.clone());
        }

        // Consume data length (already verified we have it)
        self.read_buffer.advance(2);

        if data_len == 0 {
            // Empty data, try to decode next frame
            return self.try_decode_one_frame();
        }

        // Extract data (already verified we have it)
        let data = self.read_buffer[..data_len].to_vec();
        self.read_buffer.advance(data_len);

        // Determine destination
        let destination = if let Some(ref target) = metadata.target {
            target.clone()
        } else {
            // Look up in session map
            self.session_to_destination
                .get(&metadata.session_id)
                .cloned()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown session ID: {}", metadata.session_id),
                    )
                })?
        };

        log::debug!(
            "[XUDP READ] Decoded complete frame with {} bytes for destination {}",
            data.len(),
            destination
        );
        Ok(Some((data, destination)))
    }
}

impl AsyncFlushMessage for XudpMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while !this.write_buffer.is_empty() {
            let n = ready!(Pin::new(&mut this.inner_stream).poll_write(cx, &this.write_buffer))?;
            this.write_buffer.advance(n);
        }

        Pin::new(&mut this.inner_stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for XudpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.get_mut().inner_stream).poll_shutdown(cx)
    }
}

impl AsyncPing for XudpMessageStream {
    fn supports_ping(&self) -> bool {
        self.inner_stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner_stream).poll_write_ping(cx)
    }
}

impl AsyncReadSessionMessage for XudpMessageStream {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        let this = self.get_mut();

        // Return buffered message if available
        if let Some((data, original_destination, resolved_opt)) = this.incoming_message.take() {
            if data.len() > buf.remaining() {
                // Re-buffer it
                this.incoming_message = Some((data, original_destination, resolved_opt));
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "buffer too small for incoming message",
                )));
            }

            // Resolve if not already resolved
            let resolved_destination = if let Some(resolved) = resolved_opt {
                resolved
            } else {
                match this
                    .resolver_cache
                    .poll_resolve_location(cx, &original_destination)
                {
                    Poll::Ready(Ok(socket_addr)) => match socket_addr {
                        SocketAddr::V4(addr) => {
                            NetLocation::new(Address::Ipv4(*addr.ip()), addr.port())
                        }
                        SocketAddr::V6(addr) => {
                            NetLocation::new(Address::Ipv6(*addr.ip()), addr.port())
                        }
                    },
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        // Re-buffer and wait for DNS
                        this.incoming_message = Some((data, original_destination, None));
                        return Poll::Pending;
                    }
                }
            };

            // Find session ID for resolved destination, preserving original
            let (session_id, _is_new) =
                this.get_or_create_session(&resolved_destination, &original_destination);

            // Convert to SocketAddr for return
            let socket_addr = futures::ready!(
                this.resolver_cache
                    .poll_resolve_location(cx, &original_destination)
            )?;

            buf.put_slice(&data);
            return Poll::Ready(Ok((session_id, socket_addr)));
        }

        if this.is_eof {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF reached",
            )));
        }

        loop {
            // Try to decode a complete frame from the read buffer
            match this.try_decode_one_frame()? {
                Some((data, destination)) => {
                    // Resolve hostname to IP if needed
                    log::debug!("[XUDP SESSION READ] Resolving destination: {}", destination);
                    let socket_addr =
                        match this.resolver_cache.poll_resolve_location(cx, &destination) {
                            Poll::Ready(Ok(addr)) => addr,
                            Poll::Ready(Err(e)) => {
                                return Poll::Ready(Err(e));
                            }
                            Poll::Pending => {
                                // DNS resolution pending - buffer the frame and wait
                                this.incoming_message = Some((data, destination, None));
                                return Poll::Pending;
                            }
                        };

                    let resolved_destination = match socket_addr {
                        SocketAddr::V4(addr) => {
                            NetLocation::new(Address::Ipv4(*addr.ip()), addr.port())
                        }
                        SocketAddr::V6(addr) => {
                            NetLocation::new(Address::Ipv6(*addr.ip()), addr.port())
                        }
                    };
                    log::debug!(
                        "[XUDP SESSION READ] Resolved {} -> {}",
                        destination,
                        resolved_destination
                    );

                    // Get or create session, preserving original destination (may be hostname)
                    let (session_id, _is_new) =
                        this.get_or_create_session(&resolved_destination, &destination);
                    log::debug!(
                        "[XUDP SESSION READ] Session {} mapped to {}",
                        session_id,
                        resolved_destination
                    );

                    // Successfully decoded a frame
                    if data.len() > buf.remaining() {
                        // Buffer it with resolved destination for next read
                        this.incoming_message =
                            Some((data, destination, Some(resolved_destination)));
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "buffer too small for incoming message",
                        )));
                    }

                    buf.put_slice(&data);
                    log::debug!(
                        "[XUDP SESSION READ] Returning {} bytes for session {} to {}",
                        data.len(),
                        session_id,
                        socket_addr
                    );
                    return Poll::Ready(Ok((session_id, socket_addr)));
                }
                None => {
                    // Buffer doesn't have a complete frame, need to read more data
                }
            }

            // Read more data from inner stream
            let original_filled = this.read_buffer.len();
            this.read_buffer.resize(original_filled + 8192, 0);
            let mut temp_buf = ReadBuf::new(&mut this.read_buffer[original_filled..]);

            log::debug!(
                "[XUDP SESSION READ] Reading from inner stream, current buffer has {} bytes",
                original_filled
            );
            let poll_result = Pin::new(&mut this.inner_stream).poll_read(cx, &mut temp_buf);

            let n = temp_buf.filled().len();
            this.read_buffer.truncate(original_filled + n);

            match ready!(poll_result) {
                Ok(()) => {
                    log::debug!(
                        "[XUDP SESSION READ] Got {} bytes from inner stream (total buffer: {})",
                        n,
                        this.read_buffer.len()
                    );

                    if n == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF reached",
                        )));
                    }

                    // Got new data, continue loop to try decoding again
                    continue;
                }
                Err(e) => {
                    log::error!("[XUDP SESSION READ] Error reading from inner stream: {}", e);
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl AsyncWriteSessionMessage for XudpMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        // This is the reverse direction: UDP response from internet → XUDP client
        // Use original destination (may be hostname) in response frame, NOT resolved IP

        log::debug!(
            "[XUDP SESSION WRITE] Writing {} bytes for session {} from source {}",
            buf.len(),
            session_id,
            target
        );

        // Flush any pending write buffer first
        if !self.write_buffer.is_empty() {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }

        // Check if this is a new session BEFORE looking up or creating entries.
        // XUDP protocol requires first frame for a session to be StatusNew.
        let is_new_session = !self
            .session_to_original_destination
            .contains_key(&session_id);

        // Use original destination (hostname) instead of resolved IP
        // Look up the original destination that the client requested.
        // If not found (e.g., XUDP-to-XUDP forwarding), use the target from the caller
        // and create a new session entry.
        let target_location = if let Some(original) = self
            .session_to_original_destination
            .get(&session_id)
            .cloned()
        {
            original
        } else {
            // Session doesn't exist yet - this happens when forwarding from another XUDP stream.
            // Create a new session using the target address.
            let addr = match target.ip() {
                std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
                std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
            };
            let target_location = NetLocation::new(addr, target.port());
            log::debug!(
                "[XUDP SESSION WRITE] Creating new session {} for destination {} (forwarding mode)",
                session_id,
                target_location
            );
            // Store the mapping for potential future writes with same session_id
            self.session_to_original_destination
                .insert(session_id, target_location.clone());
            let resolved = target_location.clone();
            self.destination_to_session
                .insert(resolved.clone(), session_id);
            self.session_to_destination.insert(session_id, resolved);
            target_location
        };

        log::debug!(
            "[XUDP SESSION WRITE] Using original destination {} for session {} (response came from {})",
            target_location,
            session_id,
            target
        );

        // Build frame with appropriate status (New for first frame, Keep for subsequent)
        let status = if is_new_session {
            log::debug!(
                "[XUDP SESSION WRITE] Sending NEW frame for session {} (first write)",
                session_id
            );
            SessionStatus::New
        } else {
            SessionStatus::Keep
        };

        let metadata = FrameMetadata {
            session_id,
            status,
            option: FrameOption::new().with_data(),
            target: Some(target_location.clone()), // Use ORIGINAL (hostname), not resolved IP!
            network: Some(TargetNetwork::Udp),
        };

        log::debug!(
            "[XUDP SESSION WRITE] Encoding {:?} frame: session_id={}, target={}, data_len={}",
            status,
            session_id,
            target_location,
            buf.len()
        );

        // Encode metadata
        metadata.encode(&mut self.write_buffer)?;

        // Write data length
        self.write_buffer.put_u16(buf.len() as u16);

        // Write data
        self.write_buffer.extend_from_slice(buf);

        // Flush immediately

        self.poll_flush_message(cx)
    }
}

impl AsyncSessionMessageStream for XudpMessageStream {}
