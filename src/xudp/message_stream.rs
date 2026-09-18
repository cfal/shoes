// XUDP message stream - protocol-agnostic UDP session multiplexing
// Wraps any AsyncStream and provides XUDP frame encoding/decoding with session management
// Used by both VLESS and VMess protocols

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage, AsyncSessionMessageStream,
    AsyncShutdownMessage, AsyncStream, AsyncWriteSessionMessage, MessageSessionId,
};
use crate::resolver::{NativeResolver, ResolverCache};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};

pub(crate) const MAX_XUDP_ROUTES: usize = 1024;

pub struct XudpMessageStream {
    /// Underlying byte stream (VLESS VisionStream, VMess stream, or any TLS stream) that reads/writes raw XUDP frame bytes
    inner_stream: Box<dyn AsyncStream>,

    /// Read buffer for incoming XUDP frames
    read_buffer: BytesMut,

    /// Write buffer for outgoing XUDP frames
    write_buffer: BytesMut,

    next_route_id: MessageSessionId,

    /// Active protocol sessions and their independently routed destinations.
    wire_sessions: HashMap<u16, WireSession>,

    /// Translates router identities back to protocol session IDs and destinations.
    routes: HashMap<MessageSessionId, RoutedSession>,

    /// Route identities whose protocol session has ended.
    closed_routes: VecDeque<MessageSessionId>,

    /// Resolver cache for hostname resolution
    /// Resolves hostnames to IPs before storing in session maps
    resolver_cache: ResolverCache,

    /// Buffered incoming message waiting for destination resolution.
    incoming_message: Option<(Vec<u8>, NetLocation, u16)>,

    /// EOF flag
    is_eof: bool,
}

struct WireSession {
    default_destination: NetLocation,
    routes: HashMap<NetLocation, MessageSessionId>,
}

struct RoutedSession {
    wire_session_id: u16,
    original_destination: NetLocation,
}

impl XudpMessageStream {
    pub fn new(inner_stream: Box<dyn AsyncStream>) -> Self {
        Self::new_with_resolver(inner_stream, Arc::new(NativeResolver::new()))
    }

    pub(crate) fn new_with_resolver(
        inner_stream: Box<dyn AsyncStream>,
        resolver: Arc<dyn crate::resolver::Resolver>,
    ) -> Self {
        Self {
            inner_stream,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::with_capacity(65536),
            next_route_id: 1,
            wire_sessions: HashMap::new(),
            routes: HashMap::new(),
            closed_routes: VecDeque::new(),
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

    fn allocate_route_id(&mut self) -> std::io::Result<MessageSessionId> {
        let id = self.next_route_id;
        self.next_route_id = self.next_route_id.checked_add(1).ok_or_else(|| {
            std::io::Error::other("XUDP internal session identifier space exhausted")
        })?;
        Ok(id)
    }

    fn close_wire_session(&mut self, wire_session_id: u16) {
        let Some(session) = self.wire_sessions.remove(&wire_session_id) else {
            return;
        };
        for route_id in session.routes.into_values() {
            self.routes.remove(&route_id);
            self.closed_routes.push_back(route_id);
        }
    }

    fn start_wire_session(&mut self, wire_session_id: u16, destination: NetLocation) {
        self.close_wire_session(wire_session_id);
        self.wire_sessions.insert(
            wire_session_id,
            WireSession {
                default_destination: destination,
                routes: HashMap::new(),
            },
        );
    }

    fn get_or_create_route(
        &mut self,
        wire_session_id: u16,
        original_destination: &NetLocation,
    ) -> std::io::Result<Option<MessageSessionId>> {
        let Some(session) = self.wire_sessions.get(&wire_session_id) else {
            return Ok(None);
        };
        if let Some(route_id) = session.routes.get(original_destination) {
            return Ok(Some(*route_id));
        }
        if self.routes.len() >= MAX_XUDP_ROUTES {
            log::warn!(
                "[XUDP SESSION READ] Dropping packet for new destination {} after reaching the {}-route limit",
                original_destination,
                MAX_XUDP_ROUTES
            );
            return Ok(None);
        }

        let route_id = self.allocate_route_id()?;
        self.wire_sessions
            .get_mut(&wire_session_id)
            .expect("wire session disappeared during route allocation")
            .routes
            .insert(original_destination.clone(), route_id);
        self.routes.insert(
            route_id,
            RoutedSession {
                wire_session_id,
                original_destination: original_destination.clone(),
            },
        );
        Ok(Some(route_id))
    }

    /// Try to decode one complete XUDP frame from the read buffer.
    ///
    /// This function must NOT consume any bytes from the buffer unless
    /// it successfully decodes a complete frame. Otherwise, partial frames would
    /// be lost when the function is called again with more data.
    ///
    /// Returns:
    ///   Ok(Some((data, destination, session_id))) - Successfully decoded a complete frame
    ///   Ok(None) - Buffer doesn't contain a complete frame yet (need more data)
    ///   Err(e) - Error during decoding
    fn try_decode_one_frame(&mut self) -> std::io::Result<Option<(Vec<u8>, NetLocation, u16)>> {
        loop {
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

            let metadata_len =
                u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

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

            let option_byte = self.read_buffer[2 + 3];
            let has_data = option_byte & FrameOption::DATA != 0;
            let data_len_offset = 2 + metadata_len;
            if has_data && self.read_buffer.len() < data_len_offset + 2 {
                log::debug!("[XUDP READ] Buffer too short for data length field");
                return Ok(None);
            }

            let data_len = if has_data {
                u16::from_be_bytes([
                    self.read_buffer[data_len_offset],
                    self.read_buffer[data_len_offset + 1],
                ]) as usize
            } else {
                0
            };

            let total_frame_len = data_len_offset + usize::from(has_data) * (2 + data_len);
            if self.read_buffer.len() < total_frame_len {
                log::debug!(
                    "[XUDP READ] Buffer too short for complete frame: have {}, need {}",
                    self.read_buffer.len(),
                    total_frame_len
                );
                return Ok(None);
            }

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

            if has_data {
                self.read_buffer.advance(2);
            }
            let data = self.read_buffer.split_to(data_len).to_vec();

            if metadata.status == SessionStatus::End {
                self.close_wire_session(metadata.session_id);
                continue;
            }

            if metadata.status == SessionStatus::KeepAlive {
                continue;
            }

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

            let destination = match metadata.status {
                SessionStatus::New => {
                    let target = metadata.target.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "XUDP New frame is missing its destination",
                        )
                    })?;
                    self.start_wire_session(metadata.session_id, target.clone());
                    target
                }
                SessionStatus::Keep => {
                    let Some(session) = self.wire_sessions.get(&metadata.session_id) else {
                        log::warn!(
                            "[XUDP READ] Ignoring data for unknown session {}",
                            metadata.session_id
                        );
                        continue;
                    };
                    metadata
                        .target
                        .unwrap_or_else(|| session.default_destination.clone())
                }
                SessionStatus::End | SessionStatus::KeepAlive => unreachable!(),
            };

            if !has_data || data.is_empty() {
                continue;
            }

            log::debug!(
                "[XUDP READ] Decoded complete frame with {} bytes for destination {}",
                data.len(),
                destination
            );
            return Ok(Some((data, destination, metadata.session_id)));
        }
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
    ) -> Poll<std::io::Result<(MessageSessionId, SocketAddr)>> {
        let this = self.get_mut();

        // Return buffered message if available
        if let Some((data, original_destination, wire_session_id)) = this.incoming_message.take() {
            if data.len() > buf.remaining() {
                this.incoming_message = Some((data, original_destination, wire_session_id));
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "buffer too small for incoming message",
                )));
            }

            if let Some(session_id) =
                this.get_or_create_route(wire_session_id, &original_destination)?
            {
                let socket_addr = match this
                    .resolver_cache
                    .poll_resolve_location(cx, &original_destination)
                {
                    Poll::Ready(result) => result?,
                    Poll::Pending => {
                        this.incoming_message = Some((data, original_destination, wire_session_id));
                        return Poll::Pending;
                    }
                };

                buf.put_slice(&data);
                return Poll::Ready(Ok((session_id, socket_addr)));
            }
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
                Some((data, destination, wire_session_id)) => {
                    let Some(session_id) =
                        this.get_or_create_route(wire_session_id, &destination)?
                    else {
                        log::warn!(
                            "[XUDP SESSION READ] Dropping data without an admitted route for session {}",
                            wire_session_id
                        );
                        continue;
                    };

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
                                this.incoming_message = Some((data, destination, wire_session_id));
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

                    log::debug!(
                        "[XUDP SESSION READ] Session {} mapped to {}",
                        session_id,
                        resolved_destination
                    );

                    // Successfully decoded a frame
                    if data.len() > buf.remaining() {
                        // Buffer it with resolved destination for next read
                        this.incoming_message = Some((data, destination, wire_session_id));
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

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        self.closed_routes.pop_front()
    }
}

impl AsyncWriteSessionMessage for XudpMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: MessageSessionId,
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

        let Some(route) = self.routes.get(&session_id) else {
            log::debug!(
                "[XUDP SESSION WRITE] Discarding response for closed route {}",
                session_id
            );
            return Poll::Ready(Ok(()));
        };
        let wire_session_id = route.wire_session_id;
        let target_location = route.original_destination.clone();

        log::debug!(
            "[XUDP SESSION WRITE] Using original destination {} for session {} (response came from {})",
            target_location,
            wire_session_id,
            target
        );

        let metadata = FrameMetadata {
            session_id: wire_session_id,
            status: SessionStatus::Keep,
            option: FrameOption::new().with_data(),
            target: Some(target_location.clone()),
            network: Some(TargetNetwork::Udp),
        };

        log::debug!(
            "[XUDP SESSION WRITE] Encoding {:?} frame: session_id={}, target={}, data_len={}",
            SessionStatus::Keep,
            wire_session_id,
            target_location,
            buf.len()
        );

        // Encode metadata
        metadata.encode(&mut self.write_buffer)?;

        // Write data length
        self.write_buffer.put_u16(buf.len() as u16);

        // Write data
        self.write_buffer.extend_from_slice(buf);

        Poll::Ready(Ok(()))
    }
}

impl AsyncSessionMessageStream for XudpMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker;
    use std::collections::HashSet;
    use std::io;
    use std::sync::Mutex;

    struct PendingOnceWriter {
        output: Arc<Mutex<Vec<u8>>>,
        pending: bool,
    }

    impl AsyncRead for PendingOnceWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingOnceWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.output.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PendingOnceWriter {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for PendingOnceWriter {}

    #[test]
    fn buffered_response_is_accepted_once_when_output_blocks() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let inner = PendingOnceWriter {
            output: Arc::clone(&output),
            pending: true,
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let destination = NetLocation::new(Address::Ipv4("127.0.0.1".parse().unwrap()), 53);
        stream.start_wire_session(10, destination.clone());
        let route_id = stream
            .get_or_create_route(10, &destination)
            .unwrap()
            .unwrap();
        let source = "127.0.0.1:53".parse().unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_message(&mut cx, route_id, b"x", &source),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_flush_message(&mut cx),
            Poll::Pending
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_flush_message(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            *output.lock().unwrap(),
            [0, 12, 0, 10, 2, 1, 2, 0, 53, 1, 127, 0, 0, 1, 0, 1, b'x']
        );
    }

    #[test]
    fn closed_routes_cannot_emit_or_reuse_internal_ids() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let inner = PendingOnceWriter {
            output: Arc::clone(&output),
            pending: false,
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let destination = NetLocation::new(Address::Ipv4("127.0.0.1".parse().unwrap()), 53);
        stream.start_wire_session(0, destination.clone());
        let old_route = stream
            .get_or_create_route(0, &destination)
            .unwrap()
            .unwrap();
        stream.close_wire_session(0);
        assert_eq!(stream.take_closed_session(), Some(old_route));
        assert_eq!(stream.take_closed_session(), None);

        let source = "127.0.0.1:53".parse().unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_message(&mut cx, old_route, b"late", &source),
            Poll::Ready(Ok(()))
        ));
        assert!(output.lock().unwrap().is_empty());

        stream.start_wire_session(0, destination.clone());
        let new_route = stream
            .get_or_create_route(0, &destination)
            .unwrap()
            .unwrap();
        assert_ne!(new_route, old_route);
    }

    #[test]
    fn route_limit_preserves_existing_routes_and_releases_closed_routes() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let inner = PendingOnceWriter {
            output,
            pending: false,
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let address = Address::Ipv4("127.0.0.1".parse().unwrap());
        let first_destination = NetLocation::new(address.clone(), 1);
        stream.start_wire_session(10, first_destination.clone());
        let preserved_destination = NetLocation::new(address.clone(), u16::MAX);
        stream.start_wire_session(20, preserved_destination.clone());

        let first_route = stream
            .get_or_create_route(10, &first_destination)
            .unwrap()
            .unwrap();
        let preserved_route = stream
            .get_or_create_route(20, &preserved_destination)
            .unwrap()
            .unwrap();
        assert_eq!(
            stream.get_or_create_route(10, &first_destination).unwrap(),
            Some(first_route)
        );

        for port in 2..MAX_XUDP_ROUTES as u16 {
            let destination = NetLocation::new(address.clone(), port);
            assert!(
                stream
                    .get_or_create_route(10, &destination)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(stream.routes.len(), MAX_XUDP_ROUTES);
        assert_eq!(
            stream.get_or_create_route(10, &first_destination).unwrap(),
            Some(first_route)
        );
        assert_eq!(
            stream
                .get_or_create_route(20, &preserved_destination)
                .unwrap(),
            Some(preserved_route)
        );

        let rejected_destination = NetLocation::new(address.clone(), u16::MAX - 1);
        let error = stream
            .get_or_create_route(20, &rejected_destination)
            .unwrap();
        assert_eq!(error, None);
        assert_eq!(stream.routes.len(), MAX_XUDP_ROUTES);

        stream.close_wire_session(10);
        assert_eq!(stream.routes.len(), 1);
        assert!(stream.routes.contains_key(&preserved_route));
        let closed_routes: HashSet<_> =
            std::iter::from_fn(|| stream.take_closed_session()).collect();
        assert_eq!(closed_routes.len(), MAX_XUDP_ROUTES - 1);
        assert!(closed_routes.contains(&first_route));
        assert!(!closed_routes.contains(&preserved_route));
        assert_eq!(stream.take_closed_session(), None);

        assert!(
            stream
                .get_or_create_route(20, &rejected_destination)
                .unwrap()
                .is_some()
        );
    }
}
