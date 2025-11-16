use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage, AsyncSessionMessageStream,
    AsyncShutdownMessage, AsyncWriteSessionMessage,
};
use crate::socket_util::new_udp_socket;

/// Configuration for creating UDP sockets for each session.
/// Preserves user's interface binding configuration.
#[derive(Clone, Debug)]
pub struct UdpSocketConfig {
    /// Optional network interface to bind sockets to (e.g., "tun0" for VPN)
    pub bind_interface: Option<String>,
}

/// Message from a session socket reader task containing data received from a UDP peer.
struct SessionMessage {
    session_id: u16,
    data: Vec<u8>,
    source_addr: SocketAddr,
}

/// Session-based UDP message stream that manages dedicated UDP sockets for each session.
/// Used for protocols like XUDP that require socket-per-session architecture.
/// This eliminates the need for destination-based session mapping by using socket identity
/// as session identity.
pub struct UdpSessionMessageStream {
    /// Receives messages from all session socket readers
    receiver: mpsc::UnboundedReceiver<SessionMessage>,
    /// Used to send to session socket readers (cloned for each new session)
    sender: mpsc::UnboundedSender<SessionMessage>,
    /// Maps session ID to the sender for that session's writer task
    session_writers: HashMap<u16, mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    /// Configuration for creating new UDP sockets
    config: UdpSocketConfig,
    /// Counter for session IDs (not used yet, reserved for future session creation API)
    _next_session_id: u16,
}

impl UdpSessionMessageStream {
    /// Creates a new UdpSessionMessageStream with the specified configuration.
    pub fn new(config: UdpSocketConfig) -> Self {
        // Use unbounded channel for maximum performance (no backpressure)
        let (sender, receiver) = mpsc::unbounded_channel();

        Self {
            receiver,
            sender,
            session_writers: HashMap::new(),
            config,
            _next_session_id: 0,
        }
    }

    /// Creates a new session with a dedicated UDP socket.
    /// Returns the session ID that was created.
    ///
    /// This spawns two tasks:
    /// - Reader task: reads from UDP socket and sends to manager's channel
    /// - Writer task: receives write requests and sends to UDP socket
    pub fn create_session(&mut self, session_id: u16, is_ipv6: bool) -> std::io::Result<()> {
        // Create dedicated UDP socket for this session
        let socket = new_udp_socket(is_ipv6, self.config.bind_interface.clone())?;
        let socket = Arc::new(socket);

        // Create channel for write requests to this session
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();

        // Spawn reader task
        let reader_socket = socket.clone();
        let reader_sender = self.sender.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match reader_socket.recv_from(&mut buf).await {
                    Ok((len, source_addr)) => {
                        let data = buf[..len].to_vec();
                        let msg = SessionMessage {
                            session_id,
                            data,
                            source_addr,
                        };

                        // For unbounded channels, send() doesn't need to be awaited
                        if reader_sender.send(msg).is_err() {
                            // Manager dropped, exit reader task
                            log::debug!(
                                "[Session {}] Manager dropped, stopping reader",
                                session_id
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("[Session {}] UDP recv error: {}", session_id, e);
                        break;
                    }
                }
            }
        });

        // Spawn writer task
        let writer_socket = socket.clone();
        tokio::spawn(async move {
            while let Some((data, target_addr)) = write_rx.recv().await {
                match writer_socket.send_to(&data, target_addr).await {
                    Ok(sent) => {
                        log::debug!(
                            "[Session {}] Sent {} bytes to {}",
                            session_id,
                            sent,
                            target_addr
                        );
                    }
                    Err(e) => {
                        log::error!("[Session {}] UDP send error: {}", session_id, e);
                        break;
                    }
                }
            }
            log::debug!("[Session {}] Writer task exiting", session_id);
        });

        // Store the writer channel
        self.session_writers.insert(session_id, write_tx);

        log::info!(
            "[Session {}] Created dedicated UDP socket (IPv6: {})",
            session_id,
            is_ipv6
        );
        Ok(())
    }

    /// Removes a session and its associated socket.
    /// The socket will be closed when the writer task exits.
    /// TODO: why isn't this used? add session cleanup
    #[allow(dead_code)]
    pub fn remove_session(&mut self, session_id: u16) {
        if self.session_writers.remove(&session_id).is_some() {
            log::info!("[Session {}] Removed session", session_id);
        }
    }
}

impl AsyncReadSessionMessage for UdpSessionMessageStream {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        // Poll the receiver for messages from any session socket
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(msg)) => {
                // Write the data to the buffer
                let len = msg.data.len();
                if buf.remaining() < len {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Buffer too small: need {} bytes, have {}",
                            len,
                            buf.remaining()
                        ),
                    )));
                }

                buf.put_slice(&msg.data);
                Poll::Ready(Ok((msg.session_id, msg.source_addr)))
            }
            Poll::Ready(None) => {
                // All session sockets dropped
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "All session sockets closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteSessionMessage for UdpSessionMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        // Auto-create session if it doesn't exist yet
        if !self.session_writers.contains_key(&session_id) {
            let is_ipv6 = target.is_ipv6();
            if let Err(e) = self.create_session(session_id, is_ipv6) {
                return Poll::Ready(Err(e));
            }
        }

        // Get the writer channel for this session
        match self.session_writers.get(&session_id) {
            Some(writer) => {
                let data = buf.to_vec();
                let target_addr = *target;

                // Send write request to the writer task
                // For unbounded channels, send() doesn't need to be awaited
                if writer.send((data, target_addr)).is_err() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("Session {} writer task closed", session_id),
                    )));
                }

                Poll::Ready(Ok(()))
            }
            None => {
                // Should never happen because we just created it above
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Session {} not found", session_id),
                )))
            }
        }
    }
}

impl AsyncFlushMessage for UdpSessionMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // UDP is connectionless, no flushing needed
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSessionMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Close all sessions
        self.session_writers.clear();
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for UdpSessionMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncSessionMessageStream for UdpSessionMessageStream {}
