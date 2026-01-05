//! SOCKS5 UDP relay implementation.
//!
//! This module implements the SOCKS5 UDP relay protocol as specified in RFC 1928.
//! When a SOCKS5 client sends a UDP ASSOCIATE request, this module creates a
//! local UDP socket and handles forwarding UDP datagrams between the client
//! and the target destination.
//!
//! SOCKS5 UDP datagram format:
//! ```text
//! | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT | DATA     |
//! | 2    | 1    | 1    | variable | 2        | variable |
//! ```

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use log::{debug, error, warn};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};

/// SOCKS5 address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const ATYP_DOMAIN: u8 = 0x03;

/// Buffer size for receiving from client
const RECEIVE_BUFFER_SIZE: usize = 65536;

/// SOCKS5 UDP relay stream.
///
/// This struct manages a SOCKS5 UDP association, handling the UDP socket
/// and coordinating between the TCP control connection and UDP datagram traffic.
pub struct SocksUdpRelay {
    /// The UDP socket for receiving/sending datagrams
    udp_socket: Arc<UdpSocket>,
    /// Channel for receiving datagrams from the UDP socket
    recv_ch: mpsc::Receiver<(BytesMut, SocketAddr)>,
    /// Flag to indicate shutdown
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl SocksUdpRelay {
    /// Create a new SOCKS5 UDP relay.
    ///
    /// # Arguments
    /// * `udp_socket` - The UDP socket bound for relaying
    pub fn new(udp_socket: Arc<UdpSocket>) -> Self {
        let (tx, recv_ch) = mpsc::channel(128);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let udp_socket_clone = udp_socket.clone();

        // Spawn task to read from UDP socket and send to channel
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECEIVE_BUFFER_SIZE];
            loop {
                if shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match udp_socket_clone.recv_from(&mut buf).await {
                    Ok((len, from_addr)) => {
                        let data = BytesMut::from(&buf[..len]);
                        if tx.send((data, from_addr)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            error!("SOCKS5 UDP recv error: {}", e);
                        }
                        break;
                    }
                }
            }
        });

        Self {
            udp_socket,
            recv_ch,
            shutdown,
        }
    }

    /// Get the bound address of the UDP socket
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp_socket.local_addr()
    }
}

impl AsyncPing for SocksUdpRelay {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncReadTargetedMessage for SocksUdpRelay {
    /// Read a UDP datagram from the SOCKS5 client.
    /// The datagram should be in SOCKS5 format: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT + DATA
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        loop {
            match Pin::new(&mut this.recv_ch).poll_recv(cx) {
                Poll::Ready(Some((data, _from_addr))) => {
                    // Parse SOCKS5 datagram header to get destination address
                    // Header format: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT
                    if data.len() < 10 {
                        // Datagram too short, skip
                        continue;
                    }

                    // Skip RSV (2 bytes) and FRAG (1 byte)
                    let atyp = data[3];

                    // Calculate payload start and target address based on ATYP
                    let (target_addr, header_len) = match atyp {
                        ATYP_IPV4 => {
                            // ATYP(1) + IPv4(4) + PORT(2) = 7 bytes after the first 3 bytes
                            if data.len() < 10 {
                                continue;
                            }
                            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                            let port = u16::from_be_bytes([data[8], data[9]]);
                            (
                                NetLocation::new(Address::Ipv4(ip), port),
                                10, // 3 (RSV+FRAG) + 1 (ATYP) + 4 (IP) + 2 (PORT)
                            )
                        }
                        ATYP_IPV6 => {
                            // ATYP(1) + IPv6(16) + PORT(2) = 19 bytes after the first 3 bytes
                            if data.len() < 22 {
                                continue;
                            }
                            let ip_bytes: [u8; 16] = data[4..20].try_into().unwrap();
                            let ip = std::net::Ipv6Addr::from(ip_bytes);
                            let port = u16::from_be_bytes([data[20], data[21]]);
                            (
                                NetLocation::new(Address::Ipv6(ip), port),
                                22, // 3 (RSV+FRAG) + 1 (ATYP) + 16 (IP) + 2 (PORT)
                            )
                        }
                        ATYP_DOMAIN => {
                            // ATYP(1) + LEN(1) + DOMAIN + PORT(2)
                            if data.len() < 5 {
                                continue;
                            }
                            let domain_len = data[4] as usize;
                            if data.len() < 5 + domain_len + 2 {
                                continue;
                            }
                            let domain = std::str::from_utf8(&data[5..5 + domain_len])
                                .ok()
                                .map(|s| s.to_string());
                            let port = u16::from_be_bytes([data[5 + domain_len], data[6 + domain_len]]);
                            if let Some(d) = domain {
                                (
                                    NetLocation::new(Address::from(d.as_str()).unwrap(), port),
                                    3 + 1 + 1 + domain_len + 2,
                                )
                            } else {
                                continue;
                            }
                        }
                        _ => {
                            // Unknown ATYP, skip
                            continue;
                        }
                    };

                    // Extract payload
                    let payload = &data[header_len..];

                    if payload.len() > buf.remaining() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "UDP payload too large: {} > {}",
                                payload.len(),
                                buf.remaining()
                            ),
                        )));
                    }

                    buf.put_slice(payload);
                    return Poll::Ready(Ok(target_addr));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "UDP relay channel closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWriteSourcedMessage for SocksUdpRelay {
    /// Write a UDP datagram to be sent to the SOCKS5 client.
    /// We need to wrap it in SOCKS5 format.
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Build SOCKS5 response datagram
        // Format: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT + DATA
        let mut response = Vec::with_capacity(65536);

        // RSV (2 bytes) + FRAG (1 byte) = 3 bytes header
        response.push(0);
        response.push(0);
        response.push(0);

        match source {
            SocketAddr::V4(addr) => {
                response.push(ATYP_IPV4);
                response.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                response.push(ATYP_IPV6);
                response.extend_from_slice(&addr.ip().octets());
            }
        }

        // Port (2 bytes)
        response.push((source.port() >> 8) as u8);
        response.push((source.port() & 0xff) as u8);

        // Data
        response.extend_from_slice(data);

        // Send to the UDP socket
        // Note: we need to send to the client that originally sent the datagram
        // The `source` here is the address from the client, so we send back to it
        let send_result = std::pin::Pin::new(&*this.udp_socket).poll_send_to(
            _cx,
            &response,
            *source,
        );

        match send_result {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for SocksUdpRelay {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // UDP is connectionless, no flushing needed
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for SocksUdpRelay {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncTargetedMessageStream for SocksUdpRelay {}