//! UDP hopping socket for non-disruptive port hopping.
//!
//! Wraps a UDP socket and periodically swaps the underlying socket and target
//! server port. The QUIC connection survives because QUIC uses Connection IDs,
//! not IP:port, for connection identity.
//!
//! Design mirrors the official Hysteria2 `udpHopPacketConn` in Go.

use std::fmt::Debug;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use log::{debug, info, warn};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use rand::Rng;

use crate::socket_util::new_udp_socket;

/// A UDP socket that supports non-disruptive port hopping.
///
/// Implements `quinn::AsyncUdpSocket` and transparently swaps the underlying
/// UDP socket and target server port at a configurable interval. Keeps both
/// old and new sockets alive briefly during transition to avoid packet loss.
pub struct UdpHopSocket {
    /// Current inner socket state (swapped on hop).
    inner: RwLock<HopState>,
    /// All possible server addresses (one per port).
    server_addrs: Vec<SocketAddr>,
    /// The original server address used for the initial connection.
    /// All received packets are reported as coming from this address,
    /// matching the official Hysteria2 behavior where ReadFrom always
    /// returns u.Addr to prevent QUIC from seeing connection migration.
    original_addr: RwLock<SocketAddr>,
    /// Whether the server is IPv6.
    is_ipv6: bool,
    /// Optional bind interface.
    bind_interface: Option<String>,
}

struct HopState {
    /// The current active socket.
    current: Arc<InnerSocket>,
    /// The previous socket (kept alive briefly during transition).
    prev: Option<Arc<InnerSocket>>,
    /// Index into `server_addrs` for the current target port.
    addr_index: usize,
}

struct InnerSocket {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl Debug for InnerSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerSocket")
            .field("local_addr", &self.io.local_addr())
            .finish()
    }
}

impl Debug for UdpHopSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHopSocket")
            .field("num_ports", &self.server_addrs.len())
            .finish()
    }
}

impl UdpHopSocket {
    /// Create a new hopping socket.
    ///
    /// `server_ip` is the resolved server IP address.
    /// `ports` is the list of server ports to hop between.
    /// `is_ipv6` indicates whether the server uses IPv6.
    /// `bind_interface` is an optional network interface to bind to.
    pub fn new(
        server_ip: std::net::IpAddr,
        ports: &[u16],
        is_ipv6: bool,
        bind_interface: Option<String>,
    ) -> io::Result<Self> {
        let server_addrs: Vec<SocketAddr> = ports
            .iter()
            .map(|&port| SocketAddr::new(server_ip, port))
            .collect();

        let initial_index = rand::rng().random_range(0..server_addrs.len());
        let initial_socket = Self::create_inner_socket(is_ipv6, bind_interface.clone())?;

        let initial_addr = server_addrs[initial_index];

        Ok(Self {
            inner: RwLock::new(HopState {
                current: Arc::new(initial_socket),
                prev: None,
                addr_index: initial_index,
            }),
            server_addrs,
            original_addr: RwLock::new(initial_addr),
            is_ipv6,
            bind_interface,
        })
    }

    /// Get the initial server address to connect to.
    pub fn initial_server_addr(&self) -> SocketAddr {
        let state = self.inner.read().unwrap();
        self.server_addrs[state.addr_index]
    }

    /// Perform a port hop: create a new socket and pick a new target port.
    ///
    /// The old socket is kept alive briefly to receive in-flight packets.
    pub fn hop(&self) -> io::Result<()> {
        let new_socket = Self::create_inner_socket(self.is_ipv6, self.bind_interface.clone())?;
        let new_index = rand::rng().random_range(0..self.server_addrs.len());
        let new_addr = self.server_addrs[new_index];

        let mut state = self.inner.write().unwrap();

        // Drop the previous socket (its recv loop will exit).
        // Move current to prev, set new as current.
        state.prev = Some(state.current.clone());
        state.current = Arc::new(new_socket);
        state.addr_index = new_index;

        info!(
            "Port hop: now targeting {} (local: {:?})",
            new_addr,
            state.current.io.local_addr()
        );

        Ok(())
    }

    fn create_inner_socket(
        is_ipv6: bool,
        bind_interface: Option<String>,
    ) -> io::Result<InnerSocket> {
        let udp_socket = new_udp_socket(is_ipv6, bind_interface)?;
        let std_socket = udp_socket
            .into_std()
            .map_err(|e| io::Error::other(format!("Failed to convert UDP socket: {e}")))?;
        let state = UdpSocketState::new((&std_socket).into())?;
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

        Ok(InnerSocket {
            io: tokio_socket,
            state,
        })
    }

    /// Get the current target server address.
    pub fn current_server_addr(&self) -> SocketAddr {
        let state = self.inner.read().unwrap();
        self.server_addrs[state.addr_index]
    }

    /// Get a snapshot of current socket, prev socket, target addr, and original addr.
    fn snapshot(&self) -> (Arc<InnerSocket>, Option<Arc<InnerSocket>>, SocketAddr, SocketAddr) {
        let state = self.inner.read().unwrap();
        let orig = *self.original_addr.read().unwrap();
        (
            state.current.clone(),
            state.prev.clone(),
            self.server_addrs[state.addr_index],
            orig,
        )
    }
}

impl quinn::AsyncUdpSocket for UdpHopSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(HopUdpPoller {
            socket: self,
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (current, _, target_addr, _) = self.snapshot();

        // Override the destination to the current hop target
        let hopped_transmit = Transmit {
            destination: target_addr,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };

        current
            .io
            .try_io(tokio::io::Interest::WRITABLE, || {
                current.state.send((&current.io).into(), &hopped_transmit)
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (current, prev, _, original_addr) = self.snapshot();

        // Try reading from the previous socket first (drain old packets)
        if let Some(ref prev_sock) = prev {
            loop {
                match prev_sock.io.poll_recv_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        if let Ok(res) =
                            prev_sock.io.try_io(tokio::io::Interest::READABLE, || {
                                prev_sock.state.recv((&prev_sock.io).into(), bufs, meta)
                            })
                        {
                            // Mask the source address to the original address,
                            // matching official Hysteria2 ReadFrom behavior.
                            for m in meta.iter_mut().take(res) {
                                m.addr = original_addr;
                            }
                            return Poll::Ready(Ok(res));
                        }
                    }
                    Poll::Ready(Err(_)) => break,
                    Poll::Pending => break,
                }
            }
        }

        // Read from the current socket
        loop {
            match current.io.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Ok(res) = current.io.try_io(tokio::io::Interest::READABLE, || {
                        current.state.recv((&current.io).into(), bufs, meta)
                    }) {
                        // Mask the source address to the original address
                        for m in meta.iter_mut().take(res) {
                            m.addr = original_addr;
                        }
                        return Poll::Ready(Ok(res));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let (current, _, _, _) = self.snapshot();
        current.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        let (current, _, _, _) = self.snapshot();
        current.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        let (current, _, _, _) = self.snapshot();
        current.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        let (current, _, _, _) = self.snapshot();
        current.state.gro_segments()
    }
}

/// Poller implementation for UdpHopSocket.
struct HopUdpPoller {
    socket: Arc<UdpHopSocket>,
    fut: Option<std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl Debug for HopUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopUdpPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for HopUdpPoller {
    fn poll_writable(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            // Take a snapshot of the current socket outside the lock,
            // so the future doesn't hold the RwLockReadGuard across await.
            let (current, _, _, _) = self.socket.snapshot();
            self.fut = Some(Box::pin(async move { current.io.writable().await }));
        }

        let result = self.fut.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            self.fut = None;
        }
        result
    }
}

/// Spawn a background task that periodically calls `hop()` on the socket.
pub fn spawn_hop_loop(socket: Arc<UdpHopSocket>, hop_interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(hop_interval);
        // Skip immediate first tick
        interval.tick().await;

        loop {
            interval.tick().await;
            match socket.hop() {
                Ok(()) => {}
                Err(e) => {
                    warn!("Port hop failed: {e}, will retry next interval");
                }
            }
        }
    });
}
