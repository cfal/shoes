//! AmneziaWG tunnel runtime.
//!
//! Owns the boringtun Tunn, endpoint UDP socket, and drives the
//! encapsulate/decapsulate loop between the virtual IP stack and the network.

use std::net::SocketAddr;
use std::sync::Arc;

use boringtun::amnezia::Amnezia2Config;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use log::{debug, error, info, warn};
use parking_lot::Mutex as ParkingMutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Maximum UDP datagram size (outer AmneziaWG packets).
const MAX_UDP_SIZE: usize = 65536;

/// Tunnel runtime state shared between tasks.
pub struct TunnelRuntime {
    /// Channel to send IP packets from the virtual stack to be encapsulated and sent.
    pub ip_to_tunnel_tx: mpsc::Sender<Vec<u8>>,
    /// Channel to receive decapsulated IP packets for the virtual stack.
    pub ip_from_tunnel_rx: ParkingMutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Abort handles for background tasks.
    abort_handles: Vec<tokio::task::AbortHandle>,
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        for handle in &self.abort_handles {
            handle.abort();
        }
        info!("AmneziaWG tunnel runtime stopped");
    }
}

impl TunnelRuntime {
    /// Start the tunnel runtime.
    pub async fn start(
        private_key: x25519::StaticSecret,
        peer_public_key: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        amnezia: Amnezia2Config,
        endpoint_addr: SocketAddr,
    ) -> std::io::Result<Arc<Self>> {
        // Create the boringtun tunnel
        let tunn = Tunn::new_with_amnezia(
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            0,
            None,
            amnezia,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("AmneziaWG tunnel config error: {}", e)))?;
        let tunn = Arc::new(ParkingMutex::new(tunn));

        // Create endpoint UDP socket
        let is_ipv6 = endpoint_addr.is_ipv6();
        let bind_addr: SocketAddr = if is_ipv6 {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        udp_socket.connect(endpoint_addr).await?;
        let udp_socket = Arc::new(udp_socket);

        // Protect socket on mobile platforms
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            crate::tun::protect_socket(udp_socket.as_raw_fd());
        }

        info!("AmneziaWG tunnel started, endpoint={}", endpoint_addr);

        // Channels between virtual IP stack and tunnel
        let (ip_to_tunnel_tx, ip_to_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ip_from_tunnel_tx, ip_from_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);

        // Task 1: Read UDP datagrams from server, decapsulate, send IP packets to stack
        let recv_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            let tx = ip_from_tunnel_tx;
            tokio::spawn(async move {
                decapsulate_loop(tunn, udp, tx).await;
            })
        };

        // Task 2: Read IP packets from virtual stack, encapsulate, send UDP to server
        let send_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            tokio::spawn(async move {
                encapsulate_loop(tunn, udp, ip_to_tunnel_rx).await;
            })
        };

        // Task 3: Timer tick task
        let timer_task = {
            let tunn = tunn.clone();
            let udp = udp_socket.clone();
            tokio::spawn(async move {
                timer_loop(tunn, udp).await;
            })
        };

        let abort_handles = vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
        ];

        Ok(Arc::new(Self {
            ip_to_tunnel_tx,
            ip_from_tunnel_rx: ParkingMutex::new(Some(ip_from_tunnel_rx)),
            abort_handles,
        }))
    }
}

async fn decapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<UdpSocket>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut out = vec![0u8; MAX_UDP_SIZE];

    loop {
        let n = match udp.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!("AmneziaWG UDP recv error: {}", e);
                break;
            }
        };

        // Decapsulate with lock held briefly
        let result = {
            let mut tunn = tunn.lock();
            tunn.decapsulate(None, &buf[..n], &mut out)
        };

        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!("AmneziaWG decapsulate error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                let packet = data.to_vec();
                if let Err(e) = udp.send(&packet).await {
                    warn!("AmneziaWG UDP send (handshake) error: {}", e);
                }
                // Drain queued packets
                drain_queued_packets(&tunn, &udp, &mut out).await;
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                let _ = tx.try_send(data.to_vec());
                // Check for more queued outputs
                drain_queued_packets(&tunn, &udp, &mut out).await;
            }
        }

        // Drain pre-handshake packets (I-packets, junk)
        drain_outgoing_packets(&tunn, &udp).await;
    }
}

async fn drain_queued_packets(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<UdpSocket>,
    out: &mut [u8],
) {
    loop {
        let result = {
            let mut tunn = tunn.lock();
            tunn.decapsulate(None, &[], out)
        };
        match result {
            TunnResult::Done => break,
            TunnResult::WriteToNetwork(data) => {
                let packet = data.to_vec();
                if let Err(e) = udp.send(&packet).await {
                    warn!("AmneziaWG UDP send (drain) error: {}", e);
                }
            }
            _ => break,
        }
    }
}

async fn drain_outgoing_packets(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<UdpSocket>,
) {
    loop {
        let packet = {
            let mut tunn = tunn.lock();
            tunn.poll_outgoing_packet()
        };
        match packet {
            Some(data) => {
                if let Err(e) = udp.send(&data).await {
                    warn!("AmneziaWG UDP send (outgoing) error: {}", e);
                }
            }
            None => break,
        }
    }
}

async fn encapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];

    while let Some(ip_packet) = rx.recv().await {
        // Drain any pre-handshake packets first
        drain_outgoing_packets(&tunn, &udp).await;

        let result = {
            let mut tunn = tunn.lock();
            tunn.encapsulate(&ip_packet, &mut out)
        };

        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!("AmneziaWG encapsulate error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                let packet = data.to_vec();
                if let Err(e) = udp.send(&packet).await {
                    warn!("AmneziaWG UDP send (encap) error: {}", e);
                }
            }
            _ => {
                debug!("AmneziaWG encapsulate: unexpected tunnel write result");
            }
        }

        // Drain pre-handshake packets after encapsulate
        drain_outgoing_packets(&tunn, &udp).await;
    }
}

async fn timer_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<UdpSocket>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let result = {
            let mut tunn = tunn.lock();
            tunn.update_timers(&mut out)
        };

        match result {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!("AmneziaWG timer error: {:?}", e);
            }
            TunnResult::WriteToNetwork(data) => {
                let packet = data.to_vec();
                if let Err(e) = udp.send(&packet).await {
                    warn!("AmneziaWG UDP send (timer) error: {}", e);
                }
                drain_outgoing_packets(&tunn, &udp).await;
            }
            _ => {}
        }
    }
}
