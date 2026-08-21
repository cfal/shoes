//! The tunnel's own UDP socket, and how it survives the network moving.
//!
//! A phone changes networks constantly — Wi-Fi to cellular, one cell to the
//! next, a new address on the same interface after a doze wake-up. A UDP socket
//! bound to the old local address does not report this. It simply stops
//! receiving, and sends either vanish or fail with `ENETUNREACH`. The tunnel
//! does not error; it goes quiet, and stays quiet until something restarts it.
//!
//! So the socket here is replaceable. The three tunnel tasks hold this type
//! rather than a `UdpSocket`, read the live socket through a `watch` channel,
//! and are woken when it is swapped underneath them.
//!
//! A rebind is triggered two ways:
//!
//! * the app tells us, through [`notify_network_change`] — the FFI call an
//!   Android `ConnectivityManager.NetworkCallback` or an iOS `NWPathMonitor`
//!   should make; and
//! * we notice, when a send fails with an error that means the route is gone.
//!   Apps that never wire up the callback still recover this way, one failed
//!   send later.
//!
//! Rebinding is enough on its own: WireGuard peers roam. The server updates the
//! endpoint it has for us as soon as an authenticated packet arrives from the
//! new address, so the first packet after the swap repairs the path without a
//! new handshake.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use log::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

/// Live endpoint sockets, so a network change can reach all of them.
///
/// Weak, because the registry must not be what keeps a tunnel alive; dead
/// entries are swept on the next notification.
static ENDPOINTS: Mutex<Vec<Weak<EndpointSocket>>> = Mutex::new(Vec::new());

/// Tell every live tunnel that the network moved.
///
/// Safe to call from any thread, including a platform callback thread — it
/// takes an uncontended lock and wakes a task per tunnel, doing no I/O itself.
/// Returns the number of tunnels notified.
// Called from the mobile FFI, which the desktop binary does not compile.
#[allow(dead_code)]
pub fn notify_network_change() -> usize {
    let mut endpoints = ENDPOINTS.lock().unwrap_or_else(|e| e.into_inner());
    endpoints.retain(|weak| weak.strong_count() > 0);

    for endpoint in endpoints.iter() {
        if let Some(endpoint) = endpoint.upgrade() {
            endpoint.request_rebind();
        }
    }

    let count = endpoints.len();
    info!("network change: notified {} tunnel endpoint(s)", count);
    count
}

/// A UDP socket to the tunnel's peer that can be replaced underneath its users.
pub struct EndpointSocket {
    endpoint: SocketAddr,
    /// The socket in use. `watch` rather than a lock plus a notify because it
    /// closes the race between reading the socket and waiting for a change:
    /// a swap that lands in between is still seen by the next `changed()`.
    socket: watch::Sender<Arc<UdpSocket>>,
    rebind_requested: Notify,
}

impl EndpointSocket {
    /// Bind a socket to the peer and register it for network-change notices.
    pub async fn connect(endpoint: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = Self::bind(endpoint).await?;
        let (tx, _) = watch::channel(Arc::new(socket));

        let endpoint_socket = Arc::new(Self {
            endpoint,
            socket: tx,
            rebind_requested: Notify::new(),
        });

        {
            // Swept here as well as on notification, so a process that starts
            // many tunnels and never changes network does not accumulate dead
            // entries.
            let mut endpoints = ENDPOINTS.lock().unwrap_or_else(|e| e.into_inner());
            endpoints.retain(|weak| weak.strong_count() > 0);
            endpoints.push(Arc::downgrade(&endpoint_socket));
        }

        Ok(endpoint_socket)
    }

    async fn bind(endpoint: SocketAddr) -> std::io::Result<UdpSocket> {
        let bind_addr = if endpoint.is_ipv6() {
            SocketAddr::from(([0u8; 16], 0u16))
        } else {
            SocketAddr::from(([0u8; 4], 0u16))
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        // Exclude the endpoint socket from the VPN route before connecting.
        // Without this the tunnel's own UDP is captured by the TUN interface it
        // feeds, and every packet loops back into itself. This socket is bound
        // directly rather than through socket_util, so it protects itself.
        crate::socket_util::protect_outbound(&socket).map_err(|e| {
            std::io::Error::other(format!("failed to protect AmneziaWG endpoint socket: {e}"))
        })?;

        socket.connect(endpoint).await?;
        Ok(socket)
    }

    /// Ask for a rebind. Returns immediately; the work happens in
    /// [`run_rebind_task`].
    pub fn request_rebind(&self) {
        self.rebind_requested.notify_one();
    }

    /// Send one datagram over the current socket.
    ///
    /// A failure that means the route is gone schedules a rebind, so a tunnel
    /// recovers even when the app never reports the network change itself.
    pub async fn send(&self, datagram: &[u8]) -> std::io::Result<usize> {
        let socket = self.socket.borrow().clone();
        let result = socket.send(datagram).await;

        if let Err(ref e) = result
            && is_route_gone(e)
        {
            debug!("AmneziaWG send failed with {e}; scheduling a rebind");
            self.request_rebind();
        }

        result
    }

    /// Receive one datagram, following the socket across a rebind.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut changes = self.socket.subscribe();
        loop {
            let socket = changes.borrow_and_update().clone();
            tokio::select! {
                result = socket.recv(buf) => return result,
                // The socket was replaced. The pending recv belonged to an
                // address that no longer exists, so drop it and read from the
                // new one.
                _ = changes.changed() => continue,
            }
        }
    }

    /// Rebind whenever one is asked for. Runs for the life of the tunnel.
    ///
    /// `on_rebound` is called after each successful swap, for the state that
    /// belongs to the path rather than to the peer — see the AmneziaWG 3.1
    /// trailer window in `tunnel.rs`.
    pub async fn run_rebind_task(self: Arc<Self>, on_rebound: impl Fn() + Send + 'static) {
        loop {
            self.rebind_requested.notified().await;

            match Self::bind(self.endpoint).await {
                Ok(socket) => {
                    let local = socket
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    // send_replace, not send: `send` fails and leaves the
                    // value untouched when no receiver happens to be parked,
                    // which is most of the time — the tunnel tasks subscribe
                    // only for the duration of a recv.
                    self.socket.send_replace(Arc::new(socket));
                    on_rebound();
                    info!(
                        "AmneziaWG endpoint rebound to {} -> {}",
                        local, self.endpoint
                    );
                }
                Err(e) => {
                    // Normal while the device is between networks. The next
                    // failed send, or the app's next notification, tries again.
                    warn!("AmneziaWG endpoint rebind failed: {e}");
                }
            }
        }
    }

    /// The peer this socket is connected to.
    #[cfg(test)]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// The address the current socket is bound to.
    #[cfg(test)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.borrow().local_addr()
    }
}

/// Whether an error means the path this socket was bound to is gone.
///
/// `ECONNREFUSED` and `ECONNRESET` are deliberately absent: on a connected UDP
/// socket they are the peer's ICMP replies, which say nothing about our own
/// address and arrive routinely when a peer restarts.
fn is_route_gone(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::AddrNotAvailable
    ) || e.raw_os_error() == Some(libc::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn peer() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }

    #[tokio::test]
    async fn a_rebind_moves_the_socket_and_keeps_the_peer() {
        let (peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr).await.unwrap();
        let before = endpoint.local_addr().unwrap();

        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));
        endpoint.request_rebind();

        // The rebind is asynchronous; wait for the address to actually move.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(endpoint.endpoint(), peer_addr, "the peer must not change");

        // And the new socket still reaches the peer, which is what makes a
        // rebind a recovery rather than just a different kind of broken.
        endpoint.send(b"after rebind").await.unwrap();
        let mut buf = [0u8; 32];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer_socket.recv_from(&mut buf),
        )
        .await
        .expect("peer never received the datagram")
        .unwrap();

        assert_eq!(&buf[..n], b"after rebind");
        assert_eq!(
            from,
            endpoint.local_addr().unwrap(),
            "the datagram came from the pre-rebind socket"
        );
    }

    #[tokio::test]
    async fn recv_follows_the_socket_across_a_rebind() {
        let (peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr).await.unwrap();
        tokio::spawn(endpoint.clone().run_rebind_task(|| {}));

        // Park a receive on the pre-rebind socket, then move it. Without the
        // watch channel this future would wait on the old address forever.
        let receiver = {
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 32];
                let n = endpoint.recv(&mut buf).await.unwrap();
                buf[..n].to_vec()
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let before = endpoint.local_addr().unwrap();
        endpoint.request_rebind();

        // Wait for the swap rather than racing it: a `hello` sent from the old
        // socket would be answered on the old address, and the assertion below
        // would then be testing the race instead of the handover.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while endpoint.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "rebind never happened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Now make the peer answer the new socket.
        endpoint.send(b"hello").await.unwrap();
        let mut buf = [0u8; 32];
        let (_, from) = peer_socket.recv_from(&mut buf).await.unwrap();
        peer_socket.send_to(b"reply", from).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .expect("recv did not follow the rebind")
            .unwrap();
        assert_eq!(received, b"reply");
    }

    /// The rebind callback is what resets AmneziaWG 3.1's trailer window, and
    /// a silently-never-called callback would look exactly like a working
    /// tunnel until the trailer sizes were inspected on the wire.
    #[tokio::test]
    async fn a_successful_rebind_calls_back() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_peer_socket, peer_addr) = peer().await;
        let endpoint = EndpointSocket::connect(peer_addr).await.unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        tokio::spawn(endpoint.clone().run_rebind_task(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing rebound yet");
        endpoint.request_rebind();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the rebind callback never ran"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_network_change_reaches_a_live_endpoint_and_not_a_dropped_one() {
        let (_peer_socket, peer_addr) = peer().await;
        let dropped = EndpointSocket::connect(peer_addr).await.unwrap();
        drop(dropped);

        let live = EndpointSocket::connect(peer_addr).await.unwrap();
        tokio::spawn(live.clone().run_rebind_task(|| {}));
        let before = live.local_addr().unwrap();

        // Other tests in this binary may have live endpoints of their own, so
        // assert on the effect rather than on the count.
        notify_network_change();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while live.local_addr().unwrap() == before {
            assert!(
                std::time::Instant::now() < deadline,
                "the notification did not reach the live endpoint"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
