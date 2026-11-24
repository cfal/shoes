//! Detects local network changes on the direct path so a Phobos client can reconnect.
//!
//! shoes binds the WireGuard socket once, so a Wi-Fi to cellular switch leaves it on a stale
//! source address. The watcher asks the OS which source address it would use for each peer
//! and reports when any answer changes.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

pub(super) const WATCH_INTERVAL: Duration = Duration::from_secs(2);

pub(super) trait SourceProbe: Send + Sync + 'static {
    /// The local address the OS would use to reach `target`, or `None` when it has no route.
    /// An error means the probe itself could not run, which says nothing about the network.
    fn source(&self, target: SocketAddr) -> io::Result<Option<IpAddr>>;
}

/// Probes with a connected, never-written UDP socket, which sends no packets. The socket is
/// built like the real WireGuard socket (`new_outbound_socket2_udp_socket`), so inside a VPN
/// app it is protected and the OS answers for the physical network, not the tunnel.
pub(super) struct OsProbe {
    pub interface: Option<String>,
}

impl SourceProbe for OsProbe {
    fn source(&self, target: SocketAddr) -> io::Result<Option<IpAddr>> {
        let socket = crate::socket_util::new_outbound_socket2_udp_socket(
            target.is_ipv6(),
            self.interface.clone(),
            None,
        )?;
        // Only the route lookup describes the network. Creating or protecting the socket can
        // fail for local reasons such as descriptor exhaustion.
        if socket.connect(&target.into()).is_err() {
            return Ok(None);
        }
        let local = socket.local_addr()?;
        local
            .as_socket()
            .map(|address| Some(address.ip()))
            .ok_or_else(|| io::Error::other("probe socket has no IP address"))
    }
}

/// Probes every target off the async runtime: socket creation and VPN protection are blocking
/// syscalls (protection is a JNI call on Android).
async fn snapshot<P: SourceProbe>(
    targets: &Arc<[SocketAddr]>,
    probe: &Arc<P>,
) -> Vec<io::Result<Option<IpAddr>>> {
    let (targets, probe) = (targets.clone(), probe.clone());
    let count = targets.len();
    tokio::task::spawn_blocking(move || {
        targets.iter().map(|target| probe.source(*target)).collect()
    })
    .await
    .unwrap_or_else(|error| {
        (0..count)
            .map(|_| Err(io::Error::other(format!("probe task failed: {error}"))))
            .collect()
    })
}

/// The new view of each target. A probe that could not run keeps the previous answer.
fn summarize(
    targets: &[SocketAddr],
    last: &[Option<IpAddr>],
    results: Vec<io::Result<Option<IpAddr>>>,
) -> Vec<Option<IpAddr>> {
    results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            let previous = last.get(index).copied().flatten();
            match result {
                Ok(current) => {
                    if current != previous {
                        log::debug!(
                            "WireGuard source address for {} changed: {previous:?} -> {current:?}",
                            targets[index]
                        );
                    }
                    current
                }
                Err(error) => {
                    log::debug!(
                        "WireGuard source probe for {} could not run: {error}",
                        targets[index]
                    );
                    previous
                }
            }
        })
        .collect()
}

/// Calls `on_change` once per tick whose snapshot differs from the previous one. Losing the
/// route and getting it back are both changes; a probe that could not run is not. Never returns.
pub(super) async fn run<P: SourceProbe>(
    targets: Vec<SocketAddr>,
    probe: P,
    interval: Duration,
    on_change: impl Fn() + Send,
) {
    let targets: Arc<[SocketAddr]> = targets.into();
    let probe = Arc::new(probe);
    let mut last = summarize(&targets, &[], snapshot(&targets, &probe).await);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let current = summarize(&targets, &last, snapshot(&targets, &probe).await);
        if current != last {
            last = current;
            on_change();
        }
    }
}

#[cfg(test)]
mod tests;
