//! AmneziaWG tunnel runtime.
//!
//! Owns the awgtun Tunn, endpoint UDP socket, and drives the
//! encapsulate/decapsulate loop between the virtual IP stack and the network.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use awgtun::amnezia::Amnezia3Config;
use awgtun::noise::{Tunn, TunnResult};
use awgtun::x25519;
use log::{debug, error, info, warn};
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::mpsc;

use super::endpoint::EndpointSocket;

/// Maximum UDP datagram size (outer AmneziaWG packets).
const MAX_UDP_SIZE: usize = 65536;

/// How long a tunnel with AmneziaWG 3.1 random trailers on may fail to
/// handshake before the setting is tried the other way round.
///
/// Long enough for several handshake initiations — awgtun retries every
/// `rekey_timeout`, five seconds by default — so a lossy path is not mistaken
/// for a peer that disagrees about trailers.
const TRAILER_PROBE_INTERVAL: Duration = Duration::from_secs(15);

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
        amnezia: Amnezia3Config,
        endpoint_addr: SocketAddr,
    ) -> std::io::Result<Arc<Self>> {
        // Create the awgtun tunnel
        let private_key_copy = private_key.clone();
        let amnezia_copy = amnezia.clone();

        let tunn = Tunn::new_with_amnezia3(
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            0,
            None,
            amnezia,
        )
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("AmneziaWG tunnel config error: {}", e),
            )
        })?;
        let tunn = Arc::new(ParkingMutex::new(tunn));

        // What a rebuild needs. Cheap to hold: two keys and a config struct.
        let rebuild = TunnelKeys {
            private_key: private_key_copy,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            amnezia: amnezia_copy,
        };

        // Packets the virtual stack handed us. The trailer probe reads this to
        // tell "no handshake because nothing was ever sent" — an idle tunnel,
        // which is fine — from "no handshake although we kept trying".
        let packets_offered = Arc::new(AtomicUsize::new(0));

        // Rebindable rather than a plain UdpSocket: on mobile the address this
        // is bound to stops existing every time the device changes network.
        // See src/amneziawg/endpoint.rs.
        let udp_socket = EndpointSocket::connect(endpoint_addr).await?;

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
            let offered = packets_offered.clone();
            tokio::spawn(async move {
                encapsulate_loop(tunn, udp, ip_to_tunnel_rx, offered).await;
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

        // Task 4: Rebind the endpoint socket when the network moves.
        let rebind_task = {
            let tunn = tunn.clone();
            tokio::spawn(udp_socket.clone().run_rebind_task(move || {
                // AmneziaWG 3.1 sizes its random trailers from a high-water
                // mark of datagrams seen on this path. A rebind is a new path,
                // so the mark it carried no longer describes anything. awgtun
                // leaves this to the caller because `Tunn` has no endpoint of
                // its own; upstream's `Device` does the same on a peer roam.
                // A no-op when random trailers are off.
                tunn.lock().reset_udp_window();
            }))
        };

        let mut abort_handles = vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
            rebind_task.abort_handle(),
        ];

        // Task 5: only for a tunnel that asked for AmneziaWG 3.1 random
        // trailers, which is the one setting here that cannot be wrong on its
        // own — it has to match the peer, and a mismatch is silent.
        if rebuild.amnezia.random_trailers {
            warn!(
                "AmneziaWG random trailers are on; the peer must have them on too. If no handshake completes within {}s they will be tried off.",
                TRAILER_PROBE_INTERVAL.as_secs()
            );
            let probe_task = tokio::spawn(trailer_probe_loop(
                tunn.clone(),
                rebuild,
                packets_offered.clone(),
                TRAILER_PROBE_INTERVAL,
            ));
            abort_handles.push(probe_task.abort_handle());
        }

        Ok(Arc::new(Self {
            ip_to_tunnel_tx,
            ip_from_tunnel_rx: ParkingMutex::new(Some(ip_from_tunnel_rx)),
            abort_handles,
        }))
    }
}

async fn decapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut out = vec![0u8; MAX_UDP_SIZE];
    // Reused for every packet this loop sends. See the comment in
    // drain_queued_packets for why the copy is needed at all.
    let mut packet = Vec::new();

    loop {
        let n = match udp.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                // A connected UDP socket reports ICMP port-unreachable (e.g. the
                // peer restarting) as ECONNREFUSED, and a stale mapping as
                // ECONNRESET. The socket is still usable, so keep listening rather
                // than killing inbound for the rest of the process's life.
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                ) {
                    debug!("AmneziaWG UDP recv transient error, continuing: {}", e);
                    continue;
                }
                error!("AmneziaWG UDP recv error, stopping decapsulate loop: {}", e);
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
                packet.clear();
                packet.extend_from_slice(data);
                send_to_network(&tunn, &udp, &packet, "handshake").await;
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet).await;
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                if tx.try_send(data.to_vec()).is_err() {
                    // The virtual stack is not keeping up. Dropping is correct
                    // for a tunnel — the inner protocol will retransmit — but
                    // it is worth seeing when throughput is being lost.
                    debug!("AmneziaWG: virtual stack queue full, dropping inbound packet");
                }
                drain_queued_packets(&tunn, &udp, &mut out, &mut packet).await;
            }
        }
    }
}

/// Take the datagrams awgtun has queued ahead of the packet that queued
/// them.
///
/// Any call that can start a handshake queues the AmneziaWG decoys — the I1-I5
/// chains followed by `Jc` junk packets — and returns the handshake initiation
/// separately. awgtun requires the queued datagrams to reach the network
/// *before* it: that ordering is the whole point of the decoys, since a censor
/// is meant to see junk lead the exchange rather than a recognisable WireGuard
/// handshake.
///
/// Empty in the steady state, and an empty `Vec` does not allocate — which
/// matters because this sits on the path every packet takes. Takes `&mut Tunn`
/// rather than the mutex so the lock is released before any of it is sent.
fn take_queued_decoys(tunn: &mut Tunn) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    while let Some(queued) = tunn.poll_outgoing_packet() {
        datagrams.push(queued);
    }
    datagrams
}

/// The queued decoys followed by `packet`, in the order they must be sent.
///
/// Only the test uses this; the send path streams the same sequence to the
/// socket without collecting it. Kept so the ordering can be asserted without a
/// socket.
#[cfg(test)]
fn ordered_outgoing(tunn: &mut Tunn, packet: Vec<u8>) -> Vec<Vec<u8>> {
    let mut datagrams = take_queued_decoys(tunn);
    datagrams.push(packet);
    datagrams
}

/// Send the datagrams for a `WriteToNetwork` result, decoys first.
async fn send_to_network(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    packet: &[u8],
    context: &str,
) {
    let decoys = take_queued_decoys(&mut tunn.lock());
    for datagram in &decoys {
        if let Err(e) = udp.send(datagram).await {
            warn!("AmneziaWG UDP send ({}) error: {}", context, e);
        }
    }

    if let Err(e) = udp.send(packet).await {
        warn!("AmneziaWG UDP send ({}) error: {}", context, e);
    }
}

/// Repeat `decapsulate` with an empty datagram until it stops producing output,
/// as its contract requires, sending anything it yields.
async fn drain_queued_packets(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    out: &mut [u8],
    packet: &mut Vec<u8>,
) {
    loop {
        {
            let mut tunn = tunn.lock();
            match tunn.decapsulate(None, &[], out) {
                // Copied into `packet` rather than sent from `out`: the result
                // borrows `out` for as long as it lives, and `out` is needed
                // again on the next turn of this loop. `packet` keeps its
                // capacity across calls, so the copy costs no allocation.
                TunnResult::WriteToNetwork(data) => {
                    packet.clear();
                    packet.extend_from_slice(data);
                }
                _ => break,
            }
        }
        send_to_network(tunn, udp, packet, "drain").await;
    }
}

async fn encapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    packets_offered: Arc<AtomicUsize>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];
    let mut packet = Vec::new();

    while let Some(ip_packet) = rx.recv().await {
        // Counted before encapsulation rather than after: a packet that only
        // starts a handshake is exactly the case the trailer probe is looking
        // for. Relaxed — the probe reads it every 15 seconds and only cares
        // whether it has ever moved.
        packets_offered.fetch_add(1, Ordering::Relaxed);

        let has_packet = {
            let mut tunn = tunn.lock();
            match tunn.encapsulate(&ip_packet, &mut out) {
                TunnResult::WriteToNetwork(data) => {
                    packet.clear();
                    packet.extend_from_slice(data);
                    true
                }
                TunnResult::Done => false,
                TunnResult::Err(e) => {
                    debug!("AmneziaWG encapsulate error: {:?}", e);
                    false
                }
                _ => {
                    debug!("AmneziaWG encapsulate: unexpected tunnel write result");
                    false
                }
            }
        };

        if has_packet {
            send_to_network(&tunn, &udp, &packet, "encap").await;
        }
    }
}

/// Everything needed to build the tunnel's `Tunn` again.
struct TunnelKeys {
    private_key: x25519::StaticSecret,
    peer_public_key: x25519::PublicKey,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
    amnezia: Amnezia3Config,
}

/// Whether a tunnel has gone quiet in the particular way a random-trailer
/// mismatch produces: packets offered, handshake never completed.
///
/// `None` for the handshake means this `Tunn` has never had one — a tunnel
/// that handshaked and then expired reports the age of the last one, so an
/// established tunnel that later goes idle is never mistaken for this.
fn trailers_look_wrong(last_handshake: Option<Duration>, packets_offered: usize) -> bool {
    last_handshake.is_none() && packets_offered > 0
}

/// Try random trailers the other way round when the handshake never completes.
///
/// A random-trailer mismatch cannot be detected by asking: the peer's setting
/// is not on the wire, and a peer that disagrees does not answer at all — it
/// drops the initiation as malformed. The only evidence available is the
/// silence, so this converges by alternating rather than by negotiating.
///
/// It flips back as well as forth, which matters: a peer that really is 3.1
/// but was merely unreachable for a while must not leave the tunnel stuck in
/// the setting that cannot receive its trailered responses. Whichever setting
/// completes a handshake is the one the tunnel stays on, because a `Tunn` that
/// has handshaked is never flipped again.
async fn trailer_probe_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    keys: TunnelKeys,
    packets_offered: Arc<AtomicUsize>,
    interval: Duration,
) {
    let mut random_trailers = keys.amnezia.random_trailers;

    loop {
        tokio::time::sleep(interval).await;

        let offered = packets_offered.load(Ordering::Relaxed);
        {
            let tunn = tunn.lock();
            if !trailers_look_wrong(tunn.stats().0, offered) {
                continue;
            }
        }

        random_trailers = !random_trailers;
        let mut amnezia = keys.amnezia.clone();
        amnezia.random_trailers = random_trailers;

        // A fresh Tunn, because awgtun bakes the configuration in at
        // construction. Nothing is lost by discarding the old one: it never
        // completed a handshake, so it holds no session, and the virtual stack
        // above is untouched — the inner protocols retransmit.
        match Tunn::new_with_amnezia3(
            keys.private_key.clone(),
            keys.peer_public_key,
            keys.preshared_key,
            keys.persistent_keepalive,
            0,
            None,
            amnezia,
        ) {
            Ok(replacement) => {
                *tunn.lock() = replacement;
                let state = if random_trailers { "on" } else { "off" };
                warn!(
                    "AmneziaWG: no handshake after {offered} packets; retrying with random trailers {state}. If this is what fixes the tunnel, set random_trailers to match the peer."
                );
            }
            Err(e) => {
                // The same configuration validated at startup, so this is not
                // reachable by a config error; log rather than kill the tunnel.
                error!("AmneziaWG: could not rebuild the tunnel to probe trailers: {e}");
                return;
            }
        }
    }
}

async fn timer_loop(tunn: Arc<ParkingMutex<Tunn>>, udp: Arc<EndpointSocket>) {
    let mut out = vec![0u8; MAX_UDP_SIZE];
    let mut packet = Vec::new();

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
                packet.clear();
                packet.extend_from_slice(data);
                send_to_network(&tunn, &udp, &packet, "timer").await;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amneziawg::convert_amnezia_config;
    use crate::config::AmneziaWgParams;
    use awgtun::noise::PacketClassifier;
    use base64::Engine as _;

    /// The obfuscation parameters from a real AmneziaWG 3.0 server profile.
    ///
    /// Keys are synthetic — only the shape of the configuration is taken from
    /// the real profile, which is what exercises the conversion and the wire
    /// ordering. Every 3.0 feature is on: header protection (which forces
    /// S1-S4 >= 12), content padding, and four randomized timing ranges.
    fn real_world_params() -> AmneziaWgParams {
        AmneziaWgParams {
            jc: 8,
            jmin: 75,
            jmax: 112,
            s1: 41,
            s2: 51,
            s3: 21,
            s4: 15,
            h1: Some("1279129381".to_string()),
            h2: Some("1420981222".to_string()),
            h3: Some("1740261821".to_string()),
            h4: Some("1930391293".to_string()),
            // A TLS ClientHello prefix, then random and timestamp chains, as a
            // real profile uses to make the opening datagrams look like a
            // browser rather than a VPN.
            i1: Some("<b 0x160301006f010000b1030390eb08b1>".to_string()),
            i2: Some("<r 27>".to_string()),
            i3: Some("<r 23><t>".to_string()),
            i4: Some("<r 34>".to_string()),
            i5: Some("<t><r 16>".to_string()),
            header_protection_key: Some(
                base64::engine::general_purpose::STANDARD
                    .encode([0x5au8; 32])
                    .into(),
            ),
            content_padding_addition: Some("0-64".to_string()),
            rekey_after_time: Some("123-156".to_string()),
            rekey_timeout: Some("5".to_string()),
            reject_after_time: Some("190-207".to_string()),
            keepalive_timeout: Some("14-22".to_string()),
            max_handshake_attempts: Some("18".to_string()),
            persistent_keepalive_interval: None,
            // Deliberately a 3.0 profile: the tests below are what pins 3.0
            // behaviour as unchanged now that 3.1 exists. `awg31_params`
            // covers the 3.1 additions.
            random_trailers: false,
            disable_cookies: false,
        }
    }

    /// The same profile with the two AmneziaWG 3.1 parameters on.
    fn awg31_params() -> AmneziaWgParams {
        AmneziaWgParams {
            random_trailers: true,
            disable_cookies: true,
            ..real_world_params()
        }
    }

    fn keypair(seed: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
        let secret = x25519::StaticSecret::from([seed; 32]);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    /// Build a client/server pair that share one AmneziaWG configuration, the
    /// way two ends of a real tunnel must.
    fn tunnel_pair(config: &Amnezia3Config) -> (Tunn, Tunn) {
        let (client_secret, client_public) = keypair(1);
        let (server_secret, server_public) = keypair(2);
        let psk = [0x33u8; 32];

        let client = Tunn::new_with_amnezia3(
            client_secret,
            server_public,
            Some(psk),
            Some(25),
            1,
            None,
            config.clone(),
        )
        .expect("client config must be valid");

        let server = Tunn::new_with_amnezia3(
            server_secret,
            client_public,
            Some(psk),
            Some(25),
            2,
            None,
            config.clone(),
        )
        .expect("server config must be valid");

        (client, server)
    }

    /// Everything the real profile sets must survive the YAML -> awgtun
    /// conversion. A parameter silently dropped here is invisible until the
    /// handshake fails against a real server.
    #[test]
    fn real_world_parameters_survive_conversion() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();

        assert_eq!(config.junk.count, 8);
        assert_eq!(config.junk.min_size, 75);
        assert_eq!(config.junk.max_size, 112);
        assert_eq!(config.paddings.s1, 41);
        assert_eq!(config.paddings.s2, 51);
        assert_eq!(config.paddings.s3, 21);
        assert_eq!(config.paddings.s4, 15);

        assert!(config.init_packets.i1.is_some());
        assert!(config.init_packets.i2.is_some());
        assert!(config.init_packets.i3.is_some());
        assert!(config.init_packets.i4.is_some());
        assert!(config.init_packets.i5.is_some());

        assert_eq!(config.header_protection_key, Some([0x5au8; 32]));
        assert_eq!(config.content_padding_addition.unwrap().lo, 0);
        assert_eq!(config.content_padding_addition.unwrap().hi, 64);

        assert_eq!(config.timing_ranges.rekey_after_time.lo, 123);
        assert_eq!(config.timing_ranges.rekey_after_time.hi, 156);
        assert_eq!(config.timing_ranges.reject_after_time.hi, 207);
        assert_eq!(config.timing_ranges.keepalive_timeout.lo, 14);
        assert_eq!(config.timing_ranges.max_handshake_attempts.lo, 18);

        // The clamp for content padding is the tunnel MTU, not awgtun's
        // default, so the two cannot drift apart.
        assert_eq!(config.mtu, 1420);
    }

    /// The decoys must reach the network before the handshake they precede.
    ///
    /// This is the ordering awgtun documents on `poll_outgoing_packet` and
    /// `format_handshake_initiation`. Getting it backwards still completes a
    /// handshake — the peer ignores junk whenever it arrives — so nothing but
    /// an explicit order assertion catches it.
    #[test]
    fn decoys_are_sent_before_the_handshake_initiation() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (mut client, _server) = tunnel_pair(&config);

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let packet = match client.encapsulate(&[0u8; 64], &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("first packet must start a handshake, got {:?}", other),
        };

        let datagrams = ordered_outgoing(&mut client, packet);

        // I1-I5 plus Jc=8 junk datagrams, then the initiation itself.
        assert_eq!(
            datagrams.len(),
            14,
            "expected 5 I-packets + 8 junk + 1 initiation"
        );

        let classifier = PacketClassifier::from_config(&config);
        let initiation_positions: Vec<usize> = datagrams
            .iter()
            .enumerate()
            .filter(|(_, datagram)| classifier.classify(datagram).is_some())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(
            initiation_positions,
            vec![datagrams.len() - 1],
            "the only recognisable WireGuard datagram must be the last one; \
             anything earlier means a decoy was sent after the handshake"
        );
    }

    /// A full handshake and a data packet, both ends driven through the shoes
    /// config path. Proves the parameters are not merely accepted but actually
    /// interoperate.
    #[test]
    fn a_full_handshake_completes_and_carries_data() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        handshake_and_carry_data(&config);
    }

    /// The same, with the 3.1 parameters on at both ends. Trailers change the
    /// size of every handshake datagram and widen the content padding of every
    /// transport packet, so a payload that still arrives byte-for-byte is what
    /// says the trimming is right in both directions.
    #[test]
    fn a_full_31_handshake_completes_and_carries_data() {
        let config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        assert!(config.random_trailers);
        assert!(config.disable_cookies);
        handshake_and_carry_data(&config);
    }

    fn handshake_and_carry_data(config: &Amnezia3Config) {
        let (mut client, mut server) = tunnel_pair(config);

        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];

        // Client starts a handshake. An IP-shaped payload, since awgtun
        // validates the inner packet.
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // IPv4, IHL 5
        ip_packet[2] = 0;
        ip_packet[3] = 40; // total length

        let initiation = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        // Decoys are discarded by the peer; only the initiation carries meaning.
        let response = match server.decapsulate(None, &initiation, &mut server_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("server must answer the initiation, got {:?}", other),
        };

        // Client consumes the response, completing the handshake.
        match client.decapsulate(None, &response, &mut client_buf) {
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
            other => panic!("client failed to complete the handshake: {:?}", other),
        }

        // Drain whatever the completion queued, per decapsulate's contract.
        while let TunnResult::WriteToNetwork(data) = client.decapsulate(None, &[], &mut client_buf)
        {
            let keepalive = data.to_vec();
            let _ = server.decapsulate(None, &keepalive, &mut server_buf);
        }

        // A session now exists: real data crosses and comes out intact.
        let transport = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!(
                "expected a transport packet after handshake, got {:?}",
                other
            ),
        };

        match server.decapsulate(None, &transport, &mut server_buf) {
            TunnResult::WriteToTunnelV4(data, _) => {
                assert_eq!(data, &ip_packet[..], "payload must survive the tunnel");
            }
            other => panic!("server did not decrypt the data packet: {:?}", other),
        }
    }

    /// With header protection on, the message type is encrypted, so a peer
    /// configured without the key cannot even classify the datagram. This is
    /// what makes a key mismatch look like an unreachable server.
    #[test]
    fn header_protection_hides_the_message_type_from_a_mismatched_peer() {
        let config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let (mut client, _server) = tunnel_pair(&config);

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let initiation = match client.encapsulate(&[0u8; 64], &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        let mut wrong_params = real_world_params();
        wrong_params.header_protection_key = Some(
            base64::engine::general_purpose::STANDARD
                .encode([0x77u8; 32])
                .into(),
        );
        let wrong_config = convert_amnezia_config(&wrong_params, 1420).unwrap();

        assert!(
            PacketClassifier::from_config(&config)
                .classify(&initiation)
                .is_some(),
            "the matching config must recognise its own initiation"
        );
        assert!(
            PacketClassifier::from_config(&wrong_config)
                .classify(&initiation)
                .is_none(),
            "a peer with the wrong header protection key must not recognise it"
        );
    }

    /// The probe fires only for the shape a trailer mismatch actually has.
    #[test]
    fn only_a_tunnel_that_tried_and_never_handshaked_looks_wrong() {
        assert!(trailers_look_wrong(None, 1));
        // Idle: nothing was ever sent, so there is nothing to conclude.
        assert!(!trailers_look_wrong(None, 0));
        // Established, then quiet. Flipping this would break a working tunnel.
        assert!(!trailers_look_wrong(Some(Duration::from_secs(600)), 4200));
    }

    /// End to end: a 3.1 client whose peer is 3.0 gets there by itself.
    ///
    /// Before the probe the client's initiations carry a trailer the 3.0 peer
    /// drops without answering, which is a tunnel that never comes up and
    /// never says why. After it, the same client speaks 3.0 framing and the
    /// peer answers.
    #[tokio::test]
    async fn a_stalled_31_tunnel_probes_its_way_back_to_30_framing() {
        let client_config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        let server_config = convert_amnezia_config(&real_world_params(), 1420).unwrap();

        let (client, _) = tunnel_pair(&client_config);
        let tunn = Arc::new(ParkingMutex::new(client));

        let (client_secret, _) = keypair(1);
        let (_, server_public) = keypair(2);
        let keys = TunnelKeys {
            private_key: client_secret,
            peer_public_key: server_public,
            preshared_key: Some([0x33u8; 32]),
            persistent_keepalive: Some(25),
            amnezia: client_config,
        };

        // One packet offered and no handshake: the state the probe acts on.
        let offered = Arc::new(AtomicUsize::new(1));
        // A probe interval scaled down for the test; the production one is
        // TRAILER_PROBE_INTERVAL, which the loop takes as a parameter for
        // exactly this reason.
        let interval = Duration::from_millis(50);
        tokio::spawn(trailer_probe_loop(tunn.clone(), keys, offered, interval));

        // Past the first probe but short of the second, which would flip back.
        tokio::time::sleep(interval + interval / 2).await;

        let (_, mut server) = tunnel_pair(&server_config);
        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];

        let initiation = match tunn.lock().encapsulate(&[0u8; 64], &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };

        assert!(
            matches!(
                server.decapsulate(None, &initiation, &mut server_buf),
                TunnResult::WriteToNetwork(_)
            ),
            "after the probe the 3.0 peer must be able to answer the initiation"
        );
    }

    /// Random trailers must be enabled on both peers or on neither.
    ///
    /// A receiver only tolerates bytes past the end of a handshake message
    /// when `random_trailers` is on; without it the exact-size test that
    /// identifies the message rejects the datagram. Enabling it one-sided is
    /// therefore not a degraded tunnel, it is a dead one, and this pins that
    /// so nobody "fixes" the asymmetry by making the receiver lenient.
    #[test]
    fn a_30_peer_rejects_an_initiation_that_carries_a_trailer() {
        let client_config = convert_amnezia_config(&awg31_params(), 1420).unwrap();
        let server_config = convert_amnezia_config(&real_world_params(), 1420).unwrap();
        let plain_len = {
            let (mut client, _) = tunnel_pair(&server_config);
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            match client.encapsulate(&[0u8; 64], &mut buf) {
                TunnResult::WriteToNetwork(data) => data.len(),
                other => panic!("expected a handshake initiation, got {:?}", other),
            }
        };

        // A trailer's length is drawn from the UDP window, so it is sometimes
        // zero and that datagram is a valid 3.0 one. Keep drawing until one
        // actually grew — that is the case with something to assert about.
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];
        let mut with_trailer = None;
        for _ in 0..64 {
            let (mut client, _) = tunnel_pair(&client_config);
            if let TunnResult::WriteToNetwork(data) = client.encapsulate(&[0u8; 64], &mut buf)
                && data.len() > plain_len
            {
                with_trailer = Some(data.to_vec());
                break;
            }
        }
        let with_trailer =
            with_trailer.expect("64 initiations in a row drew a zero-length trailer");

        let (_, mut server) = tunnel_pair(&server_config);
        assert!(
            !matches!(
                server.decapsulate(None, &with_trailer, &mut server_buf),
                TunnResult::WriteToNetwork(_)
            ),
            "a 3.0 peer must not answer an initiation with bytes on the end"
        );
    }
}
