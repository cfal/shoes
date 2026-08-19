//! AmneziaWG tunnel runtime.
//!
//! Owns the boringtun Tunn, endpoint UDP socket, and drives the
//! encapsulate/decapsulate loop between the virtual IP stack and the network.

use std::net::SocketAddr;
use std::sync::Arc;

use boringtun::amnezia::Amnezia3Config;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use log::{debug, error, info, warn};
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::mpsc;

use super::endpoint::EndpointSocket;

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
        amnezia: Amnezia3Config,
        endpoint_addr: SocketAddr,
    ) -> std::io::Result<Arc<Self>> {
        // Create the boringtun tunnel
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

        // Task 4: Rebind the endpoint socket when the network moves.
        let rebind_task = tokio::spawn(udp_socket.clone().run_rebind_task());

        let abort_handles = vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
            rebind_task.abort_handle(),
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
    udp: Arc<EndpointSocket>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut out = vec![0u8; MAX_UDP_SIZE];

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
                let packet = data.to_vec();
                send_to_network(&tunn, &udp, packet, "handshake").await;
                drain_queued_packets(&tunn, &udp, &mut out).await;
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                if tx.try_send(data.to_vec()).is_err() {
                    // The virtual stack is not keeping up. Dropping is correct
                    // for a tunnel — the inner protocol will retransmit — but
                    // it is worth seeing when throughput is being lost.
                    debug!("AmneziaWG: virtual stack queue full, dropping inbound packet");
                }
                drain_queued_packets(&tunn, &udp, &mut out).await;
            }
        }
    }
}

/// Order the datagrams produced by a `WriteToNetwork` result.
///
/// Any call that can start a handshake queues the AmneziaWG decoys — the I1-I5
/// chains followed by `Jc` junk packets — and returns the handshake initiation
/// separately. boringtun requires the queued datagrams to reach the network
/// *before* the packet that queued them: that ordering is the whole point of
/// the decoys, since a censor is meant to see junk lead the exchange rather
/// than a recognisable WireGuard handshake.
///
/// Returns the queued datagrams followed by `packet`. Takes `&mut Tunn` rather
/// than the mutex so the lock is released before any of this is sent, and so
/// the ordering can be asserted in a test without a socket.
fn ordered_outgoing(tunn: &mut Tunn, packet: Vec<u8>) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    while let Some(queued) = tunn.poll_outgoing_packet() {
        datagrams.push(queued);
    }
    datagrams.push(packet);
    datagrams
}

/// Send the datagrams for a `WriteToNetwork` result, decoys first.
async fn send_to_network(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    packet: Vec<u8>,
    context: &str,
) {
    let datagrams = ordered_outgoing(&mut tunn.lock(), packet);
    for datagram in datagrams {
        if let Err(e) = udp.send(&datagram).await {
            warn!("AmneziaWG UDP send ({}) error: {}", context, e);
        }
    }
}

/// Repeat `decapsulate` with an empty datagram until it stops producing output,
/// as its contract requires, sending anything it yields.
async fn drain_queued_packets(
    tunn: &Arc<ParkingMutex<Tunn>>,
    udp: &Arc<EndpointSocket>,
    out: &mut [u8],
) {
    loop {
        let packet = {
            let mut tunn = tunn.lock();
            match tunn.decapsulate(None, &[], out) {
                TunnResult::WriteToNetwork(data) => data.to_vec(),
                _ => break,
            }
        };
        send_to_network(tunn, udp, packet, "drain").await;
    }
}

async fn encapsulate_loop(
    tunn: Arc<ParkingMutex<Tunn>>,
    udp: Arc<EndpointSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut out = vec![0u8; MAX_UDP_SIZE];

    while let Some(ip_packet) = rx.recv().await {
        let result = {
            let mut tunn = tunn.lock();
            match tunn.encapsulate(&ip_packet, &mut out) {
                TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
                TunnResult::Done => None,
                TunnResult::Err(e) => {
                    debug!("AmneziaWG encapsulate error: {:?}", e);
                    None
                }
                _ => {
                    debug!("AmneziaWG encapsulate: unexpected tunnel write result");
                    None
                }
            }
        };

        if let Some(packet) = result {
            send_to_network(&tunn, &udp, packet, "encap").await;
        }
    }
}

async fn timer_loop(tunn: Arc<ParkingMutex<Tunn>>, udp: Arc<EndpointSocket>) {
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
                send_to_network(&tunn, &udp, packet, "timer").await;
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
    use base64::Engine as _;
    use boringtun::noise::PacketClassifier;

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

    /// Everything the real profile sets must survive the YAML -> boringtun
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

        // The clamp for content padding is the tunnel MTU, not boringtun's
        // default, so the two cannot drift apart.
        assert_eq!(config.mtu, 1420);
    }

    /// The decoys must reach the network before the handshake they precede.
    ///
    /// This is the ordering boringtun documents on `poll_outgoing_packet` and
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
        let (mut client, mut server) = tunnel_pair(&config);

        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut server_buf = vec![0u8; MAX_UDP_SIZE];

        // Client starts a handshake. An IP-shaped payload, since boringtun
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
}
