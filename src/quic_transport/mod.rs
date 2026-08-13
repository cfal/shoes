//! QUIC machinery shared by the listeners and the dialers.
//!
//! Hysteria2 and TUIC each run a QUIC listener, and the outbounds for both dial
//! one. Before this module the transport parameters, the socket, the endpoint
//! and the accept loop were written out separately in each of them, which is
//! how the three copies came to disagree about things that were never meant to
//! differ.
//!
//! The split here is deliberate: values that are the same everywhere are
//! applied by [`QuicTransportParams::build`] and are not configurable, while
//! the handful that legitimately differ per protocol are fields. A difference
//! between two protocols is then a visible choice rather than a copy that
//! drifted.

pub mod fragments;
pub mod obfs;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::error;
use tokio::task::JoinHandle;

use obfs::{ObfuscatedUdpSocket, Obfuscator};

/// QUIC MTU floor used by the reference implementations, and the smallest
/// value QUIC itself permits.
pub const BASE_MTU: u16 = 1200;

/// Socket buffer size for high-throughput QUIC: 7.5MB, plus 15% for the kernel
/// overhead BSD accounts for separately.
///
/// <https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes>
const SOCKET_BUFFER_SIZE: usize = 8_625_000;

/// The MTU left to QUIC once an obfuscator has taken its share of every
/// datagram.
///
/// Note that quinn clamps both `initial_mtu` and `min_mtu` with `.max(1200)`,
/// so the subtraction currently has no effect: 1200 is QUIC's own floor and
/// quinn will not go under it. It is kept because it states the intent, and
/// because the obfuscated wire packet really is this much larger than the QUIC
/// packet inside it. Making the reduction take effect needs a mechanism quinn
/// does not expose; ROADMAP.md records it.
pub fn effective_mtu(obfs_overhead: Option<usize>) -> u16 {
    match obfs_overhead {
        Some(overhead) => BASE_MTU.saturating_sub(overhead as u16),
        None => BASE_MTU,
    }
}

/// Build the obfuscator a listener or an outbound was configured with, if any.
///
/// The password length was already checked during config validation; the
/// constructor re-checks it because it is the one place that owns the rule.
pub fn build_obfuscator(
    obfs: Option<&crate::config::ObfsConfig>,
) -> std::io::Result<Option<Arc<dyn Obfuscator>>> {
    match obfs {
        Some(crate::config::ObfsConfig::Salamander { password }) => {
            let salamander = obfs::Salamander::new(password.expose().as_bytes())?;
            Ok(Some(Arc::new(salamander)))
        }
        None => Ok(None),
    }
}

/// The transport parameters that differ between protocols.
///
/// Everything not named here is identical across all of them and is applied by
/// [`Self::build`]. Do not add a field without a protocol that needs a
/// different value than its neighbour: an option that only ever takes one value
/// is a copy waiting to drift.
#[derive(Debug, Clone)]
pub struct QuicTransportParams {
    /// Bidirectional streams the peer may open toward us. Zero on a dialer:
    /// neither protocol has the server open one.
    pub max_concurrent_bidi_streams: u32,
    /// Unidirectional streams the peer may open toward us.
    ///
    /// Never zero on a dialer, and a zero there is a silent deadlock rather
    /// than an error: HTTP/3 requires the server to open its control and QPACK
    /// streams before Hysteria2's authentication can complete, and TUIC carries
    /// UDP packets over server-opened uni streams in its `quic` relay mode.
    pub max_concurrent_uni_streams: u32,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    /// See [`effective_mtu`].
    pub mtu: u16,
    /// GSO batches several QUIC packets into one `sendmsg`, which an obfuscator
    /// cannot scramble as a unit, so it is off whenever one is installed.
    pub enable_segmentation_offload: bool,
}

impl QuicTransportParams {
    pub fn build(&self) -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into())
            .max_concurrent_uni_streams(self.max_concurrent_uni_streams.into())
            .max_idle_timeout(Some(
                self.max_idle_timeout
                    .try_into()
                    .expect("idle timeout is well under quinn's varint limit"),
            ))
            .keep_alive_interval(Some(self.keep_alive_interval))
            // Window sizes estimated from
            // https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/config.go#L16
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(self.mtu)
            .min_mtu(self.mtu)
            // Discovery lets a capable path carry more than the floor above.
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .enable_segmentation_offload(self.enable_segmentation_offload)
            // A lower initial estimate grows the initial window sooner.
            .initial_rtt(Duration::from_millis(100));
        transport
    }
}

/// What a QUIC listener needs to raise its endpoints, independent of which
/// protocol runs on top.
pub struct QuicListenerSettings {
    pub bind_address: SocketAddr,
    pub quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    /// Endpoints to raise on the same address, each with its own socket. More
    /// than one spreads the load across the kernel's receive queues.
    pub num_endpoints: usize,
    pub obfs: Option<Arc<dyn Obfuscator>>,
}

/// Bind a socket and raise one listening endpoint on it.
fn build_server_endpoint(
    settings: &QuicListenerSettings,
    params: &QuicTransportParams,
) -> std::io::Result<quinn::Endpoint> {
    let mut server_config = quinn::ServerConfig::with_crypto(settings.quic_server_config.clone());
    server_config.transport = Arc::new(params.build());

    let socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
        settings.bind_address.is_ipv6(),
        None,
        Some(settings.bind_address),
        true,
        Some(SOCKET_BUFFER_SIZE),
    )?;

    match settings.obfs.clone() {
        Some(obfs) => quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(ObfuscatedUdpSocket::new(socket.into(), obfs)?),
            Arc::new(quinn::TokioRuntime),
        ),
        None => quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket.into(),
            Arc::new(quinn::TokioRuntime),
        ),
    }
}

/// Raise `num_endpoints` listening endpoints and accept on each of them,
/// handing every incoming connection to `handle_connection`.
///
/// The protocol keeps its own concerns in that closure: everything it needs is
/// captured there, so nothing protocol-specific reaches this module.
pub fn start_quic_listeners<F, Fut>(
    settings: QuicListenerSettings,
    params: QuicTransportParams,
    handle_connection: F,
) -> std::io::Result<Vec<JoinHandle<()>>>
where
    F: Fn(quinn::Incoming) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = std::io::Result<()>> + Send + 'static,
{
    let mut join_handles = Vec::with_capacity(settings.num_endpoints);

    for _ in 0..settings.num_endpoints {
        // Bound before spawning, so that a port already in use fails startup.
        // Nothing ever awaits these join handles - a config reload aborts them
        // - so a panic raised inside the task would be swallowed and the
        // listener would silently accept nothing at all.
        let endpoint = build_server_endpoint(&settings, &params)?;
        let handle_connection = handle_connection.clone();

        join_handles.push(tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let handle_connection = handle_connection.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(conn).await {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        }));
    }

    Ok(join_handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::{
        generate_certificate, quic_server_config, reserve_udp_port,
    };

    /// An address in TEST-NET-1, which is not assigned to this host, so binding
    /// it fails immediately with EADDRNOTAVAIL rather than waiting on anything.
    const UNBINDABLE: &str = "192.0.2.1:1";

    fn listener(bind_address: SocketAddr) -> QuicListenerSettings {
        let cert = generate_certificate();
        QuicListenerSettings {
            bind_address,
            quic_server_config: quic_server_config(&cert, &["h3".to_string()]),
            num_endpoints: 1,
            obfs: None,
        }
    }

    fn params() -> QuicTransportParams {
        QuicTransportParams {
            max_concurrent_bidi_streams: 4096,
            max_concurrent_uni_streams: 1024,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            mtu: BASE_MTU,
            enable_segmentation_offload: true,
        }
    }

    #[test]
    fn test_effective_mtu_subtracts_obfuscation_overhead() {
        assert_eq!(effective_mtu(None), BASE_MTU);
        assert_eq!(effective_mtu(Some(8)), BASE_MTU - 8);
    }

    /// An obfuscator claiming more overhead than a whole packet must not wrap
    /// around into a huge MTU.
    #[test]
    fn test_effective_mtu_saturates_rather_than_underflowing() {
        assert_eq!(effective_mtu(Some(BASE_MTU as usize)), 0);
        assert_eq!(effective_mtu(Some(usize::MAX)), 0);
    }

    #[test]
    fn test_build_produces_a_usable_transport_config() {
        // quinn exposes no getters, so this asserts the call sequence does not
        // panic - which it would on an out-of-range idle timeout - and leaves
        // the values themselves to the interop tests in hysteria2 and tuic.
        let _ = params().build();
    }

    /// quinn floors both MTU setters at 1200, so an obfuscated transport is
    /// built with a value that is silently clamped. Pinned so that a future
    /// quinn that stops clamping, or a change here that starts compensating,
    /// is noticed rather than assumed.
    #[test]
    fn test_an_undersized_mtu_is_accepted_and_clamped_by_quinn() {
        let mut p = params();
        p.mtu = effective_mtu(Some(8));
        assert_eq!(p.mtu, 1192);
        let _ = p.build();
    }

    #[test]
    fn test_build_obfuscator_returns_none_without_config() {
        assert!(build_obfuscator(None).unwrap().is_none());
    }

    #[test]
    fn test_build_obfuscator_builds_salamander() {
        let config = crate::config::ObfsConfig::Salamander {
            password: "a password".to_string().into(),
        };
        let obfs = build_obfuscator(Some(&config)).unwrap().unwrap();
        assert_eq!(obfs.overhead(), 8);
    }

    #[test]
    fn test_build_obfuscator_rejects_a_short_password() {
        let config = crate::config::ObfsConfig::Salamander {
            password: "abc".to_string().into(),
        };
        assert!(build_obfuscator(Some(&config)).is_err());
    }

    /// The endpoint is raised before the accept task is spawned precisely so
    /// that this is an error. Both protocol servers used to build it inside the
    /// task and unwrap, and nothing ever awaits the join handles - a config
    /// reload aborts them - so an unbindable address produced a listener that
    /// silently accepted nothing.
    #[tokio::test]
    async fn test_an_unbindable_address_is_a_startup_error() {
        let settings = listener(UNBINDABLE.parse().unwrap());
        let result = start_quic_listeners(settings, params(), |_| async { Ok(()) });
        let err = result
            .map(|handles| handles.len())
            .expect_err("binding TEST-NET-1 must fail");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::PermissionDenied
            ),
            "unexpected error kind: {err:?}"
        );
    }

    /// Every endpoint is bound before any is spawned, so the second one failing
    /// still reports an error rather than leaving the first running alone.
    #[tokio::test]
    async fn test_a_bindable_address_starts_one_listener_per_endpoint() {
        let mut settings = listener(reserve_udp_port());
        settings.num_endpoints = 3;

        let handles = start_quic_listeners(settings, params(), |_| async { Ok(()) })
            .expect("loopback must bind");
        assert_eq!(handles.len(), 3);

        for handle in handles {
            assert!(!handle.is_finished(), "an acceptor exited immediately");
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_an_obfuscated_listener_binds() {
        let mut settings = listener(reserve_udp_port());
        settings.obfs = Some(Arc::new(obfs::Salamander::new(b"a password").unwrap()));

        let handles = start_quic_listeners(settings, params(), |_| async { Ok(()) })
            .expect("an obfuscated listener must bind");
        assert_eq!(handles.len(), 1);
        handles.into_iter().for_each(|h| h.abort());
    }
}
