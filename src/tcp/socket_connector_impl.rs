//! SocketConnectorImpl - Implementation of SocketConnector trait.
//!
//! Handles TCP and QUIC transports with bind_interface support.
//! Created from the socket-related fields of any ClientConfig.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::config::{ClientConfig, ClientQuicConfig, Transport};
use crate::quic_endpoint::QuicEndpoint;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_addresses, resolve_location};
use crate::rustls_config_util::try_create_client_config;
use crate::socket_util::{new_tcp_socket, new_udp_socket, set_tcp_keepalive};
use crate::thread_util::get_num_threads;

use super::socket_connector::SocketConnector;

const MAX_QUIC_ENDPOINTS: usize = 32;
const TCP_FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const TCP_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_TCP_ATTEMPTS: usize = 2;

fn interleave_tcp_addresses(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let prefer_ipv6 = first.is_ipv6();
    let (preferred, alternate): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == prefer_ipv6);
    let mut alternate = alternate.into_iter();
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    for address in preferred {
        ordered.push(address);
        if let Some(address) = alternate.next() {
            ordered.push(address);
        }
    }
    ordered.extend(alternate);
    ordered
}

async fn connect_tcp_candidates<T, F>(
    addresses: Vec<SocketAddr>,
    mut connect: impl FnMut(SocketAddr) -> std::io::Result<F>,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    if addresses.len() == 1 {
        return connect(addresses[0])?.await;
    }

    let mut candidates = interleave_tcp_addresses(addresses).into_iter().enumerate();
    let mut attempts = FuturesUnordered::new();
    let mut next_launch = tokio::time::Instant::now();
    let mut last_error: Option<(usize, std::io::Error)> = None;

    while candidates.len() != 0 || !attempts.is_empty() {
        tokio::select! {
            biased;
            Some((index, address, result)) = attempts.next(), if !attempts.is_empty() => {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => {
                        debug!("TCP connect to {address} failed: {error}");
                        if last_error.as_ref().is_none_or(|(previous, _)| index > *previous) {
                            last_error = Some((index, error));
                        }
                        next_launch = tokio::time::Instant::now();
                    }
                }
            }
            _ = tokio::time::sleep_until(next_launch),
                if candidates.len() != 0 && attempts.len() < MAX_TCP_ATTEMPTS =>
            {
                let (index, address) = candidates.next().unwrap();
                // Socket creation, binding and protection still fail closed.
                let attempt = connect(address)?;
                attempts.push(async move {
                    let result = tokio::time::timeout(TCP_ATTEMPT_TIMEOUT, attempt)
                        .await
                        .unwrap_or_else(|_| Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut, format!("TCP connect to {address} timed out"),
                        )));
                    (index, address, result)
                });
                next_launch = tokio::time::Instant::now() + TCP_FALLBACK_DELAY;
            }
        }
    }
    Err(last_error
        .map(|(_, error)| error)
        .unwrap_or_else(|| std::io::Error::other("no resolved addresses succeeded")))
}

#[derive(Debug)]
enum TransportConfig {
    Tcp {
        no_delay: bool,
    },
    Quic {
        sni_hostname: Option<String>,
        endpoints: Vec<Arc<QuicEndpoint>>,
        next_endpoint_index: AtomicU8,
    },
}

/// Implementation of SocketConnector for TCP and QUIC transports.
///
/// Created from the socket-related fields of any ClientConfig:
/// - `bind_interface`
/// - `transport`
/// - `tcp_settings`
/// - `quic_settings`
#[derive(Debug)]
pub struct SocketConnectorImpl {
    bind_interface: Option<String>,
    transport: TransportConfig,
}

impl SocketConnectorImpl {
    /// Create a SocketConnector from a ClientConfig's socket-related fields.
    ///
    /// # Arguments
    /// * `config` - The client config (socket fields are extracted)
    /// * `target_address` - The address this connector will connect to (used for QUIC SNI default).
    ///   Pass None for direct protocol (QUIC is not supported for direct).
    ///
    /// # Returns
    /// Returns any socket or QUIC endpoint initialization error.
    #[cfg(test)]
    pub fn from_config(
        config: &ClientConfig,
        target_address: Option<&NetLocation>,
    ) -> std::io::Result<Self> {
        Self::from_config_with_limits(config, target_address, crate::resources::limits())
    }

    pub fn from_config_with_limits(
        config: &ClientConfig,
        target_address: Option<&NetLocation>,
        limits: crate::config::GlobalLimits,
    ) -> std::io::Result<Self> {
        let bind_interface = config.bind_interface.clone().into_option();

        let default_sni_hostname =
            target_address.and_then(|addr| addr.address().hostname().map(ToString::to_string));

        // Direct protocol only supports TCP (no proxy server to connect via QUIC)
        let effective_transport = if config.protocol.is_direct() {
            &Transport::Tcp
        } else {
            &config.transport
        };

        let transport = match *effective_transport {
            Transport::Tcp | Transport::Udp => {
                let no_delay = config
                    .tcp_settings
                    .as_ref()
                    .map(|tc| tc.no_delay)
                    .unwrap_or(true);
                TransportConfig::Tcp { no_delay }
            }
            Transport::Quic => {
                // QUIC requires a target address for endpoint creation
                let target_address = target_address.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "QUIC transport requires a target address",
                    )
                })?;

                let ClientQuicConfig {
                    verify,
                    server_fingerprints,
                    alpn_protocols,
                    sni_hostname,
                    key,
                    cert,
                } = config.quic_settings.clone().unwrap_or_default();

                let sni_hostname = if sni_hostname.is_unspecified() {
                    if let Some(ref hostname) = default_sni_hostname {
                        debug!(
                            "Using default sni hostname for QUIC client connection: {}",
                            hostname
                        );
                    }
                    default_sni_hostname.clone()
                } else {
                    sni_hostname.into_option()
                };

                let tls13_suite =
                    match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
                        rustls::SupportedCipherSuite::Tls13(t) => t,
                        _ => {
                            panic!("Could not retrieve Tls13CipherSuite");
                        }
                    };

                let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                    let cert_bytes = cert.as_bytes().to_vec();
                    let key_bytes = key.as_bytes().to_vec();
                    (key_bytes, cert_bytes)
                });

                let rustls_client_config = try_create_client_config(
                    verify,
                    server_fingerprints.into_vec(),
                    alpn_protocols.into_vec(),
                    sni_hostname.is_some(),
                    key_and_cert_bytes,
                    false, // tls13_only - QUIC enforces TLS 1.3 anyway
                )?;

                let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
                    Arc::new(rustls_client_config),
                    tls13_suite.quic_suite().unwrap(),
                )
                .map_err(std::io::Error::other)?;

                let mut quinn_client_config =
                    quinn::ClientConfig::new(Arc::new(quic_client_config));

                let mut transport_config = quinn::TransportConfig::default();
                let memory_bytes = crate::resources::configure_quic_transport_with_limits(
                    &mut transport_config,
                    limits,
                );
                transport_config
                    .max_concurrent_bidi_streams(0_u32.into())
                    .max_concurrent_uni_streams(0_u8.into())
                    .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                    .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

                quinn_client_config.transport_config(Arc::new(transport_config));

                let endpoints_len = std::cmp::min(get_num_threads(), MAX_QUIC_ENDPOINTS);
                let mut endpoints = Vec::with_capacity(endpoints_len);

                for _ in 0..endpoints_len {
                    let udp_socket = if target_address.address().hostname().is_some() {
                        crate::socket_util::new_hostname_udp_socket(bind_interface.clone())?
                    } else {
                        new_udp_socket(target_address.address().is_ipv6(), bind_interface.clone())?
                    };
                    let udp_socket = udp_socket.into_std()?;

                    let mut endpoint = QuicEndpoint::new(None, udp_socket, memory_bytes)?;
                    endpoint.set_default_client_config(quinn_client_config.clone());
                    endpoints.push(Arc::new(endpoint));
                }

                TransportConfig::Quic {
                    sni_hostname,
                    endpoints,
                    next_endpoint_index: AtomicU8::new(0),
                }
            }
        };

        Ok(Self {
            bind_interface,
            transport,
        })
    }

    /// Create a simple TCP SocketConnector for direct connections.
    ///
    /// Used when only TCP is needed (no QUIC).
    #[cfg(test)]
    pub fn new_tcp(bind_interface: Option<String>, no_delay: bool) -> Self {
        Self {
            bind_interface,
            transport: TransportConfig::Tcp { no_delay },
        }
    }
}

#[async_trait]
impl SocketConnector for SocketConnectorImpl {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let mut target_addrs = match address.resolved_addr() {
            Some(r) => vec![r],
            None => resolve_addresses(resolver, address.location()).await?,
        };

        match &self.transport {
            TransportConfig::Tcp { no_delay } => {
                let stream = connect_tcp_candidates(target_addrs, |address| {
                    let socket = new_tcp_socket(self.bind_interface.clone(), address.is_ipv6())?;
                    Ok(socket.connect(address))
                })
                .await?;
                if let Err(e) = set_tcp_keepalive(
                    &stream,
                    std::time::Duration::from_secs(120),
                    std::time::Duration::from_secs(30),
                ) {
                    error!("Failed to set TCP keepalive: {e}");
                }
                if *no_delay && let Err(e) = stream.set_nodelay(true) {
                    error!("Failed to set TCP no-delay: {e}");
                }
                Ok(Box::new(stream))
            }
            TransportConfig::Quic {
                endpoints,
                next_endpoint_index,
                sni_hostname,
            } => {
                // Preserve IPv4 preference for hostnames without excluding IPv6-only targets.
                if address.address().hostname().is_some() {
                    target_addrs.sort_by_key(SocketAddr::is_ipv6);
                }
                let domain = match sni_hostname {
                    Some(s) => s.as_str(),
                    None => address.address().hostname().unwrap_or("example.com"),
                };

                let mut last_err = None;
                for (i, target_addr) in target_addrs.iter().enumerate() {
                    let endpoint = if endpoints.len() == 1 {
                        &endpoints[0]
                    } else {
                        let idx = next_endpoint_index.fetch_add(1, Ordering::Relaxed) as usize;
                        &endpoints[idx % endpoints.len()]
                    };

                    match endpoint.connect(*target_addr, domain) {
                        Ok(connecting) => match connecting.await {
                            Ok(conn) => match conn.open_bi().await {
                                Ok((send, recv)) => {
                                    if i > 0 {
                                        debug!(
                                            "QUIC connect succeeded on address #{} ({}) after {} failures",
                                            i, target_addr, i
                                        );
                                    }
                                    return Ok(Box::new(QuicStream::from(send, recv)));
                                }
                                Err(e) => {
                                    debug!("QUIC open_bi to {} failed: {}", target_addr, e);
                                    last_err = Some(std::io::Error::other(format!(
                                        "Failed to open QUIC stream: {e}"
                                    )));
                                }
                            },
                            Err(e) => {
                                debug!("QUIC connection to {} failed: {}", target_addr, e);
                                last_err = Some(std::io::Error::other(format!(
                                    "QUIC connection failed: {e}"
                                )));
                            }
                        },
                        Err(e) => {
                            debug!("QUIC connect to {} failed: {}", target_addr, e);
                            last_err = Some(std::io::Error::other(format!(
                                "Failed to connect to QUIC endpoint: {e}"
                            )));
                        }
                    }
                }
                Err(last_err
                    .unwrap_or_else(|| std::io::Error::other("no resolved addresses succeeded")))
            }
        }
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        mut target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        debug!(
            "[SocketConnector] connect_udp_bidirectional called, target: {}",
            target.location()
        );

        let remote_addr = resolve_location(&mut target, resolver).await?;
        let client_socket = new_udp_socket(remote_addr.is_ipv6(), self.bind_interface.clone())?;

        // Don't use connect() - wrap in UnconnectedUdpSocket instead.
        // A connected UDP socket filters incoming packets by source address,
        // which breaks when bind_interface causes packets to arrive from
        // a different source than the target address.
        Ok(Box::new(UnconnectedUdpSocket::new(
            client_socket,
            remote_addr,
        )))
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }
}

/// A UDP socket wrapper that tracks the destination and uses send_to/recv_from.
/// Unlike a connected UDP socket, this accepts incoming packets from any source.
struct UnconnectedUdpSocket {
    socket: UdpSocket,
    destination: SocketAddr,
}

impl UnconnectedUdpSocket {
    fn new(socket: UdpSocket, destination: SocketAddr) -> Self {
        Self {
            socket,
            destination,
        }
    }
}

impl crate::async_stream::AsyncReadMessage for UnconnectedUdpSocket {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.socket.poll_recv_from(cx, buf) {
            Poll::Ready(Ok(addr)) => {
                log::debug!(
                    "[UnconnectedUdp] Received {} bytes from {} (target: {})",
                    buf.filled().len(),
                    addr,
                    this.destination
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteMessage for UnconnectedUdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.socket
            .poll_send_to(cx, buf, this.destination)
            .map(|r| r.map(|_| ()))
    }
}

impl crate::async_stream::AsyncFlushMessage for UnconnectedUdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for UnconnectedUdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for UnconnectedUdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncMessageStream for UnconnectedUdpSocket {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::time::Instant;

    #[derive(Debug)]
    struct FixedResolver(Vec<SocketAddr>);

    impl Resolver for FixedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[tokio::test]
    async fn hostname_quic_prefers_ipv4_without_waiting_for_stalled_ipv6() {
        use tokio::io::AsyncWriteExt;
        let Ok(blackhole) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let stalled = blackhole.local_addr().unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let server =
                quinn::Endpoint::server(server_config.clone(), bind.parse().unwrap()).unwrap();
            let server_addr = server.local_addr().unwrap();
            let addresses = if server_addr.is_ipv4() {
                vec![stalled, server_addr]
            } else {
                vec![server_addr]
            };
            let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver(addresses));
            let config: ClientConfig = serde_yaml::from_str("address: 'localhost:443'\ntransport: quic\nquic_settings: {verify: false}\nprotocol: {type: socks}\n").unwrap();
            let connector =
                SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                let (client, received) = tokio::join!(
                    async {
                        let mut stream = connector
                            .connect(&resolver, &ResolvedLocation::new(config.address.clone()))
                            .await
                            .unwrap();
                        stream.write_all(b"ping").await.unwrap();
                        stream.flush().await.unwrap();
                        stream
                    },
                    async {
                        let connection = server.accept().await.unwrap().await.unwrap();
                        let (_send, mut recv) = connection.accept_bi().await.unwrap();
                        let mut data = [0; 4];
                        recv.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"ping");
                        connection
                    },
                );
                drop((client, received));
            })
            .await
            .unwrap();
            server.close(0u32.into(), b"done");
        }
    }

    fn addresses(count: u16) -> Vec<SocketAddr> {
        (1..=count)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect()
    }

    #[derive(Default)]
    struct Attempts {
        active: AtomicUsize,
        peak: AtomicUsize,
        starts: parking_lot::Mutex<Vec<(SocketAddr, Instant)>>,
    }

    struct ActiveAttempt(Arc<Attempts>);

    impl Attempts {
        fn start(self: &Arc<Self>, address: SocketAddr) -> ActiveAttempt {
            let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
            self.peak.fetch_max(active, Ordering::Relaxed);
            self.starts.lock().push((address, Instant::now()));
            ActiveAttempt(self.clone())
        }
    }

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn address_interleaving_preserves_resolver_family_preference() {
        let v4 = addresses(3);
        let v6: Vec<SocketAddr> = ["[::1]:1", "[::1]:2"].map(|s| s.parse().unwrap()).to_vec();
        assert_eq!(
            interleave_tcp_addresses(vec![v4[0], v4[1], v6[0], v6[1], v4[2]]),
            vec![v4[0], v6[0], v4[1], v6[1], v4[2]]
        );
        assert_eq!(
            interleave_tcp_addresses(vec![v6[0], v6[1], v4[0], v4[1]]),
            vec![v6[0], v4[0], v6[1], v4[1]]
        );
        assert_eq!(interleave_tcp_addresses(v4.clone()), v4);
        assert!(interleave_tcp_addresses(vec![]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stagger_keeps_slow_viable_attempts_and_cancels_losers() {
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates(addresses(3), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                if address.port() != 1 {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(Duration::from_millis(750)).await;
                Ok(address)
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 1);
        assert_eq!(start.elapsed(), Duration::from_millis(750));
        let starts = attempts.starts.lock();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[1].1 - starts[0].1, TCP_FALLBACK_DELAY);
        assert_eq!(attempts.peak.load(Ordering::Relaxed), 2);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn attempt_timeout_reaches_later_candidates_without_exceeding_the_cap() {
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates(addresses(4), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                if address.port() < 3 {
                    std::future::pending::<()>().await;
                }
                Ok(address)
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 3);
        assert_eq!(start.elapsed(), TCP_ATTEMPT_TIMEOUT);
        assert_eq!(attempts.starts.lock().len(), 3);
        assert_eq!(attempts.peak.load(Ordering::Relaxed), MAX_TCP_ATTEMPTS);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_advance_immediately_and_singletons_keep_their_deadline() {
        let start = Instant::now();
        let error = connect_tcp_candidates(addresses(3), |address| {
            Ok(async move { Err::<(), _>(std::io::Error::other(address.to_string())) })
        })
        .await
        .unwrap_err();
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(error.to_string(), "127.0.0.1:3");
        connect_tcp_candidates(addresses(1), |_| {
            Ok(async {
                tokio::time::sleep(TCP_ATTEMPT_TIMEOUT * 2).await;
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(start.elapsed(), TCP_ATTEMPT_TIMEOUT * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn outer_cancellation_drops_every_pending_socket() {
        let attempts = Arc::new(Attempts::default());
        let mut connect = Box::pin(connect_tcp_candidates(addresses(4), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                std::future::pending::<std::io::Result<()>>().await
            })
        }));
        assert!(futures::poll!(&mut connect).is_pending());
        tokio::time::advance(TCP_FALLBACK_DELAY).await;
        assert!(futures::poll!(&mut connect).is_pending());
        assert_eq!(attempts.active.load(Ordering::Relaxed), 2);
        drop(connect);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn socket_creation_failure_does_not_bypass_protection_or_binding() {
        let attempts = Arc::new(Attempts::default());
        let error = connect_tcp_candidates(addresses(3), |address| {
            if address.port() == 2 {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                std::future::pending::<std::io::Result<()>>().await
            })
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(attempts.starts.lock().len(), 1);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn pinned_tcp_target_bypasses_dns() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        #[derive(Debug)]
        struct NoDns;
        impl Resolver for NoDns {
            fn resolve_location(
                &self,
                _: &NetLocation,
            ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
            {
                panic!("a policy-pinned target must not resolve again")
            }
        }
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let target = ResolvedLocation::with_resolved(
            NetLocation::from_str("unknown.invalid:443", None).unwrap(),
            address,
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
        let mut stream = SocketConnectorImpl::new_tcp(None, true)
            .connect(&resolver, &target)
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        stream.write_all(b"pinned").await.unwrap();
        let mut data = [0; 6];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pinned");
    }

    #[test]
    fn test_new_tcp() {
        let connector = SocketConnectorImpl::new_tcp(Some("eth0".to_string()), true);
        assert!(matches!(
            connector.transport,
            TransportConfig::Tcp { no_delay: true }
        ));
        assert_eq!(connector.bind_interface, Some("eth0".to_string()));
    }

    #[test]
    fn test_from_config_direct_protocol() {
        let config = ClientConfig::default(); // default is direct protocol
        let connector = SocketConnectorImpl::from_config(&config, None);
        assert!(connector.is_ok());
        assert!(matches!(
            connector.unwrap().transport,
            TransportConfig::Tcp { .. }
        ));
    }
}
