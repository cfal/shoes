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
use log::{debug, error};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::config::{ClientConfig, ClientQuicConfig, Transport};
use crate::quic_stream::QuicStream;
use crate::resolver::{resolve_location, resolve_single_address, Resolver};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::{new_tcp_socket, new_udp_socket, set_tcp_keepalive};
use crate::thread_util::get_num_threads;

use super::socket_connector::SocketConnector;

const MAX_QUIC_ENDPOINTS: usize = 32;

#[derive(Debug)]
enum TransportConfig {
    Tcp {
        no_delay: bool,
    },
    Quic {
        sni_hostname: Option<String>,
        endpoints: Vec<Arc<quinn::Endpoint>>,
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
    /// None if QUIC endpoint creation fails.
    pub fn from_config(
        config: &ClientConfig,
        target_address: Option<&NetLocation>,
    ) -> Option<Self> {
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
                let target_address = target_address.expect(
                    "QUIC transport requires target_address (direct protocol should use TCP)",
                );

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

                let rustls_client_config = create_client_config(
                    verify,
                    server_fingerprints.into_vec(),
                    alpn_protocols.into_vec(),
                    sni_hostname.is_some(),
                    key_and_cert_bytes,
                    false, // tls13_only - QUIC enforces TLS 1.3 anyway
                );

                let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
                    Arc::new(rustls_client_config),
                    tls13_suite.quic_suite().unwrap(),
                )
                .unwrap();

                let mut quinn_client_config =
                    quinn::ClientConfig::new(Arc::new(quic_client_config));

                let mut transport_config = quinn::TransportConfig::default();
                transport_config
                    .max_concurrent_bidi_streams(0_u32.into())
                    .max_concurrent_uni_streams(0_u8.into())
                    .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                    .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

                quinn_client_config.transport_config(Arc::new(transport_config));

                let endpoints_len = std::cmp::min(get_num_threads(), MAX_QUIC_ENDPOINTS);
                let mut endpoints = Vec::with_capacity(endpoints_len);

                for _ in 0..endpoints_len {
                    let udp_socket = match new_udp_socket(
                        target_address.address().is_ipv6(),
                        bind_interface.clone(),
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to bind new UDP socket for QUIC: {e}");
                            return None;
                        }
                    };
                    let udp_socket = udp_socket.into_std().unwrap();

                    let mut endpoint = quinn::Endpoint::new(
                        quinn::EndpointConfig::default(),
                        None,
                        udp_socket,
                        Arc::new(quinn::TokioRuntime),
                    )
                    .unwrap();
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

        Some(Self {
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
        let target_addr = match address.resolved_addr() {
            Some(r) => r,
            None => resolve_single_address(resolver, address.location()).await?,
        };

        match &self.transport {
            TransportConfig::Tcp { no_delay } => {
                let tcp_socket =
                    new_tcp_socket(self.bind_interface.clone(), target_addr.is_ipv6())?;
                let stream = tcp_socket.connect(target_addr).await?;

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
                let domain = match sni_hostname {
                    Some(s) => s.as_str(),
                    None => address.address().hostname().unwrap_or("example.com"),
                };

                let endpoint = if endpoints.len() == 1 {
                    &endpoints[0]
                } else {
                    let idx = next_endpoint_index.fetch_add(1, Ordering::Relaxed) as usize;
                    &endpoints[idx % endpoints.len()]
                };

                let conn = endpoint
                    .connect(target_addr, domain)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to connect to QUIC endpoint: {e}"))
                    })?
                    .await
                    .map_err(|e| std::io::Error::other(format!("QUIC connection failed: {e}")))?;

                let (send, recv) = conn.open_bi().await.map_err(|e| {
                    std::io::Error::other(format!("Failed to open QUIC stream: {e}"))
                })?;

                Ok(Box::new(QuicStream::from(send, recv)))
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
        assert!(connector.is_some());
        assert!(matches!(
            connector.unwrap().transport,
            TransportConfig::Tcp { .. }
        ));
    }
}
