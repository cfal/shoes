//! ProxyConnectorImpl - Implementation of ProxyConnector trait.
//!
//! Handles protocol setup for proxy connections on existing streams.
//! Created from the protocol-related fields of a ClientConfig.

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;

use super::proxy_connector::ProxyConnector;
use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// Implementation of ProxyConnector for proxy protocol setup.
///
/// Created from the protocol-related fields of a ClientConfig:
/// - `protocol`
/// - `address`
///
/// This connector only wraps protocols on existing streams - it does not
/// create socket connections. Socket creation is handled by SocketConnector.
#[derive(Debug)]
pub struct ProxyConnectorImpl {
    location: NetLocation,
    client_handler: Box<dyn TcpClientHandler>,
}

impl ProxyConnectorImpl {
    /// Create a ProxyConnector from a ClientConfig's protocol-related fields.
    ///
    /// Returns None for direct protocol (direct has no ProxyConnector).
    pub fn from_config(config: ClientConfig, resolver: Arc<dyn Resolver>) -> Option<Self> {
        if config.protocol.is_direct() {
            return None;
        }

        let default_sni_hostname = config.address.address().hostname().map(ToString::to_string);

        // QUIC-based protocols (TUIC, Hysteria2) need the full config (address,
        // quic_settings, bind_interface) because they manage their own QUIC connections.
        let client_handler =
            if let crate::config::ClientProxyConfig::Tuic {
                ref uuid,
                ref password,
                ref ports,
                ref hop_interval,
            } = config.protocol
            {
                let quic_config = config.quic_settings.clone().unwrap_or_default();
                let bind_interface = config.bind_interface.clone().into_option();

                let port_hop = ports.as_ref().map(|port_str| {
                    let port_list = crate::hysteria2_client::parse_port_range(port_str)
                        .unwrap_or_else(|e| panic!("Invalid TUIC port range: {e}"));
                    let interval = hop_interval
                        .map(|s| std::time::Duration::from_secs(s))
                        .unwrap_or(std::time::Duration::from_secs(30));
                    crate::hysteria2_client::PortHopConfig {
                        ports: port_list,
                        hop_interval: interval,
                    }
                });

                Box::new(crate::tuic_client::TuicTcpClientHandler::new(
                    config.address.clone(),
                    uuid,
                    password,
                    quic_config,
                    bind_interface,
                    resolver.clone(),
                    port_hop,
                )) as Box<dyn TcpClientHandler>
            } else if let crate::config::ClientProxyConfig::Hysteria2 {
                ref password,
                ref ports,
                ref hop_interval,
            } = config.protocol
            {
                let quic_config = config.quic_settings.clone().unwrap_or_default();
                let bind_interface = config.bind_interface.clone().into_option();

                let port_hop = ports.as_ref().map(|port_str| {
                    let port_list = crate::hysteria2_client::parse_port_range(port_str)
                        .unwrap_or_else(|e| panic!("Invalid Hysteria2 port range: {e}"));
                    let interval = hop_interval
                        .map(|s| std::time::Duration::from_secs(s))
                        .unwrap_or(std::time::Duration::from_secs(30));
                    crate::hysteria2_client::PortHopConfig {
                        ports: port_list,
                        hop_interval: interval,
                    }
                });

                Box::new(crate::hysteria2_client::Hysteria2TcpClientHandler::new(
                    config.address.clone(),
                    password,
                    quic_config,
                    bind_interface,
                    resolver.clone(),
                    port_hop,
                )) as Box<dyn TcpClientHandler>
            } else {
                create_tcp_client_handler(config.protocol, default_sni_hostname, resolver)
            };

        Some(Self {
            location: config.address,
            client_handler,
        })
    }

    /// Create a ProxyConnector directly from components.
    #[cfg(test)]
    pub fn new(location: NetLocation, handler: Box<dyn TcpClientHandler>) -> Self {
        Self {
            location,
            client_handler: handler,
        }
    }
}

#[async_trait]
impl ProxyConnector for ProxyConnectorImpl {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.client_handler.supports_udp_over_tcp()
    }

    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        debug!(
            "[ProxyConnector] setup_tcp_stream: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_tcp_stream(stream, target.clone())
            .await
    }

    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        debug!(
            "[ProxyConnector] setup_udp_bidirectional: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_udp_bidirectional(stream, target)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProxyConfig;
    use crate::resolver::NativeResolver;
    use std::net::{IpAddr, Ipv4Addr};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    #[test]
    fn test_from_direct_config_returns_none() {
        let config = ClientConfig::default();
        assert!(config.protocol.is_direct());
        assert!(ProxyConnectorImpl::from_config(config, mock_resolver()).is_none());
    }

    #[test]
    fn test_from_proxy_config_returns_some() {
        let config = ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let connector = ProxyConnectorImpl::from_config(config, mock_resolver());
        assert!(connector.is_some());
        let connector = connector.unwrap();
        assert_eq!(connector.proxy_location().port(), 1080);
    }
}
