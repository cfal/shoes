//! ProxyConnectorImpl - Implementation of ProxyConnector trait.
//!
//! Handles protocol setup for proxy connections on existing streams.
//! Created from the protocol-related fields of a ClientConfig.

use async_trait::async_trait;
use log::debug;

use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::config::ClientConfig;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpClientUdpSetupResult, UdpStreamRequest,
};

use super::proxy_connector::ProxyConnector;

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
    pub fn from_config(config: ClientConfig) -> Option<Self> {
        if config.protocol.is_direct() {
            return None;
        }

        let default_sni_hostname = config.address.address().hostname().map(ToString::to_string);

        Some(Self {
            location: config.address,
            client_handler: create_tcp_client_handler(config.protocol, default_sni_hostname),
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
        target: &NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        debug!(
            "[ProxyConnector] setup_tcp_stream: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_tcp_stream(stream, target.clone())
            .await
    }

    async fn setup_udp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        request: UdpStreamRequest,
    ) -> std::io::Result<TcpClientUdpSetupResult> {
        debug!(
            "[ProxyConnector] setup_udp_stream: {}, request: {}",
            self.location, request
        );
        self.client_handler
            .setup_client_udp_stream(stream, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProxyConfig;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_from_direct_config_returns_none() {
        let config = ClientConfig::default();
        assert!(config.protocol.is_direct());
        assert!(ProxyConnectorImpl::from_config(config).is_none());
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
        let connector = ProxyConnectorImpl::from_config(config);
        assert!(connector.is_some());
        let connector = connector.unwrap();
        assert_eq!(connector.proxy_location().port(), 1080);
    }
}
