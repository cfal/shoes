//! AmneziaWG virtual network connector implementation.

use std::sync::Arc;

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::config::AmneziaWgClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::virtual_network_connector::VirtualNetworkConnector;

/// AmneziaWG virtual network connector.
///
/// Owns a long-lived AmneziaWG tunnel and exposes TCP/UDP dialing through
/// its virtual network stack. The tunnel is initialized lazily on first use.
#[derive(Debug)]
pub struct AmneziaWgConnector {
    config: AmneziaWgClientConfig,
    endpoint: NetLocation,
}

impl AmneziaWgConnector {
    pub fn new(config: AmneziaWgClientConfig, endpoint: NetLocation) -> Self {
        Self { config, endpoint }
    }
}

#[async_trait]
impl VirtualNetworkConnector for AmneziaWgConnector {
    async fn connect_tcp(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AmneziaWG TCP support not yet implemented",
        ))
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AmneziaWG UDP support not yet implemented",
        ))
    }
}
