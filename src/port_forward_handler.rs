use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::tcp_handler::{
    TcpServerHandler, TcpServerRemoteLocationTlsConfig, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct PortForwardServerHandler {
    targets: Vec<PortForwardTarget>,
    next_target_index: AtomicUsize,
}

#[derive(Debug)]
pub struct PortForwardTarget {
    location: NetLocation,
    tls_config: Option<TcpServerRemoteLocationTlsConfig>,
}

impl PortForwardTarget {
    pub fn new(
        location: NetLocation,
        tls_config: Option<TcpServerRemoteLocationTlsConfig>,
    ) -> Self {
        Self {
            location,
            tls_config,
        }
    }
}

impl PortForwardServerHandler {
    pub fn new(targets: Vec<PortForwardTarget>) -> Self {
        Self {
            targets,
            next_target_index: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl TcpServerHandler for PortForwardServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let target = if self.targets.len() == 1 {
            &self.targets[0]
        } else {
            let target_index = self.next_target_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.targets[target_index % self.targets.len()]
        };

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: target.location.clone(),
            remote_location_tls_config: target.tls_config.clone(),
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: None,
            override_proxy_provider: NoneOrOne::Unspecified,
        })
    }
}
