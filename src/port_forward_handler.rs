use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct PortForwardServerHandler {
    targets: Vec<NetLocation>,
    next_target_index: AtomicU32,
}

impl PortForwardServerHandler {
    pub fn new(targets: Vec<NetLocation>) -> Self {
        Self {
            targets,
            next_target_index: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl TcpServerHandler for PortForwardServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let location = if self.targets.len() == 1 {
            &self.targets[0]
        } else {
            let target_index = self.next_target_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.targets[target_index % self.targets.len()]
        };

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: location.clone(),
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            initial_remote_data: None,
            override_proxy_provider: NoneOrOne::Unspecified,
        })
    }
}

#[derive(Debug)]
pub struct PortForwardClientHandler;

#[async_trait]
impl TcpClientHandler for PortForwardClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        _remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }
}
