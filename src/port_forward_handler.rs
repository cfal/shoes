use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct PortForwardServerHandler {
    targets: Vec<NetLocation>,
    next_target_index: AtomicU32,
    proxy_selector: Arc<ClientProxySelector>,
}

impl PortForwardServerHandler {
    pub fn new(targets: Vec<NetLocation>, proxy_selector: Arc<ClientProxySelector>) -> Self {
        Self {
            targets,
            next_target_index: AtomicU32::new(0),
            proxy_selector,
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
            proxy_selector: self.proxy_selector.clone(),
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
        _remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }
}
