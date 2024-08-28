use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::option_util::NoneOrOne;
use crate::tcp_client_connector::TcpClientConnector;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        // the response to write to the server stream after a connection to the remote location is
        // successful
        connection_success_response: Option<Box<[u8]>>,
        // initial data to send to the remote location.
        initial_remote_data: Option<Box<[u8]>>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
    },
    // TODO: support udp client proxy selector
    BidirectionalUdp {
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
    },
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult>;
}
