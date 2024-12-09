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
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
    },
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: ref mut flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: ref mut flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: ref mut flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
        }
    }
    pub fn override_proxy_provider_unspecified(&self) -> bool {
        match self {
            TcpServerSetupResult::TcpForward {
                override_proxy_provider,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                override_proxy_provider,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                override_proxy_provider,
                ..
            } => override_proxy_provider.is_unspecified(),
        }
    }

    pub fn set_override_proxy_provider(
        &mut self,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
    ) {
        match self {
            TcpServerSetupResult::TcpForward {
                override_proxy_provider: ref mut provider,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                override_proxy_provider: ref mut provider,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                override_proxy_provider: ref mut provider,
                ..
            } => {
                *provider = override_proxy_provider;
            }
        }
    }
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
