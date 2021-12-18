use std::sync::Arc;

use crate::address::Location;
use crate::async_tls::{AsyncTlsConnector, AsyncTlsFactory};
use crate::config::ClientConfig;
use crate::protocol_handler::TcpClientHandler;

pub struct ClientProxy {
    pub location: Location,
    pub tls_connector: Option<Arc<Box<dyn AsyncTlsConnector>>>,
    pub client_handler: Box<dyn TcpClientHandler>,
}

impl ClientProxy {
    pub fn from_configs(
        configs: Vec<ClientConfig>,
        tls_factory: &Arc<dyn AsyncTlsFactory>,
    ) -> Vec<Self> {
        let mut ret = vec![];
        let mut cached_connector = None;
        for config in configs {
            ret.push(Self::from_config(
                config,
                tls_factory,
                &mut cached_connector,
            ));
        }
        ret
    }

    fn from_config(
        config: ClientConfig,
        tls_factory: &Arc<dyn AsyncTlsFactory>,
        cached_connector: &mut Option<Arc<Box<dyn AsyncTlsConnector>>>,
    ) -> Self {
        let location = config.location;

        let tls_connector = if config.secure {
            if cached_connector.is_none() {
                cached_connector.replace(Arc::new(tls_factory.create_connector(false)));
            }
            cached_connector.clone()
        } else {
            None
        };
        Self {
            location,
            tls_connector,
            client_handler: config.client_proxy_config.into(),
        }
    }
}
