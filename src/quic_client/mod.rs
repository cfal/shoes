mod hysteria2;
#[cfg(all(test, feature = "optional-peer-tests"))]
mod interop;
mod session;
mod tuic;
mod udp;

use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    config::{ClientConfig, ClientProxyConfig, Transport},
    tcp::{
        carrier_dialer::CarrierDialer, proxy_connector::ProxyConnector,
        tcp_handler::TcpClientSetupResult,
    },
};

pub(crate) fn validate(config: &ClientConfig, first: bool) -> io::Result<()> {
    if !config.protocol.is_native_quic() {
        return Ok(());
    }
    if !first || config.transport != Transport::Quic || config.tcp_settings.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native QUIC clients require transport: quic at hop 0 without TCP settings",
        ));
    }
    match &config.protocol {
        ClientProxyConfig::Hysteria2(settings) => settings.validate(),
        ClientProxyConfig::Tuic(settings) => settings.validate(),
        _ => unreachable!(),
    }
}

#[derive(Clone, Debug)]
enum Protocol {
    Hysteria2(crate::config::quic_client::Hysteria2ClientConfig),
    Tuic(crate::config::quic_client::TuicClientConfig),
}

impl Protocol {
    fn udp_enabled(&self) -> bool {
        match self {
            Self::Hysteria2(config) => config.udp_enabled,
            Self::Tuic(config) => config.udp_enabled,
        }
    }
}

pub(crate) struct Client {
    location: NetLocation,
    protocol: Protocol,
    sessions: session::Pool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicClient")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> io::Result<Self> {
        validate(&config, true)?;
        let protocol = match config.protocol {
            ClientProxyConfig::Hysteria2(config) => Protocol::Hysteria2(config),
            ClientProxyConfig::Tuic(config) => Protocol::Tuic(config),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a native QUIC client",
                ));
            }
        };
        Ok(Self {
            location: config.address,
            protocol,
            sessions: session::Pool::default(),
        })
    }
}

#[async_trait]
impl ProxyConnector for Client {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp(&self) -> bool {
        self.protocol.udp_enabled()
    }
    fn needs_carrier_dialer(&self) -> bool {
        true
    }

    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let generation = self
            .sessions
            .get(dialer, self.protocol.clone(), false)
            .await?;
        match &self.protocol {
            Protocol::Hysteria2(_) => hysteria2::connect(generation, target).await,
            Protocol::Tuic(_) => tuic::connect(generation, target).await,
        }
    }

    async fn connect_udp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        if !self.supports_udp() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "UDP disabled"));
        }
        // Allocation races can exhaust a generation after the pool checked it.
        loop {
            let generation = self
                .sessions
                .get(dialer.clone(), self.protocol.clone(), true)
                .await?;
            if !generation.udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "peer disabled UDP",
                ));
            }
            if generation.connection().max_datagram_size().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "peer did not negotiate QUIC datagrams",
                ));
            }
            if let Some(stream) = udp::Association::new(generation, target.location().clone())? {
                return Ok(Box::new(stream));
            }
        }
    }

    async fn setup_tcp_stream(
        &self,
        _: Box<dyn AsyncStream>,
        _: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native QUIC requires a carrier dialer",
        ))
    }

    async fn setup_udp_bidirectional(
        &self,
        _: Box<dyn AsyncStream>,
        _: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native QUIC requires a carrier dialer",
        ))
    }
}
