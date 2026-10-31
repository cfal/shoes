//! AnyTLS Client Handler
//!
//! Implements TcpClientHandler for AnyTLS protocol outbound connections.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::anytls_client_pool::{OpeningSession, PoolOptions, SessionPool};
use super::anytls_client_session::{AnyTlsClientSession, validate_destination};
use super::anytls_stream::AnyTlsStream;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::anytls::anytls_padding::{PaddingFactory, SharedPadding};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::socks_handler::write_location_to_vec;
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use crate::vless::VlessMessageStream;

/// AnyTLS client handler implementing TcpClientHandler.
///
/// Creates an AnyTLS session on the provided transport (expected to be TLS-wrapped),
/// opens multiplexed streams to destinations, and supports UDP-over-TCP via UoT magic addresses.
#[derive(Clone)]
pub struct AnyTlsClientHandler {
    /// Authentication password
    password: String,
    /// Padding factory for traffic obfuscation
    padding: SharedPadding,
    pool: Arc<SessionPool>,
    /// UDP enabled
    udp_enabled: bool,
}

impl std::fmt::Debug for AnyTlsClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientHandler")
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl AnyTlsClientHandler {
    pub fn with_options(
        password: String,
        padding: Arc<PaddingFactory>,
        udp_enabled: bool,
        options: PoolOptions,
    ) -> Self {
        Self {
            password,
            padding: Arc::new(parking_lot::RwLock::new(padding)),
            pool: SessionPool::new(options),
            udp_enabled,
        }
    }

    async fn acquire(&self, transport: ClientTransport<'_>) -> std::io::Result<OpeningSession> {
        if let Some(session) = self.pool.take(transport.route.route_key()) {
            return Ok(OpeningSession::new(session));
        }
        self.create(transport.open.await?).await
    }

    async fn create(&self, transport: Box<dyn AsyncStream>) -> std::io::Result<OpeningSession> {
        Ok(OpeningSession::new(
            AnyTlsClientSession::new(transport, &self.password, self.padding.clone()).await?,
        ))
    }

    fn validate_udp(&self, target: &ResolvedLocation) -> std::io::Result<()> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS client",
            ));
        }
        validate_destination(target.location())
    }

    async fn open_udp(
        &self,
        session: &Arc<AnyTlsClientSession>,
        target: &ResolvedLocation,
    ) -> std::io::Result<AnyTlsStream> {
        let uot_dest = NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut stream = session.open_stream(uot_dest).await?;
        stream.write_u8(1).await?;
        stream
            .write_all(&write_location_to_vec(target.location())?)
            .await?;
        stream.flush().await?;
        Ok(stream)
    }
}

#[async_trait]
impl TcpClientHandler for AnyTlsClientHandler {
    fn has_session_pool(&self) -> bool {
        true
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        validate_destination(target.location())?;
        let route = transport.route.clone();
        let opening = self.acquire(transport).await?;
        let stream = opening.session.open_stream(target.into_location()).await?;
        stream.attach_pool(&self.pool, route);
        opening.disarm();
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.validate_udp(&target)?;
        let route = transport.route.clone();
        let opening = self.acquire(transport).await?;
        let stream = self.open_udp(&opening.session, &target).await?;
        stream.attach_pool(&self.pool, route);
        opening.disarm();
        Ok(Box::new(VlessMessageStream::new(stream)))
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        validate_destination(remote_location.location())?;
        let opening = self.create(client_stream).await?;
        let stream = opening
            .session
            .open_stream(remote_location.into_location())
            .await?;
        opening.disarm();

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.validate_udp(&target)?;
        let opening = self.create(client_stream).await?;
        let stream = self.open_udp(&opening.session, &target).await?;
        opening.disarm();
        Ok(Box::new(VlessMessageStream::new(stream)))
    }
}
