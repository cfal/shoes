use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    address::ResolvedLocation,
    async_stream::{AsyncMessageStream, AsyncStream},
    resolver::Resolver,
    tcp::tcp_handler::{
        TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
    },
};

use super::{Prepared, Role, stream::SudokuStream};

#[derive(Debug)]
pub(crate) struct ClientHandler {
    pub config: Arc<Prepared>,
    pub inner: Box<dyn TcpClientHandler>,
}

#[async_trait]
impl TcpClientHandler for ClientHandler {
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<ResolvedLocation> {
        self.inner.prepare_target(target, resolver).await
    }

    fn validate_alpn(&self, alpn: Option<&[u8]>) -> io::Result<()> {
        self.inner.validate_alpn(alpn)
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> io::Result<Option<TcpClientSetupResult>> {
        self.inner.try_reuse_tcp_stream(target).await
    }

    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.inner
            .setup_client_tcp_stream(
                Box::new(SudokuStream::new(stream, self.config.clone(), Role::Client)),
                target,
            )
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.inner.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.inner
            .setup_client_udp_bidirectional(
                Box::new(SudokuStream::new(stream, self.config.clone(), Role::Client)),
                target,
            )
            .await
    }
}

#[derive(Debug)]
pub(crate) struct ServerHandler {
    pub config: Arc<Prepared>,
    pub inner: Box<dyn TcpServerHandler>,
}

#[async_trait]
impl TcpServerHandler for ServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let mut result = self
            .inner
            .setup_server_stream(Box::new(SudokuStream::new(
                stream,
                self.config.clone(),
                Role::Server,
            )))
            .await?;
        result.set_need_initial_flush(true);
        Ok(result)
    }
}
