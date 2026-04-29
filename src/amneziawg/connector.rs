//! AmneziaWG virtual network connector implementation.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::config::AmneziaWgClientConfig;
use crate::resolver::{self, Resolver};
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::virtual_network_connector::VirtualNetworkConnector;

use super::config::AwgRuntimeConfig;
use super::netstack::{NetStackRequest, VirtualNetStack};
use super::tunnel::TunnelRuntime;

struct TunnelState {
    _runtime: Arc<TunnelRuntime>,
    request_tx: mpsc::Sender<NetStackRequest>,
}

pub struct AmneziaWgConnector {
    config: AmneziaWgClientConfig,
    endpoint: NetLocation,
    state: Mutex<Option<TunnelState>>,
}

impl std::fmt::Debug for AmneziaWgConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmneziaWgConnector")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl AmneziaWgConnector {
    pub fn new(config: AmneziaWgClientConfig, endpoint: NetLocation) -> Self {
        Self {
            config,
            endpoint,
            state: Mutex::new(None),
        }
    }

    async fn ensure_initialized(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<mpsc::Sender<NetStackRequest>> {
        let mut state = self.state.lock().await;
        if let Some(ref s) = *state {
            return Ok(s.request_tx.clone());
        }

        info!("AmneziaWG: initializing tunnel to {}", self.endpoint);

        let runtime_config = AwgRuntimeConfig::from_client_config(&self.config)?;
        let endpoint_addr = resolver::resolve_single_address(resolver, &self.endpoint).await?;

        let tunnel_runtime = TunnelRuntime::start(
            runtime_config.private_key,
            runtime_config.peer_public_key,
            runtime_config.preshared_key,
            runtime_config.persistent_keepalive,
            runtime_config.amnezia,
            endpoint_addr,
        )
        .await?;

        let ip_from_tunnel_rx = tunnel_runtime
            .ip_from_tunnel_rx
            .lock()
            .take()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "AmneziaWG tunnel already initialized",
                )
            })?;

        let netstack = VirtualNetStack::new(
            &runtime_config.local_addresses,
            runtime_config.mtu,
            tunnel_runtime.ip_to_tunnel_tx.clone(),
            ip_from_tunnel_rx,
        );

        let (request_tx, request_rx) = mpsc::channel::<NetStackRequest>(64);

        tokio::spawn(async move {
            netstack.run(request_rx).await;
        });

        *state = Some(TunnelState {
            _runtime: tunnel_runtime,
            request_tx: request_tx.clone(),
        });

        Ok(request_tx)
    }
}

#[async_trait]
impl VirtualNetworkConnector for AmneziaWgConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let request_tx = self.ensure_initialized(resolver).await?;
        let target_addr = resolve_target(resolver, &target).await?;

        debug!("AmneziaWG: TCP connect to {}", target_addr);

        let (reply_tx, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectTcp {
                target: target_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "AmneziaWG netstack stopped",
                )
            })?;

        let stream = reply_rx.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AmneziaWG netstack did not reply",
            )
        })??;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let request_tx = self.ensure_initialized(resolver).await?;
        let target_addr = resolve_target(resolver, &target).await?;

        debug!("AmneziaWG: UDP connect to {}", target_addr);

        let (reply_tx, reply_rx) = oneshot::channel();
        request_tx
            .send(NetStackRequest::ConnectUdp {
                target: target_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "AmneziaWG netstack stopped",
                )
            })?;

        let stream = reply_rx.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AmneziaWG netstack did not reply",
            )
        })??;

        Ok(Box::new(stream))
    }
}

async fn resolve_target(
    resolver: &Arc<dyn Resolver>,
    target: &ResolvedLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = target.resolved_addr() {
        return Ok(addr);
    }
    resolver::resolve_single_address(resolver, target.location()).await
}
