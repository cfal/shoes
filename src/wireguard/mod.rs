mod detour;
mod io;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::{
    device::{DeviceBuilder, Peer},
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    fmt, io as stdio,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    config::{ClientProxyConfig, ValidatedConfigs, wireguard::WireguardConfig},
    dns::DnsRegistry,
    ip_stack::driver::{PacketStack, StackHandle},
    resolver::{NativeResolver, Resolver, resolve_addresses},
    tcp::socket_connector::SocketConnector,
};

struct Connector {
    name: String,
    active: Mutex<Option<StackHandle>>,
    addresses: Vec<IpAddr>,
    routes: Vec<IpNetwork>,
}
impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireguardConnector")
            .field("endpoint", &self.name)
            .finish()
    }
}
impl Connector {
    fn handle(&self) -> stdio::Result<StackHandle> {
        self.active.lock().clone().ok_or_else(|| {
            stdio::Error::new(
                stdio::ErrorKind::NotConnected,
                format!("WireGuard endpoint {} is not active", self.name),
            )
        })
    }
    fn reachable(&self, address: SocketAddr) -> bool {
        self.addresses
            .iter()
            .any(|ip| ip.is_ipv4() == address.is_ipv4())
            && self
                .routes
                .iter()
                .any(|network| network.contains(address.ip()))
    }
    async fn destinations(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> stdio::Result<Vec<SocketAddr>> {
        let addresses = if let Some(address) = target.resolved_addr() {
            vec![address]
        } else {
            resolve_addresses(resolver, target.location()).await?
        };
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|address| self.reachable(*address))
            .collect();
        if addresses.is_empty() {
            return Err(stdio::Error::new(
                stdio::ErrorKind::AddrNotAvailable,
                "WireGuard destination has no allowed route or local address family",
            ));
        }
        Ok(addresses)
    }
}
#[async_trait]
impl SocketConnector for Connector {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> stdio::Result<Box<dyn AsyncStream>> {
        let handle = self.handle()?;
        let mut last_error = stdio::Error::from(stdio::ErrorKind::NotConnected);
        for address in self.destinations(resolver, target).await? {
            match handle.connect(address).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> stdio::Result<Box<dyn AsyncMessageStream>> {
        let handle = self.handle()?;
        let address = self.destinations(resolver, &target).await?[0];
        Ok(Box::new(handle.open_udp(address).await?))
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

struct PreparedEndpoint {
    config: WireguardConfig,
    peers: Vec<Peer>,
    connector: Arc<Connector>,
    global_limits: crate::config::GlobalLimits,
}

#[derive(Default)]
pub(crate) struct Prepared {
    endpoints: Vec<PreparedEndpoint>,
}

impl Prepared {
    pub async fn new(validated: &mut ValidatedConfigs) -> stdio::Result<Self> {
        let mut pending = Vec::new();
        let mut connectors = HashMap::new();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        for config in &validated.wireguard_endpoints {
            config.validate()?;
            let mut peers = Vec::new();
            for peer_config in &config.peers {
                let mut peer = Peer::new(PublicKey::from(peer_config.public_key.0));
                peer.allowed_ips = peer_config
                    .allowed_ips
                    .iter()
                    .map(|prefix| prefix.parse().map_err(stdio::Error::other))
                    .collect::<stdio::Result<_>>()?;
                peer.preshared_key = peer_config.pre_shared_key.as_ref().map(|key| key.0);
                peer.keepalive = (peer_config.persistent_keepalive != 0)
                    .then_some(peer_config.persistent_keepalive);
                if let Some(endpoint) = &peer_config.endpoint {
                    let address = NetLocation::from_str(endpoint, None)?;
                    peer.endpoint = Some(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            resolve_addresses(&resolver, &address),
                        )
                        .await
                        .map_err(|_| {
                            stdio::Error::new(
                                stdio::ErrorKind::TimedOut,
                                "WireGuard endpoint DNS timed out",
                            )
                        })??
                        .into_iter()
                        .find(|address| config.can_reach_endpoint(*address))
                        .ok_or_else(|| {
                            stdio::Error::new(
                                stdio::ErrorKind::AddrNotAvailable,
                                "WireGuard peer has no endpoint compatible with the listen address",
                            )
                        })?,
                    );
                }
                peers.push(peer);
            }
            let addresses = config
                .addresses
                .iter()
                .map(|address| {
                    address
                        .parse::<IpNetwork>()
                        .map(|network| network.ip())
                        .map_err(stdio::Error::other)
                })
                .collect::<stdio::Result<_>>()?;
            let connector = Arc::new(Connector {
                name: config.wireguard.clone(),
                active: Mutex::new(None),
                addresses,
                routes: peers
                    .iter()
                    .flat_map(|peer| peer.allowed_ips.iter().copied())
                    .collect(),
            });
            connectors.insert(config.wireguard.clone(), connector.clone());
            pending.push((peers, connector));
        }
        validated.visit_clients(&mut |client| {
            if let ClientProxyConfig::Wireguard(reference) = &mut client.protocol {
                reference.connector = Some(
                    connectors
                        .get(&reference.endpoint)
                        .ok_or_else(|| stdio::Error::other("unknown WireGuard endpoint"))?
                        .clone(),
                );
            }
            Ok(())
        })?;
        // Endpoint chains share the prepared handles used by ordinary listeners and DNS.
        let mut endpoints = Vec::with_capacity(pending.len());
        for ((peers, connector), config) in pending.into_iter().zip(&validated.wireguard_endpoints)
        {
            let endpoint = PreparedEndpoint {
                config: config.clone(),
                peers,
                connector,
                global_limits: validated.global_limits,
            };
            endpoint.build_outer_chain(&resolver)?;
            endpoints.push(endpoint);
        }
        Ok(Self { endpoints })
    }

    pub async fn start(&self, dns: &mut DnsRegistry, running: &mut Running) -> stdio::Result<()> {
        for endpoint in &self.endpoints {
            let runtime = endpoint.start(dns).await?;
            running.endpoints.push(runtime);
        }
        Ok(())
    }
}

struct EndpointRuntime {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
impl Drop for EndpointRuntime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Default)]
pub(crate) struct Running {
    endpoints: Vec<EndpointRuntime>,
}
impl Running {
    pub async fn stop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.cancel.cancel();
        }
        for mut endpoint in self.endpoints.drain(..) {
            let _ = (&mut endpoint.task).await;
        }
    }
}

impl PreparedEndpoint {
    fn build_outer_chain(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> stdio::Result<Option<Arc<crate::client_proxy_chain::ClientProxyChain>>> {
        let Some(config) = &self.config.outer_client_chain else {
            return Ok(None);
        };
        let chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
            config.hops.clone(),
            resolver.clone(),
            self.global_limits,
        )?;
        if !chain.supports_udp() {
            return Err(crate::config::wireguard::invalid(format!(
                "WireGuard endpoint {} outer_client_chain does not support UDP",
                self.config.wireguard,
            )));
        }
        Ok(Some(Arc::new(chain)))
    }

    async fn start(&self, dns: &mut DnsRegistry) -> stdio::Result<EndpointRuntime> {
        let config = &self.config;
        let inbound = if let Some(inbound) = &config.inbound {
            let resolver = dns.get_for_server(inbound.dns.as_ref());
            let rules = inbound
                .rules
                .clone()
                .map(crate::config::ConfigSelection::unwrap_config)
                .into_vec();
            let selector = Arc::new(
                crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
                    rules,
                    resolver.clone(),
                )?,
            );
            Some((selector, resolver))
        } else {
            None
        };
        let limits = config.limits();
        let mut stack = PacketStack::new(
            self.connector.addresses.clone(),
            config.mtu,
            inbound.is_some(),
            limits.clone(),
        )?;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        // Rebuilding after preflight gives each start fresh pool indices and handler lifetimes.
        let (udp, released) = if let Some(chain) = self.build_outer_chain(&resolver)? {
            let (sender, receiver, released) = detour::start(
                config.wireguard.clone(),
                chain,
                resolver,
                self.peers.iter().map(|peer| peer.endpoint.unwrap()),
                stack.drops.clone(),
            );
            log::info!(
                "WireGuard endpoint {} using outer_client_chain",
                config.wireguard
            );
            (io::Factory::detour(sender, receiver), released)
        } else {
            let (udp, released, local) =
                io::Factory::new(config.listen, config.bind_interface.clone())?;
            log::info!(
                "WireGuard endpoint {} listening on {local}",
                config.wireguard
            );
            (udp, released)
        };
        let mut device = DeviceBuilder::new()
            .with_udp(udp)
            .with_private_key(StaticSecret::from(config.private_key.0))
            .with_peers(self.peers.clone())
            .with_ip_pair(
                io::IpSink {
                    sender: stack.input.clone(),
                    wake: stack.handle.wake.clone(),
                    mtu: config.mtu,
                    drops: stack.drops.clone(),
                },
                io::IpSource {
                    receiver: stack.output.take().unwrap(),
                    mtu: config.mtu,
                },
            )
            .build()
            .await
            .map_err(|error| {
                stdio::Error::other(format!("WireGuard device startup failed: {error}"))
            })?;
        *self.connector.active.lock() = Some(stack.handle.clone());
        let connector = self.connector.clone();
        let name = config.wireguard.clone();
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let mut inbound_udp_count = None;
            if let Some((selector, resolver)) = inbound {
                let udp = stack.udp.take().unwrap();
                let (reader, writer) = crate::tun::udp_handler::UdpHandler::new(
                    udp,
                    stack.replies.clone(),
                    stack.handle.wake.clone(),
                )
                .split();
                let manager = crate::tun::udp_manager::TunUdpManager::new(
                    reader,
                    writer,
                    selector.clone(),
                    resolver.clone(),
                    limits,
                );
                inbound_udp_count = Some(manager.destination_counter());
                tasks.spawn(async move {
                    if let Err(error) = manager.run().await {
                        log::warn!("WireGuard UDP forwarding stopped: {error}");
                    }
                });
                let mut tcp = stack.tcp.take().unwrap();
                tasks.spawn(async move {
                    let mut flows = JoinSet::new();
                    loop {
                        tokio::select! {
                            connection = tcp.recv() => {
                                let Some(connection) = connection else { break; };
                                let selector = selector.clone();
                                let resolver = resolver.clone();
                                flows.spawn(async move {
                                    log::debug!("WireGuard TCP {} -> {}", connection.source, connection.target);
                                    let target = NetLocation::from_ip_addr(
                                        connection.target.ip(), connection.target.port(),
                                    );
                                    let _ = crate::tun::handle_tcp_connection(
                                        connection.connection, target, selector, resolver,
                                    ).await;
                                });
                            }
                            _ = flows.join_next(), if !flows.is_empty() => {}
                        }
                    }
                });
            }
            let mut report = tokio::time::interval(std::time::Duration::from_secs(60));
            report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let failed = loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break false,
                    _ = device.wait() => break true,
                    _ = &mut stack.done => break true,
                    _ = tasks.join_next(), if !tasks.is_empty() => break true,
                    _ = report.tick() => {
                        log::info!(
                            "WireGuard endpoint {name} tcp_flows={} outbound_udp_flows={} inbound_udp_destinations={} packet_drops={}",
                            stack.counts.tcp.load(std::sync::atomic::Ordering::Relaxed),
                            stack.counts.outbound_udp.load(std::sync::atomic::Ordering::Relaxed),
                            inbound_udp_count.as_ref().map_or(0, |count| count.snapshot().active),
                            stack.drops.load(std::sync::atomic::Ordering::Relaxed),
                        );
                        for peer in device.peers().await {
                            log::info!(
                                "WireGuard endpoint {name} peer={} handshake_age={:?} rx_bytes={} tx_bytes={}",
                                STANDARD.encode(peer.peer.public_key.as_bytes()),
                                peer.stats.last_handshake,
                                peer.stats.rx_bytes,
                                peer.stats.tx_bytes,
                            );
                        }
                    }
                }
            };
            *connector.active.lock() = None;
            if failed {
                log::error!("WireGuard endpoint {name} stopped unexpectedly; routes remain closed");
            }
            tasks.shutdown().await;
            device.stop().await;
            // GotaTun aborts buffered socket tasks during stop; their destruction releases the bind.
            let _ = released.await;
            log::info!(
                "WireGuard endpoint {name} stopped; packet drops={}",
                stack.drops.load(std::sync::atomic::Ordering::Relaxed)
            );
            drop(stack);
        });
        Ok(EndpointRuntime { cancel, task })
    }
}
