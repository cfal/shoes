mod detour;
mod io;
#[cfg(test)]
#[path = "../../tests/cases/wireguard_support.rs"]
pub(crate) mod test_support;
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
    sync::{Arc, atomic::Ordering},
};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    client_proxy_selector::ClientProxySelector,
    config::{
        ClientProxyConfig, ValidatedConfigs,
        wireguard::{WireguardDeviceConfig, WireguardPeer},
    },
    dns::DnsRegistry,
    ip_stack::driver::{PacketStack, StackHandle},
    resolver::{NativeResolver, Resolver, resolve_addresses},
    tcp::socket_connector::SocketConnector,
};

fn canonical_socket_addr(mut address: SocketAddr) -> SocketAddr {
    address.set_ip(address.ip().to_canonical());
    address
}

struct Connector {
    name: String,
    active: Mutex<Option<ActiveEndpoint>>,
    addresses: Vec<IpAddr>,
    routes: Vec<IpNetwork>,
}

#[derive(Clone)]
struct ActiveEndpoint {
    handle: StackHandle,
    carrier: Option<Arc<crate::client_proxy_chain::ClientProxyChain>>,
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
        let active = self.active.lock().clone().ok_or_else(|| {
            stdio::Error::new(
                stdio::ErrorKind::NotConnected,
                format!("WireGuard endpoint {} is not active", self.name),
            )
        })?;
        if let Some(carrier) = active.carrier {
            carrier.record_carrier_demand();
        }
        Ok(active.handle)
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
            .map(canonical_socket_addr)
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
    fn record_demand(&self) {
        let carrier = self
            .active
            .lock()
            .as_ref()
            .and_then(|active| active.carrier.clone());
        if let Some(carrier) = carrier {
            carrier.record_carrier_demand();
        }
    }

    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> stdio::Result<Box<dyn AsyncStream>> {
        let handle = self.handle()?;
        let addresses = self.destinations(resolver, target).await?;
        let stream =
            crate::tcp::socket_connector_impl::connect_tcp_candidates(addresses, |address| {
                Ok(handle.connect(address))
            })
            .await?;
        Ok(Box::new(stream))
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

struct PreparedPeer {
    config: Peer,
    endpoints: Vec<SocketAddr>,
}

impl PreparedPeer {
    async fn resolve(
        config: &WireguardDeviceConfig,
        peer_config: &WireguardPeer,
        resolver: &Arc<dyn Resolver>,
    ) -> stdio::Result<Self> {
        let mut peer = Peer::new(PublicKey::from(peer_config.public_key.0));
        peer.allowed_ips = peer_config
            .allowed_ips
            .iter()
            .map(|prefix| prefix.parse().map_err(stdio::Error::other))
            .collect::<stdio::Result<_>>()?;
        peer.preshared_key = peer_config.pre_shared_key.as_ref().map(|key| key.0);
        peer.keepalive =
            (peer_config.persistent_keepalive != 0).then_some(peer_config.persistent_keepalive);
        let endpoints = if let Some(endpoint) = &peer_config.endpoint {
            let address = NetLocation::from_str(endpoint, None)?;
            let addresses = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                resolve_addresses(resolver, &address),
            )
            .await
            .map_err(|_| {
                stdio::Error::new(
                    stdio::ErrorKind::TimedOut,
                    "WireGuard endpoint DNS timed out",
                )
            })??;
            let endpoints: Vec<_> = addresses
                .into_iter()
                .map(canonical_socket_addr)
                .filter(|address| config.can_reach_endpoint(*address))
                .collect();
            if endpoints.is_empty() {
                return Err(stdio::Error::new(
                    stdio::ErrorKind::AddrNotAvailable,
                    "WireGuard peer has no endpoint compatible with the listen address",
                ));
            }
            endpoints
        } else {
            Vec::new()
        };
        Ok(Self {
            config: peer,
            endpoints,
        })
    }
}

struct PreparedEndpoint {
    config: WireguardDeviceConfig,
    peers: Vec<PreparedPeer>,
    connector: Arc<Connector>,
    global_limits: crate::config::GlobalLimits,
    outer_resolver: Arc<dyn Resolver>,
}

#[derive(Default)]
pub(crate) struct Prepared {
    endpoints: Vec<PreparedEndpoint>,
}

impl Prepared {
    pub async fn new(validated: &mut ValidatedConfigs) -> stdio::Result<Self> {
        Self::with_forbidden(validated, &[]).await
    }

    pub async fn with_forbidden(
        validated: &mut ValidatedConfigs,
        inherited: &[IpNetwork],
    ) -> stdio::Result<Self> {
        let mut pending = Vec::new();
        let mut connectors = HashMap::new();
        let ranges: Result<Vec<IpNetwork>, _> = validated
            .dns_groups
            .iter()
            .filter_map(|group| group.fake_ip.as_ref())
            .flat_map(|options| options.ipv4_range.iter().chain(options.ipv6_range.iter()))
            .map(|range| range.parse())
            .collect();
        let mut ranges = ranges.map_err(stdio::Error::other)?;
        ranges.extend_from_slice(inherited);
        if !ranges.is_empty() {
            ranges.extend(
                crate::config::tun_endpoint_ips(&validated.configs)
                    .map(|ip| IpNetwork::from(ip.to_canonical())),
            );
            validated.validate_network_endpoints(&ranges)?;
        }
        let resolver = crate::dns::real_only(Arc::new(NativeResolver::new()), ranges.into());
        for config in &validated.wireguard_endpoints {
            config.validate()?;
            let mut peers = Vec::new();
            for peer_config in &config.peers {
                peers.push(PreparedPeer::resolve(config, peer_config, &resolver).await?);
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
                name: config.id.clone(),
                active: Mutex::new(None),
                addresses,
                routes: peers
                    .iter()
                    .flat_map(|peer| peer.config.allowed_ips.iter().copied())
                    .collect(),
            });
            connectors.insert(config.id.clone(), connector.clone());
            pending.push((peers, connector));
        }
        validated.visit_clients(&mut |client| {
            if let ClientProxyConfig::Wireguard(reference) = &mut client.protocol {
                reference.connector = Some(
                    connectors
                        .get(&reference.endpoint_id)
                        .ok_or_else(|| stdio::Error::other("unknown WireGuard endpoint"))?
                        .clone(),
                );
            }
            Ok(())
        })?;
        if let Some(catalog) = &mut validated.catalog {
            for node in catalog.nodes.values_mut() {
                if let crate::control::catalog::CatalogNode::Leaf(client) = node {
                    crate::config::client_visit::visit_client(client, &mut |client| {
                        if let ClientProxyConfig::Wireguard(reference) = &mut client.protocol {
                            // Probe pools include unselected leaves; fail at dial, not construction.
                            reference.connector = Some(
                                connectors
                                    .get(&reference.endpoint_id)
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        Arc::new(Connector {
                                            name: reference.endpoint_id.clone(),
                                            active: Mutex::new(None),
                                            addresses: Vec::new(),
                                            routes: Vec::new(),
                                        })
                                    }),
                            );
                        }
                        Ok(())
                    })?;
                }
            }
        }
        // Endpoint chains share the prepared handles used by ordinary listeners and DNS.
        let mut endpoints = Vec::with_capacity(pending.len());
        for ((peers, connector), config) in pending.into_iter().zip(&validated.wireguard_endpoints)
        {
            let endpoint = PreparedEndpoint {
                config: config.clone(),
                peers,
                connector,
                global_limits: validated.global_limits,
                outer_resolver: resolver.clone(),
            };
            endpoint.build_outer_chain()?;
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
    fn peers_for_socket(&self, local: Option<SocketAddr>) -> stdio::Result<Vec<Peer>> {
        self.peers
            .iter()
            .map(|prepared| {
                let mut peer = prepared.config.clone();
                if !prepared.endpoints.is_empty() {
                    // Candidates match the configured bind, but the socket may fall back to IPv4.
                    let endpoint = prepared
                        .endpoints
                        .iter()
                        .copied()
                        .find(|address| {
                            local.is_none_or(|local| local.is_ipv6() || address.is_ipv4())
                        })
                        .ok_or_else(|| {
                            stdio::Error::new(
                                stdio::ErrorKind::AddrNotAvailable,
                                "WireGuard peer has no endpoint compatible with the bound socket",
                            )
                        })?;
                    peer.endpoint = Some(endpoint);
                }
                Ok(peer)
            })
            .collect()
    }

    fn build_outer_chain(
        &self,
    ) -> stdio::Result<Option<Arc<crate::client_proxy_chain::ClientProxyChain>>> {
        let Some(config) = &self.config.peer_client_chain else {
            return Ok(None);
        };
        let chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
            config.hops.clone(),
            self.outer_resolver.clone(),
            self.global_limits,
        )?;
        if !chain.supports_udp() {
            return Err(crate::config::wireguard::invalid(format!(
                "WireGuard endpoint {} peer_client_chain does not support UDP",
                self.config.id,
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
                )?
                .with_sniff(inbound.sniff),
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
        let resolver = self.outer_resolver.clone();
        // Rebuilding after preflight gives each start fresh pool indices and handler lifetimes.
        let outer_chain = self.build_outer_chain()?;
        let (udp, released, peers) = if let Some(chain) = &outer_chain {
            let peers = self.peers_for_socket(None)?;
            let (sender, receiver, released) = detour::start(
                config.id.clone(),
                chain.clone(),
                resolver,
                peers.iter().map(|peer| peer.endpoint.unwrap()),
                stack.drops.clone(),
            );
            log::info!("WireGuard endpoint {} using peer_client_chain", config.id);
            (io::Factory::detour(sender, receiver), released, peers)
        } else {
            let (udp, released, local) =
                io::Factory::new(config.listen, config.bind_interface.clone())?;
            let peers = self.peers_for_socket(Some(local))?;
            log::info!("WireGuard endpoint {} listening on {local}", config.id);
            (udp, released, peers)
        };
        let mut device = DeviceBuilder::new()
            .with_udp(udp)
            .with_private_key(StaticSecret::from(config.private_key.0))
            .with_peers(peers)
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
        *self.connector.active.lock() = Some(ActiveEndpoint {
            handle: stack.handle.clone(),
            carrier: outer_chain,
        });
        let connector = self.connector.clone();
        let name = config.id.clone();
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let mut inbound_udp_count = None;
            if let Some((selector, resolver)) = inbound {
                inbound_udp_count = Some(spawn_inbound(
                    &mut tasks, &mut stack, selector, resolver, limits,
                ));
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
                            stack.counts.tcp.load(Ordering::Relaxed),
                            stack.counts.outbound_udp.load(Ordering::Relaxed),
                            inbound_udp_count.as_ref().map_or(0, |count| count.snapshot().active),
                            stack.drops.load(Ordering::Relaxed),
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
                stack.drops.load(Ordering::Relaxed)
            );
            drop(stack);
        });
        Ok(EndpointRuntime { cancel, task })
    }
}

fn spawn_inbound(
    tasks: &mut JoinSet<()>,
    stack: &mut PacketStack,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::tun::TunResourceLimits,
) -> Arc<crate::resources::Budget> {
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
    let udp_count = manager.destination_counter();
    tasks.spawn(async move {
        if let Err(error) = manager.run().await {
            log::warn!("WireGuard UDP forwarding stopped: {error}");
        }
    });
    let mut tcp = stack.tcp.take().unwrap();
    tasks.spawn(async move {
        let mut flows = JoinSet::new();
        loop {
            let connection = tokio::select! {
                connection = tcp.recv() => match connection {
                    Some(connection) => connection,
                    None => break,
                },
                _ = flows.join_next(), if !flows.is_empty() => continue,
            };
            let selector = selector.clone();
            let resolver = resolver.clone();
            flows.spawn(async move {
                log::debug!(
                    "WireGuard TCP {} -> {}",
                    connection.source,
                    connection.target
                );
                let target =
                    NetLocation::from_ip_addr(connection.target.ip(), connection.target.port());
                let _ = crate::tun::handle_tcp_connection(
                    connection.connection,
                    target,
                    selector,
                    resolver,
                    Some(connection.source),
                )
                .await;
            });
        }
    });
    udp_count
}
