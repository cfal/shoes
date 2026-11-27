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
    device::{Device, DeviceBuilder, DeviceTransports, Peer, configure::PeerStats},
    noise::PresharedKey,
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    fmt, io as stdio,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
    client_proxy_selector::ClientProxySelector,
    config::{
        ResolvedClientProxyConfig, ValidatedConfigs,
        wireguard::{WireguardDeviceConfig, WireguardPeer},
    },
    dns::DnsRegistry,
    ip_stack::driver::{PacketStack, StackHandle},
    resolver::{NativeResolver, Resolver, resolve_addresses},
    tcp::socket_connector::SocketConnector,
};

const REPORT_INTERVAL: Duration = Duration::from_secs(60);
const ENDPOINT_DNS_TIMEOUT: Duration = Duration::from_secs(10);
// WireGuard's REJECT_AFTER_TIME: sessions older than this cannot carry data.
const STALE_HANDSHAKE: Duration = Duration::from_secs(180);
// Grace period for a persistent-keepalive peer to finish re-handshaking after session expiry.
const HANDSHAKE_REFRESH_GRACE: Duration = Duration::from_secs(15);
// Bounds stale-peer DNS retries at five report intervals (300 seconds by default).
const MAX_REFRESH_BACKOFF_INTERVALS: u32 = 5;

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
        peer.preshared_key = peer_config
            .pre_shared_key
            .as_ref()
            .map(|key| PresharedKey::copy_from(&key.0));
        peer.keepalive =
            (peer_config.persistent_keepalive != 0).then_some(peer_config.persistent_keepalive);
        let endpoints = if let Some(endpoint) = &peer_config.endpoint {
            let address = NetLocation::from_str(endpoint, None)?;
            let endpoints: Vec<_> = resolve_endpoint(resolver, &address)
                .await?
                .into_iter()
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

async fn resolve_endpoint(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> stdio::Result<Vec<SocketAddr>> {
    let addresses =
        tokio::time::timeout(ENDPOINT_DNS_TIMEOUT, resolve_addresses(resolver, location))
            .await
            .map_err(|_| {
                stdio::Error::new(
                    stdio::ErrorKind::TimedOut,
                    "WireGuard endpoint DNS timed out",
                )
            })??;
    Ok(addresses.into_iter().map(canonical_socket_addr).collect())
}

struct PreparedEndpoint {
    config: WireguardDeviceConfig,
    peers: Vec<PreparedPeer>,
    connector: Arc<Connector>,
    global_limits: crate::config::GlobalLimits,
    outer_resolver: Arc<dyn Resolver>,
    report_interval: Duration,
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
            if let ResolvedClientProxyConfig::Wireguard(reference) = &mut client.protocol {
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
                    crate::config::resolved_visit::visit_client(client, &mut |client| {
                        if let ResolvedClientProxyConfig::Wireguard(reference) =
                            &mut client.protocol
                        {
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
                report_interval: REPORT_INTERVAL,
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

    pub(crate) async fn refresh_peers(&mut self) -> stdio::Result<()> {
        let mut failure = None;
        for endpoint in &mut self.endpoints {
            for (peer, current) in endpoint.config.peers.iter().zip(&mut endpoint.peers) {
                match PreparedPeer::resolve(&endpoint.config, peer, &endpoint.outer_resolver).await
                {
                    Ok(refreshed) => *current = refreshed,
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
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
    pub(crate) fn cancel(&self) {
        for endpoint in &self.endpoints {
            endpoint.cancel.cancel();
        }
    }

    pub async fn stop(&mut self) {
        self.cancel();
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
            let rules = inbound.rules.clone().into_vec();
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
        let (udp, released, peers, mut refresh) = if let Some(chain) = &outer_chain {
            let peers = self.peers_for_socket(None)?;
            let (sender, receiver, released) = detour::start(
                config.id.clone(),
                chain.clone(),
                resolver,
                peers.iter().map(|peer| peer.endpoint.unwrap()),
                stack.drops.clone(),
            );
            log::info!("WireGuard endpoint {} using peer_client_chain", config.id);
            (io::Factory::detour(sender, receiver), released, peers, None)
        } else {
            let (udp, released, local) = io::Factory::new(
                config.listen,
                config.bind_interface.clone(),
                self.global_limits.wireguard_socket_buffer,
            )?;
            let peers = self.peers_for_socket(Some(local))?;
            log::info!("WireGuard endpoint {} listening on {local}", config.id);
            let refresh = StalePeerRefresh::new(self, local);
            (udp, released, peers, refresh)
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
                io::IpSource::new(
                    stack.output.take().unwrap(),
                    stack.handle.wake.clone(),
                    stack.egress_backpressured.clone(),
                    config.mtu,
                ),
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
        let report_interval = self.report_interval;
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let task = tokio::spawn(crate::network_tasks::inherit(async move {
            let mut tasks = JoinSet::new();
            let mut inbound_udp_count = None;
            if let Some((selector, resolver)) = inbound {
                inbound_udp_count = Some(spawn_inbound(
                    &mut tasks, &mut stack, selector, resolver, limits,
                ));
            }
            let mut report = tokio::time::interval(report_interval);
            report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let failed = loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break false,
                    _ = device.wait() => break true,
                    _ = &mut stack.done => break true,
                    _ = tasks.join_next(), if !tasks.is_empty() => break true,
                    _ = report.tick() => {
                        log::info!(
                            "WireGuard endpoint {name} tcp_flows={} outbound_udp_flows={} inbound_udp_destinations={} {}",
                            stack.counts.tcp.load(Ordering::Relaxed),
                            stack.counts.outbound_udp.load(Ordering::Relaxed),
                            inbound_udp_count.as_ref().map_or(0, |count| count.snapshot().active),
                            stack.drops,
                        );
                        let peers = device.peers().await;
                        for peer in &peers {
                            log::info!(
                                "WireGuard endpoint {name} peer={} handshake_age={:?} rx_bytes={} tx_bytes={}",
                                STANDARD.encode(peer.peer.public_key.as_bytes()),
                                peer.stats.last_handshake,
                                peer.stats.rx_bytes,
                                peer.stats.tx_bytes,
                            );
                        }
                        if let Some(refresh) = &mut refresh {
                            tokio::select! {
                                biased;
                                _ = shutdown.cancelled() => break false,
                                _ = refresh.run(&name, &device, &peers) => {}
                            }
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
            log::info!("WireGuard endpoint {name} stopped; {}", stack.drops);
            drop(stack);
        }));
        Ok(EndpointRuntime { cancel, task })
    }
}

/// Re-resolves configured peer hostnames for direct-mode peers whose handshake went stale.
/// Healthy peers are never touched, so authenticated roaming addresses are preserved.
struct StalePeerRefresh {
    peers: Vec<HostnamePeer>,
    resolver: Arc<dyn Resolver>,
    listen: Option<SocketAddr>,
    local: SocketAddr,
    started: Instant,
    interval: Duration,
}

struct HostnamePeer {
    public_key: PublicKey,
    location: NetLocation,
    retry_at: Instant,
    backoff: Duration,
    last_handshake_at: Option<Instant>,
}

impl StalePeerRefresh {
    fn new(endpoint: &PreparedEndpoint, local: SocketAddr) -> Option<Self> {
        let started = Instant::now();
        let peers: Vec<_> = endpoint
            .config
            .peers
            .iter()
            .filter_map(|peer| {
                let location = NetLocation::from_str(peer.endpoint.as_deref()?, None).ok()?;
                location.address().hostname()?;
                Some(HostnamePeer {
                    public_key: PublicKey::from(peer.public_key.0),
                    location,
                    retry_at: started,
                    backoff: endpoint.report_interval,
                    last_handshake_at: None,
                })
            })
            .collect();
        (!peers.is_empty()).then(|| Self {
            peers,
            resolver: endpoint.outer_resolver.clone(),
            listen: endpoint.config.listen,
            local,
            started,
            interval: endpoint.report_interval,
        })
    }

    /// Computes how long a peer can go without a new handshake before hostname refresh runs.
    ///
    /// Idle peers with `persistent_keepalive` do not rekey on keepalive packets until the session
    /// expires at `REJECT_AFTER_TIME`, then re-handshake on the next keepalive tick.
    fn stale_threshold(keepalive: Option<u16>) -> Duration {
        match keepalive.filter(|&seconds| seconds > 0) {
            Some(seconds) => STALE_HANDSHAKE
                .saturating_add(Duration::from_secs(u64::from(seconds)))
                .saturating_add(HANDSHAKE_REFRESH_GRACE),
            None => STALE_HANDSHAKE,
        }
    }

    fn is_stale(
        &self,
        last_handshake: Option<Duration>,
        last_handshake_at: Option<Instant>,
        keepalive: Option<u16>,
        now: Instant,
    ) -> bool {
        let threshold = Self::stale_threshold(keepalive);
        match (last_handshake, last_handshake_at) {
            (Some(age), _) => age >= threshold,
            // GotaTun drops expired sessions at REJECT_AFTER_TIME, clearing `last_handshake` to
            // None before a configured persistent keepalive fires its next handshake.
            (None, Some(at)) => now.duration_since(at) >= threshold,
            (None, None) => now.duration_since(self.started) >= self.interval,
        }
    }

    fn compatible(&self, address: SocketAddr) -> bool {
        crate::config::wireguard::can_reach_endpoint(self.listen, address)
            && (self.local.is_ipv6() || address.is_ipv4())
    }

    async fn run<T: DeviceTransports>(
        &mut self,
        name: &str,
        device: &Device<T>,
        stats: &[PeerStats],
    ) {
        let now = Instant::now();
        let stats_by_key: HashMap<_, _> = stats
            .iter()
            .map(|entry| (entry.peer.public_key, entry))
            .collect();
        let mut due = Vec::new();
        for index in 0..self.peers.len() {
            let public_key = self.peers[index].public_key;
            let Some(&current) = stats_by_key.get(&public_key) else {
                continue;
            };
            if let Some(age) = current.stats.last_handshake {
                let observed = now.checked_sub(age).unwrap_or(now);
                let slot = &mut self.peers[index].last_handshake_at;
                *slot = Some(slot.map_or(observed, |previous| previous.max(observed)));
            }
            let last_handshake_at = self.peers[index].last_handshake_at;
            let stale = self.is_stale(
                current.stats.last_handshake,
                last_handshake_at,
                current.peer.keepalive,
                now,
            );
            let peer = &mut self.peers[index];
            if !stale {
                peer.retry_at = now;
                peer.backoff = self.interval;
                continue;
            }
            if now < peer.retry_at {
                continue;
            }
            peer.retry_at = now + peer.backoff;
            peer.backoff = (peer.backoff * 2).min(self.interval * MAX_REFRESH_BACKOFF_INTERVALS);
            due.push((index, current.peer.endpoint, last_handshake_at));
        }
        if due.is_empty() {
            return;
        }
        let resolved =
            futures::future::join_all(due.iter().map(|(index, _, _)| {
                resolve_endpoint(&self.resolver, &self.peers[*index].location)
            }))
            .await;
        let mut updates = Vec::new();
        for ((index, previous, last_handshake_at), result) in due.into_iter().zip(resolved) {
            let peer = &self.peers[index];
            match result.map(|addresses| addresses.into_iter().find(|a| self.compatible(*a))) {
                Ok(Some(address)) if previous != Some(address) => {
                    updates.push((peer.public_key, previous, address, last_handshake_at));
                }
                Ok(Some(_)) => {}
                Ok(None) => log::warn!(
                    "WireGuard endpoint {name} peer hostname {} has no address compatible with {}",
                    peer.location,
                    self.local
                ),
                Err(error) => log::warn!(
                    "WireGuard endpoint {name} peer hostname {} refresh failed: {error}",
                    peer.location
                ),
            }
        }
        if updates.is_empty() {
            return;
        }
        let applied = device
            .write(async |device| {
                // Rechecks under the write lock so a handshake or roam since the snapshot wins.
                let current = device.peers().await;
                let current_by_key: HashMap<_, _> = current
                    .iter()
                    .map(|peer| (peer.peer.public_key, peer))
                    .collect();
                let now = Instant::now();
                let mut applied = Vec::new();
                for (public_key, previous, address, last_handshake_at) in updates {
                    let unchanged = current_by_key.get(&public_key).is_some_and(|peer| {
                        peer.peer.endpoint == previous
                            && self.is_stale(
                                peer.stats.last_handshake,
                                last_handshake_at,
                                peer.peer.keepalive,
                                now,
                            )
                    });
                    if unchanged
                        && device
                            .modify_peer(&public_key, |peer| peer.set_endpoint(Some(address)))
                            .await
                    {
                        applied.push((public_key, previous, address));
                    }
                }
                applied
            })
            .await;
        match applied {
            Ok(applied) => {
                for (public_key, previous, address) in applied {
                    log::info!(
                        "WireGuard endpoint {name} peer={} stale endpoint {previous:?} re-resolved to {address}",
                        STANDARD.encode(public_key.as_bytes()),
                    );
                }
            }
            Err(error) => {
                log::warn!("WireGuard endpoint {name} peer endpoint refresh failed: {error}");
            }
        }
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
    crate::network_tasks::spawn_in(tasks, async move {
        if let Err(error) = manager.run().await {
            log::warn!("WireGuard UDP forwarding stopped: {error}");
        }
    });
    let mut tcp = stack.tcp.take().unwrap();
    crate::network_tasks::spawn_in(tasks, async move {
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
            crate::network_tasks::spawn_in(&mut flows, async move {
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
