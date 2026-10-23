//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents an ordered sequence of proxy hops, where each hop
//! can be a pool of connectors (for round-robin selection). Traffic flows through
//! each hop in sequence to reach the final destination.
//!
//! ## Design: InitialHopEntry for Hop 0
//!
//! Hop 0 is fundamentally different from subsequent hops:
//! - **Hop 0**: Creates socket AND optionally sets up protocol (if not direct)
//! - **Hops 1+**: Only set up protocol on existing stream
//!
//! To handle mixed pools at hop 0 (e.g., direct + various proxy types), we use
//! `InitialHopEntry` which pairs socket and proxy together, ensuring they are
//! always selected atomically during round-robin.
//!
//! ## Structure
//!
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::debug;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::control::catalog::{MemberOrigin, RuleDescription};
use crate::control::flows::{FlowContext, FlowGuard, FlowInfo};
use crate::resolver::Resolver;
use crate::tcp::carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// Entry in the initial hop (hop 0) pool.
///
/// Each entry pairs socket creation with optional protocol setup,
/// ensuring they are always selected together during round-robin.
pub enum InitialHopEntry {
    /// Direct connection - socket only, no protocol setup.
    /// Connects directly to the next hop's proxy or final destination.
    Direct(Arc<dyn SocketConnector>),
    Wireguard(Arc<dyn SocketConnector>),

    /// Proxy connection - socket + protocol setup paired together.
    /// Socket connects to proxy_location, then protocol wraps the stream.
    Proxy {
        socket: Arc<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Wireguard(socket) => f.debug_tuple("Wireguard").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) | InitialHopEntry::Wireguard(_) => true,
            InitialHopEntry::Proxy { proxy, .. } => proxy.supports_udp_over_tcp(),
        }
    }
}

/// A chain of proxy hops with paired initial hop entries.
///
/// Structure:
/// - `initial_hop`: Pool of InitialHopEntry for hop 0 (socket + optional proxy paired)
/// - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation needed)
pub struct ClientProxyChain {
    origins: Vec<Vec<Option<MemberOrigin>>>,
    selection: Option<Arc<crate::control::selection::SelectionView>>,
    selector_hops: Vec<bool>,
    /// Initial hop pool: each entry is either Direct or Proxy.
    /// Socket and proxy are paired and selected together.
    initial_hop: Vec<Arc<InitialHopEntry>>,
    /// Round-robin index for initial hop selection.
    initial_hop_next_index: AtomicU32,

    /// Protocol connectors for subsequent hops (hops 1+).
    /// Outer vec = hops, inner vec = round-robin pool per hop.
    subsequent_hops: Vec<Vec<Arc<dyn ProxyConnector>>>,
    /// Round-robin indices for each subsequent hop's pool.
    subsequent_next_indices: Vec<AtomicU32>,

    /// Indices into the FINAL hop pool for UDP-capable entries.
    /// This is either indices into initial_hop (if no subsequent hops),
    /// or indices into the last subsequent hop pool.
    udp_final_hop_indices: Vec<usize>,
    /// Round-robin index for UDP-capable final hop entries.
    udp_final_hop_next_index: AtomicU32,
    /// Flag indicating which pool udp_final_hop_indices refers to.
    /// true = udp_final_hop_indices points to initial_hop
    /// false = udp_final_hop_indices points to last subsequent hop
    udp_uses_initial_hop: bool,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("initial_hop_count", &self.initial_hop.len())
            .field(
                "subsequent_hops",
                &self
                    .subsequent_hops
                    .iter()
                    .map(|h| h.len())
                    .collect::<Vec<_>>(),
            )
            .field("udp_final_hop_indices", &self.udp_final_hop_indices)
            .field("udp_uses_initial_hop", &self.udp_uses_initial_hop)
            .finish()
    }
}

impl ClientProxyChain {
    fn needs_carrier_dialer(&self) -> bool {
        self.initial_hop.iter().any(|entry| matches!(entry.as_ref(), InitialHopEntry::Proxy { proxy, .. } if proxy.needs_carrier_dialer()))
            || self.subsequent_hops.iter().flatten().any(|proxy| proxy.needs_carrier_dialer())
    }

    fn selected_route(&self, resolver: &Arc<dyn Resolver>, indices: &[usize]) -> SelectedRoute {
        let initial_index = indices[0];
        let subsequent = self
            .subsequent_hops
            .iter()
            .enumerate()
            .map(|(i, hop)| hop[indices[i + 1]].clone())
            .collect();
        SelectedRoute {
            socket: match self.initial_hop[initial_index].as_ref() {
                InitialHopEntry::Direct(socket)
                | InitialHopEntry::Wireguard(socket)
                | InitialHopEntry::Proxy { socket, .. } => socket.clone(),
            },
            initial: Some(self.initial_hop[initial_index].clone()),
            subsequent,
            resolver: resolver.clone(),
        }
    }

    pub(crate) fn with_origins(mut self, origins: Vec<Vec<Option<MemberOrigin>>>) -> Self {
        self.selector_hops = origins
            .iter()
            .map(|pool| pool.iter().flatten().any(MemberOrigin::has_selector))
            .collect();
        self.selection = origins
            .iter()
            .flatten()
            .flatten()
            .find(|origin| origin.has_selector())
            .map(|origin| origin.selection.clone());
        self.origins = origins;
        self
    }

    fn select_indices(&self, udp: bool) -> std::io::Result<Vec<usize>> {
        let choices = self
            .selection
            .as_ref()
            .map(|selection| selection.snapshot());
        (0..self.num_hops())
            .map(|hop| {
                let final_udp = udp && hop + 1 == self.num_hops();
                let (length, counter) = if final_udp {
                    (
                        self.udp_final_hop_indices.len(),
                        &self.udp_final_hop_next_index,
                    )
                } else if hop == 0 {
                    (self.initial_hop.len(), &self.initial_hop_next_index)
                } else {
                    (
                        self.subsequent_hops[hop - 1].len(),
                        &self.subsequent_next_indices[hop - 1],
                    )
                };
                let candidate = |index: usize| {
                    if final_udp {
                        self.udp_final_hop_indices[index]
                    } else {
                        index
                    }
                };
                let choices = choices.as_ref().filter(|_| self.selector_hops[hop]);
                let allowed = |index: &usize| {
                    choices.is_none_or(|choices| {
                        self.origin(hop, candidate(*index))
                            .is_none_or(|origin| origin.allowed(choices))
                    })
                };
                let count = if choices.is_some() {
                    (0..length).filter(allowed).count()
                } else {
                    length
                };
                if count == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "selected branch cannot carry this flow",
                    ));
                }
                let ordinal = counter.fetch_add(1, Ordering::Relaxed) as usize % count;
                Ok(candidate(if choices.is_some() {
                    (0..length).filter(allowed).nth(ordinal).unwrap()
                } else {
                    ordinal
                }))
            })
            .collect()
    }

    fn origin(&self, hop: usize, index: usize) -> Option<&MemberOrigin> {
        self.origins.get(hop)?.get(index)?.as_ref()
    }

    fn route_names(&self, indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .enumerate()
            .rev()
            .flat_map(|(hop, index)| {
                self.origin(hop, *index)
                    .into_iter()
                    .flat_map(MemberOrigin::chains)
            })
            .collect()
    }

    /// Create a new chain from initial hop entries and subsequent hop pools.
    ///
    /// # Arguments
    /// * `initial_hop` - Pool of InitialHopEntry for hop 0
    /// * `subsequent_hops` - Protocol connectors for hops 1+
    ///
    /// # Panics
    /// Panics if initial_hop is empty.
    pub fn new(
        initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );

        // Compute UDP-capable indices in the FINAL hop pool.
        // The final hop is either initial_hop (if no subsequent) or the last subsequent hop.
        // Only the hop that calls setup_udp_stream() needs UDP support.
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            // No subsequent hops: initial hop IS the final hop
            // Filter initial_hop for UDP-capable entries
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
            // Has subsequent hops: filter the FINAL subsequent hop for UDP-capable entries
            let final_hop = subsequent_hops.last().unwrap();
            let indices = final_hop
                .iter()
                .enumerate()
                .filter(|(_, p)| p.supports_udp_over_tcp())
                .map(|(i, _)| i)
                .collect();
            (indices, false)
        };

        let subsequent_next_indices = subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect();

        Self {
            origins: Vec::new(),
            selection: None,
            selector_hops: Vec::new(),
            initial_hop: initial_hop.into_iter().map(Arc::new).collect(),
            initial_hop_next_index: AtomicU32::new(0),
            subsequent_hops: subsequent_hops
                .into_iter()
                .map(|hop| hop.into_iter().map(Arc::from).collect())
                .collect(),
            subsequent_next_indices,
            udp_final_hop_indices,
            udp_final_hop_next_index: AtomicU32::new(0),
            udp_uses_initial_hop,
        }
    }

    /// Returns the total number of hops.
    pub fn num_hops(&self) -> usize {
        1 + self.subsequent_hops.len()
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        !self.udp_final_hop_indices.is_empty()
    }

    /// Returns true if this chain is "direct-only": all initial hops are Direct
    /// and there are no subsequent hops. Such chains can be used for UDP/QUIC
    /// DNS while still supporting bind_interface.
    pub fn is_direct_only(&self) -> bool {
        if !self.subsequent_hops.is_empty() {
            return false;
        }
        self.initial_hop
            .iter()
            .all(|entry| matches!(entry.as_ref(), InitialHopEntry::Direct(_)))
    }

    fn select_subsequent_proxies(&self, indices: &[usize]) -> Vec<&dyn ProxyConnector> {
        self.subsequent_hops
            .iter()
            .enumerate()
            .map(|(i, hop)| hop[indices[i + 1]].as_ref())
            .collect()
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.connect_tcp_observed(remote_location, resolver, None)
            .await
    }

    async fn connect_tcp_observed(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        path: Option<&mut Vec<String>>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let indices = self.select_indices(false)?;
        if let Some(path) = path {
            *path = self.route_names(&indices);
        }
        if self.needs_carrier_dialer() {
            return self
                .selected_route(resolver, &indices)
                .connect(remote_location)
                .await;
        }
        // Select initial hop entry (socket + optional proxy paired)
        let entry = self.initial_hop[indices[0]].as_ref();

        // Select proxy connectors for subsequent hops
        let subsequent_proxies = self.select_subsequent_proxies(&indices);

        debug!(
            "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
            subsequent_proxies.len(),
            remote_location.location()
        );

        // Determine first target after initial hop (proxy locations need wrapping)
        let first_subsequent_target: ResolvedLocation = subsequent_proxies
            .first()
            .map(|p| p.proxy_location().into())
            .unwrap_or_else(|| remote_location.clone());

        // Connect based on initial hop type
        let mut result = match entry {
            InitialHopEntry::Direct(socket) | InitialHopEntry::Wireguard(socket) => {
                // Socket connects to first subsequent proxy (or final target)
                debug!(
                    "Initial hop: {entry:?} -> {}",
                    first_subsequent_target.location()
                );
                let stream = socket.connect(resolver, &first_subsequent_target).await?;
                TcpClientSetupResult {
                    client_stream: stream,
                    early_data: None,
                }
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                let target = proxy
                    .prepare_target(first_subsequent_target, resolver)
                    .await?;
                if subsequent_proxies.is_empty()
                    && let Some(result) = proxy.try_reuse_tcp_stream(&target).await?
                {
                    return Ok(result);
                }
                // Socket connects to this proxy's location
                debug!(
                    "Initial hop: Proxy {} -> {}",
                    proxy.proxy_location(),
                    target.location()
                );
                let proxy_loc = proxy.proxy_location().into();
                let stream = socket.connect(resolver, &proxy_loc).await?;
                // Protocol setup targeting first subsequent proxy (or final target)
                proxy.setup_tcp_stream(stream, &target).await?
            }
        };

        // Process subsequent hops
        for (i, proxy) in subsequent_proxies.iter().enumerate() {
            let target: ResolvedLocation = subsequent_proxies
                .get(i + 1)
                .map(|p| p.proxy_location().into())
                .unwrap_or_else(|| remote_location.clone());
            let target = proxy.prepare_target(target, resolver).await?;

            debug!(
                "Subsequent hop {}/{}: {} -> {}",
                i + 1,
                subsequent_proxies.len(),
                proxy.proxy_location(),
                target.location()
            );

            result = proxy
                .setup_tcp_stream(result.client_stream, &target)
                .await?;

            // Early data from intermediate hops is unexpected
            if let Some(data) = &result.early_data
                && i < subsequent_proxies.len() - 1
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Unexpected early data ({} bytes) from intermediate hop {}",
                        data.len(),
                        i + 1
                    ),
                ));
            }
        }

        debug!(
            "Chain TCP complete: {} total hop(s) to {}",
            1 + subsequent_proxies.len(),
            remote_location.location()
        );

        Ok(result)
    }

    /// Connect for bidirectional UDP traffic through the chain.
    ///
    /// Returns an AsyncMessageStream that sends/receives UDP packets to the target.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.connect_udp_observed(resolver, target, None).await
    }

    async fn connect_udp_observed(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
        path: Option<&mut Vec<String>>,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // Check if UDP is supported
        if self.udp_final_hop_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Chain does not support UDP",
            ));
        }

        let indices = self.select_indices(true)?;
        if let Some(path) = path {
            *path = self.route_names(&indices);
        }
        if self.needs_carrier_dialer() {
            let route = self.selected_route(resolver, &indices);
            return match route.last_proxy() {
                Some(proxy) => {
                    proxy
                        .connect_udp_with_dialer(
                            route.prefix(proxy.proxy_location().into()),
                            target,
                        )
                        .await
                }
                None => {
                    route
                        .socket()
                        .connect_udp_bidirectional(resolver, target)
                        .await
                }
            };
        }

        if self.udp_uses_initial_hop {
            // Case 1: No subsequent hops - initial hop IS the final hop
            // Select from UDP-capable initial hop entries
            let pool_idx = indices[0];
            let entry = self.initial_hop[pool_idx].as_ref();

            debug!(
                "Chain UDP connect: 1 hop (initial IS final), target={}",
                target.location()
            );

            match entry {
                InitialHopEntry::Direct(socket) | InitialHopEntry::Wireguard(socket) => {
                    debug!("Chain UDP: {entry:?}");
                    socket.connect_udp_bidirectional(resolver, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} (UDP, no subsequent)",
                        proxy.proxy_location()
                    );
                    let proxy_loc = proxy.proxy_location().into();
                    let stream = socket.connect(resolver, &proxy_loc).await?;
                    proxy.setup_udp_bidirectional(stream, target).await
                }
            }
        } else {
            // Case 2: Has subsequent hops - select initial hop normally,
            // select intermediate hops normally, select final hop from UDP-capable

            // Select initial hop normally (ALL entries work - they just do TCP)
            let entry = self.initial_hop[indices[0]].as_ref();

            // Select intermediate hops normally (ALL entries work - they just do TCP)
            let intermediate_proxies: Vec<&dyn ProxyConnector> = self
                .subsequent_hops
                .iter()
                .enumerate()
                .take(self.subsequent_hops.len() - 1) // All but last
                .map(|(i, hop)| hop[indices[i + 1]].as_ref())
                .collect();

            // Select final hop from UDP-capable entries
            let final_hop_pool = self.subsequent_hops.last().unwrap();
            let pool_idx = *indices.last().unwrap();
            let final_proxy = final_hop_pool[pool_idx].as_ref();

            debug!(
                "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                intermediate_proxies.len(),
                target.location()
            );

            let first_target: ResolvedLocation = if let Some(first) = intermediate_proxies.first() {
                first.proxy_location().into()
            } else {
                final_proxy.proxy_location().into()
            };
            let mut stream = match entry {
                InitialHopEntry::Direct(socket) | InitialHopEntry::Wireguard(socket) => {
                    debug!("Chain UDP: Direct -> {} (TCP)", first_target.location());
                    socket.connect(resolver, &first_target).await?
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} -> {} (TCP)",
                        proxy.proxy_location(),
                        first_target.location()
                    );
                    let proxy_loc = proxy.proxy_location().into();
                    let first_target = proxy.prepare_target(first_target, resolver).await?;
                    let stream = socket.connect(resolver, &proxy_loc).await?;
                    let result = proxy.setup_tcp_stream(stream, &first_target).await?;
                    result.client_stream
                }
            };

            for (i, proxy) in intermediate_proxies.iter().enumerate() {
                let next_target: ResolvedLocation = intermediate_proxies
                    .get(i + 1)
                    .map(|p| p.proxy_location().into())
                    .unwrap_or_else(|| final_proxy.proxy_location().into());
                let next_target = proxy.prepare_target(next_target, resolver).await?;
                debug!(
                    "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                    i + 1,
                    intermediate_proxies.len(),
                    proxy.proxy_location(),
                    next_target.location()
                );
                let result = proxy.setup_tcp_stream(stream, &next_target).await?;
                stream = result.client_stream;
            }

            debug!(
                "Chain UDP final hop: {} (UDP)",
                final_proxy.proxy_location()
            );
            final_proxy.setup_udp_bidirectional(stream, target).await
        }
    }
}

#[derive(Clone, Debug)]
struct SelectedRoute {
    socket: Arc<dyn SocketConnector>,
    initial: Option<Arc<InitialHopEntry>>,
    subsequent: Vec<Arc<dyn ProxyConnector>>,
    resolver: Arc<dyn Resolver>,
}

impl SelectedRoute {
    fn socket(&self) -> &dyn SocketConnector {
        self.socket.as_ref()
    }

    fn last_proxy(&self) -> Option<&dyn ProxyConnector> {
        self.subsequent
            .last()
            .map(|p| p.as_ref())
            .or_else(|| match self.initial.as_deref() {
                Some(InitialHopEntry::Proxy { proxy, .. }) => Some(proxy.as_ref()),
                _ => None,
            })
    }

    fn prefix(&self, target: ResolvedLocation) -> Arc<dyn CarrierDialer> {
        let mut route = self.clone();
        if route.subsequent.pop().is_none() {
            // A pooled prefix must not retain the connector that owns its pool.
            route.initial = None;
        }
        let mut identities = vec![Arc::as_ptr(&route.socket) as *const () as usize];
        if let Some(initial) = &route.initial {
            identities.push(Arc::as_ptr(initial) as usize);
        }
        identities.extend(
            route
                .subsequent
                .iter()
                .map(|p| Arc::as_ptr(p) as *const () as usize),
        );
        Arc::new(PrefixDialer {
            route,
            target,
            key: RouteKey(identities),
        })
    }

    async fn connect(&self, target: ResolvedLocation) -> std::io::Result<TcpClientSetupResult> {
        match self.last_proxy() {
            Some(proxy) => {
                let target = proxy.prepare_target(target, &self.resolver).await?;
                if self.subsequent.is_empty()
                    && !proxy.needs_carrier_dialer()
                    && let Some(result) = proxy.try_reuse_tcp_stream(&target).await?
                {
                    return Ok(result);
                }
                proxy
                    .connect_tcp_with_dialer(self.prefix(proxy.proxy_location().into()), &target)
                    .await
            }
            None => Ok(TcpClientSetupResult {
                client_stream: self.socket().connect(&self.resolver, &target).await?,
                early_data: None,
            }),
        }
    }
}

#[derive(Debug)]
struct PrefixDialer {
    route: SelectedRoute,
    target: ResolvedLocation,
    key: RouteKey,
}

#[cfg(test)]
mod carrier_tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::async_stream::AsyncStream;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TRANSPORT_DATA: &[u8] = b"transport";

    #[test]
    fn unselected_large_pools_keep_constant_time_round_robin() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let chain = ClientProxyChain::new(
            (0..10_000)
                .map(|index| InitialHopEntry::Direct(Arc::new(Socket(index, events.clone()))))
                .collect(),
            Vec::new(),
        );
        assert!(chain.selection.is_none());
        for index in 0..20_000 {
            assert_eq!(chain.select_indices(false).unwrap(), [index % 10_000]);
            assert_eq!(chain.select_indices(true).unwrap(), [index % 10_000]);
        }
    }

    #[test]
    fn selectors_filter_all_hops_without_changing_flattened_weights() {
        let yaml = "
- client_group: leaves
  client_proxies:
    - name: http
      address: 127.0.0.1:8000
      protocol: {type: http}
    - name: udp
      address: 127.0.0.1:8001
      protocol: {type: vless, user_id: 550e8400-e29b-41d4-a716-446655440000}
- client_group: weighted
  client_proxies: [leaves, leaves, direct]
- client_group: choose
  strategy: selector
  client_proxies: [weighted, direct]
- address: 127.0.0.1:1080
  protocol: {type: socks}
  rules: [{mask: 0.0.0.0/0, action: allow, client_chain: choose}]
";
        let mut validated =
            crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
        let catalog = validated.catalog.take().unwrap();
        let crate::config::Config::Server(server) = validated.configs.remove(0) else {
            panic!()
        };
        let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
            panic!()
        };
        let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
            panic!()
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let group =
            crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver)
                .unwrap();
        let chain = &group.chains[0];
        for index in 0..10 {
            assert_eq!(chain.select_indices(false).unwrap(), [index % 5]);
        }
        for index in [1, 3, 4, 1, 3, 4] {
            assert_eq!(chain.select_indices(true).unwrap(), [index]);
        }
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        owner.select("choose", "DIRECT").unwrap();
        assert_eq!(chain.select_indices(false).unwrap(), [5]);
        assert_eq!(chain.select_indices(true).unwrap(), [5]);
    }

    #[test]
    fn udp_selection_rejects_ineligible_member_without_falling_back() {
        let yaml = "
- client_group: leaves
  strategy: selector
  default: http
  client_proxies:
    - name: http
      address: 127.0.0.1:8000
      protocol: {type: http}
    - name: udp
      address: 127.0.0.1:8001
      protocol: {type: vless, user_id: 550e8400-e29b-41d4-a716-446655440000}
- address: 127.0.0.1:1080
  protocol: {type: socks}
  rules: [{mask: 0.0.0.0/0, action: allow, client_chain: leaves}]
";
        let mut validated =
            crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
        let catalog = validated.catalog.take().unwrap();
        let crate::config::Config::Server(server) = validated.configs.remove(0) else {
            panic!()
        };
        let crate::config::ConfigSelection::Config(rule) = server.rules.into_vec().remove(0) else {
            panic!()
        };
        let crate::config::RuleActionConfig::Allow { client_chains, .. } = rule.action else {
            panic!()
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let group =
            crate::tcp::chain_builder::try_build_client_chain_group(client_chains, resolver)
                .unwrap();
        let chain = &group.chains[0];
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        assert!(chain.select_indices(true).is_err());
        owner.select("leaves", "udp").unwrap();
        assert_eq!(chain.select_indices(true).unwrap(), [1]);
    }

    #[derive(Debug)]
    struct Socket(usize, Arc<Mutex<Vec<String>>>);
    #[async_trait::async_trait]
    impl SocketConnector for Socket {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            target: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            self.1
                .lock()
                .unwrap()
                .push(format!("socket {} -> {}", self.0, target));
            let (stream, mut peer) = tokio::io::duplex(64);
            peer.write_all(TRANSPORT_DATA).await?;
            Ok(Box::new(stream))
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[derive(Debug)]
    struct Proxy {
        location: NetLocation,
        lazy: bool,
        early_data: Option<Vec<u8>>,
        calls: Arc<Mutex<Vec<String>>>,
    }
    #[async_trait::async_trait]
    impl ProxyConnector for Proxy {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }
        fn supports_udp_over_tcp(&self) -> bool {
            true
        }
        fn needs_carrier_dialer(&self) -> bool {
            self.lazy
        }
        async fn prepare_target(
            &self,
            target: ResolvedLocation,
            _: &Arc<dyn Resolver>,
        ) -> std::io::Result<ResolvedLocation> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("prepare {} -> {}", self.location, target));
            Ok(target)
        }
        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{} -> {}", self.location, target));
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: self.early_data.clone(),
            })
        }
        async fn connect_tcp_with_dialer(
            &self,
            dialer: Arc<dyn CarrierDialer>,
            target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            if self.lazy {
                drop(dialer.open_stream().await?);
            }
            self.setup_tcp_stream(dialer.open_stream().await?, target)
                .await
        }
        async fn setup_udp_bidirectional(
            &self,
            mut stream: Box<dyn AsyncStream>,
            target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("udp {} -> {}", self.location, target));
            let mut bytes = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                stream.read_to_end(&mut bytes),
            )
            .await
            .expect("UDP chain transport did not reach EOF")?;
            assert_eq!(bytes, TRANSPORT_DATA, "intermediate early data leaked");
            Ok(Box::new(crate::vless::VlessMessageStream::new(stream)))
        }
    }

    #[tokio::test]
    async fn redial_replays_exact_selected_prefix_without_round_robin_or_direct_bypass() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let location = |s| NetLocation::from_str(s, None).unwrap();
        let proxy = |address, lazy| {
            Box::new(Proxy {
                location: location(address),
                lazy,
                early_data: None,
                calls: calls.clone(),
            }) as Box<dyn ProxyConnector>
        };
        let chain = ClientProxyChain::new(
            (0..2)
                .map(|i| InitialHopEntry::Proxy {
                    socket: Arc::new(Socket(i, calls.clone())),
                    proxy: proxy("first.test:80", false),
                })
                .collect(),
            vec![vec![proxy("xhttp.test:443", true)]],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for index in 0..2 {
            chain
                .connect_tcp(location("target.test:80").into(), &resolver)
                .await
                .unwrap();
            assert_eq!(
                *calls.lock().unwrap(),
                vec![
                    "prepare xhttp.test:443 -> target.test:80".into(),
                    "prepare first.test:80 -> xhttp.test:443".into(),
                    format!("socket {index} -> first.test:80"),
                    "first.test:80 -> xhttp.test:443".into(),
                    "prepare first.test:80 -> xhttp.test:443".into(),
                    format!("socket {index} -> first.test:80"),
                    "first.test:80 -> xhttp.test:443".into(),
                    "xhttp.test:443 -> target.test:80".into(),
                ]
            );
            calls.lock().unwrap().clear();
        }
    }

    #[tokio::test]
    async fn udp_chain_preserves_preparation_order_and_ignores_intermediate_early_data() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for initial in ["direct", "wireguard", "proxy"] {
            for intermediates in [0, 2] {
                let calls = Arc::new(Mutex::new(Vec::new()));
                let proxy = |address| {
                    Box::new(Proxy {
                        location: NetLocation::from_str(address, None).unwrap(),
                        lazy: false,
                        early_data: Some(vec![1, 2, 3]),
                        calls: calls.clone(),
                    }) as Box<dyn ProxyConnector>
                };
                let socket = Arc::new(Socket(0, calls.clone()));
                let entry = match initial {
                    "direct" => InitialHopEntry::Direct(socket),
                    "wireguard" => InitialHopEntry::Wireguard(socket),
                    "proxy" => InitialHopEntry::Proxy {
                        socket,
                        proxy: proxy("initial.test:80"),
                    },
                    _ => unreachable!(),
                };
                let mut hops = Vec::new();
                if intermediates == 2 {
                    hops.push(vec![proxy("middle1.test:80")]);
                    hops.push(vec![proxy("middle2.test:80")]);
                }
                hops.push(vec![proxy("final.test:80")]);
                let chain = ClientProxyChain::new(vec![entry], hops);
                chain
                    .connect_udp_bidirectional(
                        &resolver,
                        NetLocation::from_str("target.test:53", None)
                            .unwrap()
                            .into(),
                    )
                    .await
                    .unwrap();

                let first = if intermediates == 0 {
                    "final.test:80"
                } else {
                    "middle1.test:80"
                };
                let mut expected = if initial == "proxy" {
                    vec![
                        format!("prepare initial.test:80 -> {first}"),
                        "socket 0 -> initial.test:80".into(),
                        format!("initial.test:80 -> {first}"),
                    ]
                } else {
                    vec![format!("socket 0 -> {first}")]
                };
                if intermediates == 2 {
                    expected.extend([
                        "prepare middle1.test:80 -> middle2.test:80".into(),
                        "middle1.test:80 -> middle2.test:80".into(),
                        "prepare middle2.test:80 -> final.test:80".into(),
                        "middle2.test:80 -> final.test:80".into(),
                    ]);
                }
                expected.push("udp final.test:80 -> target.test:53".into());
                assert_eq!(
                    *calls.lock().unwrap(),
                    expected,
                    "{initial}/{intermediates}"
                );
            }
        }
    }

    #[test]
    fn pooled_prefix_does_not_retain_its_own_proxy() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket: Arc::new(Socket(0, calls.clone())),
                proxy: Box::new(Proxy {
                    location: NetLocation::from_str("xhttp.test:443", None).unwrap(),
                    lazy: true,
                    early_data: None,
                    calls,
                }),
            }],
            vec![],
        );
        let initial = Arc::downgrade(&chain.initial_hop[0]);
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let prefix = chain
            .selected_route(&resolver, &chain.select_indices(false).unwrap())
            .prefix(
                NetLocation::from_str("xhttp.test:443", None)
                    .unwrap()
                    .into(),
            );
        drop(chain);
        assert!(initial.upgrade().is_none());
        assert_eq!(prefix.route_key().0.len(), 1);
    }
}

#[async_trait::async_trait]
impl CarrierDialer for PrefixDialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }

    async fn open_stream(&self) -> std::io::Result<Box<dyn crate::async_stream::AsyncStream>> {
        let result = self.route.connect(self.target.clone()).await?;
        if result
            .early_data
            .as_ref()
            .is_some_and(|data| !data.is_empty())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected early data from intermediate proxy",
            ));
        }
        Ok(result.client_stream)
    }

    async fn open_quic(&self) -> std::io::Result<QuicCarrier> {
        if self.route.last_proxy().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "HTTP/3 requires a first-hop QUIC carrier",
            ));
        }
        self.route
            .socket()
            .connect_quic(&self.route.resolver, &self.target)
            .await
    }
}

/// A group of proxy chains for round-robin selection.
pub struct ClientChainGroup {
    description: Option<Arc<RuleDescription>>,
    chains: Vec<ClientProxyChain>,
    next_tcp_index: AtomicU32,
    pub(crate) udp_chain_indices: Vec<usize>,
    next_udp_index: AtomicU32,
}

impl std::fmt::Debug for ClientChainGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChainGroup")
            .field("chains_count", &self.chains.len())
            .field("udp_chain_indices", &self.udp_chain_indices)
            .finish()
    }
}

impl ClientChainGroup {
    fn tracking(&self) -> Option<(&RuleDescription, &FlowContext)> {
        let description = self.description.as_deref()?;
        Some((description, description.context.as_deref()?))
    }

    pub(crate) fn tracks_flows(&self) -> bool {
        self.tracking().is_some()
    }
    pub(crate) fn with_description(mut self, description: Option<Arc<RuleDescription>>) -> Self {
        self.description = description;
        self
    }

    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup must have at least one chain"
        );

        let udp_chain_indices: Vec<usize> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| chain.supports_udp())
            .map(|(i, _)| i)
            .collect();

        Self {
            description: None,
            chains,
            next_tcp_index: AtomicU32::new(0),
            udp_chain_indices,
            next_udp_index: AtomicU32::new(0),
        }
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.connect_tcp_with_info(remote_location, resolver, Default::default())
            .await
    }

    pub(crate) async fn connect_tcp_with_info(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        info: FlowInfo,
    ) -> std::io::Result<TcpClientSetupResult> {
        let idx = self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[idx % self.chains.len()];
        let Some((description, context)) = self.tracking() else {
            return chain.connect_tcp(remote_location, resolver).await;
        };
        let mut path = Vec::new();
        let mut result = chain
            .connect_tcp_observed(remote_location.clone(), resolver, Some(&mut path))
            .await?;
        let guard = register_flow(description, context, "tcp", &remote_location, path, info);
        guard
            .entry
            .counters
            .download(result.early_data.as_ref().map_or(0, Vec::len));
        result.client_stream = Box::new(crate::control::tracked_stream::TrackedStream::new(
            result.client_stream,
            guard,
        ));
        Ok(result)
    }

    pub(crate) async fn connect_udp_with_info(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
        info: FlowInfo,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain_idx = self.udp_chain_indices[idx % self.udp_chain_indices.len()];
        let chain = &self.chains[chain_idx];
        let Some((description, context)) = self.tracking() else {
            return chain.connect_udp_bidirectional(resolver, target).await;
        };
        let mut path = Vec::new();
        let stream = chain
            .connect_udp_observed(resolver, target.clone(), Some(&mut path))
            .await?;
        let guard = register_flow(description, context, "udp", &target, path, info);
        Ok(Box::new(
            crate::control::tracked_stream::TrackedMessageStream::new(stream, guard),
        ))
    }

    #[cfg(test)]
    pub fn supports_udp(&self) -> bool {
        !self.udp_chain_indices.is_empty()
    }

    /// Returns true if all chains are direct-only.
    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(|chain| chain.is_direct_only())
    }

    /// Selects the interface for a new direct UDP/QUIC DNS socket.
    pub fn select_bind_interface(&self) -> std::io::Result<Option<&str>> {
        if !self.is_direct_only() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP DNS requires a direct chain",
            ));
        }
        let index = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[index % self.chains.len()];
        let indices = chain.select_indices(true)?;
        let InitialHopEntry::Direct(socket) = chain.initial_hop[indices[0]].as_ref() else {
            unreachable!("direct-only chain checked above")
        };
        Ok(socket.bind_interface())
    }
}

fn register_flow(
    description: &RuleDescription,
    context: &FlowContext,
    network: &str,
    target: &ResolvedLocation,
    mut path: Vec<String>,
    info: FlowInfo,
) -> FlowGuard {
    if !path.contains(&description.proxy) {
        path.push(description.proxy.clone());
    }
    context.register(network, target, path, &description.payload, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::address::NetLocation;
    use crate::async_stream::AsyncStream;
    use crate::tcp::proxy_connector::ProxyConnector;
    use crate::tcp::socket_connector::SocketConnector;

    /// Mock SocketConnector that fails on connect (for unit testing structure).
    #[derive(Debug)]
    struct MockSocketConnector;

    #[async_trait]
    impl SocketConnector for MockSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            Err(std::io::Error::other(
                "MockSocketConnector::connect not implemented",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other(
                "MockSocketConnector::connect_udp_bidirectional not implemented",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// Mock ProxyConnector for testing.
    #[derive(Debug)]
    struct MockProxyConnector {
        location: NetLocation,
        supports_udp: bool,
    }

    impl MockProxyConnector {
        fn new(port: u16, supports_udp: bool) -> Self {
            Self {
                location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
                supports_udp,
            }
        }
    }

    #[derive(Debug)]
    struct ReusableProxy {
        location: NetLocation,
        fail: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl ProxyConnector for ReusableProxy {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }
        fn supports_udp_over_tcp(&self) -> bool {
            false
        }
        async fn try_reuse_tcp_stream(
            &self,
            target: &ResolvedLocation,
        ) -> std::io::Result<Option<TcpClientSetupResult>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                return Err(std::io::Error::other("CONNECT rejected"));
            }
            Ok(Some(TcpClientSetupResult {
                client_stream: Box::new(tokio::io::duplex(8).0),
                early_data: Some(target.to_string().into_bytes()),
            }))
        }
        async fn setup_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            panic!("a warm proxy must not run cold setup")
        }
        async fn setup_udp_bidirectional(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn reuse_respects_selected_entry_target_and_multihop_boundaries() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let warm = || InitialHopEntry::Proxy {
            socket: mock_socket(0),
            proxy: Box::new(ReusableProxy {
                location: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
                fail: false,
                calls: calls.clone(),
            }),
        };
        let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        let chain = ClientProxyChain::new(vec![warm(), proxy_entry(1, 1081, false)], vec![]);
        let result = chain.connect_tcp(target.clone(), &resolver).await.unwrap();
        assert_eq!(result.early_data.unwrap(), target.to_string().as_bytes());
        // The next selected entry is cold; it must not borrow the previous entry's session.
        assert!(chain.connect_tcp(target.clone(), &resolver).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let chain = ClientProxyChain::new(vec![warm()], vec![vec![mock_proxy(1082, false)]]);
        assert!(chain.connect_tcp(target, &resolver).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejected_reuse_does_not_fall_back_to_a_fresh_connect() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket: mock_socket(0),
                proxy: Box::new(ReusableProxy {
                    location: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
                    fail: true,
                    calls: calls.clone(),
                }),
            }],
            vec![],
        );
        let target = NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        let error = chain.connect_tcp(target, &resolver).await.err().unwrap();
        assert_eq!(error.to_string(), "CONNECT rejected");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[async_trait]
    impl ProxyConnector for MockProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            self.supports_udp
        }

        async fn setup_tcp_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Err(std::io::Error::other(
                "MockProxyConnector::setup_tcp_stream not implemented",
            ))
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other(
                "MockProxyConnector::setup_udp_bidirectional not implemented",
            ))
        }
    }

    fn mock_socket(_id: usize) -> Arc<dyn SocketConnector> {
        Arc::new(MockSocketConnector)
    }

    fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
        Box::new(MockProxyConnector::new(port, supports_udp))
    }

    fn direct_entry(id: usize) -> InitialHopEntry {
        InitialHopEntry::Direct(mock_socket(id))
    }

    fn proxy_entry(id: usize, port: u16, supports_udp: bool) -> InitialHopEntry {
        InitialHopEntry::Proxy {
            socket: mock_socket(id),
            proxy: mock_proxy(port, supports_udp),
        }
    }

    #[test]
    fn test_initial_hop_entry_direct_supports_udp() {
        let entry = direct_entry(0);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_supports_udp() {
        let entry = proxy_entry(0, 1080, true);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_no_udp() {
        let entry = proxy_entry(0, 1080, false);
        assert!(!entry.supports_udp());
    }

    #[test]
    fn test_chain_single_direct() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy_no_udp() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, true)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent_no_udp() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, false)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp()); // Subsequent doesn't support UDP
    }

    #[test]
    fn test_chain_proxy_with_subsequent() {
        let chain = ClientProxyChain::new(
            vec![proxy_entry(0, 1080, true)],
            vec![vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_mixed_initial_pool() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // VMess proxy
                proxy_entry(1, 1081, true), // VLESS proxy
                direct_entry(2),            // Direct
            ],
            vec![],
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
        // All 3 entries support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_chain_mixed_initial_pool_partial_udp() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // No UDP
                proxy_entry(1, 1081, true),  // Has UDP
                direct_entry(2),             // Has UDP
            ],
            vec![],
        );
        assert!(chain.supports_udp());
        // Only entries 1 and 2 support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_two_subsequent_hops() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pool_at_subsequent_hop() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(1080, true),
                mock_proxy(1081, false),
                mock_proxy(1082, true),
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp()); // At least one in pool supports UDP
    }

    #[test]
    #[should_panic(expected = "must have at least one initial hop entry")]
    fn test_chain_empty_initial_hop_panics() {
        ClientProxyChain::new(vec![], vec![]);
    }

    #[test]
    fn test_group_single_chain() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        let group = ClientChainGroup::new(vec![chain]);
        assert!(group.supports_udp());
    }

    #[test]
    #[should_panic(expected = "must have at least one chain")]
    fn test_group_empty_chains_panics() {
        ClientChainGroup::new(vec![]);
    }

    #[test]
    fn test_group_mixed_udp_support() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0]);
    }

    #[test]
    fn test_group_all_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![direct_entry(1)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0, 1]);
    }

    #[test]
    fn test_group_none_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(!group.supports_udp());
        assert!(group.udp_chain_indices.is_empty());
    }

    #[test]
    fn test_pool_pairing_fix_socket_proxy_always_paired() {
        // Create a mixed pool simulating: vmess@1080, vless@1081, direct
        // Each with a unique socket ID matching its position
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // socket_id=0, proxy_port=1080
                proxy_entry(1, 1081, true), // socket_id=1, proxy_port=1081
                direct_entry(2),            // socket_id=2, no proxy
            ],
            vec![],
        );

        // Select entries multiple times and verify pairing
        // Round-robin should cycle: 0, 1, 2, 0, 1, 2, ...
        for iteration in 0..6 {
            let entry = chain.initial_hop[chain.select_indices(false).unwrap()[0]].as_ref();
            let expected_idx = iteration % 3;

            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 0: should be vmess proxy at port 1080
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1080,
                        "Iteration {}: expected proxy port 1080, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 1: should be vless proxy at port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "Iteration {}: expected proxy port 1081, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (2, InitialHopEntry::Direct(_)) => {
                    // Entry 2: should be direct (no proxy)
                    // This is correct - direct has no proxy to mismatch
                }
                (idx, entry) => {
                    panic!(
                        "Iteration {}: unexpected entry type at index {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_pool_pairing_fix_udp_selection_also_paired() {
        // Create a mixed pool where only some support UDP
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // socket_id=0, NO UDP
                proxy_entry(1, 1081, true),  // socket_id=1, HAS UDP, port 1081
                direct_entry(2),             // socket_id=2, HAS UDP (direct always does)
            ],
            vec![],
        );

        // UDP selection should only return entries 1 and 2 (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify UDP selection cycles through UDP-capable entries only
        // Manually select using the new logic
        for iteration in 0..4 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let entry = &chain.initial_hop[pool_idx];
            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_initial_hop_indices

            match (expected_udp_idx, entry.as_ref()) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // UDP index 0 -> initial_hop[1] -> port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "UDP iteration {}: expected proxy port 1081",
                        iteration
                    );
                }
                (1, InitialHopEntry::Direct(_)) => {
                    // UDP index 1 -> initial_hop[2] -> direct
                    // Correct!
                }
                (idx, entry) => {
                    panic!(
                        "UDP iteration {}: unexpected at udp_idx {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_udp_selection_with_subsequent_hops() {
        // Test that when udp_uses_initial_hop = false, we select:
        // - Initial hop normally (from all entries)
        // - Final hop from udp_final_hop_indices
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP (but should be usable for UDP!)
                proxy_entry(1, 1081, false), // Another HTTP
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert!(!chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify that initial hop selection would use all entries (indices 0 and 1)
        // We can't easily test this without calling connect_udp_bidirectional(), but we can verify
        // that the normal round-robin will cycle through both
        for i in 0..4 {
            let entry = chain.initial_hop[chain.select_indices(false).unwrap()[0]].as_ref();
            let expected_idx = i % 2;
            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1080);
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1081);
                }
                _ => panic!("Unexpected entry"),
            }
        }

        // Verify that final hop selection cycles through udp_final_hop_indices only
        let final_hop = chain.subsequent_hops.last().unwrap();
        for iteration in 0..6 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let proxy = &final_hop[pool_idx];

            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_final_hop_indices
            match expected_udp_idx {
                0 => {
                    // udp_final_hop_indices[0] = 1 -> VMess at port 443
                    assert_eq!(proxy.proxy_location().port(), 443);
                }
                1 => {
                    // udp_final_hop_indices[1] = 2 -> VLESS at port 444
                    assert_eq!(proxy.proxy_location().port(), 444);
                }
                _ => panic!("Unexpected index"),
            }
        }
    }

    #[test]
    fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
        // Test the key insight: when has subsequent hops, udp_final_hop_indices
        // points to the FINAL subsequent hop, not the initial hop
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP
                proxy_entry(1, 1081, true),  // SOCKS5 - has UDP (irrelevant!)
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());

        // Key: udp_uses_initial_hop should be FALSE
        assert!(!chain.udp_uses_initial_hop);

        // udp_final_hop_indices should point to indices in the FINAL subsequent hop
        // NOT the initial hop! Only indices 1 and 2 (VMess, VLESS) support UDP
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
        // direct -> http (no UDP) -> vmess (has UDP)
        // Should support UDP because only final hop matters
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_all_intermediate_no_udp_final_has_udp() {
        // direct -> http -> socks5 -> vmess
        // Three intermediate hops, none with UDP, but final has UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_intermediate_has_udp_final_no_udp() {
        // direct -> vmess (has UDP) -> http (no UDP)
        // Should NOT support UDP because final hop doesn't
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(443, true)],   // VMess - has UDP
                vec![mock_proxy(8080, false)], // HTTP - no UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_partial_udp() {
        // direct -> [http (no UDP), vmess (has UDP), vless (has UDP)]
        // Should support UDP because final hop pool has UDP-capable connectors
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(443, true),   // VMess - has UDP
                mock_proxy(444, true),   // VLESS - has UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_no_udp() {
        // direct -> [http, socks5] (neither has UDP)
        // Should NOT support UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(1080, false), // SOCKS5 - no UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_complex_multi_hop_mixed_udp() {
        // direct -> http (no UDP) -> socks5 (no UDP) -> [http (no), vmess (yes)]
        // Should support UDP: intermediate hops don't matter, final pool has vmess
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![
                    mock_proxy(8081, false), // HTTP - no UDP
                    mock_proxy(443, true),   // VMess - has UDP
                ],
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }
}
