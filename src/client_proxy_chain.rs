//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! Policy selects a complete path before dialing. Fixed paths and composed choices
//! share execution without introducing another layer of per-hop selection.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::debug;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::control::catalog::{MemberOrigin, RuleDescription};
use crate::control::connection_notes::{self, Phase};
use crate::control::flows::{FlowContext, FlowGuard, FlowInfo};
use crate::resolver::Resolver;
use crate::tcp::carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

pub(crate) mod composition;

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
    fn socket(&self) -> &Arc<dyn SocketConnector> {
        match self {
            Self::Direct(socket) | Self::Wireguard(socket) | Self::Proxy { socket, .. } => socket,
        }
    }

    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) | InitialHopEntry::Wireguard(_) => true,
            InitialHopEntry::Proxy { proxy, .. } => proxy.supports_udp(),
        }
    }
}

/// A fixed path or a composition whose policy selects one complete path per flow.
pub struct ClientProxyChain {
    plan: ChainPlan,
}

enum ChainPlan {
    Fixed(SelectedPath),
    Composed(Arc<composition::Composition>),
}

/// Connector identities and origins selected before any transport is opened.
#[derive(Clone, Debug)]
struct SelectedPath {
    initial: Arc<InitialHopEntry>,
    subsequent: Vec<Arc<dyn ProxyConnector>>,
    origins: Vec<Option<MemberOrigin>>,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("num_hops", &self.num_hops())
            .field("supports_udp", &self.supports_udp())
            .finish()
    }
}

impl ClientProxyChain {
    #[cfg(unix)]
    pub(crate) fn tcp_selection_indices(&self) -> Vec<u32> {
        match &self.plan {
            ChainPlan::Fixed(_) => Vec::new(),
            ChainPlan::Composed(composition) => composition.tcp_selection_indices(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn restore_tcp_selection_indices(&mut self, indices: &[u32]) {
        match &self.plan {
            ChainPlan::Fixed(_) => assert!(indices.is_empty()),
            ChainPlan::Composed(composition) => composition.restore_tcp_selection_indices(indices),
        }
    }

    pub(crate) fn composed(
        hops: crate::option_util::OneOrSome<crate::config::ResolvedClientHop>,
        resolver: Arc<dyn Resolver>,
        limits: crate::config::GlobalLimits,
    ) -> std::io::Result<Self> {
        Ok(Self {
            plan: ChainPlan::Composed(composition::Composition::build(hops, resolver, limits)?),
        })
    }

    /// Creates round-robin choices from connector pools.
    #[cfg(test)]
    pub fn new(
        mut initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );
        assert!(subsequent_hops.iter().all(|hop| !hop.is_empty()));
        if initial_hop.len() == 1 && subsequent_hops.iter().all(|hop| hop.len() == 1) {
            return Self::fixed(
                initial_hop.pop().unwrap(),
                subsequent_hops.into_iter().flatten().collect(),
                Vec::new(),
            );
        }
        Self {
            plan: ChainPlan::Composed(composition::Composition::from_connectors(
                initial_hop,
                subsequent_hops,
            )),
        }
    }

    pub(crate) fn fixed(
        initial: InitialHopEntry,
        subsequent: Vec<Box<dyn ProxyConnector>>,
        origins: Vec<Option<MemberOrigin>>,
    ) -> Self {
        Self {
            plan: ChainPlan::Fixed(SelectedPath {
                initial: Arc::new(initial),
                subsequent: subsequent.into_iter().map(Arc::from).collect(),
                origins,
            }),
        }
    }

    fn select(&self, udp: bool) -> std::io::Result<std::borrow::Cow<'_, SelectedPath>> {
        match &self.plan {
            ChainPlan::Fixed(path) => {
                if udp && !path.supports_udp() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Chain does not support UDP",
                    ));
                }
                Ok(std::borrow::Cow::Borrowed(path))
            }
            ChainPlan::Composed(composition) => {
                composition.select(udp).map(std::borrow::Cow::Owned)
            }
        }
    }

    #[cfg(test)]
    fn composition(&self) -> Option<&Arc<composition::Composition>> {
        match &self.plan {
            ChainPlan::Fixed(_) => None,
            ChainPlan::Composed(composition) => Some(composition),
        }
    }

    #[cfg(test)]
    fn select_indices(&self, udp: bool) -> std::io::Result<Vec<usize>> {
        match &self.plan {
            ChainPlan::Fixed(_) => Ok(vec![0; self.select(udp)?.num_hops()]),
            ChainPlan::Composed(composition) => composition.test_select_indices(udp),
        }
    }

    pub(crate) fn record_carrier_demand(&self) {
        if crate::control::url_test::is_background() {
            return;
        }
        match &self.plan {
            ChainPlan::Composed(composition) => composition.record_demand(),
            ChainPlan::Fixed(path) => {
                path.touch_automatic(false);
                if let InitialHopEntry::Wireguard(socket) = path.initial.as_ref() {
                    socket.record_demand();
                }
            }
        }
    }

    /// Returns the maximum physical hop count across the configured paths.
    pub fn num_hops(&self) -> usize {
        match &self.plan {
            ChainPlan::Fixed(path) => path.num_hops(),
            ChainPlan::Composed(composition) => composition.num_hops(),
        }
    }

    pub fn supports_udp(&self) -> bool {
        match &self.plan {
            ChainPlan::Fixed(path) => path.supports_udp(),
            ChainPlan::Composed(composition) => composition.supports_udp(),
        }
    }

    pub fn is_direct_only(&self) -> bool {
        match &self.plan {
            ChainPlan::Fixed(path) => path.is_direct_only(),
            ChainPlan::Composed(composition) => composition.direct_only(),
        }
    }

    fn may_connect_directly(&self) -> bool {
        match &self.plan {
            ChainPlan::Fixed(path) => path.is_direct_only(),
            ChainPlan::Composed(composition) => composition.may_connect_directly(),
        }
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.connect_tcp_observed(remote_location, resolver, None)
            .await
    }

    pub(crate) async fn connect_tcp_pinned(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let path = self.select(false)?;
        path.with_route_activity(async {
            let mut route = path.selected_route(resolver);
            let initial = match route.initial.as_deref() {
                Some(InitialHopEntry::Proxy { proxy, .. }) => Some(proxy.as_ref()),
                _ => None,
            };
            let mut pinned = std::collections::HashMap::new();
            for proxy in initial
                .into_iter()
                .chain(route.subsequent.iter().map(AsRef::as_ref))
                // The directly dialed proxy retains the socket connector's address fallback.
                .skip(1)
            {
                let location = proxy.proxy_location();
                if pinned.contains_key(location) {
                    continue;
                }
                let addresses = crate::resolver::resolve_addresses(resolver, location).await?;
                pinned.insert(location.clone(), addresses);
            }
            // Pin wire endpoints, not connector configurations: TLS still verifies the original name.
            route.pinned_proxies = Some(Arc::new(PinnedProxies {
                endpoints: pinned,
                // Shared forks bound nested address races linearly in the selected route depth.
                extra_attempts: tokio::sync::Semaphore::new(route.subsequent.len()),
            }));
            route.connect(target).await
        })
        .await
    }

    async fn connect_tcp_observed(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        names: Option<&mut Vec<String>>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let path = self.select(false)?;
        if let Some(names) = names {
            *names = path.route_names();
        }
        path.with_route_activity(path.connect_tcp(target, resolver))
            .await
    }

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
        names: Option<&mut Vec<String>>,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let path = self.select(true)?;
        if let Some(names) = names {
            *names = path.route_names();
        }
        path.with_route_activity(path.connect_udp(resolver, target))
            .await
    }
}

impl SelectedPath {
    fn num_hops(&self) -> usize {
        1 + self.subsequent.len()
    }

    fn supports_udp(&self) -> bool {
        self.subsequent
            .last()
            .map_or_else(|| self.initial.supports_udp(), |proxy| proxy.supports_udp())
    }

    fn is_direct_only(&self) -> bool {
        self.subsequent.is_empty() && matches!(self.initial.as_ref(), InitialHopEntry::Direct(_))
    }

    fn needs_carrier_dialer(&self) -> bool {
        matches!(self.initial.as_ref(), InitialHopEntry::Proxy { proxy, .. } if proxy.needs_carrier_dialer())
            || self
                .subsequent
                .iter()
                .any(|proxy| proxy.needs_carrier_dialer())
    }

    fn selected_route(&self, resolver: &Arc<dyn Resolver>) -> SelectedRoute {
        SelectedRoute {
            socket: self.initial.socket().clone(),
            initial: Some(self.initial.clone()),
            subsequent: self.subsequent.clone(),
            resolver: resolver.clone(),
            pinned_proxies: None,
        }
    }

    fn touch_automatic(&self, failed: bool) {
        for origin in self.origins.iter().flatten() {
            for (group, _) in &origin.path {
                origin.selection.automatic.touch(group, failed);
            }
        }
    }

    async fn with_route_activity<T>(
        &self,
        connect: impl Future<Output = std::io::Result<T>>,
    ) -> std::io::Result<T> {
        self.touch_automatic(false);
        self.initial.socket().record_demand();
        let result = connect.await;
        if let Err(error) = &result
            && crate::control::url_test::remote_failure(error)
        {
            self.touch_automatic(true);
        }
        result
    }

    fn route_names(&self) -> Vec<String> {
        self.origins
            .iter()
            .rev()
            .flatten()
            .flat_map(MemberOrigin::chains)
            .collect()
    }

    #[cfg(test)]
    fn origin(&self, hop: usize) -> Option<&MemberOrigin> {
        self.origins.get(hop)?.as_ref()
    }

    async fn connect_tcp(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.needs_carrier_dialer() {
            return self.selected_route(resolver).connect(target).await;
        }
        debug!(
            "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
            self.subsequent.len(),
            target.location()
        );
        let first_target = self
            .subsequent
            .first()
            .map(|proxy| proxy.proxy_location().into())
            .unwrap_or_else(|| target.clone());
        let mut result = match self.initial.as_ref() {
            InitialHopEntry::Direct(socket) | InitialHopEntry::Wireguard(socket) => {
                debug!(
                    "Initial hop: {:?} -> {}",
                    self.initial,
                    first_target.location()
                );
                TcpClientSetupResult {
                    client_stream: socket.connect(resolver, &first_target).await?,
                    early_data: None,
                }
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                let first_target = proxy.prepare_target(first_target, resolver).await?;
                if self.subsequent.is_empty()
                    && let Some(result) = proxy.try_reuse_tcp_stream(&first_target).await?
                {
                    return Ok(result);
                }
                debug!(
                    "Initial hop: Proxy {} -> {}",
                    proxy.proxy_location(),
                    first_target.location()
                );
                let stream = socket
                    .connect(resolver, &proxy.proxy_location().into())
                    .await?;
                proxy.setup_tcp_stream(stream, &first_target).await?
            }
        };
        for (index, proxy) in self.subsequent.iter().enumerate() {
            let next = self
                .subsequent
                .get(index + 1)
                .map(|proxy| proxy.proxy_location().into())
                .unwrap_or_else(|| target.clone());
            let next = proxy.prepare_target(next, resolver).await?;
            debug!(
                "Subsequent hop {}/{}: {} -> {}",
                index + 1,
                self.subsequent.len(),
                proxy.proxy_location(),
                next.location()
            );
            result = proxy.setup_tcp_stream(result.client_stream, &next).await?;
            if let Some(data) = &result.early_data
                && index + 1 < self.subsequent.len()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Unexpected early data ({} bytes) from intermediate hop {}",
                        data.len(),
                        index + 1
                    ),
                ));
            }
        }
        debug!(
            "Chain TCP complete: {} total hop(s) to {}",
            self.num_hops(),
            target.location()
        );
        Ok(result)
    }

    async fn connect_udp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.needs_carrier_dialer() {
            let route = self.selected_route(resolver);
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
        let Some((final_proxy, intermediate)) = self.subsequent.split_last() else {
            debug!(
                "Chain UDP connect: 1 hop (initial IS final), target={}",
                target.location()
            );
            return match self.initial.as_ref() {
                InitialHopEntry::Direct(socket) | InitialHopEntry::Wireguard(socket) => {
                    debug!("Chain UDP: {:?}", self.initial);
                    socket.connect_udp_bidirectional(resolver, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} (UDP, no subsequent)",
                        proxy.proxy_location()
                    );
                    let stream = socket
                        .connect(resolver, &proxy.proxy_location().into())
                        .await?;
                    proxy.setup_udp_bidirectional(stream, target).await
                }
            };
        };
        debug!(
            "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
            intermediate.len(),
            target.location()
        );
        let first_target: ResolvedLocation = intermediate
            .first()
            .unwrap_or(final_proxy)
            .proxy_location()
            .into();
        let mut stream = match self.initial.as_ref() {
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
                let first_target = proxy.prepare_target(first_target, resolver).await?;
                let stream = socket
                    .connect(resolver, &proxy.proxy_location().into())
                    .await?;
                proxy
                    .setup_tcp_stream(stream, &first_target)
                    .await?
                    .client_stream
            }
        };
        for (index, proxy) in intermediate.iter().enumerate() {
            let next = intermediate
                .get(index + 1)
                .unwrap_or(final_proxy)
                .proxy_location()
                .into();
            let next = proxy.prepare_target(next, resolver).await?;
            debug!(
                "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                index + 1,
                intermediate.len(),
                proxy.proxy_location(),
                next.location()
            );
            stream = proxy.setup_tcp_stream(stream, &next).await?.client_stream;
        }
        debug!(
            "Chain UDP final hop: {} (UDP)",
            final_proxy.proxy_location()
        );
        final_proxy.setup_udp_bidirectional(stream, target).await
    }
}

#[derive(Debug)]
struct PinnedProxies {
    endpoints: std::collections::HashMap<NetLocation, Vec<std::net::SocketAddr>>,
    extra_attempts: tokio::sync::Semaphore,
}

#[derive(Clone, Debug)]
struct SelectedRoute {
    socket: Arc<dyn SocketConnector>,
    initial: Option<Arc<InitialHopEntry>>,
    subsequent: Vec<Arc<dyn ProxyConnector>>,
    resolver: Arc<dyn Resolver>,
    pinned_proxies: Option<Arc<PinnedProxies>>,
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
mod carrier_tests;

#[async_trait::async_trait]
impl CarrierDialer for PrefixDialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }

    async fn open_stream(&self) -> std::io::Result<Box<dyn crate::async_stream::AsyncStream>> {
        let pinned = self
            .route
            .pinned_proxies
            .as_ref()
            .filter(|_| self.route.last_proxy().is_some());
        let result = if let Some(pinned) = pinned
            && let Some(addresses) = pinned.endpoints.get(self.target.location())
        {
            crate::tcp::socket_connector_impl::connect_tcp_candidates_bounded(
                addresses.clone(),
                Some(&pinned.extra_attempts),
                |address| {
                    Ok(self
                        .route
                        .connect(NetLocation::from_ip_addr(address.ip(), address.port()).into()))
                },
            )
            .await?
        } else {
            self.route.connect(self.target.clone()).await?
        };
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
                "native QUIC requires a first-hop QUIC carrier",
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
    pub(crate) fn tracking(&self) -> Option<(&RuleDescription, &FlowContext)> {
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
        if let Some(notes) = &info.notes {
            notes.event(Phase::Dial, format_args!("begin outbound setup"));
        }
        let resolver = connection_notes::resolver(resolver, info.notes.as_ref(), Phase::Dial);
        let mut path = Vec::new();
        let mut result = chain
            .connect_tcp_observed(remote_location.clone(), &resolver, Some(&mut path))
            .await?;
        if let Some(notes) = &info.notes {
            notes.event(
                Phase::Setup,
                format_args!(
                    "outbound ready; peer {:?}",
                    result.client_stream.peer_addr()
                ),
            );
        }
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
        if let Some(notes) = &info.notes {
            notes.event(Phase::Dial, format_args!("begin outbound setup"));
        }
        let resolver = connection_notes::resolver(resolver, info.notes.as_ref(), Phase::Dial);
        let mut path = Vec::new();
        let stream = chain
            .connect_udp_observed(&resolver, target.clone(), Some(&mut path))
            .await?;
        if let Some(notes) = &info.notes {
            notes.event(Phase::Setup, format_args!("outbound ready"));
        }
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

    pub(crate) fn may_connect_directly(&self) -> bool {
        self.chains
            .iter()
            .any(ClientProxyChain::may_connect_directly)
    }

    /// Selects the interface for a new direct UDP/QUIC DNS socket.
    pub fn select_bind_interface(&self) -> std::io::Result<Option<String>> {
        if !self.is_direct_only() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP DNS requires a direct chain",
            ));
        }
        let index = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[index % self.chains.len()];
        let path = chain.select(true)?;
        path.touch_automatic(false);
        let InitialHopEntry::Direct(socket) = path.initial.as_ref() else {
            unreachable!("direct-only chain checked above")
        };
        Ok(socket.bind_interface().map(str::to_owned))
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
mod tests;

#[cfg(test)]
#[path = "../benches/path_measurement.rs"]
mod path_measurement;

#[cfg(all(test, target_os = "linux"))]
mod lifecycle_tests;
