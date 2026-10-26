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
use crate::control::connection_notes::{self, Phase};
use crate::control::flows::{FlowContext, FlowGuard, FlowInfo};
use crate::resolver::Resolver;
use crate::tcp::carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

#[cfg(test)]
mod health_tests;

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
    health_paths: Vec<HealthPath>,
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

struct HealthPath {
    indices: Vec<usize>,
    checks: Vec<Arc<crate::control::health::ProbeJob>>,
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
            socket: self.initial_hop[initial_index].socket().clone(),
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
            .find(|origin| origin.has_selector() || origin.has_fallback())
            .map(|origin| origin.selection.clone());
        self.origins = origins;
        self
    }

    fn select_indices(&self, udp: bool) -> std::io::Result<Vec<usize>> {
        let choices = self
            .selection
            .as_ref()
            .map(|selection| selection.snapshot());
        if !self.health_paths.is_empty() {
            return self.select_healthy(udp, choices.as_deref().unwrap());
        }
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
                if let Some(selection) = &self.selection
                    && !selection.automatic.0.is_empty()
                    && choices.is_some()
                {
                    let mut candidates: Vec<_> =
                        (0..length).filter(allowed).map(candidate).collect();
                    selection
                        .automatic
                        .filter(&self.origins[hop], &mut candidates, final_udp);
                    if candidates.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "selected branch cannot carry this flow",
                        ));
                    }
                    let ordinal =
                        counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
                    return Ok(candidates[ordinal]);
                }
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

    fn touch_automatic(&self, indices: &[usize], failed: bool) {
        if self
            .selection
            .as_ref()
            .is_none_or(|selection| selection.automatic.0.is_empty())
        {
            return;
        }
        for (hop, &index) in indices.iter().enumerate() {
            if let Some(origin) = self.origin(hop, index) {
                for (group, _) in &origin.path {
                    origin.selection.automatic.touch(group, failed);
                }
            }
        }
    }

    async fn with_route_activity<T>(
        &self,
        indices: &[usize],
        connect: impl Future<Output = std::io::Result<T>>,
    ) -> std::io::Result<T> {
        self.touch_automatic(indices, false);
        self.initial_hop[indices[0]].socket().record_demand();
        let result = connect.await;
        if let Err(error) = &result
            && crate::control::url_test::remote_failure(error)
        {
            self.touch_automatic(indices, true);
        }
        result
    }

    pub(crate) fn record_carrier_demand(&self) {
        if crate::control::url_test::is_background() {
            return;
        }
        // Shared carriers can have several pinned associations. Wake their groups
        // without selecting a new route or attributing a destination failure to them.
        for origin in self.origins.iter().flatten().flatten() {
            for (group, _) in &origin.path {
                origin.selection.automatic.touch(group, false);
            }
        }
        for entry in &self.initial_hop {
            if let InitialHopEntry::Wireguard(socket) = entry.as_ref() {
                socket.record_demand();
            }
        }
    }

    pub(crate) fn with_health(
        mut self,
        hops: &[Vec<crate::config::ClientConfig>],
        size: usize,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<Self> {
        let selection = self.selection.as_ref().unwrap().clone();
        let identities: Vec<Vec<_>> = hops
            .iter()
            .map(|pool| {
                pool.iter()
                    .map(|client| {
                        let mut nested_origins = Vec::new();
                        crate::config::client_visit::visit_client(
                            &mut client.clone(),
                            &mut |nested| {
                                nested_origins.push(nested.control.clone());
                                Ok(())
                            },
                        )?;
                        // visit_client is post-order: exclude the root, retain nested carrier paths.
                        nested_origins.pop();
                        let nested_paths: Vec<_> = nested_origins
                            .iter()
                            .map(|origin| {
                                origin
                                    .as_ref()
                                    .map(MemberOrigin::policy_path)
                                    .unwrap_or_default()
                            })
                            .collect();
                        let dynamic_selectors: Vec<_> = nested_origins
                            .iter()
                            .flatten()
                            .map(MemberOrigin::manual_selector_path)
                            .filter(|path| !path.is_empty())
                            .collect();
                        let mut value = serde_json::to_value((client, nested_paths))
                            .map_err(std::io::Error::other)?;
                        value.sort_all_objects();
                        Ok((value, dynamic_selectors))
                    })
                    .collect()
            })
            .collect::<std::io::Result<_>>()?;
        // Enumerate configured path order, with the last hop varying fastest.
        for ordinal in 0..size {
            let mut remaining = ordinal;
            let mut indices = vec![0; hops.len()];
            for hop in (0..hops.len()).rev() {
                indices[hop] = remaining % hops[hop].len();
                remaining /= hops[hop].len();
            }
            let path_identities: Vec<_> = indices
                .iter()
                .enumerate()
                .map(|(hop, index)| &identities[hop][*index].0)
                .collect();
            let mut dynamic_selectors: Vec<_> = indices
                .iter()
                .enumerate()
                .flat_map(|(hop, index)| identities[hop][*index].1.iter().cloned())
                .collect();
            dynamic_selectors.sort_unstable();
            dynamic_selectors.dedup();
            let fingerprint = *blake3::hash(
                &serde_json::to_vec(&path_identities).map_err(std::io::Error::other)?,
            )
            .as_bytes();
            let mut checks = Vec::new();
            let origins: Vec<_> = indices
                .iter()
                .enumerate()
                .filter_map(|(hop, index)| self.origin(hop, *index))
                .collect();
            let selectors = origins
                .iter()
                .flat_map(|origin| origin.manual_selector_path())
                .collect::<Vec<_>>();
            let definitions = origins
                .iter()
                .flat_map(|origin| &origin.path)
                .filter_map(|(group, _)| selection.health.definitions.get(group));
            for definition in definitions {
                let job = selection.health.register(
                    fingerprint,
                    &definition.check,
                    resolver.clone(),
                    selectors.clone(),
                    dynamic_selectors.clone(),
                    || self.pinned(&indices),
                )?;
                if !checks.iter().any(|existing| Arc::ptr_eq(existing, &job)) {
                    checks.push(job);
                }
            }
            self.health_paths.push(HealthPath { indices, checks });
        }
        Ok(self)
    }

    fn pinned(&self, indices: &[usize]) -> Self {
        // Probe chains are TCP-only and already selected; no policy or UDP metadata is needed.
        Self {
            origins: Vec::new(),
            selection: None,
            selector_hops: Vec::new(),
            health_paths: Vec::new(),
            initial_hop: vec![self.initial_hop[indices[0]].clone()],
            initial_hop_next_index: AtomicU32::new(0),
            subsequent_hops: self
                .subsequent_hops
                .iter()
                .enumerate()
                .map(|(hop, pool)| vec![pool[indices[hop + 1]].clone()])
                .collect(),
            subsequent_next_indices: self
                .subsequent_hops
                .iter()
                .map(|_| AtomicU32::new(0))
                .collect(),
            udp_final_hop_indices: Vec::new(),
            udp_final_hop_next_index: AtomicU32::new(0),
            udp_uses_initial_hop: self.udp_uses_initial_hop,
        }
    }

    fn select_healthy(
        &self,
        udp: bool,
        choices: &crate::control::selection::Choices,
    ) -> std::io::Result<Vec<usize>> {
        use crate::control::health::Health;
        let selection = self.selection.as_ref().unwrap();
        let now = selection.health.sample_time();
        let mut samples = std::collections::HashMap::new();
        let mut has_compatible_path = false;
        // One health/selection snapshot for the entire flow, including every prefix.
        let mut candidates: Vec<_> = self
            .health_paths
            .iter()
            .filter_map(|path| {
                if udp
                    && !self
                        .udp_final_hop_indices
                        .contains(path.indices.last().unwrap())
                {
                    return None;
                }
                if !path.indices.iter().enumerate().all(|(hop, index)| {
                    self.origin(hop, *index)
                        .is_none_or(|origin| origin.allowed(choices))
                }) {
                    return None;
                }
                has_compatible_path = true;
                let mut fully_healthy = true;
                for check in &path.checks {
                    match *samples
                        .entry(Arc::as_ptr(check))
                        .or_insert_with(|| check.health(choices, now))
                    {
                        Health::Healthy => {}
                        Health::Unknown => fully_healthy = false,
                        Health::Failed | Health::Stale => return None,
                    }
                }
                Some((path, fully_healthy))
            })
            .collect();
        if !has_compatible_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "selected branch cannot carry this flow",
            ));
        }
        if candidates.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "fallback has no healthy or unknown eligible path",
            ));
        }
        let definitions = &selection.health.definitions;
        // Resolve fallback priorities across complete paths before latency or pool choices
        // can discard a healthy candidate. Paths outside each fallback branch remain eligible.
        for hop in 0..self.num_hops() {
            let mut branches = Vec::new();
            for origin in self.origins[hop].iter().flatten() {
                for (depth, (group, _)) in origin.path.iter().enumerate() {
                    if definitions.contains_key(group) {
                        let branch = (&origin.path[..depth], group);
                        if !branches.contains(&branch) {
                            branches.push(branch);
                        }
                    }
                }
            }
            for (prefix, group) in branches {
                let member = |path: &HealthPath| {
                    let origin = self.origin(hop, path.indices[hop])?;
                    let (name, member) = origin.path.get(prefix.len())?;
                    (origin.path.starts_with(prefix) && name == group).then_some(member.as_str())
                };
                let definition = &definitions[group];
                let first_member = |require_healthy| {
                    definition.members.iter().find(|name| {
                        candidates.iter().any(|(path, fully_healthy)| {
                            *fully_healthy == require_healthy && member(path) == Some(name.as_str())
                        })
                    })
                };
                let preferred = first_member(true)
                    .map(|member| (member, true))
                    .or_else(|| first_member(false).map(|member| (member, false)));
                if let Some((preferred, require_healthy)) = preferred {
                    candidates.retain(|(path, fully_healthy)| {
                        let Some(name) = member(path) else {
                            return true;
                        };
                        name == preferred && (!require_healthy || *fully_healthy)
                    });
                }
            }
        }
        let mut result = Vec::with_capacity(self.num_hops());
        for hop in 0..self.num_hops() {
            if !selection.automatic.0.is_empty() {
                let mut indices: Vec<_> = candidates
                    .iter()
                    .map(|(path, _)| path.indices[hop])
                    .collect();
                indices.sort_unstable();
                indices.dedup();
                selection.automatic.filter(
                    &self.origins[hop],
                    &mut indices,
                    udp && hop + 1 == self.num_hops(),
                );
                candidates.retain(|(path, _)| indices.contains(&path.indices[hop]));
            }
            let mut indices: Vec<_> = candidates
                .iter()
                .map(|(path, _)| path.indices[hop])
                .collect();
            indices.sort_unstable();
            indices.dedup();
            let counter = if udp && hop + 1 == self.num_hops() {
                &self.udp_final_hop_next_index
            } else if hop == 0 {
                &self.initial_hop_next_index
            } else {
                &self.subsequent_next_indices[hop - 1]
            };
            let index = indices[counter.fetch_add(1, Ordering::Relaxed) as usize % indices.len()];
            candidates.retain(|(path, _)| path.indices[hop] == index);
            result.push(index);
        }
        Ok(result)
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
            health_paths: Vec::new(),
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
        self.with_route_activity(
            &indices,
            self.connect_tcp_selected(remote_location, resolver, &indices),
        )
        .await
    }

    async fn connect_tcp_selected(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        indices: &[usize],
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.needs_carrier_dialer() {
            return self
                .selected_route(resolver, indices)
                .connect(remote_location)
                .await;
        }
        // Select initial hop entry (socket + optional proxy paired)
        let entry = self.initial_hop[indices[0]].as_ref();

        // Select proxy connectors for subsequent hops
        let subsequent_proxies = self.select_subsequent_proxies(indices);

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
        self.with_route_activity(
            &indices,
            self.connect_udp_selected(resolver, target, &indices),
        )
        .await
    }

    async fn connect_udp_selected(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
        indices: &[usize],
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.needs_carrier_dialer() {
            let route = self.selected_route(resolver, indices);
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
mod carrier_tests;

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
        chain.touch_automatic(&indices, false);
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
mod tests;
