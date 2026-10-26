use log::debug;

#[cfg(test)]
#[path = "../benches/selector_measurement.rs"]
mod measurement_bench;
use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;

#[cfg(test)]
use crate::address::NetLocationMask;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::client_proxy_chain::ClientChainGroup;
use crate::control::connection_notes::{ConnectionNotes, Phase};
use crate::control::flows::FlowRegistry;
use crate::dns::fake_ip::FakeDnsContext;
use crate::resolver::{Resolver, resolve_location};
#[cfg(test)]
use crate::rules::Compiler;
use crate::rules::{Outcome, Predicate, domain};

/// Cache key for routing decisions.
/// We cache based on the destination address and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RoutingCacheKey {
    /// Hostname destination (e.g., "example.com:443")
    Hostname { hostname: String, port: u16 },
    /// IPv4 destination
    Ipv4 { addr: Ipv4Addr, port: u16 },
    /// IPv6 destination
    Ipv6 { addr: Ipv6Addr, port: u16 },
}

impl RoutingCacheKey {
    fn from_location(location: &NetLocation) -> Self {
        match location.address() {
            Address::Hostname(hostname) => RoutingCacheKey::Hostname {
                hostname: domain::normalize(hostname)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| hostname.clone()),
                port: location.port(),
            },
            Address::Ipv4(addr) => RoutingCacheKey::Ipv4 {
                addr: *addr,
                port: location.port(),
            },
            Address::Ipv6(addr) => match addr.to_ipv4_mapped() {
                Some(addr) => RoutingCacheKey::Ipv4 {
                    addr,
                    port: location.port(),
                },
                None => RoutingCacheKey::Ipv6 {
                    addr: *addr,
                    port: location.port(),
                },
            },
        }
    }
}

/// Cached routing decision.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CachedDecision {
    /// Index into the rules Vec for an Allow decision
    Allow(usize),
    /// Block decision
    Block,
}

/// LRU cache for routing decisions.
/// Uses RwLock for concurrent access - reads use peek() which doesn't require mutable access.
pub struct RoutingCache {
    inner: RwLock<LruCache<RoutingCacheKey, CachedDecision>>,
}

impl std::fmt::Debug for RoutingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.inner.read();
        f.debug_struct("RoutingCache")
            .field("len", &cache.len())
            .field("cap", &cache.cap())
            .finish()
    }
}

impl RoutingCache {
    /// Default cache capacity
    pub const DEFAULT_CAPACITY: usize = 10_000;

    /// Create a new routing cache with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: RwLock::new(LruCache::new(cap)),
        }
    }

    /// Look up a cached decision.
    /// Uses peek() which doesn't update LRU order (avoids write lock).
    #[inline]
    pub fn get(&self, location: &NetLocation) -> Option<CachedDecision> {
        let key = RoutingCacheKey::from_location(location);
        self.inner.read().peek(&key).copied()
    }

    /// Insert a decision into the cache.
    #[inline]
    pub fn insert(&self, location: &NetLocation, decision: CachedDecision) {
        let key = RoutingCacheKey::from_location(location);
        self.inner.write().put(key, decision);
    }

    #[cfg(test)]
    fn clear(&self) {
        self.inner.write().clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[derive(Debug)]
pub struct ConnectRule {
    pub predicate: Arc<Predicate>,
    pub no_resolve: bool,
    pub action: ConnectAction,
}

impl ConnectRule {
    #[cfg(test)]
    pub fn new(masks: Vec<NetLocationMask>, action: ConnectAction) -> Self {
        Self::compiled(
            Compiler::default()
                .legacy(masks)
                .expect("trusted built-in/test masks"),
            false,
            action,
        )
    }

    pub fn compiled(predicate: Arc<Predicate>, no_resolve: bool, action: ConnectAction) -> Self {
        Self {
            predicate,
            no_resolve,
            action,
        }
    }
}

#[derive(Debug)]
pub enum ConnectAction {
    Allow {
        override_address: Option<NetLocation>,
        /// The chain group for this rule - multiple chains for round-robin selection.
        chain_group: ClientChainGroup,
    },
    Block,
}

impl ConnectAction {
    pub fn new_allow(override_address: Option<NetLocation>, chain_group: ClientChainGroup) -> Self {
        ConnectAction::Allow {
            override_address,
            chain_group,
        }
    }

    pub fn new_block() -> Self {
        ConnectAction::Block
    }

    /// Convert this action to a decision.
    ///
    /// Takes ownership of the location. If there's an override_address, a new
    /// ResolvedLocation is created (the resolved_addr doesn't apply to a different
    /// destination). Otherwise, the original location is passed through, preserving
    /// any resolution that was done during rule matching.
    pub fn to_decision(&self, location: ResolvedLocation) -> ConnectDecision<'_> {
        match self {
            ConnectAction::Allow {
                override_address,
                chain_group,
            } => {
                let remote_location = match override_address {
                    Some(l) => {
                        // Override address - create fresh location (resolved_addr doesn't apply)
                        let new_loc = if l.port() > 0 {
                            l.clone()
                        } else {
                            // If port of 0 is specified, take the requested port.
                            NetLocation::new(l.address().clone(), location.location().port())
                        };
                        new_loc.into()
                    }
                    None => {
                        // No override - pass through with any resolution intact
                        location
                    }
                };
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                }
            }
            ConnectAction::Block => ConnectDecision::Block,
        }
    }
}

/// Threshold for enabling cache based on rule count.
/// Caching is enabled by default when the rule count exceeds this value.
const CACHE_RULE_THRESHOLD: usize = 16;

#[derive(Debug)]
pub struct ClientProxySelector {
    rules: Vec<ConnectRule>,
    /// LRU cache for routing decisions. Speeds up repeated lookups for the same destination.
    /// None when caching is disabled; DNS-dependent and sniffed routes bypass it.
    cache: Option<RoutingCache>,
    has_ip_rules: bool,
    has_hostname_rules: bool,
    sniff_enabled: bool,
    tracks_flows: bool,
    notes_registry: Option<Arc<FlowRegistry>>,
    fake_dns: Option<Arc<FakeDnsContext>>,
}

#[derive(Debug)]
pub(crate) enum IngressTarget {
    LocalDns {
        wire_destination: NetLocation,
        context: Arc<FakeDnsContext>,
    },
    Forward(PreparedDestination),
}

#[derive(Debug, PartialEq, Eq)]
enum DestinationSource {
    SuppliedHostname,
    LiteralIp,
    FakeDns,
}

#[derive(Debug)]
pub(crate) struct PreparedDestination {
    wire_destination: NetLocation,
    connection_target: ResolvedLocation,
    source: DestinationSource,
}

impl PreparedDestination {
    pub(crate) fn flow_info(&self) -> crate::control::flows::FlowInfo {
        crate::control::flows::FlowInfo {
            original: Some(self.wire_destination.clone()),
            restored_host: self
                .connection_target
                .address()
                .hostname()
                .map(str::to_owned),
            fake_dns: self.is_fake_dns(),
            ..Default::default()
        }
    }
    pub(crate) fn is_fake_dns(&self) -> bool {
        self.source == DestinationSource::FakeDns
    }

    fn is_sniffable(&self) -> bool {
        self.source != DestinationSource::SuppliedHostname
    }
}

#[derive(Debug)]
pub(crate) struct RoutedDestination<'a> {
    pub wire_destination: NetLocation,
    pub decision: ConnectDecision<'a>,
}

#[derive(Debug)]
pub enum ConnectDecision<'a> {
    Allow {
        chain_group: &'a ClientChainGroup,
        remote_location: ResolvedLocation,
    },
    Block,
}

impl ClientProxySelector {
    pub fn new(rules: Vec<ConnectRule>) -> Self {
        Self::with_options(rules, false)
    }

    /// Optionally force caching even below the rule-count threshold.
    pub fn with_options(rules: Vec<ConnectRule>, force_cache: bool) -> Self {
        Self::with_options_and_cache_size(rules, force_cache, RoutingCache::DEFAULT_CAPACITY)
    }

    /// A zero capacity disables caching. DNS-dependent and sniffed decisions always bypass it.
    pub fn with_options_and_cache_size(
        rules: Vec<ConnectRule>,
        force_cache: bool,
        cache_capacity: usize,
    ) -> Self {
        let cache = if cache_capacity != 0 && (force_cache || rules.len() > CACHE_RULE_THRESHOLD) {
            Some(RoutingCache::new(cache_capacity))
        } else {
            None
        };

        let has_ip_rules = rules.iter().any(|rule| rule.predicate.dependencies.ip);
        let tracks_flows = rules.iter().any(|rule| match &rule.action {
            ConnectAction::Allow { chain_group, .. } => chain_group.tracks_flows(),
            ConnectAction::Block => false,
        });
        let notes_registry = rules.iter().find_map(|rule| match &rule.action {
            ConnectAction::Allow { chain_group, .. } => {
                let (_, context) = chain_group.tracking()?;
                context
                    .registry
                    .notes_enabled()
                    .then(|| context.registry.clone())
            }
            ConnectAction::Block => None,
        });
        let has_hostname_rules = rules
            .iter()
            .any(|rule| rule.predicate.dependencies.hostname);
        Self {
            rules,
            cache,
            has_ip_rules,
            has_hostname_rules,
            sniff_enabled: false,
            tracks_flows,
            notes_registry,
            fake_dns: None,
        }
    }

    pub(crate) fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    pub(crate) fn tracks_flows(&self) -> bool {
        self.tracks_flows
    }

    pub(crate) fn start_notes(&self) -> Option<Arc<ConnectionNotes>> {
        self.notes_registry.as_ref()?.start_notes()
    }

    pub(crate) fn inherit_inbound_policy(mut self, parent: &Self) -> std::io::Result<Self> {
        self.sniff_enabled = parent.sniff_enabled;
        self.with_fake_dns_context(parent.fake_dns.clone())
    }

    pub(crate) fn with_fake_dns_context(
        mut self,
        context: Option<Arc<FakeDnsContext>>,
    ) -> std::io::Result<Self> {
        self.fake_dns = context;
        for rule in &self.rules {
            if let ConnectAction::Allow {
                override_address: Some(target),
                ..
            } = &rule.action
            {
                self.validate_real_target(&target.clone().into())?;
            }
        }
        Ok(self)
    }

    fn validate_real_target(&self, target: &ResolvedLocation) -> std::io::Result<()> {
        if let Some(context) = &self.fake_dns {
            for addr in [
                target.location().to_socket_addr_nonblocking(),
                target.resolved_addr(),
            ]
            .into_iter()
            .flatten()
            {
                if context.contains(addr.ip()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "synthetic address cannot be an outbound target",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prepare(&self, mut location: ResolvedLocation) -> std::io::Result<IngressTarget> {
        let wire_destination = location.location().clone();
        if let Some(hostname) = wire_destination.address().hostname() {
            if let Ok(ip) = hostname.parse() {
                location = NetLocation::from_ip_addr(ip, wire_destination.port()).into();
            } else {
                domain::normalize(hostname)?;
            }
        }
        if let Some(context) = &self.fake_dns {
            if wire_destination.port() == 53 {
                return Ok(IngressTarget::LocalDns {
                    wire_destination,
                    context: context.clone(),
                });
            }
            if let Some(addr) = location.location().to_socket_addr_nonblocking()
                && let Some(name) = context.restore(addr.ip())?
            {
                return Ok(IngressTarget::Forward(PreparedDestination {
                    wire_destination,
                    connection_target: NetLocation::new(Address::Hostname(name), addr.port())
                        .into(),
                    source: DestinationSource::FakeDns,
                }));
            }
            self.validate_real_target(&location)?;
        }
        let source = if location.address().hostname().is_some() {
            DestinationSource::SuppliedHostname
        } else {
            DestinationSource::LiteralIp
        };
        Ok(IngressTarget::Forward(PreparedDestination {
            wire_destination,
            connection_target: location,
            source,
        }))
    }

    pub(crate) fn should_sniff(&self, target: &PreparedDestination) -> bool {
        self.sniff_enabled && self.has_hostname_rules && target.is_sniffable()
    }

    pub(crate) fn fake_dns_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    pub(crate) async fn judge_prepared<'a>(
        &'a self,
        target: PreparedDestination,
        hostname: Option<&str>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<RoutedDestination<'a>> {
        let decision = if let Some(name) = hostname.filter(|name| domain::normalize(name).is_ok()) {
            if !target.is_sniffable() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "sniffed hostname requires a prepared IP-origin destination",
                ));
            }
            self.judge_uncached(target.connection_target, resolver, Some(name))
                .await?
        } else {
            self.judge_ordinary(target.connection_target, resolver)
                .await?
        };
        if let ConnectDecision::Allow {
            remote_location, ..
        } = &decision
        {
            self.validate_real_target(remote_location)?;
        }
        Ok(RoutedDestination {
            wire_destination: target.wire_destination,
            decision,
        })
    }

    pub(crate) async fn judge_prepared_with_notes<'a>(
        &'a self,
        target: PreparedDestination,
        hostname: Option<&str>,
        resolver: &Arc<dyn Resolver>,
        notes: Option<&ConnectionNotes>,
    ) -> std::io::Result<RoutedDestination<'a>> {
        if let Some(notes) = notes {
            notes.event(
                Phase::Routing,
                format_args!(
                    "target {}; fake-ip {}",
                    target.connection_target.location(),
                    target.is_fake_dns()
                ),
            );
            if let Some(hostname) = hostname {
                notes.event(Phase::Routing, format_args!("sniff hint {hostname}"));
            }
        }
        let routed = self.judge_prepared(target, hostname, resolver).await?;
        if let Some(notes) = notes
            && let ConnectDecision::Allow {
                chain_group,
                remote_location,
            } = &routed.decision
        {
            if let Some((description, _)) = chain_group.tracking() {
                notes.event(
                    Phase::Routing,
                    format_args!("selected rule: {}", description.payload),
                );
            }
            notes.event(
                Phase::Routing,
                format_args!(
                    "effective target {}; pinned {:?}",
                    remote_location.location(),
                    remote_location.resolved_addr()
                ),
            );
        }
        Ok(routed)
    }

    /// Judge a connection request, using the cache for faster repeated lookups.
    ///
    /// Takes ownership of `location` because:
    /// 1. Rule matching may resolve the hostname and cache it in the location
    /// 2. Rules may override the destination entirely
    ///
    /// The returned `ConnectDecision` contains the (possibly resolved/modified) location.
    ///
    /// By default caching is enabled only above 16 rules.
    #[inline]
    pub async fn judge<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        match self.prepare(location)? {
            IngressTarget::Forward(target) => {
                Ok(self.judge_prepared(target, None, resolver).await?.decision)
            }
            IngressTarget::LocalDns { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local DNS request bypassed ingress dispatch",
            )),
        }
    }

    async fn judge_ordinary<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        // DNS-dependent decisions must validate the address used for this connection,
        // not a hostname-only decision from a previous resolution.
        let dns_dependent = location.location().address().hostname().is_some() && self.has_ip_rules;
        if dns_dependent {
            return self.judge_uncached(location, resolver, None).await;
        }

        // If caching is disabled, go directly to rule matching
        let cache = match &self.cache {
            Some(c) => c,
            None => {
                return self.judge_uncached(location, resolver, None).await;
            }
        };

        // Fast path: check cache first
        // Note: cached decisions don't include resolved_addr, so we pass through the location
        if let Some(cached) = cache.get(location.location()) {
            return Ok(self.cached_to_decision(cached, location));
        }

        // Slow path: full rule matching (may resolve and update the location)
        let mut location = location;
        match match_rule(&self.rules, &mut location, resolver, None).await? {
            Some(rule_index) => {
                // Cache the result
                cache.insert(location.location(), CachedDecision::Allow(rule_index));
                Ok(self.rules[rule_index].action.to_decision(location))
            }
            None => {
                // Cache the block decision
                cache.insert(location.location(), CachedDecision::Block);
                Ok(ConnectDecision::Block)
            }
        }
    }

    /// Judge without using the cache. Useful for testing or when cache bypass is needed.
    #[inline]
    async fn judge_uncached<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        hostname: Option<&str>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        let mut location = location;
        match match_rule(&self.rules, &mut location, resolver, hostname).await? {
            Some(rule_index) => Ok(self.rules[rule_index].action.to_decision(location)),
            None => Ok(ConnectDecision::Block),
        }
    }

    /// Convert a cached decision back to a ConnectDecision.
    #[inline]
    fn cached_to_decision(
        &self,
        cached: CachedDecision,
        location: ResolvedLocation,
    ) -> ConnectDecision<'_> {
        match cached {
            CachedDecision::Allow(rule_index) => {
                self.rules[rule_index].action.to_decision(location)
            }
            CachedDecision::Block => ConnectDecision::Block,
        }
    }

    #[cfg(test)]
    fn cache_size(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.len())
    }

    #[cfg(test)]
    fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    #[cfg(test)]
    fn is_cache_enabled(&self) -> bool {
        self.cache.is_some()
    }
}

#[inline]
pub(crate) fn matches_domain(base_domain: &str, hostname: &str) -> bool {
    let base_domain = base_domain.strip_suffix('.').unwrap_or(base_domain);
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.len() >= base_domain.len()
        && hostname
            .get(hostname.len() - base_domain.len()..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(base_domain))
    {
        let hostname_len = hostname.len();
        let base_domain_len = base_domain.len();
        if hostname_len == base_domain_len {
            true
        } else {
            // hostname_len > base_domain_len since hostname ends with base_domain.
            hostname.as_bytes()[hostname_len - base_domain_len - 1] == b'.'
        }
    } else {
        false
    }
}

/// Returns the index of the matching rule.
/// During matching, may resolve the location's address and cache it in `location`.
#[inline]
async fn match_rule(
    rules: &[ConnectRule],
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
    sniffed_hostname: Option<&str>,
) -> std::io::Result<Option<usize>> {
    let name = sniffed_hostname
        .or_else(|| location.address().hostname())
        .map(domain::normalize)
        .transpose()?
        .map(|s| s.into_owned());
    let mut ip: Option<IpAddr> = location
        .resolved_addr()
        .or_else(|| location.location().to_socket_addr_nonblocking())
        .map(|a| a.ip().to_canonical());
    let port = location.location().port();
    for (rule_index, rule) in rules.iter().enumerate() {
        let mut outcome = rule.predicate.evaluate(name.as_deref(), ip, port);
        if outcome == (Outcome::Unknown { may_resolve: true }) && !rule.no_resolve {
            // Resolve the connection target, never the routing hint, and pin this answer.
            ip = Some(
                resolve_location(location, resolver)
                    .await?
                    .ip()
                    .to_canonical(),
            );
            outcome = rule.predicate.evaluate(name.as_deref(), ip, port);
            debug_assert!(!matches!(outcome, Outcome::Unknown { .. }));
        }
        if outcome == Outcome::Match {
            debug!(
                "Matched routing rule {rule_index} for {}",
                location.location()
            );
            return Ok(Some(rule_index));
        }
    }
    Ok(None)
}

// Helper function for testing - exposed for unit tests
#[cfg(test)]
pub fn matches_domain_for_test(base_domain: &str, hostname: &str) -> bool {
    matches_domain(base_domain, hostname)
}

#[cfg(test)]
mod tests;
