//! DNS resolver builder and registry.

use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use rustc_hash::FxHashMap;

use super::fake_ip::{FakeDnsContext, FakeDnsResolver, FakeIpOptions, FakeIpPool};
use super::real_only;
use super::system::SystemResolver;
use crate::config::{DnsConfig, ExpandedDnsGroup, ExpandedDnsSpec, GlobalLimits};
use crate::dns::composite_resolver::CompositeResolver;
use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::dns::parsed::{ParsedDnsServer, ParsedDnsServerEntry, ParsedDnsUrl};
use crate::option_util::NoneOrSome;
use crate::resolver::{
    CachingNativeResolver, NativeResolver, RefreshPolicy, RefreshingResolver, Resolver,
    ResolverFactory, TimeoutResolver,
};
use crate::tcp::chain_builder::{build_client_chain_group_with_limits, build_direct_chain_group};

#[derive(Clone)]
struct PoolState {
    options: FakeIpOptions,
    pool: Arc<FakeIpPool>,
}

impl PoolState {
    fn compatible(&self, options: &FakeIpOptions) -> std::io::Result<bool> {
        let parse_network = |range: &Option<String>| {
            range
                .as_deref()
                .map(str::parse::<IpNetwork>)
                .transpose()
                .map_err(std::io::Error::other)
        };
        if parse_network(&self.options.ipv4_range)? != parse_network(&options.ipv4_range)?
            || parse_network(&self.options.ipv6_range)? != parse_network(&options.ipv6_range)?
            || self.options.max_entries != options.max_entries
        {
            return Ok(false);
        }
        self.pool.state_file_matches(options.state_file.as_deref())
    }
}

/// Registry of resolved DNS groups with lazy default resolver.
pub struct DnsRegistry {
    limits: GlobalLimits,
    groups: FxHashMap<String, Arc<dyn Resolver>>,
    /// Default resolver, created lazily only if needed.
    default_resolver: Option<Arc<dyn Resolver>>,
    forbidden: Arc<[IpNetwork]>,
    pools: FxHashMap<String, PoolState>,
}

impl DnsRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            limits: crate::resources::limits(),
            groups: FxHashMap::default(),
            default_resolver: None,
            forbidden: Arc::from([]),
            pools: FxHashMap::default(),
        }
    }

    /// Register a DNS group.
    pub fn register(&mut self, name: String, resolver: Arc<dyn Resolver>) {
        self.groups.insert(name, resolver);
    }

    /// Get a resolver by group name, returns None if not found.
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.groups.get(name).cloned()
    }

    pub(crate) fn forbidden_ranges(&self) -> &[IpNetwork] {
        &self.forbidden
    }

    /// Get or create the guarded system resolver with cached native lookups.
    /// Used when a server has no `dns` field configured.
    pub fn get_or_create_default(&mut self) -> Arc<dyn Resolver> {
        let forbidden = self.forbidden.clone();
        self.default_resolver
            .get_or_insert_with(|| {
                real_only(
                    Arc::new(SystemResolver::new(
                        Arc::new(CachingNativeResolver::new()),
                        forbidden.clone(),
                        Duration::from_secs(5),
                    )),
                    forbidden,
                )
            })
            .clone()
    }

    /// Get resolver for a server config's dns field.
    /// After validation, dns.servers should be a single group name or None.
    pub fn get_for_server(&mut self, dns: Option<&DnsConfig>) -> Arc<dyn Resolver> {
        match dns.and_then(|c| c.resolved_group()) {
            Some(group_name) => self
                .groups
                .get(group_name)
                .cloned()
                .expect("dns group should exist (validated)"),
            None => self.get_or_create_default(),
        }
    }

    fn pool_handles(&self) -> Vec<Arc<FakeIpPool>> {
        self.pools
            .values()
            .map(|state| state.pool.clone())
            .collect()
    }

    pub async fn checkpoint(&self) -> std::io::Result<()> {
        let pools = self.pool_handles();
        tokio::task::spawn_blocking(move || checkpoint_pools(pools))
            .await
            .map_err(std::io::Error::other)?
    }

    pub async fn shutdown_checkpoint(&self) -> std::io::Result<()> {
        let pools = self.pool_handles();
        tokio::task::spawn_blocking(move || {
            let mut error = None;
            for pool in pools {
                if let Err(failure) = pool.shutdown_checkpoint() {
                    error = Some(failure);
                }
            }
            error.map_or(Ok(()), Err)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub fn snapshot_task(&self) -> DnsSnapshotTask {
        let pools: Vec<_> = self
            .pool_handles()
            .into_iter()
            .filter(|pool| pool.persistent())
            .collect();
        if pools.is_empty() {
            return DnsSnapshotTask(None);
        }
        DnsSnapshotTask(Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let pools = pools.clone();
                let result = tokio::task::spawn_blocking(move || checkpoint_pools(pools)).await;
                match result {
                    Ok(Ok(())) => (),
                    failure => log::warn!("Fake DNS snapshot failed: {failure:?}"),
                }
            }
        })))
    }
}

fn checkpoint_pools(pools: Vec<Arc<FakeIpPool>>) -> std::io::Result<()> {
    let mut error = None;
    for pool in pools {
        if let Err(failure) = pool.checkpoint() {
            log::warn!("Fake DNS pool checkpoint failed: {failure}");
            error = Some(failure);
        }
    }
    error.map_or(Ok(()), Err)
}

pub struct DnsSnapshotTask(Option<tokio::task::JoinHandle<()>>);

impl Drop for DnsSnapshotTask {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

impl Default for DnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a resolver with optional timeout and return as Arc<dyn Resolver>.
/// Wraps in TimeoutResolver before Arc to avoid double indirection.
fn wrap_resolver<T: Resolver + 'static>(resolver: T, timeout_secs: u32) -> Arc<dyn Resolver> {
    if timeout_secs > 0 {
        Arc::new(TimeoutResolver::with_timeout(
            resolver,
            Duration::from_secs(timeout_secs as u64),
        ))
    } else {
        Arc::new(resolver)
    }
}

/// Cloneable build plan that can reconstruct a fresh hickory resolver.
/// Used as the factory for RefreshingResolver so that refresh discards
/// the old hickory connection pool entirely.
#[derive(Clone)]
struct HickoryResolverPlan {
    parsed_url: ParsedDnsUrl,
    chain_group: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap_resolver: Arc<dyn Resolver>,
    chain_key: String,
    bootstrap_key: Option<String>,
    options: HickoryResolverOptions,
    description: String,
}

impl HickoryResolverPlan {
    fn is_pool_compatible_with(&self, other: &Self) -> bool {
        self.chain_key == other.chain_key
            && self.bootstrap_key == other.bootstrap_key
            && self.options == other.options
    }

    async fn resolved_name_server_pairs(
        &self,
    ) -> std::io::Result<Vec<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)>> {
        let resolved_ips = match self.parsed_url.hostname() {
            Some(hostname) => {
                let location = crate::address::NetLocation::new(
                    crate::address::Address::Hostname(hostname.to_string()),
                    0,
                );
                let addrs = self
                    .bootstrap_resolver
                    .resolve_location(&location)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to resolve DNS server hostname '{}': {}",
                            hostname, e
                        ))
                    })?;
                if addrs.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "bootstrap lookup returned no addresses for '{}'",
                        hostname
                    )));
                }

                let mut ips = Vec::with_capacity(addrs.len());
                for ip in addrs.into_iter().map(|addr| addr.ip()) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }

                log::debug!(
                    "HickoryResolverPlan ({}): resolved {} to {:?}",
                    self.description,
                    hostname,
                    ips
                );
                ips
            }
            None => vec![],
        };

        if resolved_ips.is_empty() {
            let server = self
                .parsed_url
                .to_parsed_server(None)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return server_to_ns_config(&server)
                .map(|pair| vec![pair])
                .ok_or_else(|| {
                    std::io::Error::other(format!(
                        "resolver plan '{}' did not produce a nameserver config",
                        self.description
                    ))
                });
        }

        let mut ns_pairs = Vec::with_capacity(resolved_ips.len());
        for ip in resolved_ips {
            let server = self
                .parsed_url
                .to_parsed_server(Some(ip))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let pair = server_to_ns_config(&server).ok_or_else(|| {
                std::io::Error::other(format!(
                    "resolver plan '{}' did not produce a nameserver config",
                    self.description
                ))
            })?;
            ns_pairs.push(pair);
        }

        Ok(ns_pairs)
    }

    /// Build a fresh resolver, re-resolving hostname upstreams if needed.
    /// When a hostname resolves to multiple IPs, all are expanded into
    /// nameserver configs inside a single pooled hickory resolver.
    async fn build(&self) -> std::io::Result<Arc<dyn Resolver>> {
        let ns_pairs = self.resolved_name_server_pairs().await?;

        if ns_pairs.len() > 1 {
            let resolver = HickoryResolver::build_pooled(
                ns_pairs,
                self.chain_group.clone(),
                self.bootstrap_resolver.clone(),
                self.options,
                self.description.clone(),
            )?;
            return Ok(Arc::new(resolver));
        }

        // Single IP or IP-literal upstream: build normally.
        let resolved_ip = ns_pairs.first().map(|(ip, _)| *ip);
        let server = self
            .parsed_url
            .to_parsed_server(resolved_ip)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        build_hickory_from_server(
            server,
            self.chain_group.clone(),
            self.bootstrap_resolver.clone(),
            self.options,
        )
    }
}

async fn try_build_hickory_pool_from_plans(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if plans.len() < 2 {
        return Ok(None);
    }

    let first = &plans[0];
    if plans
        .iter()
        .skip(1)
        .any(|plan| !plan.is_pool_compatible_with(first))
    {
        return Ok(None);
    }

    let mut ns_pairs = Vec::new();
    for plan in plans {
        ns_pairs.extend(plan.resolved_name_server_pairs().await?);
    }

    if ns_pairs.len() < 2 {
        return Ok(None);
    }

    let descriptions: Vec<String> = plans.iter().map(|plan| plan.description.clone()).collect();
    let description = format!("pool[{}]", descriptions.join(", "));
    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.chain_group.clone(),
        first.bootstrap_resolver.clone(),
        first.options,
        description,
    )?;
    Ok(Some(Arc::new(resolver)))
}

async fn build_hickory_resolver_group(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Arc<dyn Resolver>> {
    if plans.is_empty() {
        return Err(std::io::Error::other(
            "no hickory resolver plans configured",
        ));
    }

    if let Some(pooled) = try_build_hickory_pool_from_plans(plans).await? {
        return Ok(pooled);
    }

    let mut resolvers = Vec::with_capacity(plans.len());
    for plan in plans {
        resolvers.push(plan.build().await?);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Construct a single HickoryResolver from a ParsedDnsServer.
fn build_hickory_from_server(
    server: ParsedDnsServer,
    chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    options: HickoryResolverOptions,
) -> std::io::Result<Arc<dyn Resolver>> {
    Ok(match server {
        ParsedDnsServer::System => {
            unreachable!("system resolver should not use hickory build path")
        }
        ParsedDnsServer::Udp { addr } => {
            Arc::new(HickoryResolver::udp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tcp { addr } => {
            Arc::new(HickoryResolver::tcp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tls { addr, server_name } => Arc::new(HickoryResolver::tls(
            addr,
            server_name,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::https(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::h3(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
    })
}

/// Convert a ParsedDnsServer to (IpAddr, ConnectionConfig) for pooling.
/// Returns None for System resolvers (cannot be pooled).
fn server_to_ns_config(
    server: &ParsedDnsServer,
) -> Option<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)> {
    use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};

    match server {
        ParsedDnsServer::System => None,
        ParsedDnsServer::Udp { addr } => {
            let mut cc = ConnectionConfig::udp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tcp { addr } => {
            let mut cc = ConnectionConfig::tcp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tls { addr, server_name } => {
            let mut cc = ConnectionConfig::tls(server_name.clone());
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => {
            let mut cc = ConnectionConfig::https(server_name.clone(), Some(path.clone()));
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => {
            let protocol = ProtocolConfig::H3 {
                server_name: server_name.clone(),
                path: path.clone(),
                disable_grease: true,
            };
            let mut cc = ConnectionConfig::new(protocol);
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
    }
}

/// Build a resolver from parsed DNS server entries.
/// When all entries are hickory-backed with compatible settings, pools them
/// into a single hickory resolver instead of using CompositeResolver.
#[cfg(test)]
pub fn build_resolver(entries: Vec<ParsedDnsServerEntry>) -> std::io::Result<Arc<dyn Resolver>> {
    build_resolver_with_limits(entries, crate::resources::limits(), Arc::from([]))
}

fn build_resolver_with_limits(
    entries: Vec<ParsedDnsServerEntry>,
    limits: GlobalLimits,
    forbidden: Arc<[IpNetwork]>,
) -> std::io::Result<Arc<dyn Resolver>> {
    if entries.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    // Try to pool all hickory-backed entries into one resolver.
    if let Some(pooled) = try_build_hickory_pool(&entries, limits)? {
        return Ok(pooled);
    }

    // Fallback: build individual resolvers and composite them.
    let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let timeout_secs = entry.timeout_secs;

        let options = HickoryResolverOptions {
            ip_strategy: entry.ip_strategy,
            request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
            connect_timeout: Duration::from_secs(entry.connect_timeout_secs as u64),
            attempts: entry.attempts,
            quic_memory_bytes: limits.quic_dns_memory_bytes,
        };

        let resolver: Arc<dyn Resolver> = match entry.server {
            ParsedDnsServer::System => wrap_resolver(
                SystemResolver::new(
                    Arc::new(NativeResolver::new()),
                    forbidden.clone(),
                    options.request_timeout.unwrap_or(Duration::from_secs(5)),
                ),
                timeout_secs,
            ),
            server => build_hickory_from_server(
                server,
                entry.client_chain,
                entry.bootstrap_resolver,
                options,
            )?,
        };

        resolvers.push(resolver);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Attempt to build a single pooled hickory resolver from all entries.
/// Returns None if entries contain system resolvers, or if entries have
/// heterogeneous settings (different chains, bootstraps, timeouts, etc.).
/// Pooling is only safe when all entries share the same runtime config,
/// since a single hickory resolver applies one set of options to all its
/// nameservers.
fn try_build_hickory_pool(
    entries: &[ParsedDnsServerEntry],
    limits: GlobalLimits,
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if entries.is_empty() || entries.len() < 2 {
        return Ok(None);
    }

    let first = &entries[0];

    // All entries must be hickory-backed (no system resolvers) and share
    // the same chain group, bootstrap, and tuning options.
    let mut ns_pairs = Vec::with_capacity(entries.len());
    for entry in entries {
        match server_to_ns_config(&entry.server) {
            Some(pair) => ns_pairs.push(pair),
            None => return Ok(None),
        }

        if !Arc::ptr_eq(&entry.client_chain, &first.client_chain) {
            return Ok(None);
        }
        if !Arc::ptr_eq(&entry.bootstrap_resolver, &first.bootstrap_resolver) {
            return Ok(None);
        }
        if entry.timeout_secs != first.timeout_secs
            || entry.connect_timeout_secs != first.connect_timeout_secs
            || entry.attempts != first.attempts
            || entry.ip_strategy != first.ip_strategy
        {
            return Ok(None);
        }
    }

    let timeout_secs = first.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: first.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(first.connect_timeout_secs as u64),
        attempts: first.attempts,
        quic_memory_bytes: limits.quic_dns_memory_bytes,
    };

    let descriptions: Vec<String> = entries.iter().map(|e| format!("{:?}", e.server)).collect();
    let description = format!("pool[{}]", descriptions.join(", "));

    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.client_chain.clone(),
        first.bootstrap_resolver.clone(),
        options,
        description,
    )?;

    Ok(Some(Arc::new(resolver)))
}

/// Build DnsRegistry from expanded DNS groups.
///
/// Groups must be in topological order (bootstrap dependencies first).
/// This function:
/// - Builds client chain groups from expanded client chains
/// - Resolves hostnames in DNS URLs using bootstrap resolvers
/// - Creates HickoryResolver instances
#[allow(dead_code)] // Public library entry point; the binary prepares with explicit limits.
pub async fn build_dns_registry(groups: Vec<ExpandedDnsGroup>) -> std::io::Result<DnsRegistry> {
    build_dns_registry_with_limits(groups, crate::resources::limits()).await
}

pub async fn build_dns_registry_with_limits(
    groups: Vec<ExpandedDnsGroup>,
    limits: GlobalLimits,
) -> std::io::Result<DnsRegistry> {
    build_dns_registry_reusing(groups, limits, None).await
}

pub async fn build_dns_registry_reusing(
    groups: Vec<ExpandedDnsGroup>,
    limits: GlobalLimits,
    previous: Option<&DnsRegistry>,
) -> std::io::Result<DnsRegistry> {
    build_dns_registry_for_runtime(groups, limits, previous, &[]).await
}

pub async fn build_dns_registry_for_runtime(
    groups: Vec<ExpandedDnsGroup>,
    limits: GlobalLimits,
    previous: Option<&DnsRegistry>,
    synthetic_endpoints: &[std::net::IpAddr],
) -> std::io::Result<DnsRegistry> {
    let active_options = groups.iter().filter_map(|group| group.fake_ip.as_ref());
    let retained_options = previous
        .into_iter()
        .flat_map(|registry| registry.pools.values().map(|state| &state.options));
    let pool_ranges: Result<Vec<IpNetwork>, _> = active_options
        .chain(retained_options)
        .flat_map(|options| options.ipv4_range.iter().chain(options.ipv6_range.iter()))
        .map(|range| range.parse())
        .collect();
    let pool_ranges = pool_ranges.map_err(std::io::Error::other)?;
    crate::config::validate_tun_endpoints(synthetic_endpoints.iter().copied(), &pool_ranges)?;

    let mut forbidden = pool_ranges;
    if let Some(previous) = previous {
        for range in previous.forbidden_ranges() {
            if !forbidden.contains(range) {
                forbidden.push(*range);
            }
        }
    }
    if !forbidden.is_empty() {
        for endpoint in synthetic_endpoints {
            let range = IpNetwork::from(endpoint.to_canonical());
            if !forbidden.contains(&range) {
                forbidden.push(range);
            }
        }
    }
    let mut registry = DnsRegistry {
        limits,
        forbidden: forbidden.into(),
        pools: previous
            .map(|registry| registry.pools.clone())
            .unwrap_or_default(),
        ..DnsRegistry::new()
    };

    for group in groups {
        for spec in &group.specs {
            for endpoint in std::iter::once(spec.url.as_str()).chain(spec.bootstrap_url.as_deref())
            {
                if let Ok(url) = url::Url::parse(endpoint) {
                    let ip = match url.host() {
                        Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
                        Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
                        Some(url::Host::Domain(host)) => host.parse().ok(),
                        None => None,
                    };
                    if ip.is_some_and(|ip| {
                        registry
                            .forbidden
                            .iter()
                            .any(|range| range.contains(ip.to_canonical()))
                    }) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "DNS/bootstrap endpoint overlaps a synthetic endpoint",
                        ));
                    }
                }
            }
        }
        if group.fake_ip.is_some() && group.specs.iter().any(|spec| spec.url == "system") {
            SystemResolver::check_configuration(registry.forbidden.clone()).await?;
        }
        let resolver = if group.use_default_resolver {
            registry.get_or_create_default()
        } else {
            build_resolver_from_specs(&group.specs, &registry, &group.name).await?
        };
        let real = real_only(resolver, registry.forbidden.clone());
        let old = previous.and_then(|previous| previous.pools.get(&group.name));
        let resolver: Arc<dyn Resolver> = if let Some(options) = group.fake_ip {
            options.validate()?;
            let pool = if let Some(old) = old {
                if !old.compatible(&options)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "DNS group '{}' changes fake IP pool ownership/range/capacity; explicit restart required",
                            group.name
                        ),
                    ));
                }
                old.pool.clone()
            } else {
                let options = options.clone();
                let owner = group.name.clone();
                Arc::new(
                    tokio::task::spawn_blocking(move || FakeIpPool::new_scoped(&options, &owner))
                        .await
                        .map_err(std::io::Error::other)??,
                )
            };
            registry.pools.insert(
                group.name.clone(),
                PoolState {
                    options: options.clone(),
                    pool: pool.clone(),
                },
            );
            let context = Arc::new(FakeDnsContext::with_pool(options, real.clone(), pool)?);
            Arc::new(FakeDnsResolver::new(real, context))
        } else {
            if old.is_some() {
                log::warn!(
                    "Fake DNS disabled for '{}'; cached fake addresses may fail",
                    group.name
                );
            }
            real
        };
        registry.register(group.name, resolver);
    }

    Ok(registry)
}

/// Build a resolver from expanded DNS specs, wrapping hickory-backed groups
/// in RefreshingResolver for stale connection mitigation.
async fn build_resolver_from_specs(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
    group_name: &str,
) -> std::io::Result<Arc<dyn Resolver>> {
    if specs.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut entries: Vec<ParsedDnsServerEntry> = Vec::with_capacity(specs.len());
    let mut plans: Vec<HickoryResolverPlan> = Vec::new();
    let mut has_system = false;

    for spec in specs {
        let (entry, plan) = build_entry_and_plan(spec, registry).await?;
        if matches!(entry.server, ParsedDnsServer::System) {
            has_system = true;
        }
        if let Some(p) = plan {
            plans.push(p);
        }
        entries.push(entry);
    }

    // Wrap in RefreshingResolver only if we have hickory-backed resolvers
    // and no system resolver (mixed groups stay as-is for simplicity).
    if !plans.is_empty() && !has_system {
        let description = group_name.to_string();
        let plans = plans.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let plans = plans.clone();
            Box::pin(async move { build_hickory_resolver_group(&plans).await })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let refreshing = RefreshingResolver::new(factory, policy, description).await?;
        Ok(Arc::new(refreshing))
    } else {
        build_resolver_with_limits(entries, registry.limits, registry.forbidden.clone())
    }
}

/// Build a ParsedDnsServerEntry and optionally a HickoryResolverPlan from an expanded spec.
/// The plan is returned for non-system resolvers so they can be rebuilt on refresh.
async fn build_entry_and_plan(
    spec: &ExpandedDnsSpec,
    registry: &DnsRegistry,
) -> std::io::Result<(ParsedDnsServerEntry, Option<HickoryResolverPlan>)> {
    // Parse URL
    let parsed_url = ParsedDnsUrl::parse_with_server_name(&spec.url, spec.server_name.as_deref())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Build client chain group
    let chain_resolver = real_only(Arc::new(NativeResolver::new()), registry.forbidden.clone());
    let chain_group = if spec.client_chains.is_empty() {
        Arc::new(build_direct_chain_group(chain_resolver))
    } else {
        let chains = if spec.client_chains.len() == 1 {
            NoneOrSome::One(spec.client_chains[0].clone())
        } else {
            NoneOrSome::Some(spec.client_chains.clone())
        };
        Arc::new(build_client_chain_group_with_limits(
            chains,
            chain_resolver,
            registry.limits,
        )?)
    };

    // Build or get bootstrap resolver
    let bootstrap_resolver: Arc<dyn Resolver> = match &spec.bootstrap_url {
        Some(bootstrap_url) => {
            // Try to get from registry first (group reference)
            if let Some(resolver) = registry.get_by_name(bootstrap_url) {
                resolver
            } else {
                // Parse as URL and build a simple resolver
                let bootstrap_parsed = ParsedDnsUrl::parse(bootstrap_url).map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid bootstrap_url '{}': {}",
                        bootstrap_url, e
                    ))
                })?;

                let bootstrap_server = bootstrap_parsed
                    .to_parsed_server(None)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                let native = real_only(Arc::new(NativeResolver::new()), registry.forbidden.clone());
                let direct_chain = Arc::new(build_direct_chain_group(native.clone()));
                // Bootstrap resolvers use default timeout (10s) and 2 attempts
                let bootstrap_entry = ParsedDnsServerEntry::new(
                    bootstrap_server,
                    direct_chain,
                    native,
                    super::IpStrategy::default(),
                    10, // Default timeout for bootstrap
                    5,  // Default connect timeout for bootstrap
                    2,  // Default attempts for bootstrap
                );
                real_only(
                    build_resolver_with_limits(
                        vec![bootstrap_entry],
                        registry.limits,
                        registry.forbidden.clone(),
                    )?,
                    registry.forbidden.clone(),
                )
            }
        }
        None => real_only(Arc::new(NativeResolver::new()), registry.forbidden.clone()),
    };

    let timeout_secs = spec.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: spec.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(spec.connect_timeout_secs as u64),
        attempts: spec.attempts,
        quic_memory_bytes: registry.limits.quic_dns_memory_bytes,
    };

    // Build plan for hickory-backed resolvers (not system)
    let plan = if !matches!(parsed_url, ParsedDnsUrl::System) {
        Some(HickoryResolverPlan {
            parsed_url: parsed_url.clone(),
            chain_group: chain_group.clone(),
            bootstrap_resolver: bootstrap_resolver.clone(),
            chain_key: serde_yaml::to_string(&spec.client_chains).map_err(|e| {
                std::io::Error::other(format!("failed to serialize client_chains: {e}"))
            })?,
            bootstrap_key: spec.bootstrap_url.clone(),
            options,
            description: spec.url.clone(),
        })
    } else {
        None
    };

    // Resolve hostname if URL contains one
    let resolved_ip = match parsed_url.hostname() {
        Some(hostname) => {
            let location = crate::address::NetLocation::new(
                crate::address::Address::Hostname(hostname.to_string()),
                0,
            );

            let addrs = bootstrap_resolver
                .resolve_location(&location)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "failed to resolve DNS server hostname '{}': {}",
                        hostname, e
                    ))
                })?;

            Some(addrs[0].ip())
        }
        None => None,
    };

    // Convert to ParsedDnsServer with resolved IP
    let server = parsed_url
        .to_parsed_server(resolved_ip)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let entry = ParsedDnsServerEntry::new(
        server,
        chain_group,
        bootstrap_resolver,
        spec.ip_strategy,
        spec.timeout_secs,
        spec.connect_timeout_secs,
        spec.attempts,
    );

    Ok((entry, plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExpandedDnsSpec;
    use crate::dns::parsed::{IpStrategy, ParsedDnsServer};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;

    /// Helper to build a shared chain group and bootstrap resolver for tests.
    fn shared_test_deps() -> (
        Arc<crate::client_proxy_chain::ClientChainGroup>,
        Arc<dyn Resolver>,
    ) {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(build_direct_chain_group(resolver.clone()));
        (chain, resolver)
    }

    fn make_entry(
        server: ParsedDnsServer,
        chain: &Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: &Arc<dyn Resolver>,
    ) -> ParsedDnsServerEntry {
        ParsedDnsServerEntry::new(
            server,
            chain.clone(),
            bootstrap.clone(),
            IpStrategy::default(),
            5,
            5,
            1,
        )
    }

    fn make_spec(url: &str) -> ExpandedDnsSpec {
        ExpandedDnsSpec {
            url: url.to_string(),
            server_name: None,
            client_chains: vec![],
            bootstrap_url: None,
            ip_strategy: IpStrategy::default(),
            timeout_secs: 5,
            connect_timeout_secs: 5,
            attempts: 1,
        }
    }

    fn fake_groups(enabled: bool) -> Vec<ExpandedDnsGroup> {
        vec![ExpandedDnsGroup {
            name: "fake".into(),
            specs: vec![make_spec("system")],
            fake_ip: enabled.then(FakeIpOptions::default),
            use_default_resolver: false,
        }]
    }

    #[tokio::test]
    async fn omitted_servers_keeps_default_cache_and_retired_pools_freeze_on_shutdown() {
        let configs = crate::config::create_server_configs(
            serde_yaml::from_str(
                "- address: '0.0.0.0:1080'\n  protocol: {type: socks}\n  dns: {fake_ip: false}\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(configs.dns_groups[0].use_default_resolver);
        let name = configs.dns_groups[0].name.clone();
        let mut registry = build_dns_registry(configs.dns_groups).await.unwrap();
        assert!(Arc::ptr_eq(
            &registry.get_by_name(&name).unwrap(),
            &registry.get_or_create_default()
        ));

        let initial = build_dns_registry(fake_groups(true)).await.unwrap();
        let old = initial
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        old.allocate("before.test", false).unwrap();
        let removed = build_dns_registry_reusing(Vec::new(), initial.limits, Some(&initial))
            .await
            .unwrap();
        assert_eq!(removed.pools.len(), 1);
        removed.shutdown_checkpoint().await.unwrap();
        assert_eq!(
            old.allocate("after.test", false).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn failed_pool_checkpoint_does_not_skip_other_pools() {
        let directory = tempfile::tempdir().unwrap();
        let mut pools = Vec::new();
        for index in 0..2 {
            let options = FakeIpOptions {
                state_file: Some(directory.path().join(format!("{index}.json"))),
                ..Default::default()
            };
            pools.push(Arc::new(FakeIpPool::new(&options).unwrap()));
        }
        std::fs::create_dir(directory.path().join("0.json")).unwrap();
        assert!(checkpoint_pools(pools).is_err());
        assert!(directory.path().join("1.json").is_file());
    }

    #[test]
    fn snapshot_task_needs_persistent_pools() {
        let mut registry = DnsRegistry::new();
        assert!(registry.snapshot_task().0.is_none());
        let options = FakeIpOptions::default();
        registry.pools.insert(
            "memory".into(),
            PoolState {
                pool: Arc::new(FakeIpPool::new(&options).unwrap()),
                options,
            },
        );
        assert!(registry.snapshot_task().0.is_none());
    }

    #[tokio::test]
    async fn disabling_and_removing_contexts_retains_real_only_guards() {
        let mut groups = fake_groups(true);
        groups[0].specs = vec![make_spec("udp://192.0.2.53")];
        let initial = build_dns_registry_for_runtime(
            groups,
            crate::resources::limits(),
            None,
            &["10.99.0.1".parse().unwrap()],
        )
        .await
        .unwrap();
        let disabled =
            build_dns_registry_reusing(fake_groups(false), initial.limits, Some(&initial))
                .await
                .unwrap();
        let mut removed = build_dns_registry_reusing(Vec::new(), initial.limits, Some(&disabled))
            .await
            .unwrap();
        assert_eq!(initial.forbidden_ranges(), removed.forbidden_ranges());
        let resolver = removed.get_or_create_default();
        for address in ["198.18.0.5:443", "10.99.0.1:443"] {
            assert_eq!(
                resolver
                    .resolve_location(
                        &crate::address::NetLocation::from_str(address, None).unwrap()
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        for endpoint in ["udp://198.18.0.5", "udp://10.99.0.1"] {
            let mut groups = fake_groups(false);
            groups[0].specs = vec![make_spec(endpoint)];
            assert_eq!(
                build_dns_registry_reusing(groups, initial.limits, Some(&removed))
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test]
    async fn literal_upstreams_cannot_target_tun_endpoints_outside_the_pool() {
        for endpoint in ["10.99.0.1", "::ffff:10.99.0.1"] {
            let mut groups = fake_groups(true);
            groups[0].specs = vec![make_spec("udp://10.99.0.1:53")];
            let failure = build_dns_registry_for_runtime(
                groups,
                crate::resources::limits(),
                None,
                &[endpoint.parse().unwrap()],
            )
            .await
            .err()
            .unwrap();
            assert_eq!(failure.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[tokio::test]
    async fn fake_context_reload_sharing_disable_and_reenable_keep_pool_identity() {
        let initial = build_dns_registry(fake_groups(true)).await.unwrap();
        let context = initial
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let ip = context.allocate("stable.test", false).unwrap();
        assert!(Arc::ptr_eq(
            &context,
            &initial
                .get_by_name("fake")
                .unwrap()
                .fake_dns_context()
                .unwrap()
        ));
        let mut updated = fake_groups(true);
        updated[0]
            .fake_ip
            .as_mut()
            .unwrap()
            .bypass_domains
            .push("new.test".into());
        let next = build_dns_registry_reusing(updated, initial.limits, Some(&initial))
            .await
            .unwrap();
        assert_eq!(
            next.get_by_name("fake")
                .unwrap()
                .fake_dns_context()
                .unwrap()
                .restore(ip)
                .unwrap()
                .as_deref(),
            Some("stable.test")
        );
        let disabled = build_dns_registry_reusing(fake_groups(false), initial.limits, Some(&next))
            .await
            .unwrap();
        assert!(
            disabled
                .get_by_name("fake")
                .unwrap()
                .fake_dns_context()
                .is_none()
        );
        let enabled =
            build_dns_registry_reusing(fake_groups(true), initial.limits, Some(&disabled))
                .await
                .unwrap();
        assert_eq!(
            enabled
                .get_by_name("fake")
                .unwrap()
                .fake_dns_context()
                .unwrap()
                .restore(ip)
                .unwrap()
                .as_deref(),
            Some("stable.test")
        );
        let mut incompatible = fake_groups(true);
        incompatible[0].fake_ip.as_mut().unwrap().max_entries -= 1;
        assert!(
            build_dns_registry_reusing(incompatible, initial.limits, Some(&enabled))
                .await
                .is_err()
        );
        assert_eq!(context.restore(ip).unwrap().as_deref(), Some("stable.test"));
    }

    #[tokio::test]
    async fn equivalent_pool_ranges_reuse_live_mappings_on_reload() {
        let mut groups = fake_groups(true);
        groups[0].specs = vec![make_spec("udp://127.0.0.1:9")];
        groups[0].fake_ip.as_mut().unwrap().ipv6_range = Some("fd00::/64".into());
        let initial = build_dns_registry(groups.clone()).await.unwrap();
        let context = initial
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let v4 = context.allocate("stable.test", false).unwrap();
        let v6 = context.allocate("stable.test", true).unwrap();
        groups[0].fake_ip.as_mut().unwrap().ipv6_range = Some("FD00:0::/64".into());
        let next = build_dns_registry_reusing(groups.clone(), initial.limits, Some(&initial))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &initial.pools["fake"].pool,
            &next.pools["fake"].pool
        ));
        let next_context = next
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        for ip in [v4, v6] {
            assert_eq!(
                next_context.restore(ip).unwrap().as_deref(),
                Some("stable.test")
            );
        }
        let options = groups[0].fake_ip.as_ref().unwrap();
        for incompatible in [
            FakeIpOptions {
                ipv4_range: Some("198.19.0.0/16".into()),
                ..options.clone()
            },
            FakeIpOptions {
                ipv6_range: Some("fd01::/64".into()),
                ..options.clone()
            },
            FakeIpOptions {
                ipv6_range: None,
                ..options.clone()
            },
            FakeIpOptions {
                max_entries: 32,
                ..options.clone()
            },
        ] {
            let mut candidate = groups.clone();
            candidate[0].fake_ip = Some(incompatible);
            let error = build_dns_registry_reusing(candidate, next.limits, Some(&next))
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("explicit restart required"));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn equivalent_snapshot_parent_paths_reuse_the_open_store_on_reload() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        let alias = directory.path().join("alias");
        std::fs::create_dir(&parent).unwrap();
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        let path = parent.join("state.json");
        let mut groups = fake_groups(true);
        groups[0].specs = vec![make_spec("udp://127.0.0.1:9")];
        groups[0].fake_ip.as_mut().unwrap().state_file = Some(path.clone());
        let initial = build_dns_registry(groups.clone()).await.unwrap();
        let context = initial
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let ip = context.allocate("stable.test", false).unwrap();
        groups[0].fake_ip.as_mut().unwrap().state_file = Some(alias.join("state.json"));
        let next = build_dns_registry_reusing(groups.clone(), initial.limits, Some(&initial))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &initial.pools["fake"].pool,
            &next.pools["fake"].pool
        ));

        let file_alias = parent.join("alias.json");
        std::os::unix::fs::symlink(&path, &file_alias).unwrap();
        for state_file in [None, Some(parent.join("different.json")), Some(file_alias)] {
            let mut candidate = groups.clone();
            candidate[0].fake_ip.as_mut().unwrap().state_file = state_file;
            let error = build_dns_registry_reusing(candidate, next.limits, Some(&next))
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("explicit restart required"));
        }

        let other = directory.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&other, &alias).unwrap();
        assert!(
            build_dns_registry_reusing(groups, next.limits, Some(&next))
                .await
                .is_err()
        );
        assert_eq!(context.restore(ip).unwrap().as_deref(), Some("stable.test"));
        next.checkpoint().await.unwrap();
        assert!(path.is_file());
        assert!(!other.join("state.json").exists());
    }

    #[tokio::test]
    async fn named_fake_dns_fallback_uses_configured_exchange_and_refresh_wrapper() {
        use hickory_resolver::proto::op::{Message, Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut groups = fake_groups(true);
        groups[0].specs = vec![make_spec(&format!(
            "udp://{}",
            socket.local_addr().unwrap()
        ))];
        let registry = build_dns_registry(groups).await.unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut answer = Message::from_vec(&bytes[..len]).unwrap().into_response();
            assert_eq!(answer.queries[0].query_type, RecordType::MX);
            answer.metadata.response_code = ResponseCode::NXDomain;
            socket
                .send_to(&answer.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let context = registry
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("mail.test").unwrap(),
            RecordType::MX,
        ));
        let reply = context
            .exchange(request.to_vec().unwrap(), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&reply).unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn heterogeneous_group_retries_truncated_udp_over_configured_tcp() {
        use hickory_resolver::proto::op::{Message, Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let mut address = tcp.local_addr().unwrap();
        address.set_ip("127.0.0.1".parse().unwrap());
        let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
        let mut groups = fake_groups(true);
        let mut tcp_spec = make_spec(&format!("tcp://{address}"));
        tcp_spec.attempts = 2;
        groups[0].specs = vec![make_spec(&format!("udp://{address}")), tcp_spec];
        let registry = build_dns_registry(groups).await.unwrap();
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let mut answer = Message::from_vec(&bytes[..length]).unwrap().into_response();
            answer.metadata.truncation = true;
            udp.send_to(&answer.to_vec().unwrap(), peer).await.unwrap();

            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            let mut answer = Message::from_vec(&bytes).unwrap().into_response();
            answer.metadata.response_code = ResponseCode::NXDomain;
            let bytes = answer.to_vec().unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }));
        let context = registry
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("mail.test").unwrap(),
            RecordType::MX,
        ));
        let bytes = context
            .exchange(request.to_vec().unwrap(), true)
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert!(!response.metadata.truncation);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dns_bootstrap_uses_live_quic_admission_before_activation() {
        if std::env::var_os("SHOES_DNS_ADMISSION_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dns::builder::tests::dns_bootstrap_uses_live_quic_admission_before_activation",
                ])
                .env("SHOES_DNS_ADMISSION_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = blackhole.local_addr().unwrap();
        let live = GlobalLimits {
            quic_memory_bytes: Some(1),
            ..Default::default()
        };
        let candidate = GlobalLimits {
            quic_memory_bytes: Some(64 << 20),
            ..live
        };
        crate::resources::configure(live).unwrap();
        for server in [
            format!("url: h3://{address}/dns-query"),
            format!(
                "url: tcp://127.0.0.1\n      client_chain:\n        address: '{address}'\n        transport: quic\n        protocol: {{type: socks}}"
            ),
        ] {
            let config = format!(
                "- dns_group: bootstrap\n  dns_servers:\n    - {server}\n      timeout_secs: 1\n      attempts: 1\n- dns_group: candidate\n  dns_servers:\n    - url: https://candidate.test/dns-query\n      bootstrap_url: bootstrap\n"
            );
            let validated =
                crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap())
                    .unwrap();
            let rejected = crate::resources::snapshot().quic_buffer_bytes.rejected;
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    build_dns_registry_with_limits(validated.dns_groups, candidate)
                )
                .await
                .unwrap()
                .is_err()
            );
            assert!(crate::resources::snapshot().quic_buffer_bytes.rejected > rejected);
            assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
            assert_eq!(
                crate::resources::limits().quic_memory_bytes,
                live.quic_memory_bytes
            );
            assert!(blackhole.try_recv(&mut [0; 1500]).is_err());
        }
    }

    #[tokio::test]
    async fn prepared_dns_chains_use_candidate_quic_windows() {
        if std::env::var_os("SHOES_DNS_CANDIDATE_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dns::builder::tests::prepared_dns_chains_use_candidate_quic_windows",
                ])
                .env("SHOES_DNS_CANDIDATE_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = format!(
            "- dns_group: candidate\n  dns_servers:\n    - url: tcp://127.0.0.1\n      client_chain:\n        address: '{}'\n        transport: quic\n        protocol: {{type: socks}}\n",
            blackhole.local_addr().unwrap()
        );
        crate::resources::configure(GlobalLimits {
            quic_memory_bytes: Some(1 << 20),
            ..Default::default()
        })
        .unwrap();
        for window in [65536, 131072] {
            let previous = crate::resources::limits();
            let candidate = GlobalLimits {
                quic_receive_window: window,
                quic_send_window: window,
                quic_stream_window: 16384,
                ..previous
            };
            let configs =
                crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap())
                    .unwrap();
            let registry = build_dns_registry_with_limits(configs.dns_groups, candidate)
                .await
                .unwrap();
            assert_eq!(
                crate::resources::limits().quic_receive_window,
                previous.quic_receive_window
            );
            let resolver = registry.get_by_name("candidate").unwrap();
            {
                let target =
                    crate::address::NetLocation::from_str("candidate.test:80", None).unwrap();
                let lookup = resolver.resolve_location(&target);
                tokio::pin!(lookup);
                let mut packet = [0; 1500];
                tokio::select! {
                    result = &mut lookup => panic!("lookup completed before QUIC packet: {result:?}"),
                    result = tokio::time::timeout(std::time::Duration::from_secs(2), blackhole.recv(&mut packet)) => { result.unwrap().unwrap(); }
                }
                assert_eq!(
                    crate::resources::snapshot().quic_buffer_bytes.active,
                    window * 2 + (512 << 10)
                );
            }
            drop((resolver, registry));
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while crate::resources::snapshot().quic_buffer_bytes.active != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            crate::resources::configure(candidate).unwrap();
            while blackhole.try_recv(&mut [0; 1500]).is_ok() {}
        }
    }

    #[test]
    fn test_compatible_servers_are_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "compatible entries should be pooled into one HickoryResolver, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "compatible entries should NOT produce CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.timeout_secs = 10;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible timeouts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_attempts_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.attempts = 1;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.attempts = 3;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible attempts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_ip_strategy_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.ip_strategy = IpStrategy::Ipv4Only;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.ip_strategy = IpStrategy::Ipv6Only;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible ip_strategy should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_chain_groups_prevent_pooling() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain_a = Arc::new(build_direct_chain_group(resolver.clone()));
        let chain_b = Arc::new(build_direct_chain_group(resolver.clone()));

        let entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain_a,
            &resolver,
        );
        let entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain_b,
            &resolver,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different chain groups should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_bootstrap_resolvers_prevent_pooling() {
        let (chain, _) = shared_test_deps();
        let bootstrap_a: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let bootstrap_b: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        let entry_a = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_a,
            IpStrategy::default(),
            5,
            5,
            1,
        );
        let entry_b = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_b,
            IpStrategy::default(),
            5,
            5,
            1,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different bootstrap resolvers should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_system_resolver_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(ParsedDnsServer::System, &chain, &bootstrap),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            !debug.contains("pool["),
            "system resolver entry should prevent pooling, got: {}",
            debug
        );
    }

    #[test]
    fn test_single_entry_not_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        )];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        // Single entry should not go through pooling (no benefit).
        assert!(
            !debug.contains("pool["),
            "single entry should not be pooled, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "single entry should not be composited, got: {}",
            debug
        );
    }

    #[test]
    fn test_three_compatible_servers_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Tcp {
                    addr: "1.1.1.1:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "three compatible entries should be pooled, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_connect_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.connect_timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.connect_timeout_secs = 2;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible connect_timeout should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_pools_equivalent_specs_with_distinct_runtime_objects() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let spec_b = make_spec("udp://8.8.4.4");

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry).await.unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry).await.unwrap();
        let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "equivalent specs should pool through the refresh builder path, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "equivalent specs should not de-pool into CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_falls_back_for_incompatible_specs() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let mut spec_b = make_spec("udp://8.8.4.4");
        spec_b.attempts = 3;

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry).await.unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry).await.unwrap();
        let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible specs should fall back to CompositeResolver, got: {}",
            debug
        );
    }
}
