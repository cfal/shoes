//! DNS resolver builder and registry.

use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use rustc_hash::FxHashMap;

use super::fake_ip::{FakeDnsContext, FakeDnsResolver, FakeIpOptions, FakeIpPool};
use super::real_only;
use super::system::SystemResolver;
use crate::config::{DnsConfig, ExpandedDnsGroup, ExpandedDnsSpec, GlobalLimits};
use crate::control::selection::ManualSelectorPath;
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
                    if entry.native_cache_secs == 0 {
                        Arc::new(NativeResolver::new())
                    } else {
                        Arc::new(CachingNativeResolver::with_timeout(
                            entry.native_cache_secs.into(),
                        ))
                    },
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

    let mut bootstraps = FxHashMap::default();
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
            build_resolver_from_specs(&group.specs, &registry, &group.name, &mut bootstraps).await?
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

#[derive(Debug)]
struct SelectionDependentResolver {
    inner: Arc<dyn Resolver>,
    paths: Vec<ManualSelectorPath>,
}

impl Resolver for SelectionDependentResolver {
    fn manual_selector_paths(&self) -> Vec<ManualSelectorPath> {
        self.paths.clone()
    }

    fn resolve_location(
        &self,
        location: &crate::address::NetLocation,
    ) -> crate::resolver::ResolveFuture {
        self.inner.resolve_location(location)
    }

    fn exchange(&self, request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
        self.inner.exchange(request)
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> crate::resolver::DnsExchangeFuture {
        self.inner.exchange_with_deadline(request, deadline)
    }
}

fn collect_selector_paths(
    chain: &crate::config::ClientChain,
    enclosing: &[(String, String)],
    paths: &mut Vec<ManualSelectorPath>,
) {
    use crate::config::{ClientChainHop, ClientProxyConfig, ConfigSelection};
    for hop in chain.hops.iter() {
        let selections: Box<dyn Iterator<Item = &ConfigSelection<crate::config::ClientConfig>>> =
            match hop {
                ClientChainHop::Single(selection) => Box::new(std::iter::once(selection)),
                ClientChainHop::Pool(pool) => pool.iter(),
            };
        for selection in selections {
            let ConfigSelection::Config(client) = selection else {
                continue;
            };
            let mut path = enclosing.to_vec();
            if let Some(origin) = &client.control {
                path.extend(origin.manual_selector_path());
            }
            if !path.is_empty() {
                paths.push(path.clone());
            }
            if let ClientProxyConfig::Wireguard(config) = &client.protocol
                && let Some(carrier) = &config.peer_client_chain
            {
                collect_selector_paths(carrier, &path, paths);
            }
        }
    }
}

/// Build a resolver from expanded DNS specs, wrapping hickory-backed groups
/// in RefreshingResolver for stale connection mitigation.
async fn build_resolver_from_specs(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
    group_name: &str,
    bootstraps: &mut FxHashMap<Option<String>, Arc<dyn Resolver>>,
) -> std::io::Result<Arc<dyn Resolver>> {
    if specs.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut entries: Vec<ParsedDnsServerEntry> = Vec::with_capacity(specs.len());
    let mut plans: Vec<HickoryResolverPlan> = Vec::new();
    let mut has_system = false;
    let mut paths = Vec::new();

    for spec in specs {
        let (entry, plan) = build_entry_and_plan(spec, registry, bootstraps).await?;
        paths.extend(entry.bootstrap_resolver.manual_selector_paths());
        for chain in &spec.client_chains {
            collect_selector_paths(chain, &[], &mut paths);
        }
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
    let resolver: Arc<dyn Resolver> = if !plans.is_empty() && !has_system {
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
        Arc::new(refreshing)
    } else {
        build_resolver_with_limits(entries, registry.limits, registry.forbidden.clone())?
    };
    if paths.is_empty() {
        Ok(resolver)
    } else {
        paths.sort_unstable();
        paths.dedup();
        // Keep configuration dependencies outside refreshable transports and DNS caches.
        Ok(Arc::new(SelectionDependentResolver {
            inner: resolver,
            paths,
        }))
    }
}

/// Build a ParsedDnsServerEntry and optionally a HickoryResolverPlan from an expanded spec.
/// The plan is returned for non-system resolvers so they can be rebuilt on refresh.
async fn build_entry_and_plan(
    spec: &ExpandedDnsSpec,
    registry: &DnsRegistry,
    bootstraps: &mut FxHashMap<Option<String>, Arc<dyn Resolver>>,
) -> std::io::Result<(ParsedDnsServerEntry, Option<HickoryResolverPlan>)> {
    // Parse URL
    let parsed_url = ParsedDnsUrl::parse_with_server_name(&spec.url, spec.server_name.as_deref())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // One resolver identity per bootstrap policy lets equivalent DNS paths share checks.
    let bootstrap_resolver = if let Some(resolver) = spec
        .bootstrap_url
        .as_deref()
        .and_then(|name| registry.get_by_name(name))
    {
        resolver
    } else if let Some(resolver) = bootstraps.get(&spec.bootstrap_url) {
        resolver.clone()
    } else {
        let resolver = match &spec.bootstrap_url {
            Some(bootstrap_url) => {
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
            None => real_only(Arc::new(NativeResolver::new()), registry.forbidden.clone()),
        };
        bootstraps.insert(spec.bootstrap_url.clone(), resolver.clone());
        resolver
    };

    // Construction-time health checks and forwarding must use the same DNS policy.
    let chain_group = if spec.client_chains.is_empty() {
        Arc::new(build_direct_chain_group(bootstrap_resolver.clone()))
    } else {
        let chains = if spec.client_chains.len() == 1 {
            NoneOrSome::One(spec.client_chains[0].clone())
        } else {
            NoneOrSome::Some(spec.client_chains.clone())
        };
        Arc::new(build_client_chain_group_with_limits(
            chains,
            bootstrap_resolver.clone(),
            registry.limits,
        )?)
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
            chain_key: serde_yaml::to_string(&(
                &spec.client_chains,
                crate::control::catalog::chain_selection_key(&spec.client_chains)?,
            ))
            .map_err(|e| {
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

    let mut entry = ParsedDnsServerEntry::new(
        server,
        chain_group,
        bootstrap_resolver,
        spec.ip_strategy,
        spec.timeout_secs,
        spec.connect_timeout_secs,
        spec.attempts,
    );
    entry.native_cache_secs = spec.native_cache_secs;

    Ok((entry, plan))
}

#[cfg(test)]
mod tests;
