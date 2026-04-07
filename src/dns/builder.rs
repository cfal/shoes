//! DNS resolver builder and registry.

use std::sync::Arc;
use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::config::{DnsConfig, ExpandedDnsGroup, ExpandedDnsSpec};
use crate::dns::composite_resolver::CompositeResolver;
use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::dns::parsed::{ParsedDnsServer, ParsedDnsServerEntry, ParsedDnsUrl};
use crate::option_util::NoneOrSome;
use crate::resolver::{
    CachingNativeResolver, NativeResolver, RefreshPolicy, RefreshingResolver, Resolver,
    ResolverFactory, TimeoutResolver,
};
use crate::tcp::chain_builder::{build_client_chain_group, build_direct_chain_group};

/// Registry of resolved DNS groups with lazy default resolver.
pub struct DnsRegistry {
    groups: FxHashMap<String, Arc<dyn Resolver>>,
    /// Default resolver, created lazily only if needed.
    default_resolver: Option<Arc<dyn Resolver>>,
}

impl DnsRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            groups: FxHashMap::default(),
            default_resolver: None,
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

    /// Get or create the default resolver (CachingNativeResolver).
    /// Used when a server has no `dns` field configured.
    pub fn get_or_create_default(&mut self) -> Arc<dyn Resolver> {
        self.default_resolver
            .get_or_insert_with(|| Arc::new(CachingNativeResolver::new()))
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
    options: HickoryResolverOptions,
    description: String,
}

impl HickoryResolverPlan {
    /// Build a fresh resolver, re-resolving hostname upstreams if needed.
    async fn build(&self) -> std::io::Result<Arc<dyn Resolver>> {
        let resolved_ip = match self.parsed_url.hostname() {
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
                Some(addrs[0].ip())
            }
            None => None,
        };

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
        ParsedDnsServer::Tls { addr, server_name } => {
            Arc::new(HickoryResolver::tls(addr, server_name, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::https(
            addr, server_name, path, chain, bootstrap, options,
        )?),
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::h3(
            addr, server_name, path, chain, bootstrap, options,
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
pub fn build_resolver(entries: Vec<ParsedDnsServerEntry>) -> std::io::Result<Arc<dyn Resolver>> {
    if entries.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    // Try to pool all hickory-backed entries into one resolver.
    if let Some(pooled) = try_build_hickory_pool(&entries)? {
        return Ok(pooled);
    }

    // Fallback: build individual resolvers and composite them.
    let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let timeout_secs = entry.timeout_secs;

        let options = HickoryResolverOptions {
            ip_strategy: entry.ip_strategy,
            request_timeout: (timeout_secs > 0)
                .then(|| Duration::from_secs(timeout_secs as u64)),
            connect_timeout: Duration::from_secs(entry.connect_timeout_secs as u64),
            attempts: entry.attempts,
        };

        let resolver: Arc<dyn Resolver> = match entry.server {
            ParsedDnsServer::System => wrap_resolver(NativeResolver::new(), timeout_secs),
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
/// Returns None if entries contain system resolvers or are otherwise
/// incompatible for pooling (mixed chain groups).
fn try_build_hickory_pool(
    entries: &[ParsedDnsServerEntry],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if entries.is_empty() || entries.len() < 2 {
        return Ok(None);
    }

    // All entries must be hickory-backed (no system resolvers).
    let mut ns_pairs = Vec::with_capacity(entries.len());
    for entry in entries {
        match server_to_ns_config(&entry.server) {
            Some(pair) => ns_pairs.push(pair),
            None => return Ok(None),
        }
    }

    // Use the first entry's settings for the pooled resolver.
    let first = &entries[0];
    let timeout_secs = first.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: first.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(first.connect_timeout_secs as u64),
        attempts: first.attempts,
    };

    let descriptions: Vec<String> = entries
        .iter()
        .map(|e| format!("{:?}", e.server))
        .collect();
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
pub async fn build_dns_registry(groups: Vec<ExpandedDnsGroup>) -> std::io::Result<DnsRegistry> {
    let mut registry = DnsRegistry::new();

    for group in groups {
        let resolver = build_resolver_from_specs(&group.specs, &registry, &group.name).await?;
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

    let resolver = build_resolver(entries)?;

    // Wrap in RefreshingResolver only if we have hickory-backed resolvers
    // and no system resolver (mixed groups stay as-is for simplicity).
    if !plans.is_empty() && !has_system {
        let description = group_name.to_string();
        let plans = plans.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let plans = plans.clone();
            Box::pin(async move {
                let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(plans.len());
                for plan in &plans {
                    resolvers.push(plan.build().await?);
                }
                if resolvers.len() == 1 {
                    Ok(resolvers.pop().unwrap())
                } else {
                    Ok(Arc::new(CompositeResolver::new(resolvers)) as Arc<dyn Resolver>)
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let refreshing =
            RefreshingResolver::new(factory, policy, description).await?;
        Ok(Arc::new(refreshing))
    } else {
        Ok(resolver)
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
    let chain_resolver = Arc::new(NativeResolver::new());
    let chain_group = if spec.client_chains.is_empty() {
        Arc::new(build_direct_chain_group(chain_resolver))
    } else {
        let chains = if spec.client_chains.len() == 1 {
            NoneOrSome::One(spec.client_chains[0].clone())
        } else {
            NoneOrSome::Some(spec.client_chains.clone())
        };
        Arc::new(build_client_chain_group(chains, chain_resolver))
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

                let native = Arc::new(NativeResolver::new());
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
                build_resolver(vec![bootstrap_entry])?
            }
        }
        None => Arc::new(NativeResolver::new()),
    };

    let timeout_secs = spec.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: spec.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(spec.connect_timeout_secs as u64),
        attempts: spec.attempts,
    };

    // Build plan for hickory-backed resolvers (not system)
    let plan = if !matches!(parsed_url, ParsedDnsUrl::System) {
        Some(HickoryResolverPlan {
            parsed_url: parsed_url.clone(),
            chain_group: chain_group.clone(),
            bootstrap_resolver: bootstrap_resolver.clone(),
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
