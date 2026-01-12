//! DNS resolver builder and registry.

use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::config::{DnsConfig, ExpandedDnsGroup, ExpandedDnsSpec};
use crate::dns::composite_resolver::CompositeResolver;
use crate::dns::hickory_resolver::HickoryResolver;
use crate::dns::parsed::{ParsedDnsServer, ParsedDnsServerEntry, ParsedDnsUrl};
use crate::option_util::NoneOrSome;
use crate::resolver::{CachingNativeResolver, NativeResolver, Resolver};
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

/// Build a resolver from parsed DNS server entries.
pub fn build_resolver(entries: Vec<ParsedDnsServerEntry>) -> std::io::Result<Arc<dyn Resolver>> {
    if entries.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let bootstrap = entry.bootstrap_resolver;
        let chain = entry.client_chain;
        let ip_strategy = entry.ip_strategy;

        let resolver: Arc<dyn Resolver> = match entry.server {
            // System resolver uses NativeResolver (ignores chain_group, bootstrap, ip_strategy)
            ParsedDnsServer::System => Arc::new(NativeResolver::new()),
            // All other protocols use HickoryResolver with chain_group, bootstrap, and ip_strategy
            ParsedDnsServer::Udp { addr } => {
                Arc::new(HickoryResolver::udp(addr, chain, bootstrap, ip_strategy)?)
            }
            ParsedDnsServer::Tcp { addr } => {
                Arc::new(HickoryResolver::tcp(addr, chain, bootstrap, ip_strategy)?)
            }
            ParsedDnsServer::Tls { addr, server_name } => {
                Arc::new(HickoryResolver::tls(addr, server_name, chain, bootstrap, ip_strategy)?)
            }
            ParsedDnsServer::Https {
                addr,
                server_name,
                path,
            } => Arc::new(HickoryResolver::https(addr, server_name, path, chain, bootstrap, ip_strategy)?),
            ParsedDnsServer::H3 {
                addr,
                server_name,
                path,
            } => Arc::new(HickoryResolver::h3(addr, server_name, path, chain, bootstrap, ip_strategy)?),
        };
        resolvers.push(resolver);
    }

    // If single resolver, return it directly; otherwise wrap in CompositeResolver
    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
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
        let resolver = build_resolver_from_specs(&group.specs, &registry).await?;
        registry.register(group.name, resolver);
    }

    Ok(registry)
}

/// Build a resolver from expanded DNS specs.
async fn build_resolver_from_specs(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
) -> std::io::Result<Arc<dyn Resolver>> {
    if specs.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut entries: Vec<ParsedDnsServerEntry> = Vec::with_capacity(specs.len());

    for spec in specs {
        let entry = build_entry_from_spec(spec, registry).await?;
        entries.push(entry);
    }

    build_resolver(entries)
}

/// Build a ParsedDnsServerEntry from an expanded spec.
async fn build_entry_from_spec(
    spec: &ExpandedDnsSpec,
    registry: &DnsRegistry,
) -> std::io::Result<ParsedDnsServerEntry> {
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
                let bootstrap_parsed = ParsedDnsUrl::parse(bootstrap_url)
                    .map_err(|e| std::io::Error::other(format!(
                        "invalid bootstrap_url '{}': {}", bootstrap_url, e
                    )))?;

                let bootstrap_server = bootstrap_parsed
                    .to_parsed_server(None)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                let native = Arc::new(NativeResolver::new());
                let direct_chain = Arc::new(build_direct_chain_group(native.clone()));
                let bootstrap_entry = ParsedDnsServerEntry::new(
                    bootstrap_server,
                    direct_chain,
                    native,
                    super::IpStrategy::default(),
                );
                build_resolver(vec![bootstrap_entry])?
            }
        }
        None => Arc::new(NativeResolver::new()),
    };

    // Resolve hostname if URL contains one
    let resolved_ip = match parsed_url.hostname() {
        Some(hostname) => {
            let location = crate::address::NetLocation::new(
                crate::address::Address::Hostname(hostname.to_string().into()),
                0,
            );

            let addrs = bootstrap_resolver
                .resolve_location(&location)
                .await
                .map_err(|e| std::io::Error::other(format!(
                    "failed to resolve DNS server hostname '{}': {}", hostname, e
                )))?;

            Some(addrs[0].ip())
        }
        None => None,
    };

    // Convert to ParsedDnsServer with resolved IP
    let server = parsed_url
        .to_parsed_server(resolved_ip)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(ParsedDnsServerEntry::new(server, chain_group, bootstrap_resolver, spec.ip_strategy))
}
