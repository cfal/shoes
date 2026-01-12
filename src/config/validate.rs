//! Configuration validation - validates configs and creates final ServerConfigs.

use std::collections::{HashMap, HashSet};

use crate::address::NetLocationMask;
use crate::dns::ParsedDnsUrl;
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::reality::{decode_private_key, decode_short_id};
use crate::thread_util::get_num_threads;
use crate::uuid_util::parse_uuid;

use super::pem::{embed_optional_pem_from_map, embed_pem_from_map};
use super::types::{
    ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection,
    DEFAULT_REALITY_SHORT_ID, DnsConfig, DnsConfigGroup, DnsServerSpec, ExpandedDnsGroup,
    ExpandedDnsSpec, PemSource, RuleActionConfig, RuleConfig, ServerConfig, ServerProxyConfig,
    ServerQuicConfig, ShadowTlsServerConfig, ShadowTlsServerHandshakeConfig, ShadowsocksConfig,
    TlsServerConfig, Transport, TunConfig, WebsocketServerConfig, direct_allow_rule,
};

const MIN_TLS_BUFFER_SIZE: usize = 16 * 1024;

/// Result of config validation containing server configs and expanded DNS groups.
/// DNS resolvers are built at runtime from the expanded groups.
pub struct ValidatedConfigs {
    pub configs: Vec<Config>,
    /// Expanded DNS groups in topological order (bootstrap deps first).
    pub dns_groups: Vec<ExpandedDnsGroup>,
}

/// Validates configs and returns startable server configs with expanded DNS groups.
///
/// This function:
/// - Builds client_groups and rule_groups from ClientConfigGroup and RuleConfigGroup entries
/// - Resolves group references using topological sort
/// - Collects named PEMs
/// - Expands DNS groups (composition, client chains) and validates them
/// - Validates all ServerConfigs and TunConfigs against the groups and PEMs
/// - Returns ValidatedConfigs containing configs and expanded DNS groups
pub fn create_server_configs(all_configs: Vec<Config>) -> std::io::Result<ValidatedConfigs> {
    // First pass: collect raw groups with unresolved references
    let mut raw_client_groups: HashMap<String, OneOrSome<ConfigSelection<ClientConfig>>> =
        HashMap::new();
    raw_client_groups.insert(
        String::from("direct"),
        OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
    );

    let mut rule_groups: HashMap<String, Vec<RuleConfig>> = HashMap::new();
    rule_groups.insert(
        String::from("allow-all-direct"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_chains: NoneOrSome::One(ClientChain::default()),
            },
        }],
    );
    rule_groups.insert(
        String::from("block-all"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Block,
        }],
    );

    let mut server_configs: Vec<ServerConfig> = vec![];
    let mut tun_configs: Vec<TunConfig> = vec![];
    let mut named_pems: HashMap<String, String> = HashMap::new();
    let mut dns_groups: HashMap<String, DnsConfigGroup> = HashMap::new();

    for config in all_configs.into_iter() {
        match config {
            Config::ClientConfigGroup(group) => {
                if raw_client_groups
                    .insert(group.client_group.clone(), group.client_proxies)
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("client group already exists: {}", group.client_group),
                    ));
                }
            }
            Config::RuleConfigGroup(group) => {
                if rule_groups
                    .insert(group.rule_group.clone(), group.rules.into_vec())
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("rule group already exists: {}", group.rule_group),
                    ));
                }
            }
            Config::Server(server_config) => {
                server_configs.push(server_config);
            }
            Config::TunServer(tun_config) => {
                tun_configs.push(tun_config);
            }
            Config::NamedPem(pem) => {
                let pem_data = match pem.source {
                    PemSource::Data(data) => data,
                    PemSource::Path(_) => {
                        panic!("named pem path should have been converted to data");
                    }
                };

                if named_pems.insert(pem.pem.clone(), pem_data).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("named pem already exists: {}", pem.pem),
                    ));
                }
            }
            Config::DnsConfigGroup(group) => {
                let group_name = group.dns_group.clone();
                if dns_groups.insert(group_name.clone(), group).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("dns group already exists: {}", group_name),
                    ));
                }
            }
        }
    }

    // Resolve client groups using topological sort
    let mut client_groups = resolve_client_groups_topologically(raw_client_groups)?;

    // Embed PEMs into all client configs in groups before they're used
    for configs in client_groups.values_mut() {
        for config in configs.iter_mut() {
            validate_client_config(config, &named_pems)?;
        }
    }

    // Extract inline DNS configs from server/tun configs into dns_groups.
    // This replaces inline specs with group name references.
    let mut inline_dns_counter = 0u32;
    for config in server_configs.iter_mut() {
        extract_inline_dns(&mut config.dns, &mut dns_groups, &mut inline_dns_counter)?;
    }
    for config in tun_configs.iter_mut() {
        extract_inline_dns(&mut config.dns, &mut dns_groups, &mut inline_dns_counter)?;
    }

    // Expand DNS group composition references for ALL groups (named + inline).
    let expanded_dns_groups = expand_dns_groups_composition(dns_groups)?;

    // Topological sort by bootstrap dependencies and detect errors
    // This is necessary if we have a DNS group A with bootstrap set to DNS group B, we need
    // to know to build DNS group B first.
    let dns_group_order = topological_sort_dns_groups_by_bootstrap(&expanded_dns_groups)?;

    // Expand and validate DNS specs (client chains, protocol compatibility).
    let mut final_dns_groups: Vec<ExpandedDnsGroup> = Vec::new();
    let group_names: HashSet<&str> = expanded_dns_groups.keys().map(|s| s.as_str()).collect();

    for name in dns_group_order {
        let specs = expanded_dns_groups.get(&name).unwrap();
        let expanded_specs = expand_dns_specs(specs, &client_groups, &named_pems, &group_names)?;
        final_dns_groups.push(ExpandedDnsGroup {
            name,
            specs: expanded_specs,
        });
    }

    // Validate server configs (DNS is now just a group reference).
    for config in server_configs.iter_mut() {
        validate_server_config(config, &client_groups, &rule_groups, &named_pems)?;
        validate_dns_group_ref(&config.dns, &group_names)?;
    }

    // Validate TUN configs.
    for config in tun_configs.iter_mut() {
        validate_tun_config(config, &client_groups, &rule_groups)?;
        validate_dns_group_ref(&config.dns, &group_names)?;
    }

    // Combine into Config list (only Server and TunServer variants)
    let mut result: Vec<Config> = server_configs.into_iter().map(Config::Server).collect();
    result.extend(tun_configs.into_iter().map(Config::TunServer));

    Ok(ValidatedConfigs {
        configs: result,
        dns_groups: final_dns_groups,
    })
}

/// Resolves client group references using topological sort.
///
/// Groups can reference other groups, forming a dependency graph.
/// This function:
/// 1. Builds the dependency graph
/// 2. Detects cycles
/// 3. Resolves groups in topological order
fn resolve_client_groups_topologically(
    raw_groups: HashMap<String, OneOrSome<ConfigSelection<ClientConfig>>>,
) -> std::io::Result<HashMap<String, Vec<ClientConfig>>> {
    // Build dependency graph: for each group, collect which groups it references
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
    for (group_name, selections) in &raw_groups {
        let mut deps = vec![];
        for selection in selections.iter() {
            if let ConfigSelection::GroupName(ref_name) = selection {
                deps.push(ref_name.clone());
            }
        }
        dependencies.insert(group_name.clone(), deps);
    }

    // Check for unknown group references
    for (group_name, deps) in &dependencies {
        for dep in deps {
            if !raw_groups.contains_key(dep) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Client group '{}' references unknown group '{}'",
                        group_name, dep
                    ),
                ));
            }
        }
    }

    // Topological sort using Kahn's algorithm with cycle detection
    let sorted_groups = topological_sort(&dependencies)?;

    // Resolve groups in topological order
    let mut resolved: HashMap<String, Vec<ClientConfig>> = HashMap::new();
    for group_name in sorted_groups {
        let selections = raw_groups.get(&group_name).unwrap();
        let mut expanded_configs = vec![];

        for selection in selections.iter() {
            match selection {
                ConfigSelection::Config(config) => {
                    expanded_configs.push(config.clone());
                }
                ConfigSelection::GroupName(ref_name) => {
                    // This group should already be resolved (due to topological order)
                    let referenced_configs = resolved.get(ref_name).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "Internal error: group '{}' not resolved before '{}'",
                                ref_name, group_name
                            ),
                        )
                    })?;
                    expanded_configs.extend(referenced_configs.clone());
                }
            }
        }

        resolved.insert(group_name, expanded_configs);
    }

    Ok(resolved)
}

/// Performs topological sort on a dependency graph using Kahn's algorithm.
/// Returns groups in order such that dependencies come before dependents.
/// Returns an error if a cycle is detected.
fn topological_sort(dependencies: &HashMap<String, Vec<String>>) -> std::io::Result<Vec<String>> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

    // Initialize in-degree for all nodes
    for group_name in dependencies.keys() {
        in_degree.entry(group_name.clone()).or_insert(0);
        reverse_deps.entry(group_name.clone()).or_default();
    }

    // Build in-degree counts and reverse dependency map
    for (group_name, deps) in dependencies {
        for dep in deps {
            *in_degree.entry(group_name.clone()).or_insert(0) += 1;
            reverse_deps
                .entry(dep.clone())
                .or_default()
                .push(group_name.clone());
        }
    }

    // Find all nodes with in-degree 0 (no dependencies)
    let mut queue: Vec<String> = in_degree
        .iter()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(name, _)| name.clone())
        .collect();

    let mut result = vec![];

    while let Some(node) = queue.pop() {
        result.push(node.clone());

        // Reduce in-degree for all nodes that depend on this one
        if let Some(dependents) = reverse_deps.get(&node) {
            for dependent in dependents {
                if let Some(deg) = in_degree.get_mut(dependent) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(dependent.clone());
                    }
                }
            }
        }
    }

    // If we haven't processed all nodes, there's a cycle
    if result.len() != dependencies.len() {
        // Find the cycle for a better error message
        let processed: HashSet<_> = result.iter().collect();
        let in_cycle: Vec<_> = dependencies
            .keys()
            .filter(|k| !processed.contains(k))
            .cloned()
            .collect();

        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Circular dependency detected in client groups: {}",
                in_cycle.join(", ")
            ),
        ));
    }

    Ok(result)
}

/// Phase 1: Expand DNS group composition references.
/// Returns a map of group name to flat list of server specs (no group references).
fn expand_dns_groups_composition(
    dns_groups: HashMap<String, DnsConfigGroup>,
) -> std::io::Result<HashMap<String, Vec<DnsServerSpec>>> {
    // Build composition dependency graph and validate references
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();

    for (group_name, group) in &dns_groups {
        let deps: Vec<String> = group
            .dns_servers
            .iter()
            .filter_map(|spec| {
                spec.as_group_ref().map(|ref_name| {
                    if !dns_groups.contains_key(ref_name) {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "DNS group '{}' references unknown group '{}'",
                                group_name, ref_name
                            ),
                        ))
                    } else {
                        Ok(ref_name.to_string())
                    }
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        dependencies.insert(group_name.clone(), deps);
    }

    // Topological sort by composition dependencies
    let order = topological_sort(&dependencies).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string()
                .replace("client groups", "DNS groups (composition)"),
        )
    })?;

    // Expand in topological order
    let mut expanded: HashMap<String, Vec<DnsServerSpec>> = HashMap::new();

    for name in order {
        let group = dns_groups.get(&name).unwrap();
        let specs: Vec<DnsServerSpec> = group
            .dns_servers
            .iter()
            .flat_map(|spec| match spec.as_group_ref() {
                Some(ref_name) => expanded.get(ref_name).unwrap().clone(),
                None => vec![spec.clone()],
            })
            .collect();
        expanded.insert(name, specs);
    }

    Ok(expanded)
}

/// Phase 2: Topological sort on expanded DNS groups based on bootstrap_url dependencies.
/// Returns groups in order such that bootstrap dependencies come before dependents.
fn topological_sort_dns_groups_by_bootstrap(
    expanded_groups: &HashMap<String, Vec<DnsServerSpec>>,
) -> std::io::Result<Vec<String>> {
    // Build dependency graph: for each group, collect which groups it references via bootstrap_url
    let dependencies: HashMap<String, Vec<String>> = expanded_groups
        .iter()
        .map(|(group_name, specs)| {
            let deps: Vec<String> = specs
                .iter()
                .filter_map(|spec| spec.bootstrap_url())
                .filter(|url| expanded_groups.contains_key(*url))
                .map(String::from)
                .collect();
            (group_name.clone(), deps)
        })
        .collect();

    topological_sort(&dependencies).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string()
                .replace("client groups", "DNS groups (bootstrap)"),
        )
    })
}

/// Extracts inline DNS specs from a config into dns_groups with a generated name.
/// Replaces config.dns.servers with a single group name reference.
/// If servers is already a single group reference or empty, does nothing.
fn extract_inline_dns(
    dns: &mut Option<DnsConfig>,
    dns_groups: &mut HashMap<String, DnsConfigGroup>,
    counter: &mut u32,
) -> std::io::Result<()> {
    let Some(config) = dns else {
        return Ok(());
    };

    // Empty means use default resolver - nothing to extract
    if config.servers.is_empty() {
        return Ok(());
    }

    // Already a single group reference - nothing to extract
    if let NoneOrSome::One(spec) = &config.servers {
        if spec.as_group_ref().is_some() {
            return Ok(());
        }
    }

    // Generate unique name and extract specs into a new group
    let generated_name = format!("__inline_dns_{}", *counter);
    *counter += 1;

    let group = DnsConfigGroup {
        dns_group: generated_name.clone(),
        dns_servers: std::mem::replace(&mut config.servers, NoneOrSome::Unspecified),
    };
    dns_groups.insert(generated_name.clone(), group);

    // Replace servers with the group reference
    config.servers = NoneOrSome::One(DnsServerSpec::Simple(generated_name));

    Ok(())
}

/// Validates that DNS config references an existing group.
fn validate_dns_group_ref(
    dns: &Option<DnsConfig>,
    group_names: &HashSet<&str>,
) -> std::io::Result<()> {
    let Some(config) = dns else {
        return Ok(());
    };

    // Empty means use default resolver
    if config.servers.is_empty() {
        return Ok(());
    }

    // After extraction, servers should be a single group reference
    if let NoneOrSome::One(spec) = &config.servers {
        if let Some(group_name) = spec.as_group_ref() {
            if !group_names.contains(group_name) {
                return Err(std::io::Error::other(format!(
                    "unknown dns_group in server config: '{}'",
                    group_name
                )));
            }
            return Ok(());
        }
    }

    // Should not reach here after extract_inline_dns
    Err(std::io::Error::other(
        "DNS servers should be a single group reference after extraction",
    ))
}

/// Expand and validate DNS specs.
///
/// Expands client chains (resolves group refs to configs) and validates:
/// - Inline client configs (PEMs, etc.)
/// - Protocol compatibility (system doesn't support chains, UDP/H3 only direct chains)
/// - Bootstrap URL validity (must be a known group or valid IP-only URL)
fn expand_dns_specs(
    specs: &[DnsServerSpec],
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
    dns_group_names: &HashSet<&str>,
) -> std::io::Result<Vec<ExpandedDnsSpec>> {
    let mut result = Vec::new();

    for spec in specs {
        let url_str = spec.url();
        let server_name_override = spec.server_name();

        // Parse URL to validate and check protocol
        let parsed_url = ParsedDnsUrl::parse_with_server_name(url_str, server_name_override)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Expand and validate client chains
        let client_chains_raw = spec.client_chains();
        let mut expanded_chains: Vec<ClientChain> = Vec::new();

        for chain_selection in client_chains_raw.iter() {
            let mut chain = match chain_selection {
                ConfigSelection::Config(chain) => chain.clone(),
                ConfigSelection::GroupName(name) => ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        name.clone(),
                    ))),
                },
            };
            // Validate inline client configs before expanding
            for hop in chain.hops.iter_mut() {
                validate_client_chain_hop(hop, client_groups, named_pems)?;
            }
            expand_client_chain(&mut chain.hops, client_groups)?;
            expanded_chains.push(chain);
        }

        // Validate protocol compatibility with chains
        if !expanded_chains.is_empty() {
            // System DNS never supports client_chain
            if matches!(&parsed_url, ParsedDnsUrl::System) {
                return Err(std::io::Error::other(
                    "client_chain is not supported for system DNS resolver",
                ));
            }

            // Check if all chains are direct-only (for UDP/H3 validation)
            let all_direct = expanded_chains
                .iter()
                .all(|chain| is_chain_direct_only(chain));

            if !all_direct {
                match &parsed_url {
                    ParsedDnsUrl::Udp { .. } => {
                        return Err(std::io::Error::other(
                            "UDP DNS only supports direct client_chain (for bind_interface)",
                        ));
                    }
                    ParsedDnsUrl::H3 { .. } => {
                        return Err(std::io::Error::other(
                            "H3 DNS only supports direct client_chain (for bind_interface)",
                        ));
                    }
                    _ => {}
                }
            }
        }

        // Validate bootstrap_url
        if let Some(bootstrap_url) = spec.bootstrap_url() {
            // Must be either a known group name or a valid IP-only URL
            if !dns_group_names.contains(bootstrap_url) {
                let bootstrap_parsed = ParsedDnsUrl::parse(bootstrap_url).map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid bootstrap_url '{}': {}",
                        bootstrap_url, e
                    ))
                })?;

                if bootstrap_parsed.has_hostname() {
                    return Err(std::io::Error::other(format!(
                        "bootstrap_url '{}' contains hostname - must use IP address or dns_group name",
                        bootstrap_url
                    )));
                }
            }
        }

        result.push(ExpandedDnsSpec {
            url: url_str.to_string(),
            server_name: server_name_override.map(String::from),
            client_chains: expanded_chains,
            bootstrap_url: spec.bootstrap_url().map(String::from),
            ip_strategy: spec.ip_strategy(),
        });
    }

    Ok(result)
}

/// Check if a client chain is direct-only (single hop with all direct protocol configs).
fn is_chain_direct_only(chain: &ClientChain) -> bool {
    // Must have exactly one hop (OneOrSome::One variant)
    let hop = match &chain.hops {
        OneOrSome::One(hop) => hop,
        OneOrSome::Some(_) => return false, // Multiple hops
    };

    // The single hop must be all direct configs
    match hop {
        ClientChainHop::Single(ConfigSelection::Config(config)) => config.protocol.is_direct(),
        ClientChainHop::Single(ConfigSelection::GroupName(_)) => {
            // Should not happen after expansion
            false
        }
        ClientChainHop::Pool(selections) => selections.iter().all(|sel| match sel {
            ConfigSelection::Config(config) => config.protocol.is_direct(),
            ConfigSelection::GroupName(_) => false,
        }),
    }
}

fn validate_server_config(
    server_config: &mut ServerConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    // First handle QUIC settings certificates
    if let Some(ref mut quic_settings) = server_config.quic_settings {
        embed_pem_from_map(&mut quic_settings.cert, named_pems);
        embed_pem_from_map(&mut quic_settings.key, named_pems);
        for cert in quic_settings.client_ca_certs.iter_mut() {
            embed_pem_from_map(cert, named_pems);
        }
    }
    if server_config.transport != Transport::Tcp && server_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    if server_config.transport == Transport::Quic {
        match server_config.quic_settings {
            Some(ServerQuicConfig {
                ref mut client_fingerprints,
                ref mut num_endpoints,
                ..
            }) => {
                validate_client_fingerprints(client_fingerprints)?;

                if *num_endpoints == 0 {
                    *num_endpoints = get_num_threads();
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "QUIC transport is selected but QUIC settings not specified",
                ));
            }
        }
    } else if server_config.quic_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "QUIC transport is not selected but QUIC settings specified",
        ));
    }

    if let super::types::BindLocation::Path(_) = server_config.bind_location
        && server_config.transport != Transport::Tcp
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unix domain socket support only available for TCP transport",
        ));
    }

    ConfigSelection::replace_none_or_some_groups(&mut server_config.rules, rule_groups)?;

    if server_config.rules.is_empty() {
        server_config.rules = direct_allow_rule();
    }

    for rule_config_selection in server_config.rules.iter_mut() {
        validate_rule_config(
            rule_config_selection.unwrap_config_mut(),
            client_groups,
            named_pems,
        )?;
    }

    validate_server_proxy_config(
        &mut server_config.protocol,
        client_groups,
        rule_groups,
        named_pems,
        false, // top-level, not inside TLS/Reality
    )?;

    Ok(())
}

fn validate_client_fingerprints(
    client_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !client_fingerprints.is_unspecified() && client_fingerprints.is_empty() {
        println!("WARNING: Client fingerprints provided but empty, defaulting to 'any'");
    }

    if client_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(client_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_config_util::process_fingerprints(
            &client_fingerprints.clone().into_vec(),
        )?;
    }

    Ok(())
}

/// Validates Reality private_key to ensure it's a valid base64url-encoded X25519 key.
fn validate_reality_private_key(private_key: &str, target_name: &str) -> std::io::Result<()> {
    decode_private_key(private_key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "REALITY target '{}': invalid private_key: {}",
                target_name, e
            ),
        )
    })?;

    Ok(())
}

/// Validates Reality client short_id to ensure it's a valid hexadecimal string
fn validate_reality_client_short_id(short_id: &str) -> std::io::Result<()> {
    if short_id.len() > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Reality client short_id is too long: '{}' ({} chars, max 16)",
                short_id,
                short_id.len()
            ),
        ));
    }

    if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Reality client short_id contains non-hexadecimal characters: '{}'. \
                 Only 0-9, a-f, and A-F are allowed.",
                short_id
            ),
        ));
    }

    decode_short_id(short_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Reality client short_id decode failed: {}", e),
        )
    })?;

    Ok(())
}

fn validate_reality_server_short_ids(
    short_ids: &OneOrSome<String>,
    target_name: &str,
) -> std::io::Result<()> {
    let is_default = match short_ids {
        OneOrSome::One(id) => id == DEFAULT_REALITY_SHORT_ID,
        OneOrSome::Some(ids) => ids.len() == 1 && ids[0] == DEFAULT_REALITY_SHORT_ID,
    };

    if is_default {
        log::warn!(
            "Reality server '{}' using default short_ids (all zeros). \
             For better security in production, configure explicit short_ids.",
            target_name
        );
    }

    for (i, short_id) in short_ids.iter().enumerate() {
        if short_id.len() > 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "REALITY target '{}': short_ids[{}] is too long: '{}' ({} chars, max 16)",
                    target_name,
                    i,
                    short_id,
                    short_id.len()
                ),
            ));
        }

        if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "REALITY target '{}': short_ids[{}] contains non-hexadecimal characters: '{}'. \
                     Only 0-9, a-f, and A-F are allowed.",
                    target_name, i, short_id
                ),
            ));
        }
    }

    Ok(())
}

/// Validates that Vision is only enabled when the inner protocol is VLESS (client-side)
fn validate_client_vision_protocol(
    vision_enabled: bool,
    protocol: &ClientProxyConfig,
    config_type: &str,
) -> std::io::Result<()> {
    if !vision_enabled {
        return Ok(());
    }

    match protocol {
        ClientProxyConfig::Vless { .. } => Ok(()),
        other_protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} client config has vision=true but inner protocol is {} (not VLESS). \
                 Vision (XTLS-RPRX-Vision) requires VLESS as the inner protocol. \
                 Either set vision=false or change the inner protocol to VLESS.",
                config_type,
                other_protocol.protocol_name()
            ),
        )),
    }
}

/// Recursive validation of client proxy config structure (Vision rules, etc.)
fn validate_client_proxy_structure(config: &ClientProxyConfig) -> std::io::Result<()> {
    match config {
        ClientProxyConfig::Tls(tls_config) => {
            validate_client_vision_protocol(tls_config.vision, &tls_config.protocol, "TLS")?;
            validate_client_proxy_structure(&tls_config.protocol)?;
        }
        ClientProxyConfig::Reality {
            vision, protocol, ..
        } => {
            validate_client_vision_protocol(*vision, protocol, "Reality")?;
            validate_client_proxy_structure(protocol)?;
        }
        ClientProxyConfig::ShadowTls { protocol, .. } => {
            validate_client_proxy_structure(protocol)?;
        }
        ClientProxyConfig::Websocket(ws_config) => {
            validate_client_proxy_structure(&ws_config.protocol)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_client_config(
    client_config: &mut ClientConfig,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    if client_config.transport != Transport::Tcp && client_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    if let Some(ref mut quic_config) = client_config.quic_settings {
        if client_config.transport != Transport::Quic {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC transport is not selected but QUIC settings specified",
            ));
        }

        embed_optional_pem_from_map(&mut quic_config.cert, named_pems);
        embed_optional_pem_from_map(&mut quic_config.key, named_pems);

        let super::types::ClientQuicConfig {
            cert,
            key,
            server_fingerprints,
            ..
        } = quic_config;
        if cert.is_none() != key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both client cert and key have to be specified, or both have to be omitted",
            ));
        }
        validate_server_fingerprints(server_fingerprints)?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if client_config.bind_interface.is_one() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_interface is only available on Android, Fuchsia, or Linux.",
        ));
    }

    validate_client_proxy_config(&mut client_config.protocol, named_pems)?;

    Ok(())
}

fn validate_server_fingerprints(
    server_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !server_fingerprints.is_unspecified() && server_fingerprints.is_empty() {
        println!("WARNING: Server fingerprints provided but empty, defaulting to 'any'");
    }

    if server_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(server_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_config_util::process_fingerprints(
            &server_fingerprints.clone().into_vec(),
        )?;
    }

    Ok(())
}

fn validate_client_proxy_config(
    client_proxy_config: &mut ClientProxyConfig,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    validate_client_proxy_structure(client_proxy_config)?;

    match client_proxy_config {
        ClientProxyConfig::Reality {
            short_id, protocol, ..
        } => {
            validate_reality_client_short_id(short_id)?;

            if short_id == DEFAULT_REALITY_SHORT_ID {
                log::warn!(
                    "Reality client using default short_id (all zeros). \
                     For better security in production, configure an explicit short_id that matches your server."
                );
            }

            validate_client_proxy_config(protocol, named_pems)?;
        }

        ClientProxyConfig::Tls(tls_config) => {
            embed_optional_pem_from_map(&mut tls_config.cert, named_pems);
            embed_optional_pem_from_map(&mut tls_config.key, named_pems);

            if tls_config.cert.is_none() != tls_config.key.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Both client cert and key have to be specified, or both have to be omitted",
                ));
            }
            validate_server_fingerprints(&mut tls_config.server_fingerprints)?;

            validate_client_proxy_config(&mut tls_config.protocol, named_pems)?;
        }

        ClientProxyConfig::ShadowTls { protocol, .. } => {
            validate_client_proxy_config(protocol, named_pems)?;
        }

        ClientProxyConfig::Websocket(ws_config) => {
            validate_client_proxy_config(&mut ws_config.protocol, named_pems)?;
        }

        _ => {}
    }
    Ok(())
}

fn validate_server_proxy_config(
    server_proxy_config: &mut ServerProxyConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    inside_tls_or_reality: bool,
) -> std::io::Result<()> {
    match server_proxy_config {
        ServerProxyConfig::Naiveproxy { .. } if !inside_tls_or_reality => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NaiveProxy must be used inside a TLS or Reality protocol. \
                 Configure it as the inner protocol of tls: or reality: targets.",
            ));
        }
        ServerProxyConfig::Vless { user_id, .. } => {
            parse_uuid(user_id)?;
        }
        ServerProxyConfig::Vmess { user_id, .. } => {
            parse_uuid(user_id)?;
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            if tls_targets.is_empty()
                && default_tls_target.is_none()
                && shadowtls_targets.is_empty()
                && reality_targets.is_empty()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TLS server has no entries",
                ));
            }
            for (_, tls_server_config) in tls_targets.iter_mut() {
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }

                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut client_fingerprints,
                    ..
                } = *tls_server_config;

                validate_client_fingerprints(client_fingerprints)?;

                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    true,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                    )?;
                }
            }
            if let Some(tls_server_config) = default_tls_target {
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }

                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = **tls_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    true,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                    )?;
                }
            }
            for (sni_hostname, tls_server_config) in shadowtls_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and ShadowTLS targets: {sni_hostname}"
                        ),
                    ));
                }
                let ShadowTlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut handshake,
                    ..
                } = *tls_server_config;

                if let ShadowTlsServerHandshakeConfig::Local(local_handshake) = handshake {
                    embed_pem_from_map(&mut local_handshake.cert, named_pems);
                    embed_pem_from_map(&mut local_handshake.key, named_pems);
                    validate_client_fingerprints(&mut local_handshake.client_fingerprints)?;
                }

                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    true,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                    )?;
                }
            }

            for (sni_hostname, reality_config) in reality_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and REALITY targets: {sni_hostname}"
                        ),
                    ));
                }
                if shadowtls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between ShadowTLS and REALITY targets: {sni_hostname}"
                        ),
                    ));
                }

                validate_reality_private_key(&reality_config.private_key, sni_hostname)?;
                validate_reality_server_short_ids(&reality_config.short_ids, sni_hostname)?;

                validate_server_proxy_config(
                    &mut reality_config.protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    true,
                )?;

                ConfigSelection::replace_none_or_some_groups(
                    &mut reality_config.override_rules,
                    rule_groups,
                )?;

                for rule_config_selection in reality_config.override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                    )?;
                }
            }

            if let Some(size) = tls_buffer_size
                && *size < MIN_TLS_BUFFER_SIZE
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TLS buffer size must be at least {MIN_TLS_BUFFER_SIZE}"),
                ));
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_server_config in targets.iter_mut() {
                let WebsocketServerConfig {
                    protocol,
                    override_rules,
                    ..
                } = websocket_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    false,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                    )?;
                }
            }
        }
        ServerProxyConfig::TuicV5 { uuid, .. } => {
            parse_uuid(uuid)?;
        }
        ServerProxyConfig::Trojan { shadowsocks, .. } => {
            if matches!(shadowsocks, Some(ShadowsocksConfig::Aead2022 { .. })) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Trojan does not support shadowsocks 2022 ciphers",
                ));
            }
        }
        ServerProxyConfig::Snell { cipher, .. } => {
            if cipher.starts_with("2022-blake3-") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Snell does not support shadowsocks 2022 ciphers",
                ));
            }
        }
        _ => (),
    }
    Ok(())
}

/// Validates a TUN configuration.
fn validate_tun_config(
    config: &mut TunConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
) -> std::io::Result<()> {
    // Validate ICMP requires TCP
    if !config.tcp_enabled && config.icmp_enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN: TCP must be enabled for ICMP",
        ));
    }

    // Validate that we have either Linux config (device_name/address) or mobile config (device_fd)
    #[cfg(target_os = "linux")]
    {
        if config.device_fd.is_none() && (config.device_name.is_none() || config.address.is_none())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Linux requires either 'device_fd' or both 'device_name' and 'address'",
            ));
        }
    }
    #[cfg(target_os = "android")]
    {
        if config.device_fd.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Android requires 'device_fd' from VpnService.Builder.establish()",
            ));
        }
    }
    #[cfg(target_os = "ios")]
    {
        if config.device_fd.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on iOS requires 'device_fd' from NEPacketTunnelProvider.packetFlow",
            ));
        }
    }

    // Resolve rule group references
    ConfigSelection::replace_none_or_some_groups(&mut config.rules, rule_groups)?;

    // Validate rules
    for rule in config.rules.iter_mut() {
        let rule = rule.unwrap_config_mut();
        validate_rule_config(rule, client_groups, &HashMap::new())?;
    }

    Ok(())
}

fn validate_rule_config(
    rule_config: &mut RuleConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    if let RuleActionConfig::Allow {
        ref mut client_chains,
        ..
    } = rule_config.action
    {
        // Handle unspecified: default to single chain with direct hop
        if client_chains.is_unspecified() {
            *client_chains = NoneOrSome::One(ClientChain::default());
        }

        // Validate not explicitly empty (client_chains: [])
        if matches!(client_chains, NoneOrSome::None) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "client_chains cannot be empty; omit the field for default direct connection",
            ));
        }

        // Validate each chain
        for (chain_index, chain) in client_chains.iter_mut().enumerate() {
            // First validate all hops in this chain
            for hop in chain.hops.iter_mut() {
                validate_client_chain_hop(hop, client_groups, named_pems)?;
            }
            // Then expand group references to inline configs
            expand_client_chain(&mut chain.hops, client_groups)?;
            // Validate that direct connectors only appear at hop 0
            validate_direct_connector_positions(&chain.hops, chain_index)?;
        }
    }

    Ok(())
}

/// Validates that direct connectors only appear at hop 0.
///
/// Direct connectors can only be used as the first hop in a chain because they
/// create the TCP connection. At hop 1+, the TCP connection already exists, so
/// "direct" makes no sense there.
fn validate_direct_connector_positions(
    hops: &OneOrSome<ClientChainHop>,
    chain_index: usize,
) -> std::io::Result<()> {
    for (hop_index, hop) in hops.iter().enumerate() {
        if hop_index == 0 {
            // Direct connectors are allowed at hop 0
            continue;
        }

        // For hop 1+, check if any connector is direct
        let has_direct = match hop {
            ClientChainHop::Single(ConfigSelection::Config(config)) => config.protocol.is_direct(),
            ClientChainHop::Single(ConfigSelection::GroupName(_)) => {
                // Groups should already be expanded at this point
                unreachable!("Group references should be expanded before validation")
            }
            ClientChainHop::Pool(selections) => {
                selections.iter().any(|selection| match selection {
                    ConfigSelection::Config(config) => config.protocol.is_direct(),
                    ConfigSelection::GroupName(_) => {
                        unreachable!("Group references should be expanded before validation")
                    }
                })
            }
        };

        if has_direct {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Direct connector at chain {} hop {} is invalid. \
                     Direct connectors can only be used at hop 0 (the first hop) \
                     because they create the TCP connection. At hop 1+, the connection \
                     already exists through the previous hop.",
                    chain_index, hop_index
                ),
            ));
        }
    }

    Ok(())
}

fn validate_client_chain_hop(
    hop: &mut ClientChainHop,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => {
            validate_and_expand_selection(selection, client_groups, named_pems)?;
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                validate_and_expand_selection(selection, client_groups, named_pems)?;
            }
        }
    }
    Ok(())
}

/// Validates a ConfigSelection and expands group references to inline configs.
fn validate_and_expand_selection(
    selection: &mut ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    match selection {
        ConfigSelection::Config(client_config) => {
            validate_client_config(client_config, named_pems)?;
        }
        ConfigSelection::GroupName(group_name) => {
            let group_configs = client_groups.get(group_name).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unknown client_group in chain: {group_name}"),
                )
            })?;
            // Validate all configs in the group; expansion happens in expand_client_chain
            for mut config in group_configs.clone() {
                validate_client_config(&mut config, named_pems)?;
            }
        }
    }
    Ok(())
}

/// Expands all group references in a client chain to their resolved configs.
/// This should be called after validate_client_chain_hop to replace GroupName
/// selections with their actual configs.
fn expand_client_chain(
    client_chain: &mut OneOrSome<ClientChainHop>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<()> {
    let expanded_hops: Vec<ClientChainHop> = client_chain
        .iter()
        .map(|hop| expand_chain_hop(hop, client_groups))
        .collect::<std::io::Result<Vec<_>>>()?;

    *client_chain = if expanded_hops.len() == 1 {
        OneOrSome::One(expanded_hops.into_iter().next().unwrap())
    } else {
        OneOrSome::Some(expanded_hops)
    };
    Ok(())
}

/// Expands a single chain hop by resolving all group references.
fn expand_chain_hop(
    hop: &ClientChainHop,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<ClientChainHop> {
    match hop {
        ClientChainHop::Single(selection) => {
            let configs = expand_selection(selection, client_groups)?;
            // Single becomes a Pool if the group has multiple configs
            if configs.len() == 1 {
                Ok(ClientChainHop::Single(ConfigSelection::Config(
                    configs.into_iter().next().unwrap(),
                )))
            } else {
                Ok(ClientChainHop::Pool(OneOrSome::Some(
                    configs.into_iter().map(ConfigSelection::Config).collect(),
                )))
            }
        }
        ClientChainHop::Pool(selections) => {
            let mut all_configs = vec![];
            for selection in selections.iter() {
                all_configs.extend(expand_selection(selection, client_groups)?);
            }
            Ok(ClientChainHop::Pool(OneOrSome::Some(
                all_configs
                    .into_iter()
                    .map(ConfigSelection::Config)
                    .collect(),
            )))
        }
    }
}

/// Expands a single selection to its constituent configs.
fn expand_selection(
    selection: &ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<Vec<ClientConfig>> {
    match selection {
        ConfigSelection::Config(config) => Ok(vec![config.clone()]),
        ConfigSelection::GroupName(name) => client_groups.get(name).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown client group: {name}"),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::pem::convert_cert_paths;
    use crate::dns::IpStrategy;

    async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<Config>> {
        let (converted_configs, _) = convert_cert_paths(configs).await?;
        let validated = create_server_configs(converted_configs)?;
        Ok(validated.configs)
    }

    #[tokio::test]
    async fn test_validate_config_success() {
        use crate::config::types::ClientConfigGroup;
        use crate::config::types::groups::RuleConfigGroup;

        let configs = vec![
            Config::RuleConfigGroup(RuleConfigGroup {
                rule_group: "test-rules".to_string(),
                rules: OneOrSome::One(RuleConfig {
                    masks: OneOrSome::One(NetLocationMask::ANY),
                    action: RuleActionConfig::Allow {
                        override_address: None,
                        client_chains: NoneOrSome::One(ClientChain::default()),
                    },
                }),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-group".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_topological_sort_simple() {
        use crate::config::types::ClientConfigGroup;

        // group-b has no dependencies, group-a references group-b
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_topological_sort_cycle_detected() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-a".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Circular dependency"),
            "Error should mention circular dependency: {err}"
        );
    }

    #[tokio::test]
    async fn test_topological_sort_unknown_group() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![Config::ClientConfigGroup(ClientConfigGroup {
            client_group: "group-a".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("nonexistent".to_string())),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown group") || err.contains("Unknown"),
            "Error should mention unknown group: {err}"
        );
    }

    #[tokio::test]
    async fn test_topological_sort_diamond() {
        use crate::config::types::ClientConfigGroup;

        // Diamond: a -> b, a -> c, b -> d, c -> d
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-d".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-c".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::Some(vec![
                    ConfigSelection::GroupName("group-b".to_string()),
                    ConfigSelection::GroupName("group-c".to_string()),
                ]),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_nested_groups_resolve() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "us-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "eu-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "all-proxies".to_string(),
                client_proxies: OneOrSome::Some(vec![
                    ConfigSelection::GroupName("us-proxies".to_string()),
                    ConfigSelection::GroupName("eu-proxies".to_string()),
                ]),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_empty_config() {
        let original: Vec<Config> = vec![];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 0);
        assert!(validate_configs_test(deserialized).await.is_ok());
    }

    #[tokio::test]
    async fn test_named_pem_duplicate_names() {
        let configs = vec![
            Config::NamedPem(super::super::types::NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem1".to_string()),
            }),
            Config::NamedPem(super::super::types::NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem2".to_string()),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("named pem already exists: duplicate-name")
        );
    }

    #[tokio::test]
    async fn test_recursive_certificate_embedding() {
        crate::thread_util::set_num_threads(1);

        let test_dir = tempfile::tempdir().unwrap();
        let cert_dir = test_dir.path().join("certs");
        tokio::fs::create_dir_all(&cert_dir).await.unwrap();

        let test_cert = "-----BEGIN CERTIFICATE-----\nTEST CERT CONTENT\n-----END CERTIFICATE-----";
        let test_key = "-----BEGIN PRIVATE KEY-----\nTEST KEY CONTENT\n-----END PRIVATE KEY-----";

        let cert_files = vec![
            ("quic.crt", test_cert),
            ("quic.key", test_key),
            ("server.crt", test_cert),
            ("server.key", test_key),
            ("ca.crt", test_cert),
            ("shadow.crt", test_cert),
            ("shadow.key", test_key),
            ("client-quic.crt", test_cert),
            ("client-quic.key", test_key),
            ("client.crt", test_cert),
            ("client.key", test_key),
        ];

        for (filename, content) in cert_files {
            let path = cert_dir.join(filename);
            tokio::fs::write(&path, content).await.unwrap();
        }

        let config_yaml = format!(
            r#"
- address: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "{}/quic.crt"
    key: "{}/quic.key"
  protocol:
    type: tls
    sni_targets:
      "example.com":
        cert: "{}/server.crt"
        key: "{}/server.key"
        client_ca_certs:
          - "{}/ca.crt"
        protocol:
          type: websocket
          targets:
            - matching_path: "/ws"
              protocol:
                type: vmess
                cipher: auto
                user_id: "123e4567-e89b-42d3-a456-426614174000"
    shadowtls_targets:
      "shadow.com":
        password: "shadowpass"
        handshake:
          cert: "{}/shadow.crt"
          key: "{}/shadow.key"
        protocol:
          type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "proxy.example.com:443"
          transport: quic
          quic_settings:
            cert: "{}/client-quic.crt"
            key: "{}/client-quic.key"
          protocol:
            type: tls
            cert: "{}/client.crt"
            key: "{}/client.key"
            protocol:
              type: http
"#,
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display()
        );

        let configs: Vec<Config> = serde_yaml::from_str(&config_yaml).unwrap();
        let (converted_configs, load_count) = convert_cert_paths(configs).await.unwrap();

        assert_eq!(load_count, 11);

        let validated = create_server_configs(converted_configs).unwrap();
        let Config::Server(server_config) = &validated.configs[0] else {
            panic!("expected Config::Server");
        };

        let quic_settings = server_config.quic_settings.as_ref().unwrap();
        assert!(quic_settings.cert.contains("BEGIN CERTIFICATE"));
        assert!(quic_settings.key.contains("BEGIN PRIVATE KEY"));

        if let ServerProxyConfig::Tls {
            tls_targets,
            shadowtls_targets,
            ..
        } = &server_config.protocol
        {
            let tls_config = tls_targets.get("example.com").unwrap();
            assert!(tls_config.cert.contains("BEGIN CERTIFICATE"));
            assert!(tls_config.key.contains("BEGIN PRIVATE KEY"));

            let shadow_config = shadowtls_targets.get("shadow.com").unwrap();
            if let ShadowTlsServerHandshakeConfig::Local(handshake) = &shadow_config.handshake {
                assert!(handshake.cert.contains("BEGIN CERTIFICATE"));
                assert!(handshake.key.contains("BEGIN PRIVATE KEY"));
            }
        }
    }

    #[test]
    fn test_direct_connector_at_hop_0_allowed() {
        // Single direct connector at hop 0 should be allowed
        let hops = OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            ClientConfig::default(), // default is direct
        )));

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    fn http_proxy_config() -> ClientProxyConfig {
        ClientProxyConfig::Http {
            username: None,
            password: None,
            resolve_hostname: false,
        }
    }

    fn socks_proxy_config() -> ClientProxyConfig {
        ClientProxyConfig::Socks {
            username: None,
            password: None,
        }
    }

    #[test]
    fn test_direct_then_proxy_allowed() {
        // Direct at hop 0, proxy at hop 1 - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_proxy_then_proxy_allowed() {
        // Proxy at hop 0, proxy at hop 1 - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_direct_at_hop_1_rejected() {
        // Direct at hop 1 should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_direct_in_middle_of_chain_rejected() {
        // Direct in the middle of a 3-hop chain should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_direct_in_pool_at_hop_0_allowed() {
        // Mixed pool at hop 0 with direct - should be allowed
        let hops = OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
            ConfigSelection::Config(ClientConfig::default()), // direct
            ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            }),
        ])));

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_direct_in_pool_at_hop_1_rejected() {
        // Mixed pool at hop 1 with direct - should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(ClientConfig::default()), // direct
                ConfigSelection::Config(ClientConfig {
                    protocol: socks_proxy_config(),
                    ..Default::default()
                }),
            ])),
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_three_hop_direct_first_then_proxies_allowed() {
        // Direct at hop 0, two proxies following - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[tokio::test]
    async fn test_tun_config_parsing() {
        let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1400
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: false
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                assert_eq!(tun.device_name, Some("tun0".to_string()));
                assert_eq!(tun.address, Some("10.0.0.1".parse().unwrap()));
                assert_eq!(tun.netmask, Some("255.255.255.0".parse().unwrap()));
                assert_eq!(tun.mtu, 1400);
                assert!(tun.tcp_enabled);
                assert!(tun.udp_enabled);
                assert!(!tun.icmp_enabled);
            }
            _ => panic!("Expected TunServer config"),
        }

        // Validate the config
        let result = validate_configs_test(configs).await;
        assert!(result.is_ok(), "TUN config validation failed: {:?}", result);
    }

    #[tokio::test]
    async fn test_tun_config_with_device_fd() {
        let yaml = r#"
- device_fd: 42
  mtu: 1500
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                assert_eq!(tun.device_fd, Some(42));
                assert_eq!(tun.device_name, None);
                assert_eq!(tun.mtu, 1500);
            }
            _ => panic!("Expected TunServer config"),
        }
    }

    #[tokio::test]
    async fn test_tun_config_defaults() {
        let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                // Check defaults
                assert_eq!(tun.mtu, 1500); // default
                assert!(tun.tcp_enabled); // default true
                assert!(tun.udp_enabled); // default true
                assert!(tun.icmp_enabled); // default true
            }
            _ => panic!("Expected TunServer config"),
        }
    }

    #[tokio::test]
    async fn test_tun_icmp_requires_tcp() {
        // ICMP requires TCP to be enabled
        let tun_config = TunConfig {
            device_name: Some("tun0".to_string()),
            device_fd: None,
            address: Some("10.0.0.1".parse().unwrap()),
            netmask: None,
            destination: None,
            mtu: 1500,
            tcp_enabled: false, // TCP disabled
            udp_enabled: true,
            icmp_enabled: true, // but ICMP enabled - should fail
            rules: NoneOrSome::Unspecified,
            dns: None,
        };

        let configs = vec![Config::TunServer(tun_config)];
        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("TCP must be enabled for ICMP"),
            "Expected ICMP/TCP error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_system_with_client_chain_rejected() {
        let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "system".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::Config(ClientChain::default())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
            }),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("client_chain is not supported for system DNS"),
            "Expected system DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_udp_with_proxy_chain_rejected() {
        use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

        // Create a non-direct (socks5) chain - should be rejected for UDP.
        let mut socks_config = ClientConfig::default();
        socks_config.protocol = ClientProxyConfig::Socks {
            username: None,
            password: None,
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("UDP DNS only supports direct client_chain"),
            "Expected UDP DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_udp_with_direct_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        // Create a direct chain - should be allowed for UDP (for bind_interface).
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_h3_with_proxy_chain_rejected() {
        use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

        // Create a non-direct (socks5) chain - should be rejected for H3.
        let mut socks_config = ClientConfig::default();
        socks_config.protocol = ClientProxyConfig::Socks {
            username: None,
            password: None,
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("H3 DNS only supports direct client_chain"),
            "Expected H3 DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_h3_with_direct_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        // Create a direct chain - should be allowed for H3 (for bind_interface).
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_tcp_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tcp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        // TCP with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_tls_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tls://1.1.1.1".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        // TLS with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_https_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "https://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                }),
            }),
        ];

        // HTTPS with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_group_composition_basic() {
        // Group full-dns includes base-dns
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("udp://8.8.8.8".to_string()),
                    DnsServerSpec::Simple("udp://8.8.4.4".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "full-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // Group reference
                    DnsServerSpec::Simple("tls://1.1.1.1".to_string()),
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "composition should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_multi_level() {
        // C includes B, B includes A
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-b".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("level-a".to_string()),
                    DnsServerSpec::Simple("udp://1.1.1.1".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-c".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("level-b".to_string()),
                    DnsServerSpec::Simple("system".to_string()),
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "multi-level composition should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_cycle_detected() {
        // A includes B, B includes A - cycle!
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "group-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-b".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "group-b".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-a".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Circular dependency") || err.contains("cycle"),
            "Expected cycle error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_unknown_ref() {
        // Reference to non-existent group
        let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
            dns_group: "my-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent".to_string())),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown group") || err.contains("nonexistent"),
            "Expected unknown group error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_with_bootstrap() {
        // Composition and bootstrap work together
        // Note: Using IP-based URLs to avoid network calls during tests
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "bootstrap-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tls://1.1.1.1".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "full-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // Composition reference
                    DnsServerSpec::WithOptions {
                        url: "tls://8.8.4.4".to_string(), // IP-based, no resolution needed
                        client_chain: NoneOrSome::None,
                        bootstrap_url: Some("bootstrap-dns".to_string()), // Bootstrap reference (not used since URL is IP)
                        server_name: Some("dns.google".to_string()),      // SNI override
                        ip_strategy: IpStrategy::default(),
                    },
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "composition with bootstrap should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_server_dns_with_group_ref() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config references an existing dns_group
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "my-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                ),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::One(DnsServerSpec::Simple("my-dns".to_string())),
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with dns group ref should work: {:?}",
            result.err()
        );

        // Verify servers is still the group name (not expanded)
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            assert_eq!(s.dns.as_ref().unwrap().resolved_group(), Some("my-dns"));
        }
    }

    #[tokio::test]
    async fn test_server_dns_with_mixed_group_and_url() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config with both group ref and URL in servers
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                ),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::Some(vec![
                        DnsServerSpec::Simple("base-dns".to_string()), // group ref
                        DnsServerSpec::Simple("udp://1.1.1.1".to_string()), // URL
                    ]),
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with mixed dns should work: {:?}",
            result.err()
        );

        // Verify servers was expanded to an inline group name
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
            assert!(
                group.starts_with("__inline_dns_"),
                "should be inline group: {}",
                group
            );
        }
    }

    #[tokio::test]
    async fn test_server_dns_with_multiple_group_refs() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config with multiple group refs that need expansion
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "fast-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "secure-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tcp://1.1.1.1".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                ),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::Some(vec![
                        DnsServerSpec::Simple("fast-dns".to_string()),
                        DnsServerSpec::Simple("secure-dns".to_string()),
                    ]),
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with multiple group refs should work: {:?}",
            result.err()
        );

        // Verify servers was expanded to an inline group name
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
            assert!(
                group.starts_with("__inline_dns_"),
                "should be inline group: {}",
                group
            );
        }
    }

    #[tokio::test]
    async fn test_server_dns_unknown_group_ref() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config references non-existent dns_group
        let configs = vec![Config::Server(ServerConfig {
            bind_location: BindLocation::Address(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            ),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent-dns".to_string())),
            }),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err(), "unknown dns group should fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent-dns"),
            "error should mention group name: {}",
            err
        );
    }
}
