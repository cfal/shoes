//! Configuration validation - validates configs and creates final ServerConfigs.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::dns::ParsedDnsUrl;
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};
use crate::reality::{decode_private_key, decode_short_id};
use crate::thread_util::get_num_threads;
use crate::uuid_util::parse_uuid;

use super::pem::{embed_optional_pem_from_map, embed_pem_from_map};
use super::types::{
    BindLocation, ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config,
    ConfigSelection, DEFAULT_REALITY_SHORT_ID, DnsConfig, DnsConfigGroup, DnsServerSpec,
    ExpandedDnsGroup, ExpandedDnsSpec, GlobalLimits, PemSource, RuleActionConfig, RuleConfig,
    ServerConfig, ServerProxyConfig, ServerQuicConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig, Transport, TunConfig,
    WebsocketServerConfig, direct_allow_rule,
};

const MIN_TLS_BUFFER_SIZE: usize = 16 * 1024;

/// Result of config validation containing server configs and expanded DNS groups.
/// DNS resolvers are built at runtime from the expanded groups.
pub struct ValidatedConfigs {
    pub catalog: Option<crate::control::catalog::Catalog>,
    pub control: super::ControlConfig,
    pub certificates: Vec<std::sync::Arc<crate::certificates::Source>>,
    pub reload_files: Vec<std::path::PathBuf>,
    pub global_limits: GlobalLimits,
    pub configs: Vec<Config>,
    /// Expanded DNS groups in topological order (bootstrap deps first).
    pub dns_groups: Vec<ExpandedDnsGroup>,
    pub wireguard_endpoints: Vec<super::types::wireguard::WireguardDeviceConfig>,
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
pub fn create_server_configs(mut all_configs: Vec<Config>) -> std::io::Result<ValidatedConfigs> {
    let certificates = crate::certificates::configure(&mut all_configs)?;
    let catalog = crate::control::catalog::Catalog::capture(&mut all_configs)?;
    let mut control = super::ControlConfig::default();
    let mut compiler = crate::rules::Compiler::default();
    let mut reload_files = crate::rule_set::dependencies(&mut all_configs)?;
    reload_files.extend(super::pem_reload_dependencies(&mut all_configs)?);
    crate::rule_set::load(&mut all_configs, &mut compiler)?;
    super::rule_visit::compile(&mut all_configs, &mut compiler)?;
    let mut global_limits = None;
    // First pass: collect raw groups with unresolved references
    let mut raw_client_groups: HashMap<String, OneOrSome<ConfigSelection<ClientConfig>>> =
        HashMap::new();
    let mut direct = ClientConfig::default();
    if let Some(catalog) = &catalog {
        direct.control = Some(crate::control::catalog::MemberOrigin {
            name: std::sync::Arc::from("DIRECT"),
            path: Vec::new(),
            selection: catalog.selection.clone(),
        });
    }
    raw_client_groups.insert(
        String::from("direct"),
        OneOrSome::One(ConfigSelection::Config(direct)),
    );

    let mut rule_groups: HashMap<String, Vec<RuleConfig>> = HashMap::new();
    rule_groups.insert(
        String::from("allow-all-direct"),
        vec![RuleConfig {
            criteria: Default::default(),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_chains: NoneOrSome::One(ClientChain::default()),
            },
        }],
    );
    rule_groups.insert(
        String::from("block-all"),
        vec![RuleConfig {
            criteria: Default::default(),
            action: RuleActionConfig::Block,
        }],
    );

    let mut server_configs: Vec<ServerConfig> = vec![];
    let mut tun_configs: Vec<TunConfig> = vec![];
    let mut named_pems: HashMap<String, String> = HashMap::new();
    let mut dns_groups: HashMap<String, DnsConfigGroup> = HashMap::new();

    for config in all_configs.into_iter() {
        match config {
            Config::ClashApi(config) => control.listeners.push(config),
            Config::CacheFile(config) => {
                if control
                    .cache_file_path
                    .replace(config.cache_file_path)
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cache_file_path may only be specified once across all config files",
                    ));
                }
            }
            Config::CertificateSource(_) => {}
            Config::GlobalLimits(limits) => {
                if global_limits.replace(limits).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "global_limits may only be specified once across all config files",
                    ));
                }
                limits.validate()?;
            }
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
                let super::RuleGroupRules::Policies(rules) = group.rules else {
                    continue;
                };
                if rule_groups
                    .insert(group.rule_group.clone(), rules.into_vec())
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

    let global_limits = global_limits.unwrap_or_default();

    // Resolve client groups using topological sort
    let mut client_groups = resolve_client_groups_topologically(raw_client_groups)?;

    // Embed PEMs into all client configs in groups before they're used
    for configs in client_groups.values_mut() {
        for config in configs.iter_mut() {
            validate_client_config(config, &named_pems, global_limits)?;
        }
    }

    // Extract inline DNS configs from server/tun configs into dns_groups.
    // This replaces inline specs with group name references.
    let mut inline_dns_counter = 0u32;
    let mut default_dns_groups = HashSet::new();
    #[cfg(unix)]
    let mut wireguard_server_ids = HashSet::new();
    for config in server_configs.iter_mut() {
        let identity = match &config.protocol {
            #[cfg(unix)]
            ServerProxyConfig::Wireguard(protocol) => {
                let id = protocol.server_id();
                if !wireguard_server_ids.insert(id.clone()) {
                    return Err(super::types::wireguard::invalid(
                        "duplicate WireGuard server identity; set a distinct wireguard_name for each server",
                    ));
                }
                format!("wireguard:{id}")
            }
            _ => {
                let bind = match &config.bind_location {
                    BindLocation::Path(path) => format!(
                        "path:{}",
                        URL_SAFE_NO_PAD.encode(path.as_os_str().as_encoded_bytes())
                    ),
                    BindLocation::Address(_) => format!(
                        "address:{}",
                        URL_SAFE_NO_PAD.encode(config.bind_location.to_string())
                    ),
                    BindLocation::Unspecified {} => "no-listener".into(),
                };
                format!("server:{:?}:{bind}", config.transport)
            }
        };
        extract_inline_dns(
            &mut config.dns,
            &mut dns_groups,
            &mut inline_dns_counter,
            &identity,
            &mut default_dns_groups,
        )?;
    }
    for config in tun_configs.iter_mut() {
        let identity = format!(
            "tun:{}",
            URL_SAFE_NO_PAD.encode(config.device_name.as_deref().unwrap_or("default"))
        );
        extract_inline_dns(
            &mut config.dns,
            &mut dns_groups,
            &mut inline_dns_counter,
            &identity,
            &mut default_dns_groups,
        )?;
    }

    // Expand DNS group composition references for ALL groups (named + inline).
    let mut fake_policies = HashMap::new();
    let mut state_files = HashSet::new();
    for (name, group) in &dns_groups {
        let policy = group.fake_ip.as_ref().and_then(|config| config.options());
        if let Some(options) = &policy {
            options.validate()?;
            if let Some(path) = &options.state_file
                && !state_files.insert(path.clone())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "multiple fake DNS contexts own the same state_file",
                ));
            }
        }
        if group.fake_ip.is_none()
            && group
                .dns_servers
                .iter()
                .filter_map(|spec| spec.as_group_ref())
                .any(|name| {
                    dns_groups.get(name).is_some_and(|referenced| {
                        referenced
                            .fake_ip
                            .as_ref()
                            .and_then(|config| config.options())
                            .is_some()
                    })
                })
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS composition referencing a fake IP group requires an explicit fake_ip policy; reference the group directly to share its pool",
            ));
        }
        fake_policies.insert(name.clone(), policy);
    }
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
        let expanded_specs = expand_dns_specs(
            specs,
            &client_groups,
            &named_pems,
            &group_names,
            global_limits,
        )?;
        final_dns_groups.push(ExpandedDnsGroup {
            fake_ip: fake_policies.remove(&name).flatten(),
            use_default_resolver: default_dns_groups.contains(&name),
            name,
            specs: expanded_specs,
        });
    }

    // Validate server configs (DNS is now just a group reference).
    for config in server_configs.iter_mut() {
        validate_server_config(
            config,
            &client_groups,
            &rule_groups,
            &named_pems,
            global_limits,
        )?;
        validate_dns_group_ref(&config.dns, &group_names)?;
    }

    // Validate TUN configs.
    for config in tun_configs.iter_mut() {
        validate_tun_config(
            config,
            &client_groups,
            &rule_groups,
            &named_pems,
            global_limits,
        )?;
        validate_dns_group_ref(&config.dns, &group_names)?;
    }

    // Combine into Config list (only Server and TunServer variants)
    let mut result: Vec<Config> = server_configs.into_iter().map(Config::Server).collect();
    result.extend(tun_configs.into_iter().map(Config::TunServer));

    let mut validated = ValidatedConfigs {
        catalog,
        control,
        certificates,
        reload_files,
        global_limits,
        configs: result,
        dns_groups: final_dns_groups,
        wireguard_endpoints: Vec::new(),
    };
    validate_wireguard_dns(&validated)?;
    #[cfg(unix)]
    super::wireguard_devices::collect_devices(&mut validated, &mut client_groups)?;
    super::fake_dns::validate(&mut validated)?;
    refresh_catalog_clients(&mut validated, &client_groups)?;
    if let Some(catalog) = &mut validated.catalog {
        // Unused definitions are still probeable, but must not activate WireGuard devices.
        for node in catalog.nodes.values_mut() {
            if let crate::control::catalog::CatalogNode::Leaf(client) = node {
                expand_peer_chains(client, &client_groups)?;
                validate_client_config(client, &named_pems, global_limits)?;
            }
        }
    }
    Ok(validated)
}

pub(super) fn refresh_catalog_clients(
    validated: &mut ValidatedConfigs,
    groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<()> {
    if let Some(catalog) = &mut validated.catalog {
        for client in groups.values().flatten() {
            catalog.update_client(client);
        }
    }
    validated.refresh_catalog()
}

fn validate_wireguard_dns(validated: &ValidatedConfigs) -> std::io::Result<()> {
    let tunnel_dns: HashSet<_> = validated
        .dns_groups
        .iter()
        .filter(|group| {
            group
                .specs
                .iter()
                .any(|spec| spec.client_chains.iter().any(chain_uses_wireguard))
        })
        .map(|group| group.name.as_str())
        .collect();
    for group in &validated.dns_groups {
        for spec in &group.specs {
            if spec
                .bootstrap_url
                .as_deref()
                .is_some_and(|name| tunnel_dns.contains(name))
            {
                return Err(super::types::wireguard::invalid(
                    "DNS bootstrap cannot depend on a WireGuard-routed group",
                ));
            }
        }
    }
    Ok(())
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
            collect_client_dependencies(selection, &mut deps);
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
                    let mut config = config.clone();
                    expand_peer_chains(&mut config, &resolved)?;
                    if group_name != "direct"
                        && let Some(origin) = &mut config.control
                    {
                        origin
                            .path
                            .insert(0, (group_name.clone(), origin.name.to_string()));
                    }
                    expanded_configs.push(config);
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
                    expanded_configs.extend(referenced_configs.iter().cloned().map(
                        |mut config| {
                            if let Some(origin) = &mut config.control {
                                origin.path.insert(
                                    0,
                                    (
                                        group_name.clone(),
                                        crate::control::catalog::api_group(ref_name).to_owned(),
                                    ),
                                );
                            }
                            config
                        },
                    ));
                }
            }
        }

        resolved.insert(group_name, expanded_configs);
    }

    Ok(resolved)
}

fn collect_client_dependencies(
    selection: &ConfigSelection<ClientConfig>,
    dependencies: &mut Vec<String>,
) {
    match selection {
        ConfigSelection::GroupName(name) => dependencies.push(name.clone()),
        ConfigSelection::Config(client) => {
            if let ClientProxyConfig::Wireguard(config) = &client.protocol
                && let Some(chain) = &config.peer_client_chain
            {
                for hop in chain.hops.iter() {
                    match hop {
                        ClientChainHop::Single(selection) => {
                            collect_client_dependencies(selection, dependencies)
                        }
                        ClientChainHop::Pool(selections) => {
                            for selection in selections.iter() {
                                collect_client_dependencies(selection, dependencies);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn expand_peer_chains(
    client: &mut ClientConfig,
    groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<()> {
    if let ClientProxyConfig::Wireguard(config) = &mut client.protocol
        && let Some(chain) = &mut config.peer_client_chain
    {
        expand_client_chain(&mut chain.hops, groups)?;
        for hop in chain.hops.iter_mut() {
            match hop {
                ClientChainHop::Single(selection) => {
                    expand_peer_chains(selection.unwrap_config_mut(), groups)?
                }
                ClientChainHop::Pool(selections) => {
                    for selection in selections.iter_mut() {
                        expand_peer_chains(selection.unwrap_config_mut(), groups)?;
                    }
                }
            }
        }
    }
    Ok(())
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
/// Normalizes empty selections to None so they use the default resolver.
fn extract_inline_dns(
    dns: &mut Option<DnsConfig>,
    dns_groups: &mut HashMap<String, DnsConfigGroup>,
    counter: &mut u32,
    identity: &str,
    default_dns_groups: &mut HashSet<String>,
) -> std::io::Result<()> {
    let Some(config) = dns else {
        return Ok(());
    };

    // Empty means use default resolver - nothing to extract
    if config.servers.is_empty() && config.fake_ip.is_none() {
        config.servers = NoneOrSome::None;
        return Ok(());
    }

    // Already a single group reference - nothing to extract
    if let NoneOrSome::One(spec) = &config.servers
        && spec.as_group_ref().is_some()
        && config.fake_ip.is_none()
    {
        return Ok(());
    }

    // Generate unique name and extract specs into a new group
    let generated_name = if config.fake_ip.is_some() {
        format!("__inline_fake_dns:{identity}")
    } else {
        format!("__inline_dns_{}", *counter)
    };
    *counter += 1;

    if dns_groups.contains_key(&generated_name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ambiguous private DNS context identity; use a named DNS group",
        ));
    }
    let servers = std::mem::replace(&mut config.servers, NoneOrSome::Unspecified);
    if servers.is_empty() {
        default_dns_groups.insert(generated_name.clone());
    }

    let group = DnsConfigGroup {
        fake_ip: config.fake_ip.take(),
        dns_group: generated_name.clone(),
        dns_servers: if servers.is_empty() {
            NoneOrSome::One(DnsServerSpec::Simple("system".into()))
        } else {
            servers
        },
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
    if let NoneOrSome::One(spec) = &config.servers
        && let Some(group_name) = spec.as_group_ref()
    {
        if !group_names.contains(group_name) {
            return Err(std::io::Error::other(format!(
                "unknown dns_group in server config: '{}'",
                group_name
            )));
        }
        return Ok(());
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
    global_limits: GlobalLimits,
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
            validate_client_chain(&mut chain.hops, 0, client_groups, named_pems, global_limits)?;
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
            let all_direct = expanded_chains.iter().all(is_chain_direct_only);

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

        let uses_wireguard = expanded_chains.iter().any(chain_uses_wireguard);
        if uses_wireguard && (parsed_url.has_hostname() || spec.bootstrap_url().is_some()) {
            return Err(super::types::wireguard::invalid(
                "WireGuard DNS requires a literal upstream IP and no bootstrap_url",
            ));
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
            timeout_secs: spec.timeout_secs(),
            connect_timeout_secs: spec.connect_timeout_secs(),
            attempts: spec.attempts(),
        });
    }

    Ok(result)
}

fn hop_uses_wireguard(hop: &ClientChainHop) -> bool {
    let uses_wireguard = |selection: &ConfigSelection<ClientConfig>| match selection {
        ConfigSelection::Config(config) => config.protocol.is_wireguard(),
        ConfigSelection::GroupName(_) => false,
    };
    match hop {
        ClientChainHop::Single(selection) => uses_wireguard(selection),
        ClientChainHop::Pool(selections) => selections.iter().any(uses_wireguard),
    }
}

pub(super) fn chain_uses_wireguard(chain: &ClientChain) -> bool {
    chain.hops.iter().any(hop_uses_wireguard)
}

/// Checks if a client chain is direct-only (single hop with all direct protocol configs).
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
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    if let ServerProxyConfig::Wireguard(config) = &server_config.protocol {
        if server_config.transport != Transport::Udp
            || server_config.tcp_settings.is_some()
            || server_config.quic_settings.is_some()
        {
            return Err(super::types::wireguard::invalid(
                "WireGuard requires UDP transport without TCP/QUIC socket settings",
            ));
        }
        config.device(server_config)?.validate()?;
        if let ServerProxyConfig::Wireguard(config) = &mut server_config.protocol
            && let Some(chain) = &mut config.peer_client_chain
        {
            validate_client_chain(&mut chain.hops, 0, client_groups, named_pems, global_limits)?;
            if !crate::tcp::chain_builder::supports_udp_offline(chain)? {
                return Err(super::types::wireguard::invalid(
                    "WireGuard peer_client_chain does not support UDP",
                ));
            }
        }
        ConfigSelection::replace_none_or_some_groups(&mut server_config.rules, rule_groups)?;
        if server_config.rules.is_empty() {
            return Err(super::types::wireguard::invalid(
                "WireGuard server requires nonempty explicit rules",
            ));
        }
        for rule in server_config.rules.iter_mut() {
            validate_rule_config(
                rule.unwrap_config_mut(),
                client_groups,
                named_pems,
                global_limits,
            )?;
        }
        return Ok(());
    }
    if matches!(
        server_config.bind_location,
        super::BindLocation::Unspecified {}
    ) {
        return Err(super::types::wireguard::invalid(
            "server requires an address or path",
        ));
    }
    super::types::xhttp::validate_server_transport(
        &server_config.protocol,
        &server_config.transport,
    )?;
    if matches!(server_config.protocol, ServerProxyConfig::Xhttp(_))
        && server_config.transport == Transport::Quic
        && server_config.quic_settings.as_ref().is_some_and(|quic| {
            !quic.alpn_protocols.is_unspecified()
                && quic.alpn_protocols.clone().into_vec() != ["h3"]
        })
    {
        return Err(super::types::xhttp::invalid("QUIC XHTTP ALPN must be h3"));
    }
    if server_config.transport == Transport::Udp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP listener transport is not supported",
        ));
    }
    // First handle QUIC settings certificates
    if let Some(ref mut quic_settings) = server_config.quic_settings {
        if let ServerProxyConfig::TuicV5 {
            zero_rtt_handshake, ..
        } = &server_config.protocol
        {
            quic_settings
                .key_exchange_groups
                .validate_zero_rtt(*zero_rtt_handshake)?;
        }
        embed_pem_from_map(&mut quic_settings.cert, named_pems);
        embed_pem_from_map(&mut quic_settings.key, named_pems);
        for cert in quic_settings.client_ca_certs.iter_mut() {
            embed_pem_from_map(cert, named_pems);
        }
        validate_server_certificates(
            &quic_settings.cert,
            &quic_settings.key,
            &quic_settings.client_ca_certs,
            quic_settings.certificate_binding.as_ref(),
        )?;
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
            global_limits,
        )?;
    }

    validate_server_proxy_config(
        &mut server_config.protocol,
        client_groups,
        rule_groups,
        named_pems,
        if server_config.transport == Transport::Quic {
            ServerProtocolContext::Quic
        } else {
            ServerProtocolContext::Stream
        },
        global_limits,
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
pub(crate) fn validate_client_vision_protocol(
    vision_enabled: bool,
    protocol: &ClientProxyConfig,
    config_type: &str,
) -> std::io::Result<()> {
    if !vision_enabled {
        return Ok(());
    }

    match protocol {
        ClientProxyConfig::Vless { encryption, .. } if !encryption.is_disabled() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Native VLESS encryption requires outer TLS/REALITY vision: false; set vision: true on VLESS instead",
            ))
        }
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
    let inner = match config {
        ClientProxyConfig::Tls(tls_config) => {
            tls_config
                .key_exchange_groups
                .validate_vision(tls_config.vision)?;
            validate_client_vision_protocol(tls_config.vision, &tls_config.protocol, "TLS")?;
            Some(tls_config.protocol.as_ref())
        }
        ClientProxyConfig::Reality {
            vision, protocol, ..
        } => {
            validate_client_vision_protocol(*vision, protocol, "Reality")?;
            Some(protocol.as_ref())
        }
        ClientProxyConfig::ShadowTls { protocol, .. } => Some(protocol.as_ref()),
        ClientProxyConfig::Websocket(ws_config) => Some(ws_config.protocol.as_ref()),
        ClientProxyConfig::Xhttp(config) => {
            config.validate()?;
            Some(config.protocol.as_ref())
        }
        _ => None,
    };
    if let Some(inner) = inner {
        if inner.is_direct() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "direct cannot be used as an inner proxy protocol",
            ));
        }
        if inner.is_wireguard() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "WireGuard cannot be used as an inner proxy protocol",
            ));
        }
        validate_client_proxy_structure(inner)?;
    }
    Ok(())
}

fn validate_client_config(
    client_config: &mut ClientConfig,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    client_config.validate_quic_key_exchange(true)?;
    if let ClientProxyConfig::Wireguard(config) = &mut client_config.protocol {
        if client_config.transport != Transport::Udp
            || client_config.tcp_settings.is_some()
            || client_config.quic_settings.is_some()
        {
            return Err(super::types::wireguard::invalid(
                "WireGuard requires UDP transport without TCP/QUIC socket settings",
            ));
        }
        config
            .device(
                &client_config.address,
                client_config.bind_interface.clone().into_option(),
            )
            .validate()?;
        if let Some(chain) = &mut config.peer_client_chain {
            validate_client_chain(
                &mut chain.hops,
                0,
                &HashMap::new(),
                named_pems,
                global_limits,
            )?;
            if !crate::tcp::chain_builder::supports_udp_offline(chain)? {
                return Err(super::types::wireguard::invalid(
                    "WireGuard peer_client_chain does not support UDP",
                ));
            }
        }
    }
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
        validate_client_certificates(cert.as_deref(), key.as_deref())?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if client_config.bind_interface.is_one() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_interface is only available on Android, Fuchsia, or Linux.",
        ));
    }

    validate_client_proxy_structure(&client_config.protocol)?;
    validate_client_proxy_config(
        &mut client_config.protocol,
        named_pems,
        client_config.address.address().hostname(),
    )?;

    if crate::xhttp::connector::contains(&client_config.protocol) {
        crate::xhttp::connector::build_with_limits(
            client_config,
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
            global_limits,
        )?;
    }

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
    default_sni: Option<&str>,
) -> std::io::Result<()> {
    match client_proxy_config {
        ClientProxyConfig::Vmess {
            user_id, cipher, ..
        } => {
            parse_uuid(user_id)?;
            validate_vmess_cipher(cipher)?;
        }
        ClientProxyConfig::Vless {
            user_id,
            encryption,
            vision,
            h2mux,
            ..
        } => {
            parse_uuid(user_id)?;
            if encryption.is_disabled() {
                if *vision {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "VLESS-level vision: true requires native encryption; for legacy Vision move vision: true to TLS/REALITY (older versions ignored it on VLESS)",
                    ));
                }
            } else {
                if *vision && h2mux.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Native VLESS Vision does not support H2MUX",
                    ));
                }
                crate::vless::encryption::ClientEncryption::new(encryption.as_str())?;
            }
        }
        ClientProxyConfig::Snell {
            config: super::types::ShadowsocksConfig::Aead2022 { .. },
            ..
        } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Snell does not support shadowsocks 2022 ciphers",
            ));
        }
        ClientProxyConfig::Reality {
            public_key,
            mldsa65_verify,
            short_id,
            sni_hostname,
            protocol,
            ..
        } => {
            crate::reality::decode_public_key(public_key).map_err(std::io::Error::other)?;
            if let Some(key) = mldsa65_verify {
                crate::reality::decode_mldsa65_verify(key)?;
            }
            let sni = sni_hostname.as_deref().or(default_sni).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "REALITY client requires sni_hostname",
                )
            })?;
            crate::reality::parse_server_name(sni)?;
            validate_reality_client_short_id(short_id)?;

            if short_id == DEFAULT_REALITY_SHORT_ID {
                log::warn!(
                    "Reality client using default short_id (all zeros). \
                     For better security in production, configure an explicit short_id that matches your server."
                );
            }

            validate_client_proxy_config(protocol, named_pems, None)?;
        }

        ClientProxyConfig::Tls(tls_config) => {
            let sni = match &tls_config.sni_hostname {
                NoneOrOne::Unspecified => default_sni,
                NoneOrOne::None => None,
                NoneOrOne::One(sni) => Some(sni.as_str()),
            };
            if let Some(sni) = sni {
                validate_sni(sni)?;
            }
            embed_optional_pem_from_map(&mut tls_config.cert, named_pems);
            embed_optional_pem_from_map(&mut tls_config.key, named_pems);

            if tls_config.cert.is_none() != tls_config.key.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Both client cert and key have to be specified, or both have to be omitted",
                ));
            }
            validate_server_fingerprints(&mut tls_config.server_fingerprints)?;
            validate_client_certificates(tls_config.cert.as_deref(), tls_config.key.as_deref())?;

            validate_client_proxy_config(&mut tls_config.protocol, named_pems, None)?;
        }

        ClientProxyConfig::ShadowTls {
            protocol,
            sni_hostname,
            ..
        } => {
            if let Some(sni) = sni_hostname.as_deref().or(default_sni) {
                validate_sni(sni)?;
            }
            validate_client_proxy_config(protocol, named_pems, None)?;
        }

        ClientProxyConfig::Websocket(ws_config) => {
            validate_client_proxy_config(&mut ws_config.protocol, named_pems, None)?;
        }

        ClientProxyConfig::Xhttp(config) => {
            config.validate()?;
            validate_client_proxy_config(&mut config.protocol, named_pems, None)?;
        }

        ClientProxyConfig::Anytls {
            padding_scheme: Some(lines),
            ..
        } => {
            crate::anytls::PaddingFactory::new(lines.join("\n").as_bytes())
                .map_err(std::io::Error::other)?;
        }

        _ => {}
    }
    Ok(())
}

fn validate_sni(sni: &str) -> std::io::Result<()> {
    rustls::pki_types::ServerName::try_from(sni)
        .map(|_| ())
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid TLS server name")
        })
}

fn validate_server_certificates(
    cert: &str,
    key: &str,
    ca: &NoneOrSome<String>,
    source: Option<&std::sync::Arc<crate::certificates::Source>>,
) -> std::io::Result<()> {
    crate::rustls_config_util::try_create_server_config_with_source(
        cert.as_bytes(),
        key.as_bytes(),
        ca.iter().map(|pem| pem.as_bytes().to_vec()).collect(),
        &[],
        &[],
        &Default::default(),
        source,
    )
    .map(|_| ())
}

fn validate_client_certificates(cert: Option<&str>, key: Option<&str>) -> std::io::Result<()> {
    if let (Some(cert), Some(key)) = (cert, key) {
        crate::rustls_config_util::try_create_client_config(
            false,
            vec![],
            vec![],
            true,
            Some((key.as_bytes().to_vec(), cert.as_bytes().to_vec())),
            false,
            &Default::default(),
        )?;
    }
    Ok(())
}

fn validate_vmess_cipher(cipher: &str) -> std::io::Result<()> {
    crate::vmess::DataCipher::try_from(cipher).map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerProtocolContext {
    Stream,
    Tls,
    Quic,
}

pub(crate) fn validate_server_vision(
    vision: bool,
    protocol: &ServerProxyConfig,
) -> std::io::Result<()> {
    if vision
        && matches!(protocol, ServerProxyConfig::Vless { decryption, .. } if !decryption.is_disabled())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Native VLESS decryption requires outer TLS/REALITY vision: false; set vision: true on VLESS instead",
        ));
    }
    if vision && !matches!(protocol, ServerProxyConfig::Vless { .. }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Server Vision requires VLESS as the inner protocol",
        ));
    }
    Ok(())
}

fn validate_nonempty_secret(secret: &str, protocol: &str) -> std::io::Result<()> {
    if secret.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{protocol} server password must not be empty"),
        ));
    }
    Ok(())
}

fn validate_server_auth(protocol: &ServerProxyConfig) -> std::io::Result<()> {
    match protocol {
        ServerProxyConfig::Http { username, password } => {
            if username.is_some() || password.is_some() {
                validate_nonempty_secret(password.as_deref().unwrap_or_default(), "HTTP")?;
            }
        }
        ServerProxyConfig::Socks {
            username, password, ..
        }
        | ServerProxyConfig::Mixed {
            username, password, ..
        } => {
            if username.is_none() && password.is_none() {
                return Ok(());
            }

            let username_len = username.as_deref().unwrap_or_default().len();
            let password_len = password.as_deref().unwrap_or_default().len();
            if !(1..=255).contains(&username_len) || !(1..=255).contains(&password_len) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS/mixed server authentication requires a username and password of 1-255 bytes each",
                ));
            }
        }
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => {
            validate_nonempty_secret(password, "Trojan")?;
            if let Some(ShadowsocksConfig::Legacy { password, .. }) = shadowsocks {
                validate_nonempty_secret(password, "Trojan Shadowsocks")?;
            }
        }
        ServerProxyConfig::Snell { password, .. }
        | ServerProxyConfig::Hysteria2 { password, .. }
        | ServerProxyConfig::TuicV5 { password, .. } => {
            validate_nonempty_secret(password, &protocol.to_string())?;
        }
        ServerProxyConfig::Shadowsocks { config, .. } => {
            if let ShadowsocksConfig::Legacy { password, .. } = config {
                validate_nonempty_secret(password, "Shadowsocks")?;
            }
            config.validate_key_len()?;
        }
        ServerProxyConfig::Anytls { users, .. } => {
            for user in users.iter() {
                validate_nonempty_secret(&user.password, "AnyTLS")?;
            }
        }
        ServerProxyConfig::Naiveproxy { users, .. } => {
            for user in users.iter() {
                validate_nonempty_secret(&user.password, "NaiveProxy")?;
            }
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
    context: ServerProtocolContext,
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    validate_server_auth(server_proxy_config)?;
    match server_proxy_config {
        ServerProxyConfig::Wireguard(_) => {
            return Err(super::types::wireguard::invalid(
                "WireGuard requires a top-level server protocol",
            ));
        }
        ServerProxyConfig::Hysteria2 { .. } | ServerProxyConfig::TuicV5 { .. }
            if context != ServerProtocolContext::Quic =>
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{server_proxy_config} requires a top-level QUIC listener"),
            ));
        }
        ServerProxyConfig::Xhttp(config) => {
            config.validate()?;
            validate_server_proxy_config(
                &mut config.protocol,
                client_groups,
                rule_groups,
                named_pems,
                ServerProtocolContext::Stream,
                global_limits,
            )?;
        }
        ServerProxyConfig::Anytls {
            padding_scheme: Some(lines),
            ..
        } => {
            crate::anytls::PaddingFactory::new(lines.join("\n").as_bytes())
                .map_err(std::io::Error::other)?;
        }
        ServerProxyConfig::Naiveproxy { .. } if context != ServerProtocolContext::Tls => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NaiveProxy must be used inside a TLS or Reality protocol. \
                 Configure it as the inner protocol of tls: or reality: targets.",
            ));
        }
        ServerProxyConfig::Vless {
            user_id,
            decryption,
            vision,
            encryption_limits,
            fallback,
            ..
        } => {
            parse_uuid(user_id)?;
            if decryption.is_disabled() {
                if *vision || encryption_limits.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "VLESS-level vision and encryption_limits require native decryption; for legacy Vision move vision: true to TLS/REALITY (older versions ignored it on VLESS)",
                    ));
                }
            } else {
                if fallback.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Native VLESS decryption does not support fallback",
                    ));
                }
                crate::vless::encryption::ServerEncryption::new(
                    decryption.as_str(),
                    encryption_limits.unwrap_or_default(),
                )?;
            }
        }
        ServerProxyConfig::Vmess {
            user_id, cipher, ..
        } => {
            parse_uuid(user_id)?;
            validate_vmess_cipher(cipher)?;
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
            for tls_server_config in tls_targets.values_mut() {
                tls_server_config
                    .key_exchange_groups
                    .validate_vision(tls_server_config.vision)?;
                validate_server_vision(tls_server_config.vision, &tls_server_config.protocol)?;
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }
                validate_server_certificates(
                    &tls_server_config.cert,
                    &tls_server_config.key,
                    &tls_server_config.client_ca_certs,
                    tls_server_config.certificate_binding.as_ref(),
                )?;

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
                    ServerProtocolContext::Tls,
                    global_limits,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        global_limits,
                    )?;
                }
            }
            if let Some(tls_server_config) = default_tls_target {
                tls_server_config
                    .key_exchange_groups
                    .validate_vision(tls_server_config.vision)?;
                validate_server_vision(tls_server_config.vision, &tls_server_config.protocol)?;
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }
                validate_server_certificates(
                    &tls_server_config.cert,
                    &tls_server_config.key,
                    &tls_server_config.client_ca_certs,
                    tls_server_config.certificate_binding.as_ref(),
                )?;
                validate_client_fingerprints(&mut tls_server_config.client_fingerprints)?;

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
                    ServerProtocolContext::Tls,
                    global_limits,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        global_limits,
                    )?;
                }
            }
            for (sni_hostname, tls_server_config) in shadowtls_targets.iter_mut() {
                validate_nonempty_secret(&tls_server_config.password, "ShadowTLS")?;
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
                    for cert in local_handshake.client_ca_certs.iter_mut() {
                        embed_pem_from_map(cert, named_pems);
                    }
                    validate_server_certificates(
                        &local_handshake.cert,
                        &local_handshake.key,
                        &local_handshake.client_ca_certs,
                        None,
                    )?;
                    validate_client_fingerprints(&mut local_handshake.client_fingerprints)?;
                } else if let ShadowTlsServerHandshakeConfig::Remote(remote_handshake) = handshake {
                    validate_client_chain(
                        &mut remote_handshake.client_chain,
                        0,
                        client_groups,
                        named_pems,
                        global_limits,
                    )?;
                }

                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    ServerProtocolContext::Stream,
                    global_limits,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        global_limits,
                    )?;
                }
            }

            for (sni_hostname, reality_config) in reality_targets.iter_mut() {
                validate_server_vision(reality_config.vision, &reality_config.protocol)?;
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
                if let Some(seed) = &reality_config.mldsa65_seed {
                    crate::reality::decode_mldsa65_seed(seed)?;
                }
                validate_reality_server_short_ids(&reality_config.short_ids, sni_hostname)?;

                if !reality_config.dest_client_chain.is_empty() {
                    let mut hops = OneOrSome::Some(
                        std::mem::take(&mut reality_config.dest_client_chain).into_vec(),
                    );
                    validate_client_chain(&mut hops, 0, client_groups, named_pems, global_limits)?;
                    reality_config.dest_client_chain = NoneOrSome::Some(hops.into_vec());
                }

                validate_server_proxy_config(
                    &mut reality_config.protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    ServerProtocolContext::Tls,
                    global_limits,
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
                        global_limits,
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
                    ServerProtocolContext::Stream,
                    global_limits,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        global_limits,
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
        ServerProxyConfig::Snell { cipher, .. } if cipher.starts_with("2022-blake3-") => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Snell does not support shadowsocks 2022 ciphers",
            ));
        }
        ServerProxyConfig::Snell { cipher, .. } => {
            crate::shadowsocks::ShadowsocksCipher::try_from(cipher.as_str())?;
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
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    config.resource_limits.validate()?;
    if config.segmentation_offload == Some(true)
        && (!cfg!(target_os = "linux")
            || config.device_fd.is_some()
            || config.packet_information == Some(true))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN segmentation offload requires a created Linux device without packet information",
        ));
    }
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
        validate_rule_config(rule, client_groups, named_pems, global_limits)?;
    }

    Ok(())
}

fn validate_rule_config(
    rule_config: &mut RuleConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    // Only generated defaults remain uncompiled; user predicates compile before expansion.
    rule_config.compile(&mut crate::rules::Compiler::default())?;
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

        for (chain_index, chain) in client_chains.iter_mut().enumerate() {
            validate_client_chain(
                &mut chain.hops,
                chain_index,
                client_groups,
                named_pems,
                global_limits,
            )?;
        }
    }

    Ok(())
}

fn validate_client_chain(
    hops: &mut OneOrSome<ClientChainHop>,
    chain_index: usize,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    for hop in hops.iter_mut() {
        validate_client_chain_hop(hop, client_groups, named_pems, global_limits)?;
    }
    expand_client_chain(hops, client_groups)?;
    validate_connector_positions(hops, chain_index)
}

/// Rejects connector protocols that cannot wrap an existing stream at later hops.
fn validate_connector_positions(
    hops: &OneOrSome<ClientChainHop>,
    chain_index: usize,
) -> std::io::Result<()> {
    for (hop_index, hop) in hops.iter().enumerate() {
        if hop_index == 0 {
            // Direct connectors are allowed at hop 0
            continue;
        }

        if hop_uses_wireguard(hop) {
            return Err(super::types::wireguard::invalid(
                "WireGuard is only supported at hop 0; configure peer_client_chain in the protocol for preceding proxies",
            ));
        }

        let unsupported_h3 = |selection: &ConfigSelection<ClientConfig>| {
            matches!(selection, ConfigSelection::Config(config)
                if config.transport == Transport::Quic && crate::xhttp::connector::contains(&config.protocol))
        };
        if match hop {
            ClientChainHop::Single(selection) => unsupported_h3(selection),
            ClientChainHop::Pool(selections) => selections.iter().any(unsupported_h3),
        } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H3 is only supported at hop 0",
            ));
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
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => {
            validate_and_expand_selection(selection, client_groups, named_pems, global_limits)?;
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                validate_and_expand_selection(selection, client_groups, named_pems, global_limits)?;
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
    global_limits: GlobalLimits,
) -> std::io::Result<()> {
    match selection {
        ConfigSelection::Config(client_config) => {
            expand_peer_chains(client_config, client_groups)?;
            validate_client_config(client_config, named_pems, global_limits)?;
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
                validate_client_config(&mut config, named_pems, global_limits)?;
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

    for (index, hop) in expanded_hops.iter().enumerate() {
        let validate = |selection: &ConfigSelection<ClientConfig>| match selection {
            ConfigSelection::Config(config) => config.validate_quic_key_exchange(index == 0),
            ConfigSelection::GroupName(_) => unreachable!("groups have been expanded"),
        };
        match hop {
            ClientChainHop::Single(selection) => validate(selection)?,
            ClientChainHop::Pool(selections) => {
                for selection in selections.iter() {
                    validate(selection)?;
                }
            }
        }
    }

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

    #[test]
    fn native_vless_configuration_rejects_ambiguous_vision_and_secrets() {
        use serde_json::json;

        const KEY: &str = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let client = json!({
            "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "encryption": format!("mlkem768x25519plus.native.0rtt.{KEY}"), "vision": true,
        });
        let server = json!({
            "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "decryption": format!("mlkem768x25519plus.native.600s.{KEY}"), "vision": true,
        });
        let mut client_config = serde_json::from_value(client.clone()).unwrap();
        validate_client_proxy_config(&mut client_config, &HashMap::new(), None).unwrap();
        for outer in ["TLS", "REALITY"] {
            let error = validate_client_vision_protocol(true, &client_config, outer).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("outer TLS/REALITY vision: false")
            );
            assert!(!error.to_string().contains(KEY));
            validate_client_vision_protocol(false, &client_config, outer).unwrap();
        }
        let validate_server = |value: serde_json::Value| {
            let mut config = serde_json::from_value(value).unwrap();
            validate_server_proxy_config(
                &mut config,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                ServerProtocolContext::Stream,
                GlobalLimits::default(),
            )?;
            Ok::<_, std::io::Error>(config)
        };
        let server_config = validate_server(server.clone()).unwrap();
        assert!(
            validate_server_vision(true, &server_config)
                .unwrap_err()
                .to_string()
                .contains("outer TLS/REALITY vision: false")
        );
        validate_server_vision(false, &server_config).unwrap();
        for (key, value) in [
            ("encryption", json!("none")),
            ("encryption", json!("invalid-secret-do-not-log")),
            ("h2mux", json!({})),
        ] {
            let mut value_config = client.clone();
            value_config[key] = value;
            let mut config = serde_json::from_value(value_config).unwrap();
            let error =
                validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap_err();
            assert!(!error.to_string().contains("do-not-log"));
            assert!(!format!("{config:?}").contains("do-not-log"));
        }
        for (key, value) in [
            ("decryption", json!("none")),
            ("decryption", json!("invalid-secret-do-not-log")),
            ("fallback", json!("127.0.0.1:80")),
            ("encryption_limits", json!({"max_replays": 0})),
        ] {
            let mut config = server.clone();
            config[key] = value;
            let error = validate_server(config).unwrap_err();
            assert!(!error.to_string().contains("do-not-log"));
        }
        for disabled in ["", "none"] {
            let mut config = client.clone();
            config["encryption"] = json!(disabled);
            config["vision"] = json!(false);
            let mut config = serde_json::from_value(config).unwrap();
            validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap();
            validate_client_vision_protocol(true, &config, "TLS").unwrap();
            let mut config = server.clone();
            config["decryption"] = json!(disabled);
            config["vision"] = json!(false);
            validate_server_vision(true, &validate_server(config).unwrap()).unwrap();
        }
    }

    #[test]
    fn server_secrets_must_be_nonempty() {
        use serde_json::json;
        for mut value in [
            json!({"type": "trojan", "password": ""}),
            json!({"type": "snell", "cipher": "aes-128-gcm", "password": ""}),
            json!({"type": "shadowsocks", "cipher": "aes-128-gcm", "password": ""}),
            json!({"type": "hysteria2", "password": ""}),
            json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": ""}),
        ] {
            for password in ["", "do-not-log-this-secret", " "] {
                value["password"] = json!(password);
                let protocol = serde_json::from_value(value.clone()).unwrap();
                let result = validate_server_auth(&protocol);
                assert_eq!(result.is_ok(), !password.is_empty());
                if let Err(error) = result {
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                    assert!(!error.to_string().contains("do-not-log-this-secret"));
                }
            }
        }
        for password in ["", "do-not-log-this-secret"] {
            let protocol = serde_json::from_value(json!({
                "type": "trojan", "password": "do-not-log-this-secret",
                "shadowsocks": {"cipher": "aes-128-gcm", "password": password}
            }))
            .unwrap();
            assert_eq!(
                validate_server_auth(&protocol).is_ok(),
                !password.is_empty()
            );
            for protocol_type in ["anytls", "naive"] {
                let mut user = json!({"password": password});
                if protocol_type == "naive" {
                    user["username"] = json!("user");
                }
                let mut valid_user = user.clone();
                valid_user["password"] = json!("do-not-log-this-secret");
                for users in [user.clone(), json!([valid_user, user])] {
                    let protocol = serde_json::from_value(json!({
                        "type": protocol_type, "users": users
                    }))
                    .unwrap();
                    let result = validate_server_auth(&protocol);
                    assert_eq!(result.is_ok(), !password.is_empty());
                    if let Err(error) = result {
                        assert!(!error.to_string().contains("do-not-log-this-secret"));
                    }
                }
            }
        }
        let protocol = ServerProxyConfig::Shadowsocks {
            config: ShadowsocksConfig::Aead2022 {
                cipher: "aes-128-gcm".try_into().unwrap(),
                key_bytes: vec![0; 1].into_boxed_slice(),
            },
            udp_enabled: true,
        };
        assert!(validate_server_auth(&protocol).is_err());
    }

    #[test]
    fn optional_server_auth_preserves_no_auth_and_http_empty_username() {
        use serde_json::json;
        for protocol_type in ["http", "socks", "mixed"] {
            for (username, password, http_valid, socks_valid) in [
                (None, None, true, true),
                (Some("user"), Some("secret"), true, true),
                (None, Some("secret"), true, false),
                (Some(""), Some("secret"), true, false),
                (Some("user"), None, false, false),
                (Some("user"), Some(""), false, false),
                (None, Some(""), false, false),
                (Some(""), None, false, false),
                (Some(""), Some(""), false, false),
            ] {
                let protocol = serde_json::from_value(json!({
                    "type": protocol_type, "username": username, "password": password
                }))
                .unwrap();
                assert_eq!(
                    validate_server_auth(&protocol).is_ok(),
                    if protocol_type == "http" {
                        http_valid
                    } else {
                        socks_valid
                    },
                    "{protocol_type}: {username:?}, {password:?}"
                );
            }
            for value in [
                "a".to_string(),
                "a".repeat(255),
                "a".repeat(256),
                format!("{}a", "\u{e9}".repeat(127)),
                "\u{e9}".repeat(128),
            ] {
                for field in ["username", "password"] {
                    let mut protocol = json!({
                        "type": protocol_type, "username": "user", "password": "secret"
                    });
                    protocol[field] = json!(value);
                    let protocol = serde_json::from_value(protocol).unwrap();
                    assert_eq!(
                        validate_server_auth(&protocol).is_ok(),
                        protocol_type == "http" || value.len() <= 255,
                        "{protocol_type}: {field}, {} bytes",
                        value.len()
                    );
                }
            }
        }
    }

    #[test]
    fn server_protocol_context_enforces_transport_and_termination() {
        use serde_json::json;
        for (value, valid_context) in [
            (
                json!({"type": "hysteria2", "password": "secret"}),
                ServerProtocolContext::Quic,
            ),
            (
                json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
                ServerProtocolContext::Quic,
            ),
            (
                json!({"type": "naive", "users": [{"username": "user", "password": "secret"}]}),
                ServerProtocolContext::Tls,
            ),
        ] {
            for context in [
                ServerProtocolContext::Stream,
                ServerProtocolContext::Tls,
                ServerProtocolContext::Quic,
            ] {
                let mut protocol = serde_json::from_value(value.clone()).unwrap();
                let result = validate_server_proxy_config(
                    &mut protocol,
                    &HashMap::new(),
                    &HashMap::new(),
                    &HashMap::new(),
                    context,
                    GlobalLimits::default(),
                );
                assert_eq!(result.is_ok(), context == valid_context);
                if let Err(error) = result {
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                    assert!(!error.to_string().contains("secret"));
                }
            }
        }
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        for protocol in [
            json!({"type": "hysteria2", "password": "secret"}),
            json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
        ] {
            let configs = serde_json::from_value(json!([{
                "address": "127.0.0.1:9000", "transport": "quic", "protocol": protocol,
                "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
            }]))
            .unwrap();
            assert!(create_server_configs(configs).is_ok());
        }
    }

    #[test]
    fn nested_structure_errors_precede_protocol_field_errors() {
        let mut config = serde_json::from_value(serde_json::json!({
            "address": "example.com:443",
            "protocol": {
                "type": "reality", "public_key": "invalid",
                "protocol": {"type": "websocket", "protocol": {"type": "direct"}}
            }
        }))
        .unwrap();
        let error = validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default())
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "direct cannot be used as an inner proxy protocol"
        );
    }

    #[test]
    fn tls_sni_distinguishes_inheritance_disable_and_override() {
        for (sni, valid) in [
            (NoneOrOne::Unspecified, false),
            (NoneOrOne::None, true),
            (NoneOrOne::One("example.com".to_owned()), true),
            (NoneOrOne::One("invalid name".to_owned()), false),
        ] {
            let mut protocol = serde_json::from_value(serde_json::json!({
                "type": "tls", "protocol": {"type": "socks"}
            }))
            .unwrap();
            let ClientProxyConfig::Tls(ref mut tls) = protocol else {
                unreachable!()
            };
            tls.sni_hostname = sni;
            assert_eq!(
                validate_client_proxy_config(&mut protocol, &HashMap::new(), Some("invalid name"))
                    .is_ok(),
                valid,
            );
        }
    }

    #[test]
    fn reality_sni_defaults_only_at_the_outer_client_layer() {
        let protocol = serde_json::json!({
            "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "protocol": {"type": "socks"}
        });
        for (address, protocol, valid) in [
            ("example.com:443", protocol.clone(), true),
            ("127.0.0.1:443", protocol.clone(), false),
            (
                "example.com:443",
                serde_json::json!({"type": "websocket", "protocol": protocol}),
                false,
            ),
        ] {
            let mut config: ClientConfig = serde_json::from_value(serde_json::json!({
                "address": address, "protocol": protocol
            }))
            .unwrap();
            assert_eq!(
                validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default())
                    .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn reality_mldsa_client_key_validation() {
        let (_, valid) = crate::reality::generate_mldsa65_keypair().unwrap();
        for (key, expected) in [
            (None, true),
            (Some(valid.as_str()), true),
            (Some(""), false),
            (Some("AA"), false),
            (Some("invalid!"), false),
        ] {
            let mut value = serde_json::json!({
                "address": "cover.test:443", "protocol": {
                    "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "protocol": {"type": "socks"}
                }
            });
            if let Some(key) = key {
                value["protocol"]["mldsa65_verify"] = key.into();
            }
            let mut config: ClientConfig = serde_json::from_value(value).unwrap();
            assert_eq!(
                validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default())
                    .is_ok(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn reality_mldsa_server_seed_validation() {
        let (valid, _) = crate::reality::generate_mldsa65_keypair().unwrap();
        for (seed, expected) in [
            (None, true),
            (Some(valid.as_str()), true),
            (Some(""), false),
            (Some("AA"), false),
            (Some("invalid!"), false),
        ] {
            let mut value = serde_json::json!({
                "address": "0.0.0.0:4443", "protocol": {"type": "tls", "reality_targets": {
                    "cover.test": {"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "dest": "cover.test:443", "protocol": {"type": "socks"}}
                }}
            });
            if let Some(seed) = seed {
                value["protocol"]["reality_targets"]["cover.test"]["mldsa65_seed"] = seed.into();
            }
            let result = validate_configs_test(vec![serde_json::from_value(value).unwrap()]).await;
            assert_eq!(result.is_ok(), expected, "{result:?}");
        }
    }

    async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<Config>> {
        let (converted_configs, _) = convert_cert_paths(configs).await?;
        let validated = create_server_configs(converted_configs)?;
        Ok(validated.configs)
    }

    #[test]
    fn xhttp_split_capacity_uses_candidate_global_stream_limit() {
        use serde_json::json;

        for version in ["h1", "h2", "h3"] {
            for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
                for connections in [1, 2] {
                    for stream_limit in [None, Some(1), Some(2)] {
                        let client = json!({
                            "address": "127.0.0.1:443",
                            "transport": if version == "h3" { "quic" } else { "tcp" },
                            "protocol": {
                                "type": "xhttp", "http_version": version, "mode": mode,
                                "pool": {"max_connections": connections, "max_h1_connections": 2},
                                "limits": {"max_requests_per_connection": 2},
                                "protocol": {"type": "socks"}
                            }
                        });
                        let rules = json!([{"masks": "0.0.0.0/0", "action": "allow", "client_chain": client}]);
                        let entries = [
                            json!({"client_group": "proxy", "client_proxies": client}),
                            json!({"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "rules": rules}),
                            json!({"dns_group": "dns", "dns_servers": [{"url": "https://1.1.1.1/dns-query", "client_chain": client}]}),
                            json!({"device_fd": 1, "rules": rules}),
                            json!({"address": "0.0.0.0:1080", "protocol": {"type": "websocket", "targets": [{"protocol": {"type": "socks"}, "override_rules": rules}]}}),
                        ];
                        for entry in entries {
                            let configs = serde_json::from_value(json!([
                                entry,
                                {"global_limits": {"max_streams_per_connection": stream_limit}}
                            ]))
                            .unwrap();
                            let result = create_server_configs(configs);
                            let valid = version == "h1"
                                || mode == "stream-one"
                                || connections == 2
                                || stream_limit != Some(1);
                            assert_eq!(
                                result.is_ok(),
                                valid,
                                "version={version}, mode={mode}, connections={connections}, stream_limit={stream_limit:?}, entry={entry}: {:?}",
                                result.as_ref().err()
                            );
                            if let Err(error) = result {
                                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                                assert!(error.to_string().contains("at least two request lanes"));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn hybrid_only_rejects_vision_and_tuic_early_handshakes() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls_target = serde_json::json!({
            "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
            "key_exchange_groups": ["X25519MLKEM768"], "vision": true,
            "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
        });
        for protocol in [
            serde_json::json!({"type": "tls", "tls_targets": {"localhost": tls_target}}),
            serde_json::json!({"type": "tls", "default_tls_target": tls_target}),
        ] {
            let mut server: ServerProxyConfig = serde_json::from_value(protocol).unwrap();
            let error = validate_server_proxy_config(
                &mut server,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                ServerProtocolContext::Stream,
                GlobalLimits::default(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("hybrid-only"), "{error}");
        }
        let client: ClientProxyConfig = serde_json::from_value(serde_json::json!({
            "type": "tls", "key_exchange_groups": ["SecP256r1MLKEM768"], "vision": true,
            "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
        }))
        .unwrap();
        assert!(
            validate_client_proxy_structure(&client)
                .unwrap_err()
                .to_string()
                .contains("hybrid-only")
        );
        let mut server: ServerConfig = serde_json::from_value(serde_json::json!({
            "address": "0.0.0.0:443", "transport": "quic",
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "key_exchange_groups": ["X25519MLKEM768"]},
            "protocol": {"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "test", "zero_rtt_handshake": true}
        })).unwrap();
        assert!(
            validate_server_config(
                &mut server,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                GlobalLimits::default(),
            )
            .unwrap_err()
            .to_string()
            .contains("zero_rtt_handshake")
        );
    }

    #[test]
    fn quic_allowlists_cannot_be_ignored_by_direct_or_later_hops() {
        use serde_json::json;
        for groups in [
            None,
            Some(json!(["X25519MLKEM768"])),
            Some(json!(["X25519"])),
        ] {
            let mut settings = json!({});
            if let Some(ref groups) = groups {
                settings["key_exchange_groups"] = groups.clone();
            }
            let direct = json!({"protocol": {"type": "direct"}, "transport": "quic", "quic_settings": settings});
            let mut config: ClientConfig = serde_json::from_value(direct).unwrap();
            let result =
                validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default());
            assert_eq!(result.is_err(), groups.is_some());

            let proxy = json!({"address": "127.0.0.1:443", "protocol": {"type": "socks"}, "transport": "quic", "quic_settings": settings});
            let group_configs = HashMap::from([(
                "proxy".into(),
                vec![serde_json::from_value::<ClientConfig>(proxy.clone()).unwrap()],
            )]);
            for hop in [
                proxy.clone(),
                json!("proxy"),
                json!({"pool": ["proxy", proxy.clone()]}),
            ] {
                let direct = json!({"protocol": {"type": "direct"}});
                for chain in [json!([hop]), json!([direct, hop])] {
                    let later_hop = chain.as_array().unwrap().len() > 1;
                    let mut parsed: super::super::types::ClientChain =
                        serde_json::from_value(chain.clone()).unwrap();
                    let result = validate_client_chain(
                        &mut parsed.hops,
                        0,
                        &group_configs,
                        &HashMap::new(),
                        GlobalLimits::default(),
                    );
                    assert_eq!(result.is_err(), later_hop && groups.is_some(), "{chain}");
                    if let Err(error) = result {
                        assert!(error.to_string().contains("QUIC key_exchange_groups"));
                    }
                    let spec: DnsServerSpec = serde_json::from_value(json!({
                        "url": "https://1.1.1.1/dns-query", "client_chain": {"chain": chain}
                    }))
                    .unwrap();
                    let result = expand_dns_specs(
                        &[spec],
                        &group_configs,
                        &HashMap::new(),
                        &HashSet::new(),
                        GlobalLimits::default(),
                    );
                    assert_eq!(result.is_err(), later_hop && groups.is_some());
                    if let Err(error) = result {
                        assert!(error.to_string().contains("QUIC key_exchange_groups"));
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_validate_config_success() {
        use crate::config::types::ClientConfigGroup;
        use crate::config::types::groups::RuleConfigGroup;

        let configs = vec![
            Config::RuleConfigGroup(RuleConfigGroup {
                rule_group: "test-rules".to_string(),
                rules: crate::config::RuleGroupRules::Policies(Box::new(OneOrSome::One(
                    RuleConfig {
                        criteria: Default::default(),
                        action: RuleActionConfig::Allow {
                            override_address: None,
                            client_chains: NoneOrSome::One(ClientChain::default()),
                        },
                    },
                ))),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
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
                group_type: Default::default(),
                default: None,
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
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
                group_type: Default::default(),
                default: None,
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
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
            group_type: Default::default(),
            default: None,
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
                group_type: Default::default(),
                default: None,
                client_group: "group-d".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
                client_group: "group-c".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
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
                group_type: Default::default(),
                default: None,
                client_group: "us-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
                client_group: "eu-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
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

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = certificate.cert.pem();
        let key_pem = certificate.signing_key.serialize_pem();
        let test_cert = cert_pem.as_str();
        let test_key = key_pem.as_str();

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
                cipher: any
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

        assert!(validate_connector_positions(&hops, 0).is_ok());
    }

    fn http_proxy_config() -> ClientProxyConfig {
        ClientProxyConfig::Http {
            username: None,
            password: None,
            resolve_hostname: false,
            http_version: Default::default(),
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

        assert!(validate_connector_positions(&hops, 0).is_ok());
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

        assert!(validate_connector_positions(&hops, 0).is_ok());
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

        let result = validate_connector_positions(&hops, 0);
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

        let result = validate_connector_positions(&hops, 0);
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

        assert!(validate_connector_positions(&hops, 0).is_ok());
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

        let result = validate_connector_positions(&hops, 0);
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

        assert!(validate_connector_positions(&hops, 0).is_ok());
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
            name: None,
            sniff: false,
            segmentation_offload: None,
            resource_limits: Default::default(),
            packet_information: None,
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
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "system".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::Config(ClientChain::default())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
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
        let socks_config = ClientConfig {
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                group_type: Default::default(),
                default: None,
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_h3_with_proxy_chain_rejected() {
        use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

        // Create a non-direct (socks5) chain - should be rejected for H3.
        let socks_config = ClientConfig {
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                group_type: Default::default(),
                default: None,
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                group_type: Default::default(),
                default: None,
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                group_type: Default::default(),
                default: None,
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tcp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                group_type: Default::default(),
                default: None,
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tls://1.1.1.1".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                group_type: Default::default(),
                default: None,
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "https://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
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
                fake_ip: None,
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("udp://8.8.8.8".to_string()),
                    DnsServerSpec::Simple("udp://8.8.4.4".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
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
                fake_ip: None,
                dns_group: "level-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "level-b".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("level-a".to_string()),
                    DnsServerSpec::Simple("udp://1.1.1.1".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
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
                fake_ip: None,
                dns_group: "group-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-b".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
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
            fake_ip: None,
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
                fake_ip: None,
                dns_group: "bootstrap-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tls://1.1.1.1".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "full-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // Composition reference
                    DnsServerSpec::WithOptions {
                        url: "tls://8.8.4.4".to_string(), // IP-based, no resolution needed
                        client_chain: NoneOrSome::None,
                        bootstrap_url: Some("bootstrap-dns".to_string()), // Bootstrap reference (not used since URL is IP)
                        server_name: Some("dns.google".to_string()),      // SNI override
                        ip_strategy: IpStrategy::default(),
                        timeout_secs: 10,
                        connect_timeout_secs: 5,
                        attempts: 1,
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
    async fn test_empty_dns_lists_use_default_resolver() {
        use serde_json::json;

        let configs = serde_json::from_value(json!([
            {"address": "127.0.0.1:1080", "protocol": {"type": "socks"}, "dns": {"servers": []}},
            {"device_fd": 42, "dns": {"servers": []}},
        ]))
        .unwrap();
        let configs = validate_configs_test(configs).await.unwrap();
        assert_eq!(configs.len(), 2);
        for config in configs {
            let dns = match config {
                Config::Server(server) => server.dns.unwrap(),
                Config::TunServer(tun) => tun.dns.unwrap(),
                _ => unreachable!(),
            };
            assert!(matches!(dns.servers, NoneOrSome::None));
            assert_eq!(dns.resolved_group(), None);
        }
    }

    #[tokio::test]
    async fn test_server_dns_with_group_ref() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config references an existing dns_group
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "my-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                name: None,
                sniff: false,
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    fake_ip: None,
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
                fake_ip: None,
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                name: None,
                sniff: false,
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    fake_ip: None,
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
                fake_ip: None,
                dns_group: "fast-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                fake_ip: None,
                dns_group: "secure-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tcp://1.1.1.1".to_string())),
            }),
            Config::Server(ServerConfig {
                name: None,
                sniff: false,
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    fake_ip: None,
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
            name: None,
            sniff: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                fake_ip: None,
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
