//! Configuration validation - validates configs and creates final ServerConfigs.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::dns::ParsedDnsUrl;
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};
use crate::reality::{decode_private_key, decode_short_id};
use crate::thread_util::get_num_threads;
use crate::uuid_util::parse_uuid;

use super::compiler::{self, DraftClient};
use super::plan_ops;
use super::resolved::*;

use super::pem::{embed_optional_pem_from_map, embed_pem_from_map};
use super::types::{
    BindLocation, ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config,
    ConfigSelection, DEFAULT_REALITY_SHORT_ID, DnsConfig, DnsConfigGroup, DnsServerSpec,
    ExpandedDnsGroup, ExpandedDnsSpec, GlobalLimits, PemSource, RuleActionConfig, RuleConfig,
    ServerConfig, ServerProxyConfig, ServerQuicConfig, ShadowTlsServerHandshakeConfig,
    ShadowsocksConfig, TlsServerConfig, Transport, TunConfig, direct_allow_rule,
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
    pub configs: Vec<ResolvedConfig>,
    /// Expanded DNS groups in topological order (bootstrap deps first).
    pub dns_groups: Vec<ExpandedDnsGroup>,
    pub wireguard_endpoints: Vec<super::types::wireguard::WireguardDeviceConfig>,
    pub(crate) remote_rules: Vec<crate::rule_set::ResolvedRuleSource>,
    pub(crate) rule_cache_dir: Option<std::path::PathBuf>,
}

impl ValidatedConfigs {
    #[cfg(any(target_os = "android", target_os = "ios", feature = "ffi", test))]
    pub(crate) fn validate_ffi_support(&self) -> std::io::Result<()> {
        if self
            .configs
            .iter()
            .any(|config| matches!(config, ResolvedConfig::TunServer(tun) if tun.auto_route))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "managed TUN requires the CLI process lifecycle; FFI hosts must manage their own network",
            ));
        }
        self.control.reject_ffi()?;
        if self
            .catalog
            .as_ref()
            .is_some_and(|catalog| !catalog.selection.automatic.0.is_empty())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "url-test groups require the process runtime and are not supported by FFI",
            ));
        }
        Ok(())
    }
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
    create_server_configs_with_memory(all_configs, None)
}

pub(super) fn create_server_configs_with_memory(
    mut all_configs: Vec<Config>,
    memory: Option<crate::rule_set::MemorySources>,
) -> std::io::Result<ValidatedConfigs> {
    crate::rule_set::validate_remote_paths(&mut all_configs, &[])?;
    let rule_cache_dir = crate::rule_set::cache_directory(&all_configs)?;

    let certificates = crate::certificates::configure(&mut all_configs)?;
    let mut catalog = crate::control::catalog::CatalogDraft::capture(&mut all_configs)?;
    let mut control = super::ControlConfig::default();
    let mut compiler = crate::rules::Compiler::default();
    compiler.memory = memory.or_else(|| rule_cache_dir.is_none().then(Default::default));
    let mut reload_files = crate::rule_set::dependencies(&mut all_configs)?;
    reload_files.extend(super::pem_reload_dependencies(&mut all_configs)?);
    let remote_rules = crate::rule_set::normalize_sources(&mut all_configs, &mut compiler)?;
    crate::rule_set::load(&mut all_configs, &mut compiler)?;
    super::rule_visit::compile(&mut all_configs, &mut compiler)?;
    let mut global_limits = None;
    // First pass: collect raw groups with unresolved references
    let mut raw_client_groups: HashMap<
        String,
        (super::GroupType, OneOrSome<super::ClientGroupMember>),
    > = HashMap::new();
    raw_client_groups.insert(
        String::from("direct"),
        (
            super::GroupType::RoundRobin,
            OneOrSome::One(super::ClientGroupMember::Client(ConfigSelection::Config(
                direct_client(catalog.as_ref()),
            ))),
        ),
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
            Config::CertificateSource(_) | Config::RuleSourceGroup(_) => {}
            Config::GlobalSettings(settings) => {
                let limits = settings.limits;
                if global_limits.replace(limits).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "global_settings may only be specified once across all config files",
                    ));
                }
                limits.validate()?;
            }
            Config::ClientConfigGroup(group) => {
                if raw_client_groups
                    .insert(
                        group.client_group.clone(),
                        (group.group_type, group.client_chains),
                    )
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

    let global_limits = global_limits.unwrap_or_default();

    // Resolve client groups using topological sort
    let mut client_groups = resolve_client_groups_topologically(raw_client_groups)?;

    client_groups = client_groups
        .into_iter()
        .map(|(name, hop)| {
            let hop = plan_ops::map_hop(hop, &mut |client| {
                compiler::lower_client(client, &named_pems, global_limits).map(DraftClient::Ready)
            })?;
            Ok((name, hop))
        })
        .collect::<std::io::Result<_>>()?;

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

    let remote_rules = resolve_rule_downloads(
        remote_rules,
        &client_groups,
        &named_pems,
        &group_names,
        global_limits,
    )?;

    let mut result = Vec::new();
    for config in server_configs {
        let dns = config.dns.clone();
        let config = resolve_server_config(
            config,
            &client_groups,
            &rule_groups,
            &named_pems,
            global_limits,
        )?;
        validate_dns_group_ref(&dns, &group_names)?;
        result.push(ResolvedConfig::Server(config));
    }
    for config in tun_configs {
        let dns = config.dns.clone();
        let config = resolve_tun_config(
            config,
            &client_groups,
            &rule_groups,
            &named_pems,
            global_limits,
        )?;
        validate_dns_group_ref(&dns, &group_names)?;
        result.push(ResolvedConfig::TunServer(config));
    }
    crate::desktop::validate_config(&result)?;
    if result
        .iter()
        .any(|config| matches!(config, ResolvedConfig::TunServer(tun) if tun.auto_route))
    {
        let binds = result
            .iter()
            .filter_map(|config| match config {
                ResolvedConfig::Server(server) => Some(&server.bind_location),
                _ => None,
            })
            .chain(control.listeners.iter().map(|listener| &listener.bind));
        for bind in binds {
            if let BindLocation::Address(addresses) = bind
                && addresses.iter().any(|address| !address.is_literal())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "managed TUN requires literal listener addresses; native hostname lookup is disabled",
                ));
            }
        }
    }

    let mut evaluation_work = 0usize;
    for rule in super::resolved_visit::rules(&result) {
        let predicate = rule
            .criteria
            .compiled
            .as_ref()
            .ok_or_else(|| crate::rules::invalid("rule is missing its compiled predicate"))?;
        evaluation_work = evaluation_work.saturating_add(predicate.evaluation_work);
        if evaluation_work > crate::rules::MAX_ENTRIES {
            return Err(crate::rules::invalid(
                "expanded rule evaluation budget exceeded",
            ));
        }
    }

    let mut validated = ValidatedConfigs {
        catalog: None,
        control,
        certificates,
        reload_files,
        global_limits,
        configs: result,
        dns_groups: final_dns_groups,
        wireguard_endpoints: Vec::new(),
        remote_rules,
        rule_cache_dir,
    };
    validate_wireguard_dns(&validated)?;
    #[cfg(unix)]
    super::wireguard_devices::collect_devices(&mut validated, &mut client_groups, &mut catalog)?;
    super::fake_dns::validate(
        &mut validated,
        catalog.as_ref().map(|catalog| catalog.selection.as_ref()),
    )?;
    refresh_catalog_clients(&mut validated, &client_groups, &mut catalog)?;
    validated.catalog = catalog
        .map(|catalog| {
            catalog.finish(|client| {
                compiler::compile_client(client, &client_groups, &named_pems, global_limits)
            })
        })
        .transpose()?;
    Ok(validated)
}

fn resolve_rule_downloads(
    sources: Vec<crate::rule_set::RuleSource>,
    clients: &compiler::Groups,
    pems: &HashMap<String, String>,
    dns_names: &HashSet<&str>,
    limits: GlobalLimits,
) -> std::io::Result<Vec<crate::rule_set::ResolvedRuleSource>> {
    sources
        .into_iter()
        .map(|source| {
            let source = source
                .map_chain(|chain| compiler::compile_chain(chain.hops, clients, pems, limits))?;
            let download = source.download.as_ref().expect("remote source checked");
            if chain_uses_wireguard(&download.client_chain) {
                return Err(crate::rules::invalid(
                    "rule downloads cannot bootstrap through WireGuard devices",
                ));
            }
            if !dns_names.contains(download.bootstrap_url.as_str()) {
                let parsed = ParsedDnsUrl::parse(&download.bootstrap_url)
                    .map_err(|_| crate::rules::invalid("invalid rule download bootstrap_url"))?;
                if parsed.has_hostname() {
                    return Err(crate::rules::invalid(
                        "rule download bootstrap_url requires an IP URL, system, or DNS group",
                    ));
                }
            }
            Ok(source)
        })
        .collect()
}

#[cfg(unix)]
pub(crate) fn validate_rule_bootstrap(
    configs: &[Config],
    sources: Vec<crate::rule_set::RuleSource>,
) -> std::io::Result<(GlobalLimits, Vec<crate::rule_set::ResolvedRuleSource>)> {
    use crate::rules::invalid;

    let mut limits = None;
    let mut pems = HashMap::new();
    let mut dns_names = HashSet::new();
    for config in configs {
        match config {
            Config::GlobalSettings(settings) => {
                settings.limits.validate()?;
                if limits.replace(settings.limits).is_some() {
                    return Err(invalid("global_settings may only be specified once"));
                }
            }
            Config::NamedPem(pem) => {
                let PemSource::Data(data) = &pem.source else {
                    return Err(invalid(
                        "bootstrap PEM paths must be loaded before validation",
                    ));
                };
                if pems.insert(pem.pem.clone(), data.clone()).is_some() {
                    return Err(invalid("named pem already exists"));
                }
            }
            Config::DnsConfigGroup(group) => {
                dns_names.insert(group.dns_group.as_str());
            }
            Config::ClientConfigGroup(group) if group.client_group == "direct" => {
                return Err(invalid("client group already exists: direct"));
            }
            _ => {}
        }
    }
    let limits = limits.unwrap_or_default();
    let clients = HashMap::from([(
        "direct".into(),
        HopPlan::Single(compiler::DraftClient::Ready(ResolvedClientConfig::default())),
    )]);
    let mut resolved = Vec::with_capacity(sources.len());
    for source in sources {
        let path = source.path.clone();
        let result = (|| {
            let download = source.download.as_ref().expect("remote source checked");
            if dns_names.contains(download.bootstrap_url.as_str()) {
                return Err(invalid(
                    "named DNS groups are not supported for missing-cache bootstrap",
                ));
            }
            let dns = ParsedDnsUrl::parse(&download.bootstrap_url)
                .map_err(|_| invalid("invalid rule bootstrap_url"))?;
            if dns.has_hostname() || matches!(dns, ParsedDnsUrl::H3 { .. }) {
                return Err(invalid(
                    "missing-cache bootstrap requires system or an IP-based UDP/TCP/TLS/HTTPS DNS URL",
                ));
            }
            for hop in download.client_chain.hops.iter() {
                for member in hop.selections() {
                    match member {
                        ConfigSelection::GroupName(name) if name == "direct" => {}
                        ConfigSelection::Config(client)
                            if client.transport == Transport::Tcp
                                && !client.protocol.is_wireguard()
                                && client.control.is_none() => {}
                        _ => {
                            return Err(invalid(
                                "missing-cache bootstrap supports only direct and inline TCP clients; named client groups, selectors, WireGuard and QUIC are unsupported",
                            ));
                        }
                    }
                }
            }
            source.map_chain(|chain| compiler::compile_chain(chain.hops, &clients, &pems, limits))
        })();
        resolved.push(result.map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("rule bootstrap {}: {error}", path.display()),
            )
        })?);
    }
    Ok((limits, resolved))
}

fn direct_client(catalog: Option<&crate::control::catalog::CatalogDraft>) -> ClientConfig {
    let mut direct = ClientConfig::default();
    if let Some(catalog) = catalog {
        direct.control = Some(crate::control::catalog::MemberOrigin {
            name: std::sync::Arc::from("DIRECT"),
            path: Vec::new(),
            selection: catalog.selection.clone(),
        });
    }
    direct
}

pub(super) fn refresh_catalog_clients(
    validated: &mut ValidatedConfigs,
    groups: &compiler::Groups,
    catalog: &mut Option<crate::control::catalog::CatalogDraft>,
) -> std::io::Result<()> {
    if let Some(catalog) = catalog {
        for group in groups.values() {
            for client in plan_ops::clients(group) {
                catalog.update_client(client.resolved());
            }
        }
        validated.visit_clients(&mut |client| {
            catalog.update_client(client);
            Ok(())
        })?;
    }
    Ok(())
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
    if validated
        .remote_rules
        .iter()
        .filter_map(|source| source.download.as_ref())
        .any(|download| tunnel_dns.contains(download.bootstrap_url.as_str()))
    {
        return Err(crate::rules::invalid(
            "rule download bootstrap cannot depend on WireGuard",
        ));
    }
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
    mut raw_groups: HashMap<String, (super::GroupType, OneOrSome<super::ClientGroupMember>)>,
) -> std::io::Result<compiler::Groups> {
    let mut dependencies = HashMap::new();
    for (name, (_, members)) in &raw_groups {
        let mut deps = Vec::new();
        for member in members.iter() {
            match member {
                super::ClientGroupMember::Client(client) => {
                    collect_client_dependencies(client, &mut deps);
                }
                super::ClientGroupMember::Chain { chain, .. } => {
                    for hop in chain.hops.iter() {
                        collect_hop_dependencies(hop, &mut deps);
                    }
                }
            }
        }
        for dep in &deps {
            if !raw_groups.contains_key(dep) {
                return Err(super::composition::invalid(format!(
                    "Client group '{name}' references unknown group '{dep}'"
                )));
            }
        }
        dependencies.insert(name.clone(), deps);
    }
    let mut resolved = compiler::Groups::new();
    for name in topological_sort(&dependencies)? {
        let (kind, raw_members) = raw_groups.remove(&name).expect("sorted group exists");
        let mut labels = Vec::new();
        let mut members = Vec::new();
        let mut budget = compiler::NodeBudget::default();
        for (index, member) in raw_members.into_vec().into_iter().enumerate() {
            let label = crate::control::catalog::group_member_name(&member)
                .unwrap_or_else(|| format!("{name}-chain-{}", index + 1));
            let chain = member.into_chain();
            let mut chain = compiler::expand(chain.hops, &resolved, &mut budget)?;
            for hop in chain.hops.iter_mut() {
                prepend_origin(hop, &name, &label)?;
            }
            labels.push(label);
            members.push(chain);
        }
        let hop = if kind == super::GroupType::RoundRobin
            && members.len() == 1
            && members[0].hops.iter().count() == 1
        {
            members.remove(0).hops.into_vec().remove(0)
        } else {
            budget.charge(1)?;
            HopPlan::Choice(Box::new(ChoicePlan {
                name: name.clone(),
                group_type: kind,
                labels,
                members,
            }))
        };
        compiler::measure(&hop, 0)?;
        resolved.insert(name, hop);
    }
    Ok(resolved)
}

fn prepend_origin(
    hop: &mut HopPlan<DraftClient>,
    group: &str,
    member: &str,
) -> std::io::Result<()> {
    if group == "direct" {
        return Ok(());
    }
    plan_ops::visit_leaves(hop, &mut |client| {
        if let Some(origin) = client.origin_mut() {
            origin.path.insert(0, (group.to_owned(), member.to_owned()));
        }
        Ok(())
    })
}

fn collect_hop_dependencies(hop: &ClientChainHop, dependencies: &mut Vec<String>) {
    match hop {
        ClientChainHop::Single(selection) => collect_client_dependencies(selection, dependencies),
        ClientChainHop::Pool(pool) => {
            for selection in pool.iter() {
                collect_client_dependencies(selection, dependencies);
            }
        }
    }
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
                    collect_hop_dependencies(hop, dependencies);
                }
            }
        }
    }
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
/// - System-only use of native_cache_secs
/// - Bootstrap URL validity (must be a known group or valid IP-only URL)
fn expand_dns_specs(
    specs: &[DnsServerSpec],
    client_groups: &compiler::Groups,
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

        if spec.native_cache_secs().is_some() && !matches!(parsed_url, ParsedDnsUrl::System) {
            return Err(std::io::Error::other(
                "native_cache_secs is only supported for system DNS resolver",
            ));
        }

        // Expand and validate client chains
        let client_chains_raw = spec.client_chains();
        let mut expanded_chains: Vec<ResolvedClientChain> = Vec::new();

        for chain in client_chains_raw.iter() {
            expanded_chains.push(compiler::compile_chain(
                chain.hops.clone(),
                client_groups,
                named_pems,
                global_limits,
            )?);
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
                .all(|chain| super::composition::direct_only(&chain.hops));

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
            native_cache_secs: spec.native_cache_secs().unwrap_or(0),
        });
    }

    Ok(result)
}

pub(super) fn chain_uses_wireguard(chain: &ResolvedClientChain) -> bool {
    chain
        .hops
        .iter()
        .flat_map(super::composition::clients)
        .any(|client| client.protocol.is_wireguard())
}

fn resolve_server_config(
    mut server_config: ServerConfig,
    client_groups: &compiler::Groups,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<ResolvedServerConfig> {
    crate::sudoku_mask::validate_server(&server_config.protocol, &server_config.transport)?;
    if let ServerProxyConfig::Wireguard(config) = &server_config.protocol {
        if server_config.transport != Transport::Udp
            || server_config.tcp_settings.is_some()
            || server_config.quic_settings.is_some()
        {
            return Err(super::types::wireguard::invalid(
                "WireGuard requires UDP transport without TCP/QUIC socket settings",
            ));
        }
        config.validate_device(&server_config.bind_location, server_config.rules.is_empty())?;
        let ServerProxyConfig::Wireguard(config) = server_config.protocol else {
            unreachable!()
        };
        let peer_client_chain = config
            .peer_client_chain
            .map(|chain| {
                compiler::compile_chain(chain.hops, client_groups, named_pems, global_limits)
            })
            .transpose()?;
        if let Some(chain) = &peer_client_chain
            && !crate::tcp::chain_builder::supports_udp_offline(chain)?
        {
            return Err(super::types::wireguard::invalid(
                "WireGuard peer_client_chain does not support UDP",
            ));
        }
        ConfigSelection::replace_none_or_some_groups(&mut server_config.rules, rule_groups)?;
        if server_config.rules.is_empty() {
            return Err(super::types::wireguard::invalid(
                "WireGuard server requires nonempty explicit rules",
            ));
        }
        let rules = plan_ops::map_some(server_config.rules, &mut |rule| {
            resolve_rule_config(
                rule.unwrap_config(),
                client_groups,
                named_pems,
                global_limits,
            )
        })?;
        let protocol =
            ResolvedServerProxyConfig::Wireguard(Box::new(ResolvedWireguardServerConfig {
                wireguard_name: config.wireguard_name,
                private_key: config.private_key,
                addresses: config.addresses,
                peers: config.peers,
                mtu: config.mtu,
                resource_limits: config.resource_limits,
                bind_interface: config.bind_interface,
                peer_client_chain,
            }));
        return Ok(ResolvedServerConfig {
            name: server_config.name,
            sniff: server_config.sniff,
            bind_location: server_config.bind_location,
            protocol,
            transport: server_config.transport,
            tcp_settings: server_config.tcp_settings,
            quic_settings: server_config.quic_settings,
            rules,
            dns: resolve_dns_binding(server_config.dns),
        });
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
                normalize_fingerprints(client_fingerprints, "Client")?;

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

    let rules = plan_ops::map_some(server_config.rules, &mut |rule| {
        resolve_rule_config(
            rule.unwrap_config(),
            client_groups,
            named_pems,
            global_limits,
        )
    })?;
    let protocol = resolve_server_proxy_config(
        server_config.protocol,
        client_groups,
        rule_groups,
        named_pems,
        global_limits,
        if server_config.transport == Transport::Quic {
            ServerProtocolContext::Quic
        } else {
            ServerProtocolContext::Stream
        },
    )?;
    Ok(ResolvedServerConfig {
        name: server_config.name,
        sniff: server_config.sniff,
        bind_location: server_config.bind_location,
        protocol,
        transport: server_config.transport,
        tcp_settings: server_config.tcp_settings,
        quic_settings: server_config.quic_settings,
        rules,
        dns: resolve_dns_binding(server_config.dns),
    })
}

pub(super) fn source_contains_xhttp(protocol: &ClientProxyConfig) -> bool {
    match protocol {
        ClientProxyConfig::Xhttp(_) => true,
        ClientProxyConfig::Tls(config) => source_contains_xhttp(&config.protocol),
        ClientProxyConfig::Reality { protocol, .. }
        | ClientProxyConfig::ShadowTls { protocol, .. } => source_contains_xhttp(protocol),
        ClientProxyConfig::Websocket(config) => source_contains_xhttp(&config.protocol),
        ClientProxyConfig::SudokuMask(config) => source_contains_xhttp(&config.protocol),
        _ => false,
    }
}

fn normalize_fingerprints(
    fingerprints: &mut NoneOrSome<String>,
    peer: &str,
) -> std::io::Result<()> {
    if !fingerprints.is_unspecified() && fingerprints.is_empty() {
        println!("WARNING: {peer} fingerprints provided but empty, defaulting to 'any'");
    }

    if fingerprints.iter().any(|fp| fp == "any") {
        *fingerprints = NoneOrSome::Unspecified;
    } else {
        crate::rustls_config_util::process_fingerprints(&fingerprints.clone().into_vec())?;
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

pub(crate) fn validate_resolved_client_vision_protocol(
    vision_enabled: bool,
    protocol: &ResolvedClientProxyConfig,
    config_type: &str,
) -> std::io::Result<()> {
    if !vision_enabled {
        return Ok(());
    }

    match protocol {
        ResolvedClientProxyConfig::Vless { encryption, .. } if !encryption.is_disabled() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Native VLESS encryption requires outer TLS/REALITY vision: false; set vision: true on VLESS instead",
            ))
        }
        ResolvedClientProxyConfig::Vless { .. } => Ok(()),
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
        ClientProxyConfig::SudokuMask(config) => Some(config.protocol.as_ref()),
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
        if inner.is_native_quic() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native QUIC cannot be used as an inner proxy protocol",
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

pub(super) fn resolve_client_config(
    mut client_config: ClientConfig,
    carrier: Option<ChainPlan<DraftClient>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<ResolvedClientConfig> {
    #[cfg(test)]
    tests::CLIENT_VALIDATIONS.with(|count| count.set(count.get() + 1));
    crate::sudoku_mask::validate_client(&client_config.protocol, &client_config.transport)?;
    client_config.validate_quic_key_exchange(true)?;
    crate::quic_client::validate(&client_config, true)?;
    let mut resolved_carrier = None;
    if let ClientProxyConfig::Wireguard(config) = &mut client_config.protocol {
        if client_config.transport != Transport::Udp
            || client_config.tcp_settings.is_some()
            || client_config.quic_settings.is_some()
        {
            return Err(super::types::wireguard::invalid(
                "WireGuard requires UDP transport without TCP/QUIC socket settings",
            ));
        }
        config.validate_device(
            &client_config.address,
            client_config
                .bind_interface
                .clone()
                .into_option()
                .as_deref(),
        )?;
        if let Some(chain) = carrier {
            let chain = compiler::lower_chain(chain, named_pems, global_limits)?;
            if !crate::tcp::chain_builder::supports_udp_offline(&chain)? {
                return Err(super::types::wireguard::invalid(
                    "WireGuard peer_client_chain does not support UDP",
                ));
            }
            resolved_carrier = Some(chain);
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
        normalize_fingerprints(server_fingerprints, "Server")?;
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

    let client_config = super::lower::client(client_config, resolved_carrier);
    if crate::xhttp::connector::contains(&client_config.protocol) {
        crate::xhttp::connector::build_with_limits(
            &client_config,
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
            global_limits,
        )?;
    }

    Ok(client_config)
}

fn validate_client_proxy_config(
    client_proxy_config: &mut ClientProxyConfig,
    named_pems: &HashMap<String, String>,
    default_sni: Option<&str>,
) -> std::io::Result<()> {
    match client_proxy_config {
        ClientProxyConfig::SudokuMask(config) => {
            config.prepare()?;
            validate_client_proxy_config(&mut config.protocol, named_pems, default_sni)?;
        }
        ClientProxyConfig::Shadowsocks { config, .. } => config.validate_keys()?,
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
            normalize_fingerprints(&mut tls_config.server_fingerprints, "Server")?;
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
            crate::websocket::validate_early_data(
                ws_config.matching_path.as_deref(),
                ws_config.matching_headers.as_ref(),
                ws_config.max_early_data,
                ws_config.early_data_header_name.as_deref(),
                false,
            )?;
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

pub(crate) fn validate_resolved_server_vision(
    vision: bool,
    protocol: &ResolvedServerProxyConfig,
) -> std::io::Result<()> {
    if vision
        && matches!(protocol, ResolvedServerProxyConfig::Vless { decryption, .. } if !decryption.is_disabled())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Native VLESS decryption requires outer TLS/REALITY vision: false; set vision: true on VLESS instead",
        ));
    }
    if vision && !matches!(protocol, ResolvedServerProxyConfig::Vless { .. }) {
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
            config.validate_server_key()?;
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

fn validate_server_proxy_scalars(
    server_proxy_config: &mut ServerProxyConfig,
    context: ServerProtocolContext,
) -> std::io::Result<()> {
    validate_server_auth(server_proxy_config)?;
    match server_proxy_config {
        ServerProxyConfig::SudokuMask(config) => {
            config.prepare()?;
        }
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

fn resolve_server_proxy_config(
    mut source: ServerProxyConfig,
    groups: &compiler::Groups,
    rules: &HashMap<String, Vec<RuleConfig>>,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
    context: ServerProtocolContext,
) -> std::io::Result<ResolvedServerProxyConfig> {
    validate_server_proxy_scalars(&mut source, context)?;
    Ok(match source {
        ServerProxyConfig::Wireguard(_) => {
            unreachable!("nested WireGuard rejected by structure validation")
        }
        ServerProxyConfig::SudokuMask(config) => {
            let protocol = Box::new(resolve_server_proxy_config(
                *config.protocol,
                groups,
                rules,
                pems,
                limits,
                ServerProtocolContext::Stream,
            )?);
            ResolvedServerProxyConfig::SudokuMask(crate::sudoku_mask::SudokuMaskConfig {
                password: config.password,
                ascii: config.ascii,
                custom_table: config.custom_table,
                custom_tables: config.custom_tables,
                padding_min: config.padding_min,
                padding_max: config.padding_max,
                protocol,
            })
        }
        ServerProxyConfig::Xhttp(config) => {
            let protocol = Box::new(resolve_server_proxy_config(
                *config.protocol,
                groups,
                rules,
                pems,
                limits,
                ServerProtocolContext::Stream,
            )?);
            ResolvedServerProxyConfig::Xhttp(ResolvedXhttpServerConfig {
                path: config.path,
                host: config.host,
                matching_headers: config.matching_headers,
                mode: config.mode,
                http_version: config.http_version,
                x_padding_bytes: config.x_padding_bytes,
                sc_max_each_post_bytes: config.sc_max_each_post_bytes,
                sc_max_buffered_posts: config.sc_max_buffered_posts,
                sc_stream_up_server_secs: config.sc_stream_up_server_secs,
                server_max_header_bytes: config.server_max_header_bytes,
                no_sse_header: config.no_sse_header,
                limits: config.limits,
                protocol,
            })
        }
        ServerProxyConfig::Websocket { targets } => {
            let targets = plan_ops::map_one(*targets, &mut |config| {
                crate::websocket::validate_early_data(
                    config.matching_path.as_deref(),
                    config.matching_headers.as_ref(),
                    config.max_early_data,
                    config.early_data_header_name.as_deref(),
                    true,
                )?;
                let protocol = resolve_server_proxy_config(
                    config.protocol,
                    groups,
                    rules,
                    pems,
                    limits,
                    ServerProtocolContext::Stream,
                )?;
                let override_rules =
                    resolve_rules(config.override_rules, groups, rules, pems, limits)?;
                Ok::<_, std::io::Error>(ResolvedWebsocketServerConfig {
                    matching_path: config.matching_path,
                    matching_headers: config.matching_headers,
                    max_early_data: config.max_early_data,
                    early_data_header_name: config.early_data_header_name,
                    protocol,
                    ping_type: config.ping_type,
                    override_rules,
                })
            })?;
            ResolvedServerProxyConfig::Websocket {
                targets: Box::new(targets),
            }
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
            let tls_targets: HashMap<_, _> = tls_targets
                .into_iter()
                .map(|(name, config)| {
                    Ok((
                        name,
                        resolve_tls_server(config, groups, rules, pems, limits)?,
                    ))
                })
                .collect::<std::io::Result<_>>()?;
            let default_tls_target = default_tls_target
                .map(|config| {
                    resolve_tls_server(*config, groups, rules, pems, limits).map(Box::new)
                })
                .transpose()?;
            let mut shadow_targets = HashMap::with_capacity(shadowtls_targets.len());
            for (name, config) in shadowtls_targets {
                validate_nonempty_secret(&config.password, "ShadowTLS")?;
                if tls_targets.contains_key(&name) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and ShadowTLS targets: {name}"
                        ),
                    ));
                }
                let handshake = match config.handshake {
                    ShadowTlsServerHandshakeConfig::Local(mut local) => {
                        embed_pem_from_map(&mut local.cert, pems);
                        embed_pem_from_map(&mut local.key, pems);
                        for cert in local.client_ca_certs.iter_mut() {
                            embed_pem_from_map(cert, pems);
                        }
                        validate_server_certificates(
                            &local.cert,
                            &local.key,
                            &local.client_ca_certs,
                            None,
                        )?;
                        normalize_fingerprints(&mut local.client_fingerprints, "Client")?;
                        ResolvedShadowTlsServerHandshakeConfig::Local(local)
                    }
                    ShadowTlsServerHandshakeConfig::Remote(remote) => {
                        let chain =
                            compiler::compile_chain(remote.client_chain, groups, pems, limits)?;
                        ResolvedShadowTlsServerHandshakeConfig::Remote(
                            ResolvedShadowTlsRemoteHandshake {
                                address: remote.address,
                                client_chain: chain.hops,
                            },
                        )
                    }
                };
                let protocol = resolve_server_proxy_config(
                    config.protocol,
                    groups,
                    rules,
                    pems,
                    limits,
                    ServerProtocolContext::Stream,
                )?;
                let override_rules =
                    resolve_rules(config.override_rules, groups, rules, pems, limits)?;
                shadow_targets.insert(
                    name,
                    ResolvedShadowTlsServerConfig {
                        password: config.password,
                        handshake,
                        protocol,
                        override_rules,
                    },
                );
            }
            let mut reality = HashMap::with_capacity(reality_targets.len());
            for (name, config) in reality_targets {
                validate_server_vision(config.vision, &config.protocol)?;
                if tls_targets.contains_key(&name) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("duplicated SNI hostname between TLS and REALITY targets: {name}"),
                    ));
                }
                if shadow_targets.contains_key(&name) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between ShadowTLS and REALITY targets: {name}"
                        ),
                    ));
                }
                validate_reality_private_key(&config.private_key, &name)?;
                if let Some(seed) = &config.mldsa65_seed {
                    crate::reality::decode_mldsa65_seed(seed)?;
                }
                validate_reality_server_short_ids(&config.short_ids, &name)?;
                let dest_client_chain = if config.dest_client_chain.is_empty() {
                    match config.dest_client_chain {
                        NoneOrSome::Unspecified => NoneOrSome::Unspecified,
                        _ => NoneOrSome::None,
                    }
                } else {
                    let chain = compiler::compile_chain(
                        OneOrSome::Some(config.dest_client_chain.into_vec()),
                        groups,
                        pems,
                        limits,
                    )?;
                    NoneOrSome::Some(chain.hops.into_vec())
                };
                let protocol = resolve_server_proxy_config(
                    config.protocol,
                    groups,
                    rules,
                    pems,
                    limits,
                    ServerProtocolContext::Tls,
                )?;
                let override_rules =
                    resolve_rules(config.override_rules, groups, rules, pems, limits)?;
                reality.insert(
                    name,
                    ResolvedRealityServerConfig {
                        mldsa65_seed: config.mldsa65_seed,
                        private_key: config.private_key,
                        short_ids: config.short_ids,
                        dest: config.dest,
                        max_time_diff: config.max_time_diff,
                        min_client_version: config.min_client_version,
                        max_client_version: config.max_client_version,
                        cipher_suites: config.cipher_suites,
                        vision: config.vision,
                        protocol,
                        dest_client_chain,
                        override_rules,
                    },
                );
            }
            if let Some(size) = tls_buffer_size
                && size < MIN_TLS_BUFFER_SIZE
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TLS buffer size must be at least {MIN_TLS_BUFFER_SIZE}"),
                ));
            }
            ResolvedServerProxyConfig::Tls {
                tls_targets,
                default_tls_target,
                shadowtls_targets: shadow_targets,
                reality_targets: reality,
                tls_buffer_size,
            }
        }
        ServerProxyConfig::Http { username, password } => {
            ResolvedServerProxyConfig::Http { username, password }
        }
        ServerProxyConfig::Socks {
            username,
            password,
            udp_enabled,
        } => ResolvedServerProxyConfig::Socks {
            username,
            password,
            udp_enabled,
        },
        ServerProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => ResolvedServerProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        },
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        } => ResolvedServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        },
        ServerProxyConfig::Vless {
            user_id,
            decryption,
            _invalid_encryption,
            vision,
            encryption_limits,
            udp_enabled,
            fallback,
        } => ResolvedServerProxyConfig::Vless {
            user_id,
            decryption,
            _invalid_encryption,
            vision,
            encryption_limits,
            udp_enabled,
            fallback,
        },
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => ResolvedServerProxyConfig::Trojan {
            password,
            shadowsocks,
        },
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => ResolvedServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        },
        ServerProxyConfig::Anytls {
            users,
            padding_scheme,
            udp_enabled,
            fallback,
        } => ResolvedServerProxyConfig::Anytls {
            users,
            padding_scheme,
            udp_enabled,
            fallback,
        },
        ServerProxyConfig::PortForward { targets } => {
            ResolvedServerProxyConfig::PortForward { targets }
        }
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
        } => ResolvedServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
        },
        ServerProxyConfig::TuicV5 {
            uuid,
            password,
            zero_rtt_handshake,
        } => ResolvedServerProxyConfig::TuicV5 {
            uuid,
            password,
            zero_rtt_handshake,
        },
        ServerProxyConfig::Mixed {
            username,
            password,
            udp_enabled,
        } => ResolvedServerProxyConfig::Mixed {
            username,
            password,
            udp_enabled,
        },
        ServerProxyConfig::Naiveproxy {
            users,
            padding,
            fallback,
            udp_enabled,
        } => ResolvedServerProxyConfig::Naiveproxy {
            users,
            padding,
            fallback,
            udp_enabled,
        },
    })
}

fn resolve_tls_server(
    mut config: TlsServerConfig,
    groups: &compiler::Groups,
    rules: &HashMap<String, Vec<RuleConfig>>,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> std::io::Result<ResolvedTlsServerConfig> {
    config.key_exchange_groups.validate_vision(config.vision)?;
    validate_server_vision(config.vision, &config.protocol)?;
    embed_pem_from_map(&mut config.cert, pems);
    embed_pem_from_map(&mut config.key, pems);
    for cert in config.client_ca_certs.iter_mut() {
        embed_pem_from_map(cert, pems);
    }
    validate_server_certificates(
        &config.cert,
        &config.key,
        &config.client_ca_certs,
        config.certificate_binding.as_ref(),
    )?;
    normalize_fingerprints(&mut config.client_fingerprints, "Client")?;
    let protocol = resolve_server_proxy_config(
        config.protocol,
        groups,
        rules,
        pems,
        limits,
        ServerProtocolContext::Tls,
    )?;
    let override_rules = resolve_rules(config.override_rules, groups, rules, pems, limits)?;
    Ok(ResolvedTlsServerConfig {
        certificate_source: config.certificate_source,
        certificate_binding: config.certificate_binding,
        key_exchange_groups: config.key_exchange_groups,
        cert: config.cert,
        key: config.key,
        alpn_protocols: config.alpn_protocols,
        client_ca_certs: config.client_ca_certs,
        client_fingerprints: config.client_fingerprints,
        vision: config.vision,
        protocol,
        override_rules,
    })
}

/// Validates a TUN configuration.
fn resolve_tun_config(
    config: TunConfig,
    client_groups: &compiler::Groups,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<ResolvedTunConfig> {
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
        if !config.auto_route
            && config.device_fd.is_none()
            && (config.device_name.is_none() || config.address.is_none())
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

    let rules = resolve_rules(
        config.rules,
        client_groups,
        rule_groups,
        named_pems,
        global_limits,
    )?;
    Ok(ResolvedTunConfig {
        auto_route: config.auto_route,
        auto_redirect: config.auto_redirect,
        auto_dns: config.auto_dns,
        addresses: config.addresses,
        route_address: config.route_address,
        route_exclude_address: config.route_exclude_address,
        bootstrap_dns: config.bootstrap_dns,
        linux: config.linux,
        dns_hijack: config.dns_hijack,
        name: config.name,
        sniff: config.sniff,
        segmentation_offload: config.segmentation_offload,
        resource_limits: config.resource_limits,
        packet_information: config.packet_information,
        device_name: config.device_name,
        device_fd: config.device_fd,
        address: config.address,
        netmask: config.netmask,
        destination: config.destination,
        mtu: config.mtu,
        tcp_enabled: config.tcp_enabled,
        udp_enabled: config.udp_enabled,
        icmp_enabled: config.icmp_enabled,
        rules,
        dns: resolve_dns_binding(config.dns),
    })
}

pub(super) fn resolve_rule_config(
    mut rule: RuleConfig,
    client_groups: &compiler::Groups,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<ResolvedRuleConfig> {
    rule.compile(&mut crate::rules::Compiler::default())?;
    let action = match rule.action {
        RuleActionConfig::Block => ResolvedRuleActionConfig::Block,
        RuleActionConfig::Allow {
            override_address,
            mut client_chains,
        } => {
            if client_chains.is_unspecified() {
                client_chains = NoneOrSome::One(ClientChain::default());
            }
            if matches!(client_chains, NoneOrSome::None) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "client_chains cannot be empty; omit the field for default direct connection",
                ));
            }
            let client_chains = plan_ops::map_some(client_chains, &mut |chain| {
                compiler::compile_chain(chain.hops, client_groups, named_pems, global_limits)
            })?;
            ResolvedRuleActionConfig::Allow {
                override_address,
                client_chains,
            }
        }
    };
    Ok(ResolvedRuleConfig {
        criteria: rule.criteria,
        action,
    })
}

pub(super) fn resolve_rules(
    mut rules: NoneOrSome<ConfigSelection<RuleConfig>>,
    client_groups: &compiler::Groups,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    global_limits: GlobalLimits,
) -> std::io::Result<NoneOrSome<ResolvedRuleConfig>> {
    ConfigSelection::replace_none_or_some_groups(&mut rules, rule_groups)?;
    plan_ops::map_some(rules, &mut |rule| {
        resolve_rule_config(
            rule.unwrap_config(),
            client_groups,
            named_pems,
            global_limits,
        )
    })
}

fn resolve_dns_binding(dns: Option<DnsConfig>) -> Option<ResolvedDnsConfig> {
    dns.map(|dns| ResolvedDnsConfig {
        group: dns.resolved_group().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests;
