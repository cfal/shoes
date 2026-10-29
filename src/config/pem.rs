//! PEM file handling - loading certificates and converting file paths to inline data.

use std::collections::HashMap;

use log::debug;

use super::types::{
    ClientChainHop, ClientConfig, ClientConfigGroup, ClientProxyConfig, Config, NamedPem,
    PemSource, RuleActionConfig, ServerConfig, ServerProxyConfig, ShadowTlsServerHandshakeConfig,
    TlsServerConfig,
};
use crate::config::ConfigSelection;

/// Converts all PEM file references to inline data.
///
/// This function:
/// - Loads all named PEMs that point to files into data-backed PEMs
/// - Converts inline file paths in cert/key fields to new named PEM items
///
/// Returns the converted configs and the count of PEM files loaded.
pub async fn convert_cert_paths(
    mut all_configs: Vec<Config>,
) -> std::io::Result<(Vec<Config>, usize)> {
    crate::certificates::configure(&mut all_configs)?;
    let mut path_pem_names: HashMap<String, String> = HashMap::new();
    let mut data_configs = vec![];
    let mut load_count = 0usize;
    let mut server_configs = vec![];
    let mut client_group_configs = vec![];
    let mut other_configs = vec![];

    for config in all_configs.into_iter() {
        match config {
            Config::NamedPem(ref pem) => {
                let (path, loaded_data) = match pem.source {
                    PemSource::Path(ref path) => {
                        let loaded_data = read_pem_to_string(path).await?;
                        (path.clone(), loaded_data)
                    }
                    PemSource::Data(_) => {
                        data_configs.push(config);
                        continue;
                    }
                };

                let loaded_config = NamedPem {
                    pem: pem.pem.clone(),
                    source: PemSource::Data(loaded_data),
                };

                load_count += 1;
                path_pem_names.insert(path, loaded_config.pem.clone());
                data_configs.push(Config::NamedPem(loaded_config));
            }
            Config::Server(server_config) => {
                server_configs.push(server_config);
            }
            Config::ClientConfigGroup(client_group_config) => {
                client_group_configs.push(client_group_config);
            }
            _ => other_configs.push(config),
        }
    }

    let mut unknown_pem_paths = HashMap::new();

    let mut collect = |pem: &mut String, _| {
        process_pem_path(pem, &path_pem_names, &mut unknown_pem_paths);
    };

    // Gather all paths that are inlined but not named.
    // We do this as a separate step because we can't load the data in an async manner
    // right away due to recursion.
    for config in server_configs.iter_mut() {
        gather_pem_file_paths_from_server_config(config, &mut collect)?;
    }

    for config in client_group_configs.iter_mut() {
        gather_pem_file_paths_from_client_config_group(config, &mut collect);
    }

    for config in &mut other_configs {
        visit_config_pems(config, &mut collect)?;
    }

    let mut updated_configs = vec![];

    updated_configs.append(&mut data_configs);

    // Generate new named configs from inlined paths
    load_count += unknown_pem_paths.len();

    for (path, new_name) in unknown_pem_paths.into_iter() {
        let data = read_pem_to_string(&path).await?;
        let loaded_config = NamedPem {
            pem: new_name,
            source: PemSource::Data(data),
        };
        updated_configs.push(Config::NamedPem(loaded_config));
    }

    updated_configs.append(&mut other_configs);

    for client_group_config in client_group_configs.into_iter() {
        updated_configs.push(Config::ClientConfigGroup(client_group_config));
    }

    for server_config in server_configs.into_iter() {
        updated_configs.push(Config::Server(server_config));
    }

    Ok((updated_configs, load_count))
}

#[derive(Clone, Copy)]
enum PemUsage {
    ServerIdentity,
    Reload,
}

type PemVisitor<'a> = dyn FnMut(&mut String, PemUsage) + 'a;

/// Discover reload-only PEM dependencies before expansion erases file identity.
pub(crate) fn pem_reload_dependencies(
    configs: &mut [Config],
) -> std::io::Result<Vec<std::path::PathBuf>> {
    pem_dependencies(configs, false)
}

pub(crate) fn pem_candidate_dependencies(
    configs: &mut [Config],
) -> std::io::Result<Vec<std::path::PathBuf>> {
    pem_dependencies(configs, true)
}

fn pem_dependencies(
    configs: &mut [Config],
    include_server_identities: bool,
) -> std::io::Result<Vec<std::path::PathBuf>> {
    let named: HashMap<_, _> = configs
        .iter()
        .filter_map(|config| {
            let Config::NamedPem(pem) = config else {
                return None;
            };
            Some((pem.pem.clone(), pem.source.clone()))
        })
        .collect();
    let mut paths = std::collections::BTreeSet::new();
    if include_server_identities {
        for source in named.values() {
            if let PemSource::Path(path) = source {
                paths.insert(std::path::PathBuf::from(path));
            }
        }
    }
    for config in configs {
        if let Config::CertificateSource(source) = config {
            source.validate_file_paths()?;
            match &source.source {
                crate::certificates::SourceConfig::Files { cert, key }
                    if include_server_identities =>
                {
                    paths.extend([cert.clone(), key.clone()]);
                }
                crate::certificates::SourceConfig::Acme(acme) => {
                    paths.extend(acme.ca_cert.iter().cloned());
                }
                _ => {}
            }
        }
        visit_config_pems(config, &mut |pem, usage| {
            if matches!(usage, PemUsage::ServerIdentity) && !include_server_identities {
                return;
            }
            match named.get(pem) {
                Some(PemSource::Path(path)) => {
                    paths.insert(std::path::PathBuf::from(path));
                }
                Some(PemSource::Data(_)) => {}
                None if is_pem_file_path(pem) => {
                    paths.insert(std::path::PathBuf::from(pem.as_str()));
                }
                None => {}
            }
        })?;
    }
    Ok(paths.into_iter().collect())
}

fn visit_config_pems(config: &mut Config, visitor: &mut PemVisitor<'_>) -> std::io::Result<()> {
    match config {
        Config::Server(server) => gather_pem_file_paths_from_server_config(server, visitor)?,
        Config::ClientConfigGroup(group) => {
            gather_pem_file_paths_from_client_config_group(group, visitor)
        }
        Config::TunServer(tun) => {
            for rule in tun.rules.iter_mut() {
                gather_pem_file_paths_from_rule(rule, visitor);
            }
            if let Some(dns) = &mut tun.dns {
                gather_dns_pem_paths(&mut dns.servers, visitor);
            }
        }
        Config::DnsConfigGroup(group) => {
            gather_dns_pem_paths(&mut group.dns_servers, visitor);
        }
        Config::RuleConfigGroup(group) => {
            let super::RuleGroupRules::Policies(rules) = &mut group.rules else {
                return Ok(());
            };
            for rule in rules.iter_mut() {
                if let RuleActionConfig::Allow { client_chains, .. } = &mut rule.action {
                    for chain in client_chains.iter_mut() {
                        for hop in chain.hops.iter_mut() {
                            gather_pem_file_paths_from_chain_hop(hop, visitor);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn gather_pem_file_paths_from_server_config(
    server_config: &mut ServerConfig,
    visitor: &mut PemVisitor<'_>,
) -> std::io::Result<()> {
    // Check QUIC settings
    if let Some(ref mut quic_settings) = server_config.quic_settings {
        visitor(&mut quic_settings.cert, PemUsage::ServerIdentity);
        visitor(&mut quic_settings.key, PemUsage::ServerIdentity);
        for cert in quic_settings.client_ca_certs.iter_mut() {
            visitor(cert, PemUsage::Reload);
        }
    }

    // Recursively check the protocol
    gather_pem_file_paths_from_server_proxy(&mut server_config.protocol, visitor)?;

    // Check rules
    for rule in server_config.rules.iter_mut() {
        gather_pem_file_paths_from_rule(rule, visitor);
    }
    if let Some(dns) = &mut server_config.dns {
        gather_dns_pem_paths(&mut dns.servers, visitor);
    }
    Ok(())
}

fn gather_dns_pem_paths(
    specs: &mut crate::option_util::NoneOrSome<super::DnsServerSpec>,
    visitor: &mut PemVisitor<'_>,
) {
    for spec in specs.iter_mut() {
        if let super::DnsServerSpec::WithOptions { client_chain, .. } = spec {
            for selection in client_chain.iter_mut() {
                if let ConfigSelection::Config(chain) = selection {
                    for hop in chain.hops.iter_mut() {
                        gather_pem_file_paths_from_chain_hop(hop, visitor);
                    }
                }
            }
        }
    }
}

fn gather_pem_file_paths_from_client_config_group(
    client_group_config: &mut ClientConfigGroup,
    visitor: &mut PemVisitor<'_>,
) {
    for selection in client_group_config.client_proxies.iter_mut() {
        if let ConfigSelection::Config(client_config) = selection {
            gather_pem_file_paths_from_client_config(client_config, visitor);
        }
        // GroupName selections are resolved later, skip here
    }
}

/// Validates that Vision is only enabled when the inner protocol is VLESS.
///
/// Vision (XTLS-RPRX-Vision) is a TLS-in-TLS optimization protocol that requires
/// VLESS as the inner protocol to function correctly.
fn validate_vision_protocol(
    vision_enabled: bool,
    protocol: &ServerProxyConfig,
    config_type: &str,
) -> std::io::Result<()> {
    if !vision_enabled {
        return Ok(());
    }

    match protocol {
        ServerProxyConfig::Vless { .. } => Ok(()),
        other_protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} config has vision=true but inner protocol is {} (not VLESS). \
                 Vision (XTLS-RPRX-Vision) requires VLESS as the inner protocol. \
                 Either set vision=false or change the inner protocol to VLESS.",
                config_type, other_protocol
            ),
        )),
    }
}

fn gather_pem_file_paths_from_server_proxy(
    server_proxy: &mut ServerProxyConfig,
    visitor: &mut PemVisitor<'_>,
) -> std::io::Result<()> {
    match server_proxy {
        ServerProxyConfig::Wireguard(config) => {
            if let Some(chain) = &mut config.peer_client_chain {
                for hop in chain.hops.iter_mut() {
                    gather_pem_file_paths_from_chain_hop(hop, visitor);
                }
            }
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for (sni, tls_config) in tls_targets.iter_mut() {
                gather_pem_file_paths_from_tls_target(
                    tls_config,
                    &format!("TLS target '{}'", sni),
                    visitor,
                )?;
            }
            if let Some(tls_config) = default_tls_target {
                gather_pem_file_paths_from_tls_target(tls_config, "default TLS target", visitor)?;
            }

            // Process ShadowTLS targets
            for shadowtls_config in shadowtls_targets.values_mut() {
                if let ShadowTlsServerHandshakeConfig::Local(ref mut handshake) =
                    shadowtls_config.handshake
                {
                    visitor(&mut handshake.cert, PemUsage::Reload);
                    visitor(&mut handshake.key, PemUsage::Reload);
                    for cert in handshake.client_ca_certs.iter_mut() {
                        visitor(cert, PemUsage::Reload);
                    }
                } else if let ShadowTlsServerHandshakeConfig::Remote(handshake) =
                    &mut shadowtls_config.handshake
                {
                    for hop in handshake.client_chain.iter_mut() {
                        gather_pem_file_paths_from_chain_hop(hop, visitor);
                    }
                }
                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(&mut shadowtls_config.protocol, visitor)?;
                // Check override rules
                for rule in shadowtls_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, visitor);
                }
            }

            // Process Reality targets
            for (sni, reality_config) in reality_targets.iter_mut() {
                for hop in reality_config.dest_client_chain.iter_mut() {
                    gather_pem_file_paths_from_chain_hop(hop, visitor);
                }
                // Validate Vision configuration
                validate_vision_protocol(
                    reality_config.vision,
                    &reality_config.protocol,
                    &format!("Reality target '{}'", sni),
                )?;

                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(&mut reality_config.protocol, visitor)?;
                // Check override rules
                for rule in reality_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, visitor);
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_config in targets.iter_mut() {
                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(&mut websocket_config.protocol, visitor)?;
                // Check override rules
                for rule in websocket_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, visitor);
                }
            }
        }
        ServerProxyConfig::SudokuMask(config) => {
            gather_pem_file_paths_from_server_proxy(&mut config.protocol, visitor)?;
        }
        ServerProxyConfig::Xhttp(config) => {
            gather_pem_file_paths_from_server_proxy(&mut config.protocol, visitor)?;
        }
        _ => {}
    }
    Ok(())
}

fn gather_pem_file_paths_from_tls_target(
    target: &mut TlsServerConfig,
    label: &str,
    visitor: &mut PemVisitor<'_>,
) -> std::io::Result<()> {
    visitor(&mut target.cert, PemUsage::ServerIdentity);
    visitor(&mut target.key, PemUsage::ServerIdentity);
    for cert in target.client_ca_certs.iter_mut() {
        visitor(cert, PemUsage::Reload);
    }
    validate_vision_protocol(target.vision, &target.protocol, label)?;
    gather_pem_file_paths_from_server_proxy(&mut target.protocol, visitor)?;
    for rule in target.override_rules.iter_mut() {
        gather_pem_file_paths_from_rule(rule, visitor);
    }
    Ok(())
}

fn gather_pem_file_paths_from_rule(
    rule_selection: &mut ConfigSelection<super::types::RuleConfig>,
    visitor: &mut PemVisitor<'_>,
) {
    if let ConfigSelection::Config(rule) = rule_selection
        && let RuleActionConfig::Allow {
            ref mut client_chains,
            ..
        } = rule.action
    {
        for chain in client_chains.iter_mut() {
            for hop in chain.hops.iter_mut() {
                gather_pem_file_paths_from_chain_hop(hop, visitor);
            }
        }
    }
}

fn gather_pem_file_paths_from_chain_hop(hop: &mut ClientChainHop, visitor: &mut PemVisitor<'_>) {
    match hop {
        ClientChainHop::Single(selection) => {
            if let ConfigSelection::Config(client_config) = selection {
                gather_pem_file_paths_from_client_config(client_config, visitor);
            }
            // GroupName selections are resolved later, skip here
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                if let ConfigSelection::Config(client_config) = selection {
                    gather_pem_file_paths_from_client_config(client_config, visitor);
                }
                // GroupName selections are resolved later, skip here
            }
        }
    }
}

fn gather_pem_file_paths_from_client_config(
    client_config: &mut ClientConfig,
    visitor: &mut PemVisitor<'_>,
) {
    // Check QUIC settings
    if let Some(ref mut quic_config) = client_config.quic_settings {
        visit_optional_pem(&mut quic_config.cert, visitor);
        visit_optional_pem(&mut quic_config.key, visitor);
    }

    // Recurse into client proxy config
    gather_pem_file_paths_from_client_proxy(&mut client_config.protocol, visitor);
}

fn gather_pem_file_paths_from_client_proxy(
    client_proxy: &mut ClientProxyConfig,
    visitor: &mut PemVisitor<'_>,
) {
    match client_proxy {
        ClientProxyConfig::Wireguard(config) => {
            if let Some(chain) = &mut config.peer_client_chain {
                for hop in chain.hops.iter_mut() {
                    gather_pem_file_paths_from_chain_hop(hop, visitor);
                }
            }
        }
        ClientProxyConfig::Tls(tls_config) => {
            visit_optional_pem(&mut tls_config.cert, visitor);
            visit_optional_pem(&mut tls_config.key, visitor);
            // Recurse into inner protocol
            gather_pem_file_paths_from_client_proxy(&mut tls_config.protocol, visitor);
        }
        ClientProxyConfig::Reality { protocol, .. } => {
            // Reality doesn't have cert/key PEM files, but recurse into inner protocol
            gather_pem_file_paths_from_client_proxy(protocol, visitor);
        }
        ClientProxyConfig::ShadowTls { protocol, .. } => {
            gather_pem_file_paths_from_client_proxy(protocol, visitor);
        }
        ClientProxyConfig::Websocket(ws_config) => {
            gather_pem_file_paths_from_client_proxy(&mut ws_config.protocol, visitor);
        }
        ClientProxyConfig::SudokuMask(config) => {
            gather_pem_file_paths_from_client_proxy(&mut config.protocol, visitor);
        }
        ClientProxyConfig::Xhttp(config) => {
            gather_pem_file_paths_from_client_proxy(&mut config.protocol, visitor);
        }
        _ => {}
    }
}

pub(crate) fn is_pem_file_path(s: &str) -> bool {
    !s.trim_start().starts_with("-----BEGIN")
        && (s.contains('/')
            || s.contains('\\')
            || s.ends_with(".pem")
            || s.ends_with(".crt")
            || s.ends_with(".key"))
}

async fn read_pem_to_string(path: &str) -> std::io::Result<String> {
    debug!("Reading PEM file: {path}");
    tokio::fs::read_to_string(path).await.map_err(|e| {
        std::io::Error::new(e.kind(), format!("Failed to read PEM file '{path}': {e}"))
    })
}

fn process_pem_path(
    pem: &mut String,
    known_pem_paths: &HashMap<String, String>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if is_pem_file_path(pem) {
        match known_pem_paths.get(pem) {
            Some(name) => {
                *pem = name.clone();
            }
            None => {
                let new_name = format!("inlined-{pem}");
                unknown_pem_paths.insert(pem.clone(), new_name.clone());
                *pem = new_name;
            }
        }
    }
}

fn visit_optional_pem(pem: &mut Option<String>, visitor: &mut PemVisitor<'_>) {
    if let Some(pem) = pem {
        visitor(pem, PemUsage::Reload);
    }
}

pub(super) fn embed_pem_from_map(pem: &mut String, named_pems: &HashMap<String, String>) {
    if let Some(pem_data) = named_pems.get(pem) {
        *pem = pem_data.clone();
    } else if is_pem_file_path(pem) {
        panic!("PEM file path {pem} was not loaded during conversion");
    }
}

pub(super) fn embed_optional_pem_from_map(
    pem: &mut Option<String>,
    named_pems: &HashMap<String, String>,
) {
    if let Some(pem_str) = pem {
        embed_pem_from_map(pem_str, named_pems);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn pem_path_classification_preserves_legacy_rules() {
        for (value, is_path) in [
            ("chain", false),
            ("", false),
            ("server.pem", true),
            ("server.crt", true),
            ("server.key", true),
            ("server.PEM", false),
            ("certs/server", true),
            (r"certs\server", true),
            ("  -----BEGIN CERTIFICATE-----\nabc/def", false),
        ] {
            assert_eq!(is_pem_file_path(value), is_path, "{value:?}");
        }
    }

    #[tokio::test]
    async fn duplicate_path_aliases_preserve_declarations_and_last_name_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.pem");
        std::fs::write(&path, "fixture PEM data").unwrap();
        let configs = serde_yaml::from_value(
            serde_yaml::to_value(json!([
                {"pem": "first", "path": path},
                {"pem": "second", "path": path},
                {"client_group": "outbound", "client_proxy": {
                    "address": "127.0.0.1:443", "protocol": {
                        "type": "tls", "cert": path, "key": path, "protocol": {"type": "socks"}
                    }
                }}
            ]))
            .unwrap(),
        )
        .unwrap();
        let (configs, loaded) = convert_cert_paths(configs).await.unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(configs.len(), 3);
        for (config, name) in configs[..2].iter().zip(["first", "second"]) {
            let Config::NamedPem(pem) = config else {
                panic!()
            };
            assert_eq!(pem.pem, name);
            assert!(matches!(&pem.source, PemSource::Data(data) if data == "fixture PEM data"));
        }
        let Config::ClientConfigGroup(group) = &configs[2] else {
            panic!()
        };
        let ConfigSelection::Config(client) = group.client_proxies.iter().next().unwrap() else {
            panic!()
        };
        let ClientProxyConfig::Tls(tls) = &client.protocol else {
            panic!()
        };
        assert_eq!(tls.cert.as_deref(), Some("second"));
        assert_eq!(tls.key.as_deref(), Some("second"));
    }

    #[test]
    fn tls_pem_traversal_preserves_roles_order_and_vision_labels() {
        let target = |prefix: &str| {
            json!({
                "cert": format!("{prefix}.crt"), "key": format!("{prefix}.key"),
                "client_ca_certs": format!("{prefix}-ca.crt"), "vision": false,
                "protocol": {"type": "socks"}
            })
        };
        let expected = [
            ("named.crt", true),
            ("named.key", true),
            ("named-ca.crt", false),
            ("default.crt", true),
            ("default.key", true),
            ("default-ca.crt", false),
        ];
        for (vision_pointer, visit_count, error_label) in [
            (None, 6, None),
            (
                Some("/protocol/tls_targets/proxy.test/vision"),
                3,
                Some("TLS target 'proxy.test'"),
            ),
            (
                Some("/protocol/default_tls_target/vision"),
                6,
                Some("default TLS target"),
            ),
        ] {
            let mut value = json!({"address": "127.0.0.1:8443", "protocol": {
                "type": "tls", "tls_targets": {"proxy.test": target("named")},
                "default_tls_target": target("default")
            }});
            if let Some(pointer) = vision_pointer {
                *value.pointer_mut(pointer).unwrap() = true.into();
            }
            let mut config: Config =
                serde_yaml::from_value(serde_yaml::to_value(value).unwrap()).unwrap();
            let mut visited = Vec::new();
            let result = visit_config_pems(&mut config, &mut |pem, usage| {
                visited.push((pem.clone(), matches!(usage, PemUsage::ServerIdentity)));
            });
            assert_eq!(
                visited,
                expected[..visit_count]
                    .iter()
                    .copied()
                    .map(|(pem, identity)| (pem.to_owned(), identity))
                    .collect::<Vec<_>>()
            );
            match error_label {
                None => result.unwrap(),
                Some(label) => {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        format!(
                            "{label} config has vision=true but inner protocol is SOCKS (not VLESS). \
                             Vision (XTLS-RPRX-Vision) requires VLESS as the inner protocol. \
                             Either set vision=false or change the inner protocol to VLESS."
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn reload_dependencies_cover_pem_roles_without_live_server_identities() {
        let client = |name: &str| {
            json!({
                "address": "127.0.0.1:443",
                "protocol": {"type": "tls", "cert": format!("{name}.crt"),
                    "key": format!("{name}.key"), "protocol": {"type": "socks"}}
            })
        };
        let value = json!([
            {"pem": "named-ca", "path": "ca.crt"},
            {"pem": "inline.pem", "data": "-----BEGIN CERTIFICATE-----\ninline"},
            {"address": "127.0.0.1:8443", "transport": "quic",
                "quic_settings": {"cert": "live.crt", "key": "live.key", "client_ca_certs": "quic-ca.crt"},
                "protocol": {"type": "tls", "default_tls_target": {
                    "cert": "live.crt", "key": "live.key", "client_ca_certs": ["named-ca", "inline.pem"],
                    "protocol": {"type": "socks"}
                }, "shadowtls_targets": {"proxy.test": {
                    "password": "test", "handshake": {"cert": "shadow.crt", "key": "shadow.key", "client_ca_certs": "shadow-ca.crt"},
                    "protocol": {"type": "socks"},
                    "override_rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": [client("override")]}]
                }}},
                "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": [client("rule")]}]},
            {"client_group": "outbound", "client_proxy": {
                "address": "127.0.0.1:443", "transport": "quic",
                "quic_settings": {"cert": "client-quic.crt", "key": "client-quic.key"},
                "protocol": {"type": "tls", "cert": "live.crt", "key": "outbound.key", "protocol": {"type": "socks"}}
            }},
            {"dns_group": "dns", "dns_servers": [{"url": "udp://127.0.0.1:53", "client_chain": [client("dns")]}]},
            {"device_fd": 42, "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": [client("tun")]}]},
            {"rule_group": "rules", "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": [client("group")]}]},
            {"certificate_source": "acme", "type": "acme", "domains": ["proxy.test"],
                "directory_url": "http://127.0.0.1:9/directory", "state_dir": "unused", "ca_cert": "acme-ca.crt",
                "challenge": {"type": "http01", "listen": ["127.0.0.1:18080"]}}
        ]);
        let mut configs: Vec<Config> =
            serde_yaml::from_value(serde_yaml::to_value(value).unwrap()).unwrap();
        let before = serde_yaml::to_string(&configs).unwrap();
        let paths = pem_reload_dependencies(&mut configs).unwrap();
        let mut expected: Vec<_> = [
            "ca.crt",
            "quic-ca.crt",
            "shadow.crt",
            "shadow.key",
            "shadow-ca.crt",
            "override.crt",
            "override.key",
            "rule.crt",
            "rule.key",
            "client-quic.crt",
            "client-quic.key",
            "live.crt",
            "outbound.key",
            "dns.crt",
            "dns.key",
            "tun.crt",
            "tun.key",
            "group.crt",
            "group.key",
            "acme-ca.crt",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        expected.sort();
        assert_eq!(paths, expected);
        assert_eq!(serde_yaml::to_string(&configs).unwrap(), before);
    }

    #[tokio::test]
    async fn local_shadowtls_ca_paths_are_loaded_before_validation() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        let value = json!([{"address": "127.0.0.1:8443", "protocol": {
            "type": "tls", "shadowtls_targets": {"proxy.test": {
                "password": "test", "handshake": {"cert": cert.cert.pem(),
                    "key": cert.signing_key.serialize_pem(), "client_ca_certs": ca},
                "protocol": {"type": "socks"}
            }}
        }}]);
        let configs = serde_yaml::from_value(serde_yaml::to_value(value).unwrap()).unwrap();
        let (configs, loaded) = convert_cert_paths(configs).await.unwrap();
        assert_eq!(loaded, 1);
        super::super::create_server_configs(configs).unwrap();
    }
}
