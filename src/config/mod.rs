mod types;

pub use types::*;

use std::collections::HashMap;

use log::debug;

use crate::address::NetLocationMask;
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::thread_util::get_num_threads;
use crate::util::parse_uuid;

const MIN_TLS_BUFFER_SIZE: usize = 16 * 1024;

pub async fn load_configs(args: &Vec<String>) -> std::io::Result<Vec<Config>> {
    let mut all_configs = vec![];
    for config_filename in args {
        let config_bytes = match tokio::fs::read(config_filename).await {
            Ok(b) => b,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not read config file {config_filename}: {e}"),
                ));
            }
        };

        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as UTF8: {e}"),
                ));
            }
        };

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as config YAML: {e}"),
                ));
            }
        };
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

pub async fn convert_cert_paths(all_configs: Vec<Config>) -> std::io::Result<(Vec<Config>, usize)> {
    // this converts configs by removing all file references:
    // - all named pems that point to a file are loaded into a data-backed pem
    // - all inline file paths in cert or key fields are loaded into new named pem items
    let mut path_pem_configs: HashMap<String, NamedPem> = HashMap::new();
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
                path_pem_configs.insert(path, loaded_config);
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

    // we need to gather all the paths that are inlined, that are not named.
    // we do this as a separate step because we can't load the data in an async manner
    // right away due to recursion.
    for config in server_configs.iter_mut() {
        gather_pem_file_paths_from_server_config(
            config,
            &path_pem_configs,
            &mut unknown_pem_paths,
        )?;
    }

    for config in client_group_configs.iter_mut() {
        gather_pem_file_paths_from_client_config_group(
            config,
            &path_pem_configs,
            &mut unknown_pem_paths,
        );
    }

    let mut updated_configs = vec![];

    updated_configs.append(&mut data_configs);

    // insert the loaded path configs
    for (_, named_pem) in path_pem_configs.into_iter() {
        updated_configs.push(Config::NamedPem(named_pem));
    }

    // generate new named configs from inlined paths
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

pub async fn create_server_configs(all_configs: Vec<Config>) -> std::io::Result<Vec<ServerConfig>> {
    let mut client_groups: HashMap<String, Vec<ClientConfig>> = HashMap::new();
    client_groups.insert(String::from("direct"), vec![ClientConfig::default()]);

    let mut rule_groups: HashMap<String, Vec<RuleConfig>> = HashMap::new();
    rule_groups.insert(
        String::from("allow-all-direct"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
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
    let mut named_pems: HashMap<String, String> = HashMap::new();

    for config in all_configs.into_iter() {
        match config {
            Config::ClientConfigGroup(group) => {
                if client_groups
                    .insert(group.client_group.clone(), group.client_proxies.into_vec())
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
        }
    }

    for config in server_configs.iter_mut() {
        validate_server_config(config, &client_groups, &rule_groups, &named_pems)?;
    }

    Ok(server_configs)
}

fn gather_pem_file_paths_from_server_config(
    server_config: &mut ServerConfig,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) -> std::io::Result<()> {
    // Check QUIC settings
    if let Some(ref mut quic_settings) = server_config.quic_settings {
        process_pem_path(&mut quic_settings.cert, known_pem_paths, unknown_pem_paths);
        process_pem_path(&mut quic_settings.key, known_pem_paths, unknown_pem_paths);
        for cert in quic_settings.client_ca_certs.iter_mut() {
            process_pem_path(cert, known_pem_paths, unknown_pem_paths);
        }
    }

    // Recursively check the protocol
    gather_pem_file_paths_from_server_proxy(
        &mut server_config.protocol,
        known_pem_paths,
        unknown_pem_paths,
    )?;

    // Check rules
    for rule in server_config.rules.iter_mut() {
        gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
    }
    Ok(())
}

fn gather_pem_file_paths_from_client_config_group(
    client_group_config: &mut ClientConfigGroup,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    for client_config in client_group_config.client_proxies.iter_mut() {
        gather_pem_file_paths_from_client_config(client_config, known_pem_paths, unknown_pem_paths);
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
        // Vision not enabled, no validation needed
        return Ok(());
    }

    // Vision is enabled - verify inner protocol is VLESS
    match protocol {
        ServerProxyConfig::Vless { .. } => {
            // Valid: Vision + VLESS
            Ok(())
        }
        other_protocol => {
            // Invalid: Vision requires VLESS
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} config has vision=true but inner protocol is {} (not VLESS). \
                     Vision (XTLS-RPRX-Vision) requires VLESS as the inner protocol. \
                     Either set vision=false or change the inner protocol to VLESS.",
                    config_type, other_protocol
                ),
            ))
        }
    }
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
            validate_client_proxy_structure(&tls_config.protocol)
        }

        ClientProxyConfig::Reality {
            vision, protocol, ..
        } => {
            validate_client_vision_protocol(*vision, protocol, "Reality")?;
            validate_client_proxy_structure(protocol)
        }

        ClientProxyConfig::ShadowTls { protocol, .. } => validate_client_proxy_structure(protocol),

        ClientProxyConfig::Websocket(ws_config) => {
            validate_client_proxy_structure(&ws_config.protocol)
        }

        // Leaf protocols
        _ => Ok(()),
    }
}

fn gather_pem_file_paths_from_server_proxy(
    server_proxy: &mut ServerProxyConfig,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) -> std::io::Result<()> {
    match server_proxy {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            // Process TLS targets
            for (sni, tls_config) in tls_targets.iter_mut() {
                process_pem_path(&mut tls_config.cert, known_pem_paths, unknown_pem_paths);
                process_pem_path(&mut tls_config.key, known_pem_paths, unknown_pem_paths);
                for cert in tls_config.client_ca_certs.iter_mut() {
                    process_pem_path(cert, known_pem_paths, unknown_pem_paths);
                }

                // Validate Vision configuration
                validate_vision_protocol(
                    tls_config.vision,
                    &tls_config.protocol,
                    &format!("TLS target '{}'", sni),
                )?;

                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut tls_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in tls_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }

            // Process default TLS target
            if let Some(ref mut tls_config) = default_tls_target {
                process_pem_path(&mut tls_config.cert, known_pem_paths, unknown_pem_paths);
                process_pem_path(&mut tls_config.key, known_pem_paths, unknown_pem_paths);
                for cert in tls_config.client_ca_certs.iter_mut() {
                    process_pem_path(cert, known_pem_paths, unknown_pem_paths);
                }

                // Validate Vision configuration
                validate_vision_protocol(
                    tls_config.vision,
                    &tls_config.protocol,
                    "default TLS target",
                )?;

                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut tls_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in tls_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }

            // Process ShadowTLS targets
            for (_, shadowtls_config) in shadowtls_targets.iter_mut() {
                if let ShadowTlsServerHandshakeConfig::Local(ref mut handshake) =
                    shadowtls_config.handshake
                {
                    process_pem_path(&mut handshake.cert, known_pem_paths, unknown_pem_paths);
                    process_pem_path(&mut handshake.key, known_pem_paths, unknown_pem_paths);
                }
                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut shadowtls_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in shadowtls_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }

            // Process Reality targets
            for (sni, reality_config) in reality_targets.iter_mut() {
                // Validate Vision configuration
                validate_vision_protocol(
                    reality_config.vision,
                    &reality_config.protocol,
                    &format!("Reality target '{}'", sni),
                )?;

                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut reality_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in reality_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_config in targets.iter_mut() {
                // Recurse into inner protocol
                gather_pem_file_paths_from_server_proxy(
                    &mut websocket_config.protocol,
                    known_pem_paths,
                    unknown_pem_paths,
                )?;
                // Check override rules
                for rule in websocket_config.override_rules.iter_mut() {
                    gather_pem_file_paths_from_rule(rule, known_pem_paths, unknown_pem_paths);
                }
            }
        }
        ServerProxyConfig::Vless { .. } => {}
        _ => {}
    }
    Ok(())
}

fn gather_pem_file_paths_from_rule(
    rule_selection: &mut ConfigSelection<RuleConfig>,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if let ConfigSelection::Config(rule) = rule_selection {
        if let RuleActionConfig::Allow {
            ref mut client_proxies,
            ..
        } = rule.action
        {
            for client_selection in client_proxies.iter_mut() {
                if let ConfigSelection::Config(client_config) = client_selection {
                    gather_pem_file_paths_from_client_config(
                        client_config,
                        known_pem_paths,
                        unknown_pem_paths,
                    );
                }
            }
        }
    }
}

fn gather_pem_file_paths_from_client_config(
    client_config: &mut ClientConfig,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    // Check QUIC settings
    if let Some(ref mut quic_config) = client_config.quic_settings {
        process_optional_pem_path(&mut quic_config.cert, known_pem_paths, unknown_pem_paths);
        process_optional_pem_path(&mut quic_config.key, known_pem_paths, unknown_pem_paths);
    }

    // Recurse into client proxy config
    gather_pem_file_paths_from_client_proxy(
        &mut client_config.protocol,
        known_pem_paths,
        unknown_pem_paths,
    );
}

fn gather_pem_file_paths_from_client_proxy(
    client_proxy: &mut ClientProxyConfig,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if let ClientProxyConfig::Tls(ref mut tls_config) = client_proxy {
        process_optional_pem_path(&mut tls_config.cert, known_pem_paths, unknown_pem_paths);
        process_optional_pem_path(&mut tls_config.key, known_pem_paths, unknown_pem_paths);
        // Recurse into inner protocol
        gather_pem_file_paths_from_client_proxy(
            &mut tls_config.protocol,
            known_pem_paths,
            unknown_pem_paths,
        );
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

    if let BindLocation::Path(_) = server_config.bind_location {
        if server_config.transport != Transport::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix domain socket support only available for TCP transport",
            ));
        }
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

/// Validates Reality short_ids to ensure they are valid hexadecimal strings.
///
/// Each short_id must be:
///   - Valid hexadecimal (0-9, a-f, A-F)
///   - Even length (to decode to whole bytes)
///   - Maximum 16 characters (8 bytes when decoded)
///
/// Validates Reality private_key to ensure it's a valid base64url-encoded X25519 key.
///
/// The private key must:
///   - Be valid base64url encoding
///   - Decode to exactly 32 bytes (X25519 key size)
fn validate_reality_private_key(private_key: &str, target_name: &str) -> std::io::Result<()> {
    use crate::reality::decode_private_key;

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
    use crate::reality::decode_short_id;

    // Check length
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

    // Check for valid hexadecimal characters
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

    // Try to decode to validate format
    decode_short_id(short_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Reality client short_id decode failed: {}", e),
        )
    })?;

    Ok(())
}

fn validate_reality_server_short_ids(
    short_ids: &crate::option_util::OneOrSome<String>,
    target_name: &str,
) -> std::io::Result<()> {
    // OneOrSome ensures at least one short_id is always present (default is all zeros)

    // Check if it's exactly one short_id with the default all-zeros value
    let is_default = match short_ids {
        crate::option_util::OneOrSome::One(id) => {
            id == crate::config::types::DEFAULT_REALITY_SHORT_ID
        }
        crate::option_util::OneOrSome::Some(ids) => {
            ids.len() == 1 && ids[0] == crate::config::types::DEFAULT_REALITY_SHORT_ID
        }
    };

    if is_default {
        log::warn!(
            "Reality server '{}' using default short_ids (all zeros). \
             For better security in production, configure explicit short_ids.",
            target_name
        );
    }

    for (i, short_id) in short_ids.iter().enumerate() {
        // Check length
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

        // Check for valid hexadecimal characters
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

        // Empty string is technically valid (will be left-padded to 16 zeros)
        // but odd-length strings are also valid (will be left-padded)
        // The decode_short_id function handles padding internally
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

        // Embed certificates before validation
        embed_optional_pem_from_map(&mut quic_config.cert, named_pems);
        embed_optional_pem_from_map(&mut quic_config.key, named_pems);

        let ClientQuicConfig {
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
    // First validate the structure (Vision rules, etc.)
    validate_client_proxy_structure(client_proxy_config)?;

    match client_proxy_config {
        ClientProxyConfig::Reality {
            short_id, protocol, ..
        } => {
            // Validate short_id format
            validate_reality_client_short_id(short_id)?;

            // Warn if using default all-zeros short_id
            if short_id == crate::config::types::DEFAULT_REALITY_SHORT_ID {
                log::warn!(
                    "Reality client using default short_id (all zeros). \
                     For better security in production, configure an explicit short_id that matches your server."
                );
            }

            // Recurse into inner protocol
            validate_client_proxy_config(protocol, named_pems)?;
        }

        ClientProxyConfig::Tls(ref mut tls_config) => {
            // Embed certificates before validation
            embed_optional_pem_from_map(&mut tls_config.cert, named_pems);
            embed_optional_pem_from_map(&mut tls_config.key, named_pems);

            if tls_config.cert.is_none() != tls_config.key.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Both client cert and key have to be specified, or both have to be omitted",
                ));
            }
            validate_server_fingerprints(&mut tls_config.server_fingerprints)?;

            // Recursively validate inner protocol
            validate_client_proxy_config(&mut tls_config.protocol, named_pems)?;
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
) -> std::io::Result<()> {
    match server_proxy_config {
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
                // Embed certificates
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

                validate_server_proxy_config(protocol, client_groups, rule_groups, named_pems)?;

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
                // Embed certificates
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
                validate_server_proxy_config(protocol, client_groups, rule_groups, named_pems)?;

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

                if let ShadowTlsServerHandshakeConfig::Local(ref mut local_handshake) = handshake {
                    // Embed certificates for local handshake
                    embed_pem_from_map(&mut local_handshake.cert, named_pems);
                    embed_pem_from_map(&mut local_handshake.key, named_pems);
                    validate_client_fingerprints(&mut local_handshake.client_fingerprints)?;
                }

                validate_server_proxy_config(protocol, client_groups, rule_groups, named_pems)?;

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

                // Validate Reality private_key (must be valid base64url-encoded X25519 key)
                validate_reality_private_key(&reality_config.private_key, sni_hostname)?;

                // Validate Reality short_ids (must be valid hex strings)
                validate_reality_server_short_ids(&reality_config.short_ids, sni_hostname)?;

                // Validate inner protocol
                validate_server_proxy_config(
                    &mut reality_config.protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                )?;

                // Validate override_rules
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

            if let Some(size) = tls_buffer_size {
                if *size < MIN_TLS_BUFFER_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("TLS buffer size must be at least {MIN_TLS_BUFFER_SIZE}"),
                    ));
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_server_config in targets.iter_mut() {
                let WebsocketServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = websocket_server_config;
                validate_server_proxy_config(protocol, client_groups, rule_groups, named_pems)?;

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
        _ => (),
    }
    Ok(())
}

fn validate_rule_config(
    rule_config: &mut RuleConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    if let RuleActionConfig::Allow {
        ref mut client_proxies,
        ..
    } = rule_config.action
    {
        ConfigSelection::replace_one_or_some_groups(client_proxies, client_groups)?;
        for client_config_selection in client_proxies.iter_mut() {
            validate_client_config(client_config_selection.unwrap_config_mut(), named_pems)?
        }
    }

    Ok(())
}

fn is_pem_file_path(s: &str) -> bool {
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

// Helper function to process a PEM path during the gathering phase
fn process_pem_path(
    pem: &mut String,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if is_pem_file_path(pem) {
        match known_pem_paths.get(pem) {
            Some(named_pem) => {
                *pem = named_pem.pem.clone();
            }
            None => {
                let new_name = format!("inlined-{pem}");
                unknown_pem_paths.insert(pem.clone(), new_name.clone());
                *pem = new_name;
            }
        }
    }
}

// Helper function to process an optional PEM path during the gathering phase
fn process_optional_pem_path(
    pem: &mut Option<String>,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if let Some(ref mut pem_str) = pem {
        process_pem_path(pem_str, known_pem_paths, unknown_pem_paths);
    }
}

fn embed_pem_from_map(pem: &mut String, named_pems: &HashMap<String, String>) {
    if let Some(pem_data) = named_pems.get(pem) {
        *pem = pem_data.clone();
    } else if is_pem_file_path(pem) {
        panic!("PEM file path {pem} was not loaded during conversion");
    }
}

fn embed_optional_pem_from_map(pem: &mut Option<String>, named_pems: &HashMap<String, String>) {
    if let Some(ref mut pem_str) = pem {
        embed_pem_from_map(pem_str, named_pems);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recursive_certificate_embedding() {
        // Initialize NUM_THREADS for test
        crate::thread_util::set_num_threads(1);

        // Create test certificate files
        let test_dir = tempfile::tempdir().unwrap();
        let cert_dir = test_dir.path().join("certs");
        tokio::fs::create_dir_all(&cert_dir).await.unwrap();

        // Create test certificate contents
        let test_cert = "-----BEGIN CERTIFICATE-----\nTEST CERT CONTENT\n-----END CERTIFICATE-----";
        let test_key = "-----BEGIN PRIVATE KEY-----\nTEST KEY CONTENT\n-----END PRIVATE KEY-----";

        // Write test certificates
        let cert_files = vec![
            ("quic.crt", test_cert),
            ("quic.key", test_key),
            ("server.crt", test_cert),
            ("server.key", test_key),
            ("ca.crt", test_cert),
            ("inner.crt", test_cert),
            ("inner.key", test_key),
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

        // Create test configuration with nested certificates
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
                user_id: "123e4567-e89b-12d3-a456-426614174000"
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
      client_proxies:
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

        // Parse the configuration
        let configs: Vec<Config> = serde_yaml::from_str(&config_yaml).unwrap();

        // Convert cert paths (stage 1)
        let (converted_configs, load_count) = convert_cert_paths(configs).await.unwrap();

        // Check that certificates were loaded (11 certificate/key files total)
        assert_eq!(load_count, 11);

        // Create server configs (stage 2)
        let server_configs = create_server_configs(converted_configs).await.unwrap();

        // Verify that certificates were embedded at all levels
        let server_config = &server_configs[0];

        // Check QUIC settings
        let quic_settings = server_config.quic_settings.as_ref().unwrap();
        assert!(quic_settings.cert.contains("BEGIN CERTIFICATE"));
        assert!(quic_settings.key.contains("BEGIN PRIVATE KEY"));

        // Check TLS settings
        if let ServerProxyConfig::Tls {
            tls_targets,
            shadowtls_targets,
            ..
        } = &server_config.protocol
        {
            // Check TLS target
            let tls_config = tls_targets.get("example.com").unwrap();
            assert!(tls_config.cert.contains("BEGIN CERTIFICATE"));
            assert!(tls_config.key.contains("BEGIN PRIVATE KEY"));
            assert!(tls_config
                .client_ca_certs
                .iter()
                .next()
                .unwrap()
                .contains("BEGIN CERTIFICATE"));

            // Check nested WebSocket -> VMess (no more nested certificates)
            if let ServerProxyConfig::Websocket { targets } = &tls_config.protocol {
                let ws_config = targets.iter().next().unwrap();
                assert!(matches!(
                    &ws_config.protocol,
                    ServerProxyConfig::Vmess { .. }
                ));
            }

            // Check ShadowTLS target
            let shadow_config = shadowtls_targets.get("shadow.com").unwrap();
            if let ShadowTlsServerHandshakeConfig::Local(handshake) = &shadow_config.handshake {
                assert!(handshake.cert.contains("BEGIN CERTIFICATE"));
                assert!(handshake.key.contains("BEGIN PRIVATE KEY"));
            }
        }

        // Check client certificates in rules
        for rule_selection in server_config.rules.iter() {
            if let ConfigSelection::Config(rule) = rule_selection {
                if let RuleActionConfig::Allow { client_proxies, .. } = &rule.action {
                    for client_selection in client_proxies.iter() {
                        if let ConfigSelection::Config(client_config) = client_selection {
                            // Check client QUIC settings
                            let client_quic = client_config.quic_settings.as_ref().unwrap();
                            assert!(client_quic
                                .cert
                                .as_ref()
                                .unwrap()
                                .contains("BEGIN CERTIFICATE"));
                            assert!(client_quic
                                .key
                                .as_ref()
                                .unwrap()
                                .contains("BEGIN PRIVATE KEY"));

                            // Check client TLS settings
                            if let ClientProxyConfig::Tls(tls_client) = &client_config.protocol {
                                assert!(tls_client
                                    .cert
                                    .as_ref()
                                    .unwrap()
                                    .contains("BEGIN CERTIFICATE"));
                                assert!(tls_client
                                    .key
                                    .as_ref()
                                    .unwrap()
                                    .contains("BEGIN PRIVATE KEY"));
                            }
                        }
                    }
                }
            }
        }
    }
}
