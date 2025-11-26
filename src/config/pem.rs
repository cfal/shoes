//! PEM file handling - loading certificates and converting file paths to inline data.

use std::collections::HashMap;

use log::debug;

use super::types::{
    ClientChainHop, ClientConfig, ClientConfigGroup, ClientProxyConfig, Config, NamedPem,
    PemSource, RuleActionConfig, ServerConfig, ServerProxyConfig, ShadowTlsServerHandshakeConfig,
};
use crate::config::ConfigSelection;

/// Converts all PEM file references to inline data.
///
/// This function:
/// - Loads all named PEMs that point to files into data-backed PEMs
/// - Converts inline file paths in cert/key fields to new named PEM items
///
/// Returns the converted configs and the count of PEM files loaded.
pub async fn convert_cert_paths(all_configs: Vec<Config>) -> std::io::Result<(Vec<Config>, usize)> {
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

    // Gather all paths that are inlined but not named.
    // We do this as a separate step because we can't load the data in an async manner
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

    // Insert the loaded path configs
    for (_, named_pem) in path_pem_configs.into_iter() {
        updated_configs.push(Config::NamedPem(named_pem));
    }

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
    for selection in client_group_config.client_proxies.iter_mut() {
        if let ConfigSelection::Config(client_config) = selection {
            gather_pem_file_paths_from_client_config(
                client_config,
                known_pem_paths,
                unknown_pem_paths,
            );
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
            if let Some(tls_config) = default_tls_target {
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
        _ => {}
    }
    Ok(())
}

fn gather_pem_file_paths_from_rule(
    rule_selection: &mut ConfigSelection<super::types::RuleConfig>,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if let ConfigSelection::Config(rule) = rule_selection
        && let RuleActionConfig::Allow {
            ref mut client_chains,
            ..
        } = rule.action
    {
        for chain in client_chains.iter_mut() {
            for hop in chain.hops.iter_mut() {
                gather_pem_file_paths_from_chain_hop(hop, known_pem_paths, unknown_pem_paths);
            }
        }
    }
}

fn gather_pem_file_paths_from_chain_hop(
    hop: &mut ClientChainHop,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    match hop {
        ClientChainHop::Single(selection) => {
            if let ConfigSelection::Config(client_config) = selection {
                gather_pem_file_paths_from_client_config(
                    client_config,
                    known_pem_paths,
                    unknown_pem_paths,
                );
            }
            // GroupName selections are resolved later, skip here
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                if let ConfigSelection::Config(client_config) = selection {
                    gather_pem_file_paths_from_client_config(
                        client_config,
                        known_pem_paths,
                        unknown_pem_paths,
                    );
                }
                // GroupName selections are resolved later, skip here
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
    match client_proxy {
        ClientProxyConfig::Tls(tls_config) => {
            process_optional_pem_path(&mut tls_config.cert, known_pem_paths, unknown_pem_paths);
            process_optional_pem_path(&mut tls_config.key, known_pem_paths, unknown_pem_paths);
            // Recurse into inner protocol
            gather_pem_file_paths_from_client_proxy(
                &mut tls_config.protocol,
                known_pem_paths,
                unknown_pem_paths,
            );
        }
        ClientProxyConfig::Reality { protocol, .. } => {
            // Reality doesn't have cert/key PEM files, but recurse into inner protocol
            gather_pem_file_paths_from_client_proxy(protocol, known_pem_paths, unknown_pem_paths);
        }
        ClientProxyConfig::ShadowTls { protocol, .. } => {
            gather_pem_file_paths_from_client_proxy(protocol, known_pem_paths, unknown_pem_paths);
        }
        ClientProxyConfig::Websocket(ws_config) => {
            gather_pem_file_paths_from_client_proxy(
                &mut ws_config.protocol,
                known_pem_paths,
                unknown_pem_paths,
            );
        }
        _ => {}
    }
}

pub(super) fn is_pem_file_path(s: &str) -> bool {
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

fn process_optional_pem_path(
    pem: &mut Option<String>,
    known_pem_paths: &HashMap<String, NamedPem>,
    unknown_pem_paths: &mut HashMap<String, String>,
) {
    if let Some(pem_str) = pem {
        process_pem_path(pem_str, known_pem_paths, unknown_pem_paths);
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
