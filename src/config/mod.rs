mod types;

pub use types::*;

use std::collections::HashMap;
use std::path::Path;

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
                    format!("Could not read config file {}: {}", config_filename, e),
                ));
            }
        };

        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Could not parse config file {} as UTF8: {}",
                        config_filename, e
                    ),
                ));
            }
        };

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Could not parse config file {} as config YAML: {}",
                        config_filename, e
                    ),
                ));
            }
        };
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

pub async fn validate_configs(
    all_configs: Vec<Config>,
) -> std::io::Result<(Vec<ServerConfig>, usize)> {
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
    let mut named_certs: HashMap<String, String> = HashMap::new();
    let mut named_keys: HashMap<String, String> = HashMap::new();

    let mut embedded_keys_count = 0;

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
            Config::NamedCert(cert) => {
                let cert_data = match cert.source {
                    CertKeySource::Path(ref path) => {
                        embedded_keys_count += 1;
                        read_cert_to_string(path).await?
                    }
                    CertKeySource::Data(data) => data,
                };

                if named_certs.insert(cert.cert.clone(), cert_data).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("named certificate already exists: {}", cert.cert),
                    ));
                }
            }
            Config::NamedPrivateKey(key) => {
                let key_data = match key.source {
                    CertKeySource::Path(ref path) => {
                        embedded_keys_count += 1;
                        read_cert_to_string(path).await?
                    }
                    CertKeySource::Data(data) => data,
                };

                if named_keys.insert(key.key.clone(), key_data).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("named private key already exists: {}", key.key),
                    ));
                }
            }
        }
    }

    for config in server_configs.iter_mut() {
        validate_server_config(config, &client_groups, &rule_groups)?;
    }

    for config in server_configs.iter_mut() {
        embedded_keys_count += embed_file_based_certs(config, &named_certs, &named_keys).await?;
    }

    Ok((server_configs, embedded_keys_count))
}

fn validate_server_config(
    server_config: &mut ServerConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
) -> std::io::Result<()> {
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
        validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
    }

    validate_server_proxy_config(&mut server_config.protocol, client_groups, rule_groups)?;

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
        let _ = crate::rustls_util::process_fingerprints(&client_fingerprints.clone().into_vec())?;
    }

    Ok(())
}

fn validate_client_config(client_config: &mut ClientConfig) -> std::io::Result<()> {
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

    validate_client_proxy_config(&mut client_config.protocol)?;

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
        let _ = crate::rustls_util::process_fingerprints(&server_fingerprints.clone().into_vec())?;
    }

    Ok(())
}

fn validate_client_proxy_config(
    client_proxy_config: &mut ClientProxyConfig,
) -> std::io::Result<()> {
    if let ClientProxyConfig::Tls(TlsClientConfig {
        cert,
        key,
        server_fingerprints,
        ..
    }) = client_proxy_config
    {
        if cert.is_none() != key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both client cert and key have to be specified, or both have to be omitted",
            ));
        }
        validate_server_fingerprints(server_fingerprints)?;
    }
    Ok(())
}

fn validate_server_proxy_config(
    server_proxy_config: &mut ServerProxyConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
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
            tls_buffer_size,
        } => {
            for (_, tls_server_config) in tls_targets.iter_mut() {
                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut client_fingerprints,
                    ..
                } = *tls_server_config;

                validate_client_fingerprints(client_fingerprints)?;

                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
            if let Some(tls_server_config) = default_tls_target {
                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = **tls_server_config;
                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
            for (sni_hostname, tls_server_config) in shadowtls_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and ShadowTLS targets: {}",
                            sni_hostname
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
                    validate_client_fingerprints(&mut local_handshake.client_fingerprints)?;
                }

                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }

            if let Some(size) = tls_buffer_size {
                if *size < MIN_TLS_BUFFER_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("TLS buffer size must be at least {}", MIN_TLS_BUFFER_SIZE),
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
                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
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
) -> std::io::Result<()> {
    if let RuleActionConfig::Allow {
        ref mut client_proxies,
        ..
    } = rule_config.action
    {
        ConfigSelection::replace_one_or_some_groups(client_proxies, client_groups)?;
        for client_config_selection in client_proxies.iter_mut() {
            validate_client_config(client_config_selection.unwrap_config_mut())?
        }
    }

    Ok(())
}

async fn embed_file_based_certs(
    server_config: &mut ServerConfig,
    named_certs: &HashMap<String, String>,
    named_keys: &HashMap<String, String>,
) -> std::io::Result<usize> {
    let mut embedded_count = 0;

    if let Some(ref mut quic_settings) = server_config.quic_settings {
        if let Some(cert_data) = named_certs.get(&quic_settings.cert) {
            quic_settings.cert = cert_data.clone();
        } else if is_cert_file_path(&quic_settings.cert) {
            quic_settings.cert = read_cert_to_string(&quic_settings.cert).await?;
            embedded_count += 1;
        }

        if let Some(key_data) = named_keys.get(&quic_settings.key) {
            quic_settings.key = key_data.clone();
        } else if is_cert_file_path(&quic_settings.key) {
            quic_settings.key = read_cert_to_string(&quic_settings.key).await?;
            embedded_count += 1;
        }

        for cert in quic_settings.client_ca_certs.iter_mut() {
            if let Some(cert_data) = named_certs.get(cert) {
                *cert = cert_data.clone();
            } else if is_cert_file_path(cert) {
                *cert = read_cert_to_string(cert).await?;
                embedded_count += 1;
            }
        }
    }

    if let ServerProxyConfig::Tls {
        ref mut tls_targets,
        ref mut default_tls_target,
        ref mut shadowtls_targets,
        ..
    } = &mut server_config.protocol
    {
        for (_, tls_config) in tls_targets.iter_mut() {
            if let Some(cert_data) = named_certs.get(&tls_config.cert) {
                tls_config.cert = cert_data.clone();
            } else if is_cert_file_path(&tls_config.cert) {
                tls_config.cert = read_cert_to_string(&tls_config.cert).await?;
                embedded_count += 1;
            }

            if let Some(key_data) = named_keys.get(&tls_config.key) {
                tls_config.key = key_data.clone();
            } else if is_cert_file_path(&tls_config.key) {
                tls_config.key = read_cert_to_string(&tls_config.key).await?;
                embedded_count += 1;
            }

            for cert in tls_config.client_ca_certs.iter_mut() {
                if let Some(cert_data) = named_certs.get(cert) {
                    *cert = cert_data.clone();
                } else if is_cert_file_path(cert) {
                    *cert = read_cert_to_string(cert).await?;
                    embedded_count += 1;
                }
            }
        }

        if let Some(ref mut tls_config) = default_tls_target {
            if let Some(cert_data) = named_certs.get(&tls_config.cert) {
                tls_config.cert = cert_data.clone();
            } else if is_cert_file_path(&tls_config.cert) {
                tls_config.cert = read_cert_to_string(&tls_config.cert).await?;
                embedded_count += 1;
            }

            if let Some(key_data) = named_keys.get(&tls_config.key) {
                tls_config.key = key_data.clone();
            } else if is_cert_file_path(&tls_config.key) {
                tls_config.key = read_cert_to_string(&tls_config.key).await?;
                embedded_count += 1;
            }

            for cert in tls_config.client_ca_certs.iter_mut() {
                if let Some(cert_data) = named_certs.get(cert) {
                    *cert = cert_data.clone();
                } else if is_cert_file_path(cert) {
                    *cert = read_cert_to_string(cert).await?;
                    embedded_count += 1;
                }
            }
        }

        for (_, shadowtls_config) in shadowtls_targets.iter_mut() {
            if let ShadowTlsServerHandshakeConfig::Local(ref mut handshake) =
                shadowtls_config.handshake
            {
                if let Some(cert_data) = named_certs.get(&handshake.cert) {
                    handshake.cert = cert_data.clone();
                } else if is_cert_file_path(&handshake.cert) {
                    handshake.cert = read_cert_to_string(&handshake.cert).await?;
                    embedded_count += 1;
                }

                if let Some(key_data) = named_keys.get(&handshake.key) {
                    handshake.key = key_data.clone();
                } else if is_cert_file_path(&handshake.key) {
                    handshake.key = read_cert_to_string(&handshake.key).await?;
                    embedded_count += 1;
                }
            }
        }
    }

    Ok(embedded_count)
}
fn is_cert_file_path(s: &str) -> bool {
    !s.trim_start().starts_with("-----BEGIN")
        && (s.contains('/')
            || s.contains('\\')
            || s.ends_with(".pem")
            || s.ends_with(".crt")
            || s.ends_with(".key"))
}

async fn read_cert_to_string(path: &str) -> std::io::Result<String> {
    debug!("Reading certificate/key file: {}", path);
    tokio::fs::read_to_string(path).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("Failed to read certificate/key file '{}': {}", path, e),
        )
    })
}

#[allow(dead_code)]
pub async fn save_config(path: &Path, configs: &[Config]) -> std::io::Result<()> {
    let yaml_str = serde_yaml::to_string(configs).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to serialize to YAML: {}", e),
        )
    })?;

    tokio::fs::write(path, yaml_str).await?;
    Ok(())
}
