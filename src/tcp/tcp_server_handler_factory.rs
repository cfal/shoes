//! Factory functions for creating TCP server handlers from config.

use std::net::IpAddr;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::anytls::{AnyTlsServerHandler, PaddingFactory};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{ClientChainHop, ClientConfig};
use crate::config::{
    ConfigSelection, RealityServerConfig, RuleConfig, ServerProxyConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig, WebsocketServerConfig,
};
use crate::http_handler::HttpTcpServerHandler;
use crate::mixed_handler::MixedTcpServerHandler;
use crate::naiveproxy::UserLookup;
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::port_forward_handler::PortForwardServerHandler;
use crate::reality::RealityServerTarget;
use crate::resolver::Resolver;
use crate::rustls_config_util::try_create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellServerHandler;
use crate::socks_handler::SocksTcpServerHandler;
use crate::tcp::chain_builder::try_build_client_proxy_chain;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tls_server_handler::NaiveConfig;
use crate::tls_server_handler::{
    InnerProtocol, TlsServerHandler, TlsServerTarget, VisionVlessConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
use crate::uuid_util::parse_uuid;
use crate::vless::vless_server_handler::VlessTcpServerHandler;
use crate::vmess::VmessTcpServerHandler;
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;

#[derive(Default)]
pub(crate) struct HandlerServices {
    xhttp: std::collections::HashMap<Vec<String>, crate::xhttp::XhttpServer>,
    vless: std::collections::HashMap<Vec<String>, Arc<crate::vless::encryption::ServerEncryption>>,
}

struct ServiceScope<'a> {
    services: &'a mut HandlerServices,
    path: Vec<String>,
}

impl ServiceScope<'_> {
    fn child(&mut self, key: String) -> ServiceScope<'_> {
        let mut path = self.path.clone();
        path.push(key);
        ServiceScope {
            services: self.services,
            path,
        }
    }
}

fn create_auth_credentials(
    username: Option<String>,
    password: Option<String>,
) -> Option<(String, String)> {
    match (&username, &password) {
        (None, None) => None,
        _ => Some((username.unwrap_or_default(), password.unwrap_or_default())),
    }
}

fn create_override_selector(
    override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
    parent: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Arc<ClientProxySelector>> {
    let rules = override_rules
        .map(ConfigSelection::unwrap_config)
        .into_vec();
    Ok(Arc::new(
        create_tcp_client_proxy_selector(rules, resolver.clone())?
            .inherit_inbound_policy(parent)?,
    ))
}

/// Create a TCP server handler from config.
///
/// # Arguments
/// * `server_proxy_config` - The protocol configuration
/// * `client_proxy_selector` - Selector for outbound proxy routing
/// * `resolver` - DNS resolver
/// * `bind_ip` - Optional bind IP for handlers that need it (e.g., Socks5 UDP, Mixed)
///
/// The `bind_ip` is required for:
/// - `Socks` with `udp_enabled: true` (for UDP ASSOCIATE)
/// - `Mixed` with `udp_enabled: true` (for UDP ASSOCIATE)
pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> std::io::Result<Box<dyn TcpServerHandler>> {
    create_tcp_server_handler_shared(
        server_proxy_config,
        client_proxy_selector,
        resolver,
        bind_ip,
        &mut HandlerServices::default(),
    )
}

pub(crate) fn create_tcp_server_handler_shared(
    config: ServerProxyConfig,
    selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    services: &mut HandlerServices,
) -> std::io::Result<Box<dyn TcpServerHandler>> {
    create_handler(
        config,
        selector,
        resolver,
        bind_ip,
        &mut ServiceScope {
            services,
            path: Vec::new(),
        },
    )
}

fn create_handler(
    server_proxy_config: ServerProxyConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    scope: &mut ServiceScope<'_>,
) -> std::io::Result<Box<dyn TcpServerHandler>> {
    Ok(match server_proxy_config {
        ServerProxyConfig::Xhttp(config) => {
            let service = match scope.services.xhttp.entry(scope.path.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                    crate::xhttp::XhttpServer::new(config, client_proxy_selector, resolver, None)?,
                ),
            };
            Box::new(service.clone())
        }
        ServerProxyConfig::Http { username, password } => Box::new(HttpTcpServerHandler::new(
            create_auth_credentials(username, password),
            client_proxy_selector.clone(),
            resolver.clone(),
        )),
        ServerProxyConfig::Socks {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(SocksTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Mixed {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(MixedTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => match config {
            ShadowsocksConfig::Legacy { cipher, password } => {
                Box::new(ShadowsocksTcpHandler::new_server(
                    cipher,
                    &password,
                    udp_enabled,
                    client_proxy_selector.clone(),
                    resolver.clone(),
                ))
            }
            ShadowsocksConfig::Aead2022 {
                cipher, key_bytes, ..
            } => Box::new(ShadowsocksTcpHandler::new_aead2022_server(
                cipher,
                &key_bytes,
                udp_enabled,
                client_proxy_selector.clone(),
                resolver.clone(),
            )),
        },
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        } => Box::new(SnellServerHandler::new(
            cipher.as_str().try_into().unwrap(),
            &password,
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
        )),
        ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
            decryption,
            vision,
            encryption_limits,
            ..
        } => {
            let encryption = if decryption.is_disabled() {
                if encryption_limits.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "VLESS encryption_limits requires native decryption",
                    ));
                }
                None
            } else {
                let service = match scope.services.vless.entry(scope.path.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(Arc::new(crate::vless::encryption::ServerEncryption::new(
                            decryption.as_str(),
                            encryption_limits.unwrap_or_default(),
                        )?))
                    }
                };
                Some(service.clone())
            };
            Box::new(VlessTcpServerHandler::new(
                &user_id,
                udp_enabled,
                client_proxy_selector.clone(),
                resolver.clone(),
                fallback,
                encryption,
                vision,
            )?)
        }
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new_server(
            &password,
            &shadowsocks,
            client_proxy_selector.clone(),
            resolver.clone(),
        )),
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            let mut all_targets = tls_targets
                .into_iter()
                .map(|(sni, config)| {
                    Ok((
                        sni.clone(),
                        create_tls_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            &mut scope.child(format!("tls:{sni}")),
                        )?,
                    ))
                })
                .collect::<std::io::Result<FxHashMap<String, TlsServerTarget>>>()?;
            let default_tls_target = default_tls_target
                .map(|config| {
                    create_tls_server_target(
                        *config,
                        client_proxy_selector,
                        resolver,
                        bind_ip,
                        &mut scope.child("default".into()),
                    )
                })
                .transpose()?;
            let shadowtls_targets = shadowtls_targets
                .into_iter()
                .map(|(sni, config)| {
                    Ok((
                        sni.clone(),
                        create_shadow_tls_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            &mut scope.child(format!("shadowtls:{sni}")),
                        )?,
                    ))
                })
                .collect::<std::io::Result<FxHashMap<String, TlsServerTarget>>>()?;
            all_targets.extend(shadowtls_targets);
            let reality_server_targets = reality_targets
                .into_iter()
                .map(|(sni, config)| {
                    Ok((
                        sni.clone(),
                        create_reality_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            &mut scope.child(format!("reality:{sni}")),
                        )?,
                    ))
                })
                .collect::<std::io::Result<FxHashMap<String, TlsServerTarget>>>()?;
            all_targets.extend(reality_server_targets);
            Box::new(TlsServerHandler::new(
                all_targets,
                default_tls_target,
                tls_buffer_size,
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => Box::new(VmessTcpServerHandler::new(
            &cipher,
            &user_id,
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
        )?),
        ServerProxyConfig::Websocket { targets } => {
            let server_targets: Vec<WebsocketServerTarget> = targets
                .into_vec()
                .into_iter()
                .enumerate()
                .map(|(index, config)| {
                    create_websocket_server_target(
                        config,
                        client_proxy_selector,
                        resolver,
                        bind_ip,
                        &mut scope.child(format!("ws:{index}")),
                    )
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        ServerProxyConfig::PortForward { targets } => {
            let targets = targets.into_vec();
            Box::new(PortForwardServerHandler::new(
                targets,
                client_proxy_selector.clone(),
            ))
        }
        ServerProxyConfig::Anytls {
            users,
            padding_scheme,
            udp_enabled,
            fallback,
        } => {
            let users: Vec<(String, String)> = users
                .into_vec()
                .into_iter()
                .map(|u| (u.name, u.password))
                .collect();

            let padding = if let Some(scheme_lines) = padding_scheme {
                let scheme_str = scheme_lines.join("\n");
                Arc::new(PaddingFactory::new(scheme_str.as_bytes()).map_err(std::io::Error::other)?)
            } else {
                PaddingFactory::default_factory()
            };

            // AnyTLS handles its logical streams internally, so it needs the proxy
            // provider directly (it won't inherit from outer handler through TcpForward)
            Box::new(AnyTlsServerHandler::new(
                users,
                padding,
                resolver.clone(),
                Arc::clone(client_proxy_selector),
                udp_enabled,
                fallback,
            ))
        }
        ServerProxyConfig::Naiveproxy { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NaiveProxy must be used inside a TLS or Reality protocol",
            ));
        }
        unknown_config => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("Unsupported TCP proxy protocol: {unknown_config}"),
            ));
        }
    })
}

fn create_vision_vless_config(protocol: &ServerProxyConfig) -> std::io::Result<VisionVlessConfig> {
    crate::config::validate_server_vision(true, protocol)?;
    let ServerProxyConfig::Vless {
        user_id,
        udp_enabled,
        fallback,
        ..
    } = protocol
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Vision requires VLESS",
        ));
    };

    Ok(VisionVlessConfig {
        user_id: parse_uuid(user_id)?.into_boxed_slice(),
        udp_enabled: *udp_enabled,
        fallback: fallback.clone(),
    })
}

fn create_tls_server_target(
    tls_server_config: TlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    scope: &mut ServiceScope<'_>,
) -> std::io::Result<TlsServerTarget> {
    let TlsServerConfig {
        certificate_source: _,
        certificate_binding,
        key_exchange_groups,
        cert,
        key,
        alpn_protocols,
        client_ca_certs,
        client_fingerprints,
        vision,
        protocol,
        override_rules,
    } = tls_server_config;
    key_exchange_groups.validate_vision(vision)?;

    if vision && !matches!(protocol, ServerProxyConfig::Vless { .. }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Vision requires VLESS",
        ));
    }

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let client_ca_certs = client_ca_certs
        .into_iter()
        .map(|cert| cert.as_bytes().to_vec())
        .collect();

    // For NaiveProxy, hardcode ALPN to h2 and http/1.1
    let is_naive = matches!(protocol, ServerProxyConfig::Naiveproxy { .. });
    let effective_alpn: Vec<String> = if is_naive {
        let naive_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let user_alpn = alpn_protocols.into_vec();
        if user_alpn != naive_alpn {
            log::warn!(
                "NaiveProxy requires ALPN [\"h2\", \"http/1.1\"], ignoring user-specified {:?}",
                user_alpn
            );
        }
        naive_alpn
    } else if let ServerProxyConfig::Xhttp(config) = &protocol {
        config.tls_alpn(&alpn_protocols)?
    } else {
        alpn_protocols.into_vec()
    };

    let server_config = Arc::new(
        crate::rustls_config_util::try_create_server_config_with_source(
            &cert_bytes,
            &key_bytes,
            client_ca_certs,
            &effective_alpn,
            &client_fingerprints.into_vec(),
            &key_exchange_groups,
            certificate_binding.as_ref(),
        )?,
    );

    let effective_selector = if !override_rules.is_empty() {
        create_override_selector(override_rules, client_proxy_selector, resolver)?
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        let users_vec: Vec<(String, String, String)> = users
            .into_vec()
            .into_iter()
            .map(|u| (u.name, u.username, u.password))
            .collect();

        InnerProtocol::Naive(NaiveConfig {
            users: Arc::new(UserLookup::new(users_vec)),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        InnerProtocol::VisionVless(create_vision_vless_config(&protocol)?)
    } else {
        let handler = create_handler(protocol, &effective_selector, resolver, bind_ip, scope)?;
        InnerProtocol::Normal(handler)
    };

    Ok(TlsServerTarget::Tls {
        certificate_source: certificate_binding,
        server_config,
        effective_selector,
        inner_protocol,
    })
}

fn create_shadow_tls_server_target(
    shadow_tls_server_config: ShadowTlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    scope: &mut ServiceScope<'_>,
) -> std::io::Result<TlsServerTarget> {
    let ShadowTlsServerConfig {
        password,
        handshake,
        protocol,
        override_rules,
    } = shadow_tls_server_config;

    let target_handshake = match handshake {
        ShadowTlsServerHandshakeConfig::Local(handshake) => {
            // Certificates are already embedded as PEM data during config validation
            let cert_bytes = handshake.cert.as_bytes().to_vec();
            let key_bytes = handshake.key.as_bytes().to_vec();

            let client_ca_certs = handshake
                .client_ca_certs
                .into_iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect();

            let server_config = Arc::new(try_create_server_config(
                &cert_bytes,
                &key_bytes,
                client_ca_certs,
                &handshake.alpn_protocols.into_vec(),
                &handshake.client_fingerprints.into_vec(),
                &Default::default(),
            )?);

            ShadowTlsServerTargetHandshake::new_local(server_config)
        }
        ShadowTlsServerHandshakeConfig::Remote(handshake) => {
            // Build ClientProxyChain from client_chain
            // client_chain is guaranteed to be non-empty (defaults to direct hop)
            let client_chain =
                try_build_client_proxy_chain(handshake.client_chain, resolver.clone())?;
            ShadowTlsServerTargetHandshake::new_remote(handshake.address, client_chain)
        }
    };

    let effective_selector = if !override_rules.is_empty() {
        create_override_selector(override_rules, client_proxy_selector, resolver)?
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_handler(protocol, &effective_selector, resolver, bind_ip, scope)?;

    Ok(TlsServerTarget::ShadowTls(ShadowTlsServerTarget::new(
        password,
        target_handshake,
        handler,
    )))
}

fn create_reality_server_target(
    reality_server_config: RealityServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    scope: &mut ServiceScope<'_>,
) -> std::io::Result<TlsServerTarget> {
    let RealityServerConfig {
        mldsa65_seed,
        private_key,
        short_ids,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites,
        vision,
        protocol,
        dest_client_chain,
        override_rules,
    } = reality_server_config;

    if vision && !matches!(protocol, ServerProxyConfig::Vless { .. }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Vision requires VLESS",
        ));
    }

    // Decode private key from base64url (validated during config load)
    let private_key_bytes = crate::reality::decode_private_key(&private_key)?;

    // Decode short IDs from hex strings (validated during config load)
    // OneOrSome ensures at least one short_id is always present (default is all zeros)
    let short_id_bytes: Vec<[u8; 8]> = short_ids
        .into_vec()
        .into_iter()
        .map(|s| crate::reality::decode_short_id(&s))
        .collect::<std::io::Result<_>>()?;

    let effective_selector = if !override_rules.is_empty() {
        create_override_selector(override_rules, client_proxy_selector, resolver)?
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        let users_vec: Vec<(String, String, String)> = users
            .into_vec()
            .into_iter()
            .map(|u| (u.name, u.username, u.password))
            .collect();

        InnerProtocol::Naive(NaiveConfig {
            users: Arc::new(UserLookup::new(users_vec)),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        InnerProtocol::VisionVless(create_vision_vless_config(&protocol)?)
    } else {
        let handler = create_handler(protocol, &effective_selector, resolver, bind_ip, scope)?;
        InnerProtocol::Normal(handler)
    };

    // Build dest client chain: if specified use it, otherwise default to direct
    let dest_client_chain = {
        let hops = dest_client_chain.into_vec();
        if hops.is_empty() {
            // Default to direct connection
            try_build_client_proxy_chain(
                OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    ClientConfig::default(),
                ))),
                resolver.clone(),
            )
        } else {
            try_build_client_proxy_chain(OneOrSome::Some(hops), resolver.clone())
        }
    }?;

    Ok(TlsServerTarget::Reality(RealityServerTarget {
        mldsa65_key: mldsa65_seed
            .as_deref()
            .map(crate::reality::mldsa65_signing_key)
            .transpose()?,
        private_key: private_key_bytes,
        short_ids: short_id_bytes,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites: cipher_suites.into_vec(),
        effective_selector,
        inner_protocol,
        dest_client_chain,
    }))
}

fn create_websocket_server_target(
    websocket_server_config: WebsocketServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    scope: &mut ServiceScope<'_>,
) -> std::io::Result<WebsocketServerTarget> {
    let WebsocketServerConfig {
        matching_path,
        matching_headers,
        ping_type,
        protocol,
        override_rules,
    } = websocket_server_config;

    let matching_headers = matching_headers.map(|h| {
        h.into_iter()
            .map(|(mut key, val)| {
                key.make_ascii_lowercase();
                (key, val)
            })
            .collect::<FxHashMap<_, _>>()
    });

    let effective_selector = if !override_rules.is_empty() {
        create_override_selector(override_rules, client_proxy_selector, resolver)?
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_handler(protocol, &effective_selector, resolver, bind_ip, scope)?;

    Ok(WebsocketServerTarget {
        matching_path,
        matching_headers,
        ping_type,
        handler,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::ErrorKind;

    #[test]
    fn override_selectors_inherit_context_and_sniff_but_keep_their_own_rules() {
        use crate::address::{NetLocation, NetLocationMask};
        use crate::client_proxy_selector::IngressTarget;
        use crate::config::RuleActionConfig;
        use crate::dns::fake_ip::FakeDnsContext;

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let context = Arc::new(FakeDnsContext::new(Default::default(), resolver.clone()).unwrap());
        let parent = Arc::new(
            ClientProxySelector::new(vec![])
                .with_sniff(true)
                .with_fake_dns_context(Some(context.clone()))
                .unwrap(),
        );
        for (mask, should_sniff) in [("0.0.0.0/0", false), ("child.example", true)] {
            let mut rule = RuleConfig {
                criteria: crate::config::rules::RuleCriteria {
                    expression: crate::rules::Expression::Legacy(OneOrSome::One(
                        NetLocationMask::from(mask).unwrap(),
                    )),
                    ..Default::default()
                },
                ..Default::default()
            };
            rule.compile(&mut crate::rules::Compiler::default())
                .unwrap();
            let rules = NoneOrSome::One(ConfigSelection::Config(rule));
            let child = create_override_selector(rules, &parent, &resolver).unwrap();
            assert!(!Arc::ptr_eq(&child, &parent));
            let IngressTarget::LocalDns {
                context: inherited, ..
            } = child
                .prepare(NetLocation::from_str("198.18.0.9:53", None).unwrap().into())
                .unwrap()
            else {
                panic!("DNS was not intercepted");
            };
            assert!(Arc::ptr_eq(&inherited, &context));
            let IngressTarget::Forward(target) = child
                .prepare(
                    NetLocation::from_str("203.0.113.7:443", None)
                        .unwrap()
                        .into(),
                )
                .unwrap()
            else {
                panic!("not a forward target");
            };
            assert_eq!(child.should_sniff(&target), should_sniff);
        }

        let mut rule = RuleConfig::default();
        let RuleActionConfig::Allow {
            override_address, ..
        } = &mut rule.action
        else {
            panic!("default rule is not Allow");
        };
        *override_address = Some(NetLocation::from_str("198.18.0.9:53", None).unwrap());
        rule.compile(&mut crate::rules::Compiler::default())
            .unwrap();
        let error = create_override_selector(
            NoneOrSome::One(ConfigSelection::Config(rule)),
            &parent,
            &resolver,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "synthetic address cannot be an outbound target"
        );
    }

    #[test]
    fn native_vless_services_share_only_within_one_generation_and_protocol_path() {
        let selector = Arc::new(ClientProxySelector::new(vec![]));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let config: ServerProxyConfig = serde_json::from_value(json!({
            "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "decryption": "mlkem768x25519plus.native.600s.CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        })).unwrap();
        let mut services = HandlerServices::default();
        let first = create_tcp_server_handler_shared(
            config.clone(),
            &selector,
            &resolver,
            Some("127.0.0.1".parse().unwrap()),
            &mut services,
        )
        .unwrap();
        let session = services.vless[&Vec::new()].clone();
        let second = create_tcp_server_handler_shared(
            config.clone(),
            &selector,
            &resolver,
            Some("127.0.0.2".parse().unwrap()),
            &mut services,
        )
        .unwrap();
        assert_eq!(services.vless.len(), 1);
        assert!(Arc::ptr_eq(&session, &services.vless[&Vec::new()]));
        assert_eq!(Arc::strong_count(&session), 4);
        let scoped = create_handler(
            config.clone(),
            &selector,
            &resolver,
            None,
            &mut ServiceScope {
                services: &mut services,
                path: vec!["other-target".into()],
            },
        )
        .unwrap();
        assert!(!Arc::ptr_eq(
            &session,
            &services.vless[&vec!["other-target".into()]]
        ));
        let mut next_generation = HandlerServices::default();
        let next = create_tcp_server_handler_shared(
            config,
            &selector,
            &resolver,
            None,
            &mut next_generation,
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&session, &next_generation.vless[&Vec::new()]));
        drop((first, second, scoped, next, services, next_generation));
        assert_eq!(Arc::strong_count(&session), 1);
    }

    #[test]
    fn unsupported_protocols_return_errors_without_credentials() {
        let selector = Arc::new(ClientProxySelector::new(vec![]));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for (value, expected_kind, expected_message) in [
            (
                json!({"type": "hysteria2", "password": "do-not-log"}),
                ErrorKind::Unsupported,
                "Unsupported TCP proxy protocol: Hysteria2",
            ),
            (
                json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "do-not-log"}),
                ErrorKind::Unsupported,
                "Unsupported TCP proxy protocol: TuicV5",
            ),
            (
                json!({"type": "naive", "users": [{"username": "user", "password": "do-not-log"}]}),
                ErrorKind::InvalidInput,
                "NaiveProxy must be used inside a TLS or Reality protocol",
            ),
            (
                json!({"type": "tls", "default_target": {"cert": "unused", "key": "unused", "vision": true, "protocol": {"type": "trojan", "password": "do-not-log"}}}),
                ErrorKind::InvalidInput,
                "Vision requires VLESS",
            ),
            (
                json!({"type": "tls", "reality_targets": {"localhost": {"private_key": "unused", "dest": "localhost:443", "vision": true, "protocol": {"type": "trojan", "password": "do-not-log"}}}}),
                ErrorKind::InvalidInput,
                "Vision requires VLESS",
            ),
        ] {
            let protocol = serde_json::from_value(value).unwrap();
            let error =
                create_tcp_server_handler(protocol, &selector, &resolver, None).unwrap_err();
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(error.to_string(), expected_message);
            assert!(!error.to_string().contains("do-not-log"));
        }
    }
}
