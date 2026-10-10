use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use log::{debug, error};
use tokio::task::JoinHandle;

use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ServerQuicConfig,
};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::rustls_config_util::try_create_server_config;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
use crate::uuid_util::parse_uuid;

async fn start_quic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    num_endpoints: usize,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);
    let memory_bytes = crate::resources::configure_quic(&mut server_config, 100, 0);
    for endpoint in crate::listener_tasks::QuicListener::bind_all(
        bind_address,
        server_config,
        num_endpoints,
        memory_bytes,
    )? {
        let resolver = resolver.clone();
        let server_handler = server_handler.clone();
        let join_handle = tokio::spawn(async move {
            let mut tasks = crate::listener_tasks::ListenerTasks::immediate();
            loop {
                let conn = tokio::select! {
                    conn = endpoint.accept() => conn,
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                let Some(conn) = conn else { break };
                let Some(permit) =
                    crate::resources::try_connection(Some(conn.remote_address().ip()))
                else {
                    conn.refuse();
                    continue;
                };
                let conn = match conn.accept() {
                    Ok(conn) => conn,
                    Err(e) => {
                        debug!("QUIC accept failed: {e}");
                        continue;
                    }
                };
                let resolver = resolver.clone();
                let server_handler = server_handler.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = process_connection(resolver, server_handler, conn).await {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        });

        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

async fn process_connection(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    conn: quinn::Connecting,
) -> std::io::Result<()> {
    let connection = conn.await?;
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        let accepted = tokio::select! {
            result = connection.accept_bi() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let stream = match accepted {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("quic connection error: {e}")));
            }
            Ok(s) => s,
        };
        if crate::resources::limits()
            .max_streams_per_connection
            .is_some_and(|limit| tasks.len() >= limit)
        {
            continue;
        }
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tasks.spawn(async move {
            if let Err(e) = process_streams(cloned_resolver, cloned_handler, stream).await {
                error!("Failed to process streams: {e}");
            }
        });
    }

    Ok(())
}

async fn process_streams(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    (send, recv): (quinn::SendStream, quinn::RecvStream),
) -> std::io::Result<()> {
    crate::tcp::tcp_server::process_stream(QuicStream::from(send, recv), server_handler, resolver)
        .await
}

pub async fn start_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        quic_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} QUIC server at {}", protocol, bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // A direct entry must always exist
    assert!(!rules.is_empty());

    let bind_addresses = match bind_location {
        // TODO: switch to non-blocking resolve?
        BindLocation::Address(addresses) => {
            let mut bind_addresses = Vec::new();
            for address in addresses.into_vec() {
                bind_addresses.extend(address.to_socket_addrs()?);
            }
            bind_addresses
        }
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "Cannot listen on path, QUIC does not have unix domain socket support",
            ));
        }
    };

    let ServerQuicConfig {
        key_exchange_groups,
        cert,
        key,
        client_ca_certs,
        alpn_protocols,
        client_fingerprints,
        num_endpoints,
    } = quic_settings.unwrap();
    if let ServerProxyConfig::TuicV5 {
        zero_rtt_handshake, ..
    } = &protocol
    {
        key_exchange_groups.validate_zero_rtt(*zero_rtt_handshake)?;
    }

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let mut processed_ca_certs = Vec::with_capacity(client_ca_certs.len());
    for cert in client_ca_certs.into_iter() {
        processed_ca_certs.push(cert.as_bytes().to_vec());
    }

    let mut server_config = try_create_server_config(
        &cert_bytes,
        &key_bytes,
        processed_ca_certs,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
        &key_exchange_groups,
    )?;
    // QUIC manages early data separately; its TLS limit must be zero or u32::MAX.
    if !key_exchange_groups.requires_hybrid() {
        server_config.max_early_data_size = u32::MAX;
    }
    let server_config = Arc::new(server_config);

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|e| std::io::Error::other(format!("invalid QUIC server config: {e}")))?;

    let quic_server_config = Arc::new(quic_server_config);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    )?);

    let mut handles = vec![];

    match protocol {
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
        } => {
            // TODO: hash password instead of passing directly
            let hysteria2_password: Arc<str> = password.into();

            for bind_address in bind_addresses.into_iter() {
                let quic_server_config = quic_server_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let result = crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config,
                    hysteria2_password.clone(),
                    client_proxy_selector,
                    resolver,
                    num_endpoints,
                    udp_enabled,
                )
                .await;
                collect_started_listeners(&mut handles, result).await?;
            }
        }
        ServerProxyConfig::TuicV5 {
            uuid,
            password,
            zero_rtt_handshake,
        } => {
            let uuid: Arc<[u8]> = parse_uuid(&uuid)?.into();
            let password: Arc<str> = password.into();
            for bind_address in bind_addresses.into_iter() {
                let quic_server_config = quic_server_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let result = crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config,
                    uuid.clone(),
                    password.clone(),
                    client_proxy_selector,
                    resolver,
                    num_endpoints,
                    zero_rtt_handshake,
                )
                .await;
                collect_started_listeners(&mut handles, result).await?;
            }
        }
        tcp_protocol => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            // Construct every handler before spawning listeners so errors cannot detach tasks.
            for bind_address in &bind_addresses {
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    handlers.entry(bind_address.ip())
                {
                    entry.insert(
                        create_tcp_server_handler(
                            tcp_protocol.clone(),
                            &client_proxy_selector,
                            &resolver,
                            Some(bind_address.ip()),
                        )?
                        .into(),
                    );
                }
            }
            for bind_address in bind_addresses.into_iter() {
                let tcp_handler = handlers[&bind_address.ip()].clone();
                let quic_server_config = quic_server_config.clone();
                let resolver = resolver.clone();
                let result = start_quic_server(
                    bind_address,
                    quic_server_config,
                    resolver,
                    tcp_handler,
                    num_endpoints,
                )
                .await;

                collect_started_listeners(&mut handles, result).await?;
            }
        }
    }

    Ok(handles)
}

async fn collect_started_listeners(
    handles: &mut Vec<JoinHandle<()>>,
    result: std::io::Result<Vec<JoinHandle<()>>>,
) -> std::io::Result<()> {
    match result {
        Ok(started) => {
            handles.extend(started);
            Ok(())
        }
        Err(error) => {
            for handle in handles.iter() {
                handle.abort();
            }
            for handle in handles.drain(..) {
                let _ = handle.await;
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::config::{RuleConfig, Transport};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use std::time::Duration;

    async fn assert_partial_startup_cleanup(protocol: ServerProxyConfig) {
        let first = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let first_addr = first.local_addr().unwrap();
        let occupied = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = ServerConfig {
            bind_location: BindLocation::Address(OneOrSome::Some(
                [first_addr, occupied_addr]
                    .into_iter()
                    .map(|addr| NetLocation::from_ip_addr(addr.ip(), addr.port()).into())
                    .collect(),
            )),
            protocol,
            transport: Transport::Quic,
            tcp_settings: None,
            quic_settings: Some(ServerQuicConfig {
                key_exchange_groups: Default::default(),
                cert: cert.cert.pem(),
                key: cert.signing_key.serialize_pem(),
                alpn_protocols: NoneOrSome::One("h3".into()),
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                num_endpoints: 2,
            }),
            rules: NoneOrSome::One(ConfigSelection::Config(RuleConfig::default())),
            dns: None,
        };
        drop(first);
        let error = start_quic_servers(config, Arc::new(NativeResolver::new()))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(socket) = std::net::UdpSocket::bind(first_addr) {
                    break socket;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("partial startup left the first QUIC address bound");
    }

    #[tokio::test]
    async fn partial_hysteria2_startup_releases_earlier_listeners() {
        assert_partial_startup_cleanup(ServerProxyConfig::Hysteria2 {
            password: "password".into(),
            udp_enabled: true,
        })
        .await;
    }

    #[tokio::test]
    async fn partial_tuic_startup_releases_earlier_listeners() {
        assert_partial_startup_cleanup(ServerProxyConfig::TuicV5 {
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            password: "password".into(),
            zero_rtt_handshake: false,
        })
        .await;
    }

    #[tokio::test]
    async fn partial_generic_quic_startup_releases_earlier_listeners() {
        assert_partial_startup_cleanup(ServerProxyConfig::Http {
            username: None,
            password: None,
        })
        .await;
    }
}
