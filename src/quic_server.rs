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
use crate::rustls_config_util::create_server_config;
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
    crate::resources::configure_quic(&mut server_config, 0);
    for endpoint in
        crate::listener_tasks::QuicListener::bind_all(bind_address, server_config, num_endpoints)?
    {
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
                let Some(memory) = crate::resources::try_quic_memory() else {
                    conn.refuse();
                    continue;
                };
                let resolver = resolver.clone();
                let server_handler = server_handler.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _memory = memory;
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
    conn: quinn::Incoming,
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
        if tasks.len() >= crate::resources::LIMITS.max_streams_per_connection {
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
        cert,
        key,
        client_ca_certs,
        alpn_protocols,
        client_fingerprints,
        num_endpoints,
    } = quic_settings.unwrap();

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let mut processed_ca_certs = Vec::with_capacity(client_ca_certs.len());
    for cert in client_ca_certs.into_iter() {
        processed_ca_certs.push(cert.as_bytes().to_vec());
    }

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        processed_ca_certs,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|e| std::io::Error::other(format!("invalid QUIC server config: {e}")))?;

    let quic_server_config = Arc::new(quic_server_config);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

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
                let hysteria2_handles = crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config,
                    hysteria2_password.clone(),
                    client_proxy_selector,
                    resolver,
                    num_endpoints,
                    udp_enabled,
                )
                .await?;
                handles.extend(hysteria2_handles);
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
                let tuic_handles = crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config,
                    uuid.clone(),
                    password.clone(),
                    client_proxy_selector,
                    resolver,
                    num_endpoints,
                    zero_rtt_handshake,
                )
                .await?;
                handles.extend(tuic_handles);
            }
        }
        tcp_protocol => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();

            for bind_address in bind_addresses.into_iter() {
                let tcp_handler: Arc<dyn TcpServerHandler> = handlers
                    .entry(bind_address.ip())
                    .or_insert_with(|| {
                        create_tcp_server_handler(
                            tcp_protocol.clone(),
                            &client_proxy_selector,
                            &resolver,
                            Some(bind_address.ip()),
                        )
                        .into()
                    })
                    .clone();
                let quic_server_config = quic_server_config.clone();
                let resolver = resolver.clone();
                let quic_handles = start_quic_server(
                    bind_address,
                    quic_server_config,
                    resolver,
                    tcp_handler,
                    num_endpoints,
                )
                .await?;

                handles.extend(quic_handles);
            }
        }
    }

    Ok(handles)
}
