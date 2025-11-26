use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, warn};
use quinn::EndpointConfig;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ServerQuicConfig,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::copy_multidirectional_message::copy_multidirectional_message;
use crate::copy_session_messages::copy_session_messages;
use crate::quic_stream::QuicStream;
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_config_util::create_server_config;
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
use crate::tcp_handler::{
    TcpClientUdpSetupResult, TcpServerHandler, TcpServerSetupResult, UdpStreamRequest,
};
use crate::tcp_server::setup_client_tcp_stream;
use crate::util::parse_uuid;

async fn start_quic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    num_endpoints: usize,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // TODO: consider setting transport config
    //   Arc::get_mut(&mut server_config.transport)
    //     .unwrap()
    //     .max_concurrent_bidi_streams(1024_u32.into())
    //     .max_concurrent_uni_streams(0_u8.into())
    //     .keep_alive_interval(Some(Duration::from_secs(15)))
    //     .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

    let mut join_handles = vec![];
    for _ in 0..num_endpoints {
        let server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());

        let socket2_socket =
            new_socket2_udp_socket(bind_address.is_ipv6(), None, Some(bind_address), true).unwrap();

        let endpoint = quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let server_handler = server_handler.clone();
        let join_handle = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let server_handler = server_handler.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        process_connection(client_proxy_selector, resolver, server_handler, conn)
                            .await
                    {
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
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    conn: quinn::Incoming,
) -> std::io::Result<()> {
    let connection = conn.await?;

    loop {
        let stream = match connection.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("quic connection error: {e}")));
            }
            Ok(s) => s,
        };
        let cloned_selector = client_proxy_selector.clone();
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_streams(cloned_selector, cloned_resolver, cloned_handler, stream).await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }

    Ok(())
}

async fn process_streams(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    (send, recv): (quinn::SendStream, quinn::RecvStream),
) -> std::io::Result<()> {
    let quic_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));

    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        server_handler.setup_server_stream(quic_stream),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            ));
        }
    };

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            override_proxy_provider,
            connection_success_response,
            initial_remote_data,
        } => {
            let selected_proxy_provider = if override_proxy_provider.is_one() {
                override_proxy_provider.unwrap()
            } else {
                client_proxy_selector
            };

            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_tcp_stream(
                    &mut server_stream,
                    selected_proxy_provider,
                    resolver,
                    remote_location.clone(),
                ),
            );

            let mut client_stream = match setup_client_stream_future.await {
                Ok(Ok(Some(s))) => s,
                Ok(Ok(None)) => {
                    // Must have been blocked.
                    let _ = server_stream.shutdown().await;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    let _ = server_stream.shutdown().await;
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to setup client stream to {remote_location}: {e}"),
                    ));
                }
                Err(elapsed) => {
                    let _ = server_stream.shutdown().await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("client setup to {remote_location} timed out: {elapsed}"),
                    ));
                }
            };

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = match initial_remote_data {
                Some(data) => {
                    client_stream.write_all(&data).await?;
                    true
                }
                None => false,
            };

            let copy_result = copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
                server_need_initial_flush,
                client_need_initial_flush,
            )
            .await;

            let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            override_proxy_provider,
        } => {
            let selected_proxy_provider = if override_proxy_provider.is_one() {
                override_proxy_provider.unwrap()
            } else {
                client_proxy_selector
            };

            let action = selected_proxy_provider
                .judge(remote_location, &resolver)
                .await?;
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    // Use chain_group's UDP connection with Bidirectional mode
                    // Pass server stream so handler can return matched pair
                    let udp_result = chain_group
                        .connect_udp(
                            &resolver,
                            UdpStreamRequest::Bidirectional {
                                server_stream,
                                target: remote_location,
                            },
                        )
                        .await?;

                    match udp_result {
                        TcpClientUdpSetupResult::Bidirectional {
                            mut server_stream,
                            mut client_stream,
                        } => {
                            let copy_result = copy_bidirectional_message(
                                &mut server_stream,
                                &mut client_stream,
                                server_need_initial_flush,
                                false,
                            )
                            .await;
                            copy_result?;
                            Ok(())
                        }
                        _ => {
                            // Handler should have returned Bidirectional or errored
                            unreachable!(
                                "Handler must return Bidirectional stream type when requested, or error"
                            )
                        }
                    }
                }
                ConnectDecision::Block => {
                    // Must have been blocked.
                    Ok(())
                }
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            override_proxy_provider,
        } => {
            let selected_proxy_provider = if override_proxy_provider.is_one() {
                override_proxy_provider.unwrap()
            } else {
                client_proxy_selector
            };
            let action = selected_proxy_provider.default_decision();
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location: _,
                } => {
                    // Use chain_group's UDP connection with MultiDirectional mode
                    // Pass server stream so handler can return matched pair
                    let udp_result = chain_group
                        .connect_udp(
                            &resolver,
                            UdpStreamRequest::MultiDirectional { server_stream },
                        )
                        .await?;

                    match udp_result {
                        TcpClientUdpSetupResult::MultiDirectional {
                            mut server_stream,
                            mut client_stream,
                        } => {
                            let copy_result = copy_multidirectional_message(
                                &mut server_stream,
                                &mut client_stream,
                                server_need_initial_flush,
                                false,
                            )
                            .await;

                            copy_result?;
                            Ok(())
                        }
                        _ => {
                            // Handler should have returned MultiDirectional or errored
                            unreachable!(
                                "Handler must return MultiDirectional stream type when requested, or error"
                            )
                        }
                    }
                }
                ConnectDecision::Block => {
                    warn!(
                        "Blocked multidirectional udp forward, because the default action is to block."
                    );
                    Ok(())
                }
            }
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            override_proxy_provider,
        } => {
            let selected_proxy_provider = if override_proxy_provider.is_one() {
                override_proxy_provider.unwrap()
            } else {
                client_proxy_selector
            };
            let action = selected_proxy_provider.default_decision();
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location: _,
                } => {
                    // Use chain_group's UDP connection with SessionBased mode
                    // Pass server stream so handler can return matched pair
                    let udp_result = chain_group
                        .connect_udp(&resolver, UdpStreamRequest::SessionBased { server_stream })
                        .await?;

                    match udp_result {
                        TcpClientUdpSetupResult::SessionBased {
                            mut server_stream,
                            mut client_stream,
                        } => {
                            // Both server and client are session-based (XUDP) - use copy_session_messages
                            let copy_result = copy_session_messages(
                                &mut server_stream,
                                &mut client_stream,
                                server_need_initial_flush,
                                false,
                            )
                            .await;
                            copy_result?;
                            Ok(())
                        }
                        _ => {
                            // Handler should have returned SessionBased or errored
                            unreachable!(
                                "Handler must return SessionBased stream type when requested, or error"
                            )
                        }
                    }
                }
                ConnectDecision::Block => {
                    warn!(
                        "Blocked session-based udp forward, because the default action is to block."
                    );
                    Ok(())
                }
            }
        }
    }
}

pub async fn start_quic_servers(config: ServerConfig) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        quic_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} QUIC server at {}", &protocol, &bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let bind_addresses = match bind_location {
        // TODO: switch to non-blocking resolve?
        BindLocation::Address(a) => a.to_socket_addrs()?,
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

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(std::io::Error::other)?;

    let quic_server_config = Arc::new(quic_server_config);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules.clone()));
    let resolver = Arc::new(NativeResolver::new());

    let mut handles = vec![];

    match protocol {
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
        } => {
            // TODO: hash password instead of passing directly
            let hysteria2_password: &'static str = Box::leak(password.into_boxed_str());

            for bind_address in bind_addresses.into_iter() {
                let quic_server_config = quic_server_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let hysteria2_handles = crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config,
                    hysteria2_password,
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
            let uuid: &'static [u8] = Box::leak(parse_uuid(&uuid)?.into_boxed_slice());
            let password: &'static str = Box::leak(password.into_boxed_str());
            for bind_address in bind_addresses.into_iter() {
                let quic_server_config = quic_server_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let tuic_handles = crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config,
                    uuid,
                    password,
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
            let mut rules_stack = vec![rules];
            let tcp_handler: Arc<dyn TcpServerHandler> =
                create_tcp_server_handler(tcp_protocol, &mut rules_stack).into();

            for bind_address in bind_addresses.into_iter() {
                let quic_server_config = quic_server_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let resolver = resolver.clone();
                let tcp_handler = tcp_handler.clone();
                let quic_handles = start_quic_server(
                    bind_address,
                    quic_server_config,
                    client_proxy_selector,
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
