use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, warn};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{BindLocation, ConfigSelection, ServerConfig, ServerQuicConfig};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::copy_multidirectional_message::copy_multidirectional_message;
use crate::quic_stream::QuicStream;
use crate::resolver::{resolve_single_address, NativeResolver, Resolver};
use crate::rustls_util::create_server_config;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp_handler_util::{create_tcp_client_proxy_selector, create_tcp_server_handler};
use crate::tcp_server::setup_client_stream;
use crate::udp_direct_message_stream::UdpDirectMessageStream;

async fn run_quic_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    // TODO: check these values
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_bidi_streams(1024_u32.into())
        .max_concurrent_uni_streams(0_u8.into())
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

    let endpoint = quinn::Endpoint::server(server_config, bind_address)?;

    while let Some(conn) = endpoint.accept().await {
        let cloned_selector = client_proxy_selector.clone();
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_connection(cloned_selector, cloned_resolver, cloned_handler, conn).await
            {
                error!("Connection ended with error: {}", e);
            }
        });
    }

    Ok(())
}

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("quic connection error: {}", e),
                ));
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
                error!("Failed to process streams: {}", e);
            }
        });
    }

    Ok(())
}

async fn process_streams(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
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
                format!("failed to setup server stream: {}", e),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {}", elapsed),
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
                setup_client_stream(
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
                        format!(
                            "failed to setup client stream to {}: {}",
                            remote_location, e
                        ),
                    ));
                }
                Err(elapsed) => {
                    let _ = server_stream.shutdown().await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("client setup to {} timed out: {}", remote_location, elapsed),
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
            stream: mut server_stream,
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
                    client_proxy,
                    remote_location,
                } => {
                    let remote_addr = resolve_single_address(&resolver, &remote_location).await?;
                    let client_socket = client_proxy.configure_udp_socket(remote_addr.is_ipv6())?;
                    client_socket.connect(remote_addr).await?;

                    let mut client_socket = Box::new(client_socket);

                    let copy_result = copy_bidirectional_message(
                        &mut server_stream,
                        &mut client_socket,
                        server_need_initial_flush,
                        false,
                    )
                    .await;

                    // TODO: add async trait ext and make this work
                    //let (_, _) = futures::join!(server_stream.shutdown_message(), client_stream.shutdown_message());

                    copy_result?;
                    Ok(())
                }
                ConnectDecision::Block => {
                    // Must have been blocked.
                    // TODO: add async trait ext and make this work
                    // let _ = server_stream.shutdown_message().await;
                    Ok(())
                }
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: mut server_stream,
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
                    client_proxy,
                    remote_location: _,
                } => {
                    let client_socket = client_proxy.configure_udp_socket(true)?;
                    let mut client_stream =
                        Box::new(UdpDirectMessageStream::new(client_socket, resolver));

                    let copy_result = copy_multidirectional_message(
                        &mut server_stream,
                        &mut client_stream,
                        server_need_initial_flush,
                        false,
                    )
                    .await;

                    // TODO: add async trait ext and make this work
                    //let (_, _) = futures::join!(server_stream.shutdown_message(), client_stream.shutdown_message());

                    copy_result?;
                    Ok(())
                }
                ConnectDecision::Block => {
                    warn!("Blocked multidirectional udp forward, because the default action is to block.");
                    // TODO: add async trait ext and make this work
                    // let _ = server_stream.shutdown_message().await;
                    Ok(())
                }
            }
        }
    }
}

pub async fn start_quic_server(config: ServerConfig) -> std::io::Result<Option<JoinHandle<()>>> {
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

    let bind_address = match bind_location {
        // TODO: switch to non-blocking resolve?
        BindLocation::Address(a) => a.to_socket_addr()?,
        BindLocation::Path(_) => {
            panic!("Cannot listen on path, QUIC does not have unix domain socket support");
        }
    };

    let ServerQuicConfig {
        cert,
        key,
        alpn_protocols,
        client_fingerprints,
    } = quic_settings.unwrap();

    let mut cert_file = File::open(&cert).await?;
    let mut cert_bytes = vec![];
    cert_file.read_to_end(&mut cert_bytes).await?;

    let mut key_file = File::open(&key).await?;
    let mut key_bytes = vec![];
    key_file.read_to_end(&mut key_bytes).await?;

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules.clone()));

    let mut rules_stack = vec![rules];
    let tcp_handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(create_tcp_server_handler(protocol, &mut rules_stack));
    debug!("TCP handler: {:?}", tcp_handler);

    Ok(Some(tokio::spawn(async move {
        run_quic_server(
            bind_address,
            server_config,
            client_proxy_selector,
            tcp_handler,
        )
        .await
        .unwrap();
    })))
}
