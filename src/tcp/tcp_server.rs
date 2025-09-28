use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, warn};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::{AsyncSourcedMessageStream, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{BindLocation, ConfigSelection, ServerConfig, TcpConfig};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::copy_multidirectional_message::copy_multidirectional_message;
use crate::resolver::{resolve_single_address, NativeResolver, Resolver};
use crate::socket_util::set_tcp_keepalive;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp_handler_util::{create_tcp_client_proxy_selector, create_tcp_server_handler};
use crate::udp_message_stream::UdpMessageStream;
use crate::udp_multi_message_stream::UdpMultiMessageStream;

async fn run_tcp_server(
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    let listener = tokio::net::TcpListener::bind(bind_address).await.unwrap();

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e}");
                continue;
            }
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay {
            if let Err(e) = stream.set_nodelay(true) {
                error!("Failed to set TCP nodelay: {e}");
            }
        }

        // TODO: allow this be to Option<Arc<ClientProxySelector<..>>> when
        // there are no rules or proxies specified.
        let cloned_provider = client_proxy_selector.clone();
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_stream(stream, cloned_handler, cloned_provider, cloned_cache).await
            {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

#[cfg(target_family = "unix")]
async fn run_unix_server(
    path_buf: PathBuf,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(&path_buf).await;
    }

    let listener = tokio::net::UnixListener::bind(path_buf).unwrap();

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e:?}");
                continue;
            }
        };

        let cloned_provider = client_proxy_selector.clone();
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_stream(stream, cloned_handler, cloned_provider, cloned_cache).await
            {
                error!("{addr:?} finished with error: {e:?}");
            } else {
                debug!("{addr:?} finished successfully");
            }
        });
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
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
            num_sockets,
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
                    let mut client_stream: Box<dyn AsyncSourcedMessageStream> = if num_sockets <= 1
                    {
                        // support ipv6 since we don't know what the remote locations will be.
                        let udp_socket = client_proxy.configure_udp_socket(true)?;
                        Box::new(UdpMessageStream::new(udp_socket, resolver))
                    } else {
                        let client_sockets =
                            client_proxy.configure_reuse_udp_sockets(true, num_sockets)?;
                        let client_sockets =
                            client_sockets.into_iter().map(Arc::new).collect::<Vec<_>>();
                        Box::new(UdpMultiMessageStream::new(client_sockets, resolver))
                    };

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

pub async fn setup_client_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector
        .judge(remote_location, &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            client_proxy,
            remote_location,
        } => {
            let client_stream = client_proxy
                .connect(server_stream, remote_location, &resolver)
                .await?;
            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}

pub async fn start_tcp_servers(config: ServerConfig) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", &protocol, &bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules.clone()));

    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let mut rules_stack = vec![rules];
    let tcp_handler: Arc<dyn TcpServerHandler> =
        create_tcp_server_handler(protocol, &mut rules_stack).into();
    debug!("TCP handler: {tcp_handler:?}");

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(a) => {
            let socket_addrs = a.to_socket_addrs()?;
            for socket_addr in socket_addrs {
                let tcp_config = tcp_config.clone();
                let client_proxy_selector = client_proxy_selector.clone();
                let tcp_handler = tcp_handler.clone();
                let resolver = resolver.clone();
                let handle = tokio::spawn(async move {
                    run_tcp_server(
                        socket_addr,
                        tcp_config,
                        client_proxy_selector,
                        resolver,
                        tcp_handler,
                    )
                    .await
                    .unwrap();
                });
                handles.push(handle);
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let client_proxy_selector = client_proxy_selector.clone();
                let tcp_handler = tcp_handler.clone();
                let handle = tokio::spawn(async move {
                    run_unix_server(path_buf, client_proxy_selector, resolver, tcp_handler)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    Ok(handles)
}
