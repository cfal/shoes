use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use super::tcp_server_handler_factory::create_tcp_server_handler;

use crate::address::NetLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::quic_server::start_quic_servers;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socket_util::{new_tcp_listener, set_tcp_keepalive};
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};
#[cfg(unix)]
use crate::tun::start_tun_server;
use crate::util::write_all;

async fn run_tcp_server(
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    let listener = new_tcp_listener(bind_address, 4096, None)?;
    let mut tasks = crate::listener_tasks::ListenerTasks::new();

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (stream, addr) = match accepted {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(permit) = crate::resources::try_connection(Some(addr.ip())) else {
            continue;
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(e) = process_stream(stream, cloned_handler, cloned_resolver).await {
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

    let listener = crate::socket_util::new_unix_listener(path_buf, 4096)?;
    let mut tasks = crate::listener_tasks::ListenerTasks::new();

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (stream, addr) = match accepted {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e:?}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(permit) = crate::resources::try_connection(None) else {
            continue;
        };

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(e) = process_stream(stream, cloned_handler, cloned_resolver).await {
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

pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let _permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
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
            proxy_selector,
            connection_success_response,
            initial_remote_data,
        } => {
            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_tcp_stream(
                    &mut server_stream,
                    proxy_selector,
                    resolver,
                    remote_location.clone(),
                ),
            );

            let mut client_stream = match setup_client_stream_future.await {
                Ok(Ok(Some(s))) => s,
                Ok(Ok(None)) => {
                    // Must have been blocked.
                    crate::util::shutdown_stream(&mut server_stream).await;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    crate::util::shutdown_stream(&mut server_stream).await;
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to setup client stream to {remote_location}: {e}"),
                    ));
                }
                Err(elapsed) => {
                    crate::util::shutdown_stream(&mut server_stream).await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("client setup to {remote_location} timed out: {elapsed}"),
                    ));
                }
            };

            if let Some(data) = connection_success_response {
                write_all(&mut server_stream, &data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = match initial_remote_data {
                Some(data) => {
                    write_all(&mut client_stream, &data).await?;
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

            futures::join!(
                crate::util::shutdown_stream(&mut server_stream),
                crate::util::shutdown_stream(&mut client_stream),
            );

            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } => {
            let setup = crate::util::timeout_stream_setup(async {
                match proxy_selector
                    .judge(remote_location.into(), &resolver)
                    .await?
                {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        chain_group
                            .connect_udp_bidirectional(&resolver, remote_location)
                            .await
                    }
                    ConnectDecision::Block => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Blocked bidirectional udp forward",
                    )),
                }
            })
            .await;
            let client_stream = match setup {
                Ok(stream) => stream,
                Err(error) => {
                    crate::util::shutdown_message_stream(&mut server_stream).await;
                    return Err(error);
                }
            };
            run_udp_copy(
                server_stream,
                client_stream,
                server_need_initial_flush,
                false,
            )
            .await
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each packet is routed based on its destination
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each session is routed based on its destination
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::Session(session) => {
            session.await;
            Ok(())
        }
    }
}

pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector
        .judge(remote_location.into(), &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                server_stream.write_all(&data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    futures::join!(
        crate::util::shutdown_message_stream(&mut server_stream),
        crate::util::shutdown_message_stream(&mut client_stream),
    );

    copy_result
}

pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config {
        #[cfg(unix)]
        Config::TunServer(tun_config) => start_tun_server(tun_config, resolver)
            .await
            .map(|t| vec![t]),
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => start_tcp_or_quic_servers(server_config, resolver).await,
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => match start_tcp_servers(config.clone(), resolver).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_servers(config.clone(), resolver).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Udp => todo!(),
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", protocol, bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(addresses) => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            for address in addresses.into_vec() {
                for socket_addr in address.to_socket_addrs()? {
                    let tcp_handler = handlers
                        .entry(socket_addr.ip())
                        .or_insert_with(|| {
                            create_tcp_server_handler(
                                protocol.clone(),
                                &client_proxy_selector,
                                &resolver,
                                Some(socket_addr.ip()),
                            )
                            .into()
                        })
                        .clone();
                    let tcp_config = tcp_config.clone();
                    let resolver = resolver.clone();
                    let handle = tokio::spawn(async move {
                        run_tcp_server(socket_addr, tcp_config, resolver, tcp_handler)
                            .await
                            .unwrap();
                    });
                    handles.push(handle);
                }
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let tcp_handler: Arc<dyn TcpServerHandler> =
                    create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, None)
                        .into();
                let handle = tokio::spawn(async move {
                    run_unix_server(path_buf, resolver, tcp_handler)
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

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    use async_trait::async_trait;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
    };
    use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::tcp::socket_connector::SocketConnector;

    #[derive(Debug)]
    struct StalledMessageShutdown {
        _marker: Arc<()>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl AsyncReadMessage for StalledMessageShutdown {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }

    impl AsyncWriteMessage for StalledMessageShutdown {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for StalledMessageShutdown {
        fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for StalledMessageShutdown {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }
    }

    impl AsyncPing for StalledMessageShutdown {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for StalledMessageShutdown {}

    #[derive(Debug)]
    struct UdpHandler {
        remote: NetLocation,
        selector: Arc<ClientProxySelector>,
        marker: Arc<()>,
        shutdowns: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl TcpServerHandler for UdpHandler {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location: self.remote.clone(),
                stream: Box::new(StalledMessageShutdown {
                    _marker: self.marker.clone(),
                    shutdowns: self.shutdowns.clone(),
                }),
                need_initial_flush: false,
                proxy_selector: self.selector.clone(),
            })
        }
    }

    #[derive(Debug)]
    struct PendingResolver;

    impl Resolver for PendingResolver {
        fn resolve_location(
            &self,
            _: &NetLocation,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
        {
            Box::pin(std::future::pending())
        }
    }

    #[derive(Debug)]
    struct PendingConnector;

    #[async_trait]
    impl SocketConnector for PendingConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            std::future::pending().await
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_setup_and_error_cleanup_have_deadlines() {
        for remote in ["pending.test:53", "192.0.2.1:53"] {
            let marker = Arc::new(());
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let chain = ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Box::new(PendingConnector))],
                vec![],
            );
            let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                vec![crate::address::NetLocationMask::from("192.0.2.0/24").unwrap()],
                ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
            )]));
            let handler = Arc::new(UdpHandler {
                remote: NetLocation::from_str(remote, None).unwrap(),
                selector,
                marker: marker.clone(),
                shutdowns: shutdowns.clone(),
            });
            let (stream, _peer) = tokio::io::duplex(64);
            let started = tokio::time::Instant::now();
            let result = timeout(
                Duration::from_secs(66),
                process_stream(stream, handler, Arc::new(PendingResolver)),
            )
            .await
            .expect("UDP setup or cleanup retained the stream indefinitely");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(started.elapsed(), Duration::from_secs(65));
            assert!(shutdowns.load(Ordering::Relaxed) > 0);
            assert_eq!(Arc::strong_count(&marker), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_copy_error_cannot_stall_final_shutdown() {
        let marker = Arc::new(());
        let server_shutdowns = Arc::new(AtomicUsize::new(0));
        let client_shutdowns = Arc::new(AtomicUsize::new(0));
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(6),
            run_udp_copy(
                Box::new(StalledMessageShutdown {
                    _marker: marker.clone(),
                    shutdowns: server_shutdowns.clone(),
                }),
                Box::new(StalledMessageShutdown {
                    _marker: marker.clone(),
                    shutdowns: client_shutdowns.clone(),
                }),
                false,
                false,
            ),
        )
        .await
        .expect("final UDP shutdown retained streams indefinitely");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(started.elapsed(), crate::util::SHUTDOWN_TIMEOUT);
        assert!(server_shutdowns.load(Ordering::Relaxed) > 0);
        assert!(client_shutdowns.load(Ordering::Relaxed) > 0);
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[derive(Debug)]
    struct SessionHandler(Arc<()>);

    #[async_trait]
    impl TcpServerHandler for SessionHandler {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let owned = self.0.clone();
            Ok(TcpServerSetupResult::Session(Box::pin(async move {
                let _owned = owned;
                let _stream = stream;
                std::future::pending::<()>().await;
            })))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn session_outlives_setup_deadline_but_not_its_owner() {
        let marker = Arc::new(());
        let handler = Arc::new(SessionHandler(marker.clone()));
        let (stream, _peer) = tokio::io::duplex(64);
        let task = tokio::spawn(process_stream(
            stream,
            handler,
            Arc::new(crate::resolver::NativeResolver),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(600)).await;
        assert!(!task.is_finished());
        assert_eq!(Arc::strong_count(&marker), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(Arc::strong_count(&marker), 1);
    }
}
