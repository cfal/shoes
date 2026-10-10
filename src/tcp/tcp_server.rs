use std::collections::HashMap;
use std::net::IpAddr;
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
    listener: tokio::net::TcpListener,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

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
    listener: tokio::net::UnixListener,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
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
                setup_client_tcp_stream(proxy_selector, resolver, remote_location.clone()),
            );

            let TcpClientSetupResult {
                mut client_stream,
                early_data,
            } = match setup_client_stream_future.await {
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

            crate::util::timeout_stream_setup(async {
                let flush_server = server_need_initial_flush || early_data.is_some();
                if let Some(data) = connection_success_response {
                    write_all(&mut server_stream, &data).await?;
                }
                if let Some(data) = early_data {
                    write_all(&mut server_stream, &data).await?;
                }
                if flush_server {
                    server_stream.flush().await?;
                }
                if let Some(data) = initial_remote_data {
                    write_all(&mut client_stream, &data).await?;
                    client_stream.flush().await?;
                }
                Ok(())
            })
            .await?;

            let copy_result =
                copy_bidirectional(&mut server_stream, &mut client_stream, false, false).await;

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
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<TcpClientSetupResult>> {
    let action = client_proxy_selector
        .judge(remote_location.into(), &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => chain_group
            .connect_tcp(remote_location, &resolver)
            .await
            .map(Some),
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
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Expected a server configuration",
        )),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let bind_location = config.bind_location.to_string();
    let join_handles = match config.transport {
        Transport::Tcp => start_tcp_servers(config, resolver).await?,
        Transport::Quic => start_quic_servers(config, resolver).await?,
        Transport::Udp => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP listener transport is not supported",
            ));
        }
    };

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            bind_location
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
    )?);

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(addresses) => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            let mut listeners = Vec::new();
            for address in addresses.into_vec() {
                for socket_addr in address.to_socket_addrs()? {
                    let listener = new_tcp_listener(socket_addr, 4096, None)?;
                    let tcp_handler = match handlers.entry(socket_addr.ip()) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                            create_tcp_server_handler(
                                protocol.clone(),
                                &client_proxy_selector,
                                &resolver,
                                Some(socket_addr.ip()),
                            )?
                            .into(),
                        ),
                    }
                    .clone();
                    listeners.push((listener, tcp_handler));
                }
            }
            for (listener, tcp_handler) in listeners {
                let tcp_config = tcp_config.clone();
                let resolver = resolver.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(error) =
                        run_tcp_server(listener, tcp_config, resolver, tcp_handler).await
                    {
                        error!("TCP listener stopped: {error}");
                    }
                }));
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
                    println!(
                        "WARNING: replacing file at socket path {}",
                        path_buf.display()
                    );
                    tokio::fs::remove_file(&path_buf).await?;
                }
                let listener = crate::socket_util::new_unix_listener(path_buf, 4096)?;
                let tcp_handler: Arc<dyn TcpServerHandler> =
                    create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, None)?
                        .into();
                let handle = tokio::spawn(async move {
                    if let Err(error) = run_unix_server(listener, resolver, tcp_handler).await {
                        error!("Unix listener stopped: {error}");
                    }
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
    use std::net::SocketAddr;
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
    struct Handler(Arc<ClientProxySelector>);
    #[async_trait]
    impl TcpServerHandler for Handler {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::from_str("127.0.0.1:80", None)?,
                stream,
                need_initial_flush: true,
                proxy_selector: self.0.clone(),
                connection_success_response: Some(b"response".to_vec().into_boxed_slice()),
                initial_remote_data: Some(b"request".to_vec().into_boxed_slice()),
            })
        }
    }

    #[derive(Debug)]
    struct ReadyConnector(std::sync::Mutex<Option<FlushStream>>);

    #[derive(Debug)]
    struct FlushStream {
        inner: tokio::io::DuplexStream,
        stalled: bool,
        flushes: Arc<AtomicUsize>,
    }

    impl tokio::io::AsyncRead for FlushStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for FlushStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            if self.stalled {
                Poll::Pending
            } else {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl AsyncPing for FlushStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for FlushStream {}

    #[async_trait]
    impl SocketConnector for ReadyConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initial_writes_and_flushes_have_deadlines() {
        use tokio::io::AsyncReadExt;
        for (inbound_capacity, outbound_capacity, stall_response, stall_request) in [
            (1, 64, false, false),
            (64, 1, false, false),
            (64, 64, true, false),
            (64, 64, false, true),
        ] {
            let (inbound, mut peer) = tokio::io::duplex(inbound_capacity);
            let (outbound, mut target) = tokio::io::duplex(outbound_capacity);
            let response_flushes = Arc::new(AtomicUsize::new(0));
            let request_flushes = Arc::new(AtomicUsize::new(0));
            let inbound = FlushStream {
                inner: inbound,
                stalled: stall_response,
                flushes: response_flushes.clone(),
            };
            let outbound = FlushStream {
                inner: outbound,
                stalled: stall_request,
                flushes: request_flushes.clone(),
            };
            let chain = ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Box::new(ReadyConnector(
                    std::sync::Mutex::new(Some(outbound)),
                )))],
                vec![],
            );
            let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                vec![crate::address::NetLocationMask::ANY],
                ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
            )]));
            let started = tokio::time::Instant::now();
            let error = timeout(
                Duration::from_secs(61),
                process_stream(
                    inbound,
                    Arc::new(Handler(selector)),
                    Arc::new(PendingResolver),
                ),
            )
            .await
            .expect("initial writes retained the stream indefinitely")
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(started.elapsed(), Duration::from_secs(60));
            if stall_response {
                assert!(response_flushes.load(Ordering::Relaxed) > 0);
            }
            if stall_request {
                assert!(request_flushes.load(Ordering::Relaxed) > 0);
            }
            peer.read_to_end(&mut Vec::new()).await.unwrap();
            target.read_to_end(&mut Vec::new()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn protocol_response_precedes_chained_greeting() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rule = serde_yaml::from_str(&format!(
            "masks: '0.0.0.0/0'\nclient_proxy:\n  address: '{}'\n  protocol: {{type: socks}}\n",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let handler = Arc::new(Handler(Arc::new(
            create_tcp_client_proxy_selector(vec![rule], resolver.clone()).unwrap(),
        )));
        let (server, mut peer) = tokio::io::duplex(512);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.read_exact(&mut [0; 3]).await.unwrap();
            socket.write_all(&[5, 0]).await.unwrap();
            socket.read_exact(&mut [0; 10]).await.unwrap();
            socket
                .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00greeting")
                .await
                .unwrap();
            let mut request = [0; 7];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            socket.write_all(b"later").await.unwrap();
        });
        tasks.spawn(async move {
            process_stream(server, handler, resolver).await.unwrap();
        });
        let mut response = [0; 21];
        timeout(Duration::from_secs(3), peer.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"responsegreetinglater");
        drop(peer);
        while let Some(result) = timeout(Duration::from_secs(3), tasks.join_next())
            .await
            .unwrap()
        {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_bind_failure_releases_all_prepared_listeners() {
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_addr = first.local_addr().unwrap();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = format!(
            "- address: ['{first_addr}', '{}']\n  protocol:\n    type: http\n",
            occupied.local_addr().unwrap()
        );
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        drop(first);
        let error = start_servers(
            configs.configs.into_iter().next().unwrap(),
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        std::net::TcpListener::bind(first_addr).expect("earlier bind leaked after startup failed");
    }

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
