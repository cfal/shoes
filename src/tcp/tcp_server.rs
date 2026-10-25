use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::{debug, error};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use super::tcp_server_handler_factory::create_tcp_server_handler;

use crate::async_stream::{AsyncMessageStream, AsyncStream};
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
    listener: Arc<tokio::net::TcpListener>,
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
    let permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
    process_stream_with_permit(
        stream,
        server_handler,
        resolver,
        permit,
        Duration::from_secs(60),
    )
    .await
}

pub(crate) async fn process_stream_with_permit<AS: AsyncStream + 'static>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    _permit: crate::resources::BudgetPermit,
    setup_timeout: Duration,
) -> std::io::Result<()> {
    let source = stream.peer_addr();
    let setup_server_stream_future =
        timeout(setup_timeout, setup_server_stream(stream, server_handler));

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
            mut connection_success_response,
            initial_remote_data,
        } => {
            let setup_client_stream_future = async {
                let route = timeout(setup_timeout, async {
                    let prepared = super::ingress::PreparedTcp::new(
                        &proxy_selector,
                        remote_location.clone(),
                        initial_remote_data.map_or_else(Vec::new, |data| data.into_vec()),
                    )?
                    .with_source(source);
                    if prepared.needs_sniff_read() {
                        crate::util::timeout_stream_setup(async {
                            let response = connection_success_response.take();
                            let flush = response.is_some() || server_need_initial_flush;
                            if let Some(data) = response {
                                write_all(&mut server_stream, &data).await?;
                            }
                            if flush {
                                server_stream.flush().await?;
                            }
                            Ok(())
                        })
                        .await?;
                    }
                    prepared
                        .route(&mut server_stream, &proxy_selector, &resolver)
                        .await
                })
                .await?;
                match route {
                    Ok(route) => timeout(setup_timeout, route.connect(&resolver)).await,
                    Err(error) => Ok(Err(error)),
                }
            };

            let routed = match setup_client_stream_future.await {
                Ok(Ok(routed)) => routed,
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
            drop(proxy_selector);
            drop(resolver);
            let Some(TcpClientSetupResult {
                mut client_stream,
                early_data,
            }) = routed.setup
            else {
                crate::util::shutdown_stream(&mut server_stream).await;
                return Ok(());
            };
            log::debug!("TCP setup completed for {}", routed.wire_destination);

            let flow = client_stream.flow().cloned();
            crate::control::tracked_stream::during_flow(
                flow.as_deref(),
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
                    if !routed.is_local_dns && !routed.prefix.is_empty() {
                        write_all(&mut client_stream, &routed.prefix).await?;
                        client_stream.flush().await?;
                    }
                    Ok(())
                }),
            )
            .await?;
            // Local DNS can produce replies before it consumes a pipelined prefix.
            if routed.is_local_dns {
                server_stream = Box::new(crate::prepend_stream::PrependStream::new(
                    server_stream,
                    Some(routed.prefix.into_boxed_slice()),
                ));
            } else {
                drop(routed.prefix);
            }

            let copy_result =
                copy_bidirectional(&mut server_stream, &mut client_stream, false, false).await;

            crate::util::shutdown_stream_pair(&mut server_stream, &mut client_stream).await;

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
                crate::routing::ingress::connect_udp(
                    &proxy_selector,
                    remote_location,
                    &resolver,
                    source,
                )
                .await
                .map_err(|error| {
                    if crate::routing::ingress::is_policy_block(&error) {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "Blocked bidirectional udp forward",
                        )
                    } else {
                        error
                    }
                })
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
            drop(resolver);
            session.await;
            Ok(())
        }
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
    let server_flow = server_stream.flow().cloned();
    let client_flow = client_stream.flow().cloned();
    let copy_result = crate::control::tracked_stream::during_flows(
        server_flow.as_deref(),
        client_flow.as_deref(),
        copy_bidirectional_message(
            &mut server_stream,
            &mut client_stream,
            server_need_initial_flush,
            client_need_initial_flush,
        ),
    )
    .await;

    crate::control::tracked_stream::finish_shutdown(
        server_flow.as_deref(),
        client_flow.as_deref(),
        async {
            futures::join!(
                crate::util::shutdown_message_stream(&mut server_stream),
                crate::util::shutdown_message_stream(&mut client_stream),
            );
        },
    )
    .await;

    copy_result
}

#[cfg(any(test, target_os = "android", target_os = "ios", feature = "ffi"))]
pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    start_servers_with_listeners(config, resolver, &mut TcpListeners::default()).await
}

/// Socket ownership is independent of handlers and routing generations.
#[derive(Default)]
pub(crate) struct TcpListeners {
    sockets: HashMap<SocketAddr, Arc<tokio::net::TcpListener>>,
    // Automatic ports participate in overlap checks without extending socket ownership.
    automatic_sockets: Vec<Weak<tokio::net::TcpListener>>,
    admission: Option<tokio_util::sync::CancellationToken>,
}

impl TcpListeners {
    pub(crate) fn prepare(
        configs: &[Config],
        previous: &Self,
        retiring_http: &[SocketAddr],
    ) -> std::io::Result<Self> {
        let mut next = Self::default();
        next.defer_admission();
        let mut seen = std::collections::HashSet::new();
        for config in configs {
            let Config::Server(server) = config else {
                continue;
            };
            if server.transport != Transport::Tcp {
                continue;
            }
            let BindLocation::Address(addresses) = &server.bind_location else {
                continue;
            };
            for address in addresses.iter() {
                for address in address.to_socket_addrs()? {
                    if address.port() == 0 {
                        continue;
                    }
                    if !seen.insert(address) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            format!("duplicate TCP listener at {address}"),
                        ));
                    }
                    if let Some(listener) = previous.sockets.get(&address) {
                        next.sockets.insert(address, listener.clone());
                        continue;
                    }
                    let automatic_addresses = previous
                        .automatic_sockets
                        .iter()
                        .filter_map(Weak::upgrade)
                        .filter_map(|listener| listener.local_addr().ok());
                    let overlaps_retiring_listener = previous
                        .sockets
                        .values()
                        .filter_map(|listener| listener.local_addr().ok())
                        .chain(automatic_addresses)
                        .chain(retiring_http.iter().copied())
                        .any(|bound| {
                            let bound_ip = bound.ip().to_canonical();
                            let requested_ip = address.ip().to_canonical();
                            bound.port() == address.port()
                                && (bound_ip == requested_ip
                                    || bound_ip.is_unspecified()
                                    || requested_ip.is_unspecified())
                        });
                    // SO_REUSEADDR may permit overlapping binds before the old socket retires.
                    if overlaps_retiring_listener {
                        continue;
                    }
                    next.bind(address)?;
                }
            }
        }
        Ok(next)
    }

    pub(crate) fn retain_shared(&mut self, next: &Self) {
        self.sockets.retain(|address, listener| {
            next.sockets
                .get(address)
                .is_some_and(|next| Arc::ptr_eq(listener, next))
        });
    }

    /// Gates subsequently started listeners without affecting already draining flows.
    pub(crate) fn defer_admission(&mut self) {
        self.admission = Some(tokio_util::sync::CancellationToken::new());
    }

    pub(crate) fn activate(&self) {
        if let Some(admission) = &self.admission {
            admission.cancel();
        }
    }

    fn bind(&mut self, address: SocketAddr) -> std::io::Result<Arc<tokio::net::TcpListener>> {
        if let Some(listener) = self.sockets.get(&address) {
            return Ok(listener.clone());
        }
        let listener = Arc::new(new_tcp_listener(address, 4096, None)?);
        if address.port() != 0 {
            self.sockets.insert(address, listener.clone());
        } else {
            self.automatic_sockets
                .retain(|listener| listener.strong_count() > 0);
            self.automatic_sockets.push(Arc::downgrade(&listener));
        }
        Ok(listener)
    }
}

pub(crate) async fn start_servers_with_listeners(
    config: Config,
    resolver: Arc<dyn Resolver>,
    listeners: &mut TcpListeners,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config {
        #[cfg(unix)]
        Config::TunServer(tun_config) => {
            let task = tokio_util::task::AbortOnDropHandle::new(
                start_tun_server(tun_config, resolver).await?,
            );
            Ok(vec![tokio::spawn(async move {
                if let Err(error) = task
                    .await
                    .unwrap_or_else(|error| Err(std::io::Error::other(error)))
                {
                    error!("TUN server error: {error}");
                }
            })])
        }
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(server_config, resolver, listeners).await
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Expected a server configuration",
        )),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    listeners: &mut TcpListeners,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let bind_location = config.bind_location.to_string();
    let join_handles = match config.transport {
        Transport::Tcp => start_tcp_servers(config, resolver, listeners).await?,
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
    sockets: &mut TcpListeners,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        sniff,
        ..
    } = config;

    println!("Starting {} TCP server at {}", protocol, bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(
        create_tcp_client_proxy_selector(rules.clone(), resolver.clone())?.with_sniff(sniff),
    );

    let mut handles = vec![];

    match bind_location {
        BindLocation::Unspecified {} => {
            return Err(std::io::Error::other("TCP listener requires an address"));
        }
        BindLocation::Address(addresses) => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            let mut services = super::tcp_server_handler_factory::HandlerServices::default();
            let mut listeners = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for address in addresses.into_vec() {
                for socket_addr in address.to_socket_addrs()? {
                    if socket_addr.port() != 0 && !seen.insert(socket_addr) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            format!("duplicate TCP listener at {socket_addr}"),
                        ));
                    }
                    let listener = sockets.bind(socket_addr)?;
                    let tcp_handler = match handlers.entry(socket_addr.ip()) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                            super::tcp_server_handler_factory::create_tcp_server_handler_shared(
                                protocol.clone(),
                                &client_proxy_selector,
                                &resolver,
                                Some(socket_addr.ip()),
                                &mut services,
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
                let admission = sockets.admission.clone();
                handles.push(tokio::spawn(async move {
                    // Uncommitted flows must not outlive rollback through graceful draining.
                    if let Some(admission) = admission {
                        admission.cancelled().await;
                    }
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
                let admission = sockets.admission.clone();
                let handle = tokio::spawn(async move {
                    if let Some(admission) = admission {
                        admission.cancelled().await;
                    }
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

    use crate::address::NetLocation;
    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
    };
    use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::tcp::socket_connector::SocketConnector;

    #[tokio::test]
    async fn ephemeral_tcp_activation_does_not_cache_automatic_ports() {
        let mut sockets = TcpListeners::default();
        let first = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let second = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
        assert!(sockets.sockets.is_empty());
        assert_eq!(sockets.automatic_sockets.len(), 2);
        drop((first, second));
        let _next = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_eq!(sockets.automatic_sockets.len(), 1);
    }

    #[tokio::test]
    async fn tcp_preparation_defers_reported_http_overlap_before_binding() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        drop(reservation);
        for retiring in [
            address,
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), address.port()),
        ] {
            let next =
                TcpListeners::prepare(&configs.configs, &TcpListeners::default(), &[retiring])
                    .unwrap();
            assert!(next.sockets.is_empty(), "overlapping listener was prebound");
            std::net::TcpListener::bind(address).expect("preparation claimed a retiring address");
        }
    }

    #[tokio::test]
    async fn tcp_preparation_defers_live_automatic_ports_without_retaining_them() {
        let mut previous = TcpListeners::default();
        let live = previous.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = live.local_addr().unwrap();
        let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        let next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
        assert!(
            next.sockets.is_empty(),
            "automatic port was prebound or reused"
        );
        drop(live);
        let next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
        assert!(
            next.sockets.contains_key(&address),
            "retired port was still deferred"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_preparation_defers_ipv4_mapped_listener_transitions() {
        use tokio::io::AsyncReadExt;
        timeout(Duration::from_secs(5), async {
            for (old_ip, new_ip) in [
                ("127.0.0.1", "::ffff:127.0.0.1"),
                ("::ffff:127.0.0.1", "127.0.0.1"),
            ] {
                let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = reservation.local_addr().unwrap().port();
                drop(reservation);
                let mut previous = TcpListeners::default();
                let live = previous
                    .bind(SocketAddr::new(old_ip.parse().unwrap(), port))
                    .unwrap();
                let address = SocketAddr::new(new_ip.parse().unwrap(), port);
                let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
                let configs =
                    crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap())
                        .unwrap();
                let mut next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
                assert!(next.sockets.is_empty(), "mapped address was prebound");
                drop(live);
                previous.retain_shared(&next);
                let replacement = next.bind(address).unwrap();
                let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let (mut accepted, _) = replacement.accept().await.unwrap();
                peer.write_all(b"live").await.unwrap();
                let mut bytes = [0; 4];
                accepted.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"live");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fake_dns_udp_modes() {
        use crate::routing::ingress::tests::{PacketMode, UdpCase, UdpFixture};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        timeout(Duration::from_secs(10), async {
            for fixed in [false, true] {
                for case in [UdpCase::Dns, UdpCase::Tls, UdpCase::Http] {
                    let mut tasks = tokio::task::JoinSet::new();
                    let fixture = UdpFixture::new(case, &mut tasks).await;
                    let mode = if fixed {
                        PacketMode::Fixed
                    } else {
                        PacketMode::Uot
                    };
                    let handler = Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                        None,
                        true,
                        "127.0.0.1".parse().unwrap(),
                        fixture.selector.clone(),
                        fixture.resolver.clone(),
                    ));
                    let (server, mut peer) = tokio::io::duplex(8192);
                    let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                        process_stream(server, handler, fixture.resolver.clone()),
                    ));
                    peer.write_all(&[5, 1, 0]).await.unwrap();
                    let mut auth = [0; 2];
                    peer.read_exact(&mut auth).await.unwrap();
                    assert_eq!(auth, [5, 0]);
                    let magic =
                        NetLocation::from_str(crate::uot::UOT_V2_MAGIC_ADDRESS, Some(0)).unwrap();
                    let mut request = vec![5, 1, 0];
                    request.extend(crate::socks_handler::write_location_to_vec(&magic));
                    peer.write_all(&request).await.unwrap();
                    let mut status = [0; 3];
                    peer.read_exact(&mut status).await.unwrap();
                    assert_eq!(status, [5, 0, 0]);
                    crate::socks_handler::read_location_direct(&mut peer)
                        .await
                        .unwrap();
                    peer.write_all(&fixture.uot_header(fixed)).await.unwrap();
                    peer.write_all(&fixture.request(mode)).await.unwrap();
                    fixture.read_reply(&mut peer, mode).await;
                    while let Some(result) = tasks.join_next().await {
                        result.unwrap();
                    }
                }
            }
        })
        .await
        .unwrap();
    }

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
    struct FlushOnlyHandler(Arc<ClientProxySelector>);

    #[async_trait]
    impl TcpServerHandler for FlushOnlyHandler {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::from_str(super::super::ingress::tests::TARGET, None)?,
                stream,
                need_initial_flush: true,
                proxy_selector: self.0.clone(),
                connection_success_response: None,
                initial_remote_data: None,
            })
        }
    }

    #[tokio::test]
    async fn sniff_flushes_buffered_inbound_without_an_explicit_reply() {
        use tokio::io::AsyncReadExt;
        timeout(Duration::from_secs(5), async {
            let mut tasks = tokio::task::JoinSet::new();
            let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
            let (selector, resolver) =
                super::super::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
            let (server, mut peer) = tokio::io::duplex(8192);
            let flushes = Arc::new(AtomicUsize::new(0));
            let server = FlushStream {
                inner: server,
                stalled: false,
                flushes: flushes.clone(),
            };
            tasks.spawn(async move {
                process_stream(server, Arc::new(FlushOnlyHandler(selector)), resolver)
                    .await
                    .unwrap();
            });
            while flushes.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
            peer.write_all(&hello).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"greetinglater");
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }

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
    async fn cancelled_flow_drops_a_blocked_initial_response() {
        use crate::control::catalog::RuleDescription;
        use crate::control::flows::{FlowContext, FlowRegistry};
        let registry = Arc::new(FlowRegistry::default());
        let (inbound, _peer) = tokio::io::duplex(1);
        let (outbound, _target) = tokio::io::duplex(64);
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
                std::sync::Mutex::new(Some(FlushStream {
                    inner: outbound,
                    stalled: false,
                    flushes: Arc::new(AtomicUsize::new(0)),
                })),
            )))],
            vec![],
        );
        let group =
            ClientChainGroup::new(vec![chain]).with_description(Some(Arc::new(RuleDescription {
                payload: "all".into(),
                proxy: "DIRECT".into(),
                context: Some(Arc::new(FlowContext {
                    registry: registry.clone(),
                    generation: 1,
                    inbound: "test".into(),
                    scope: "root".into(),
                    protocol: "Socks5".into(),
                })),
            })));
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::ANY],
            ConnectAction::new_allow(None, group),
        )]));
        let relay = tokio::spawn(process_stream(
            inbound,
            Arc::new(Handler(selector)),
            Arc::new(PendingResolver),
        ));
        timeout(Duration::from_secs(1), async {
            while registry.snapshot(0).connections.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        registry.cancel_all();
        let error = timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(registry.snapshot(0).connections.is_empty());
    }

    #[tokio::test]
    async fn fixed_tcp_releases_setup_owners_before_relay_and_half_close() {
        use tokio::io::AsyncReadExt;
        timeout(Duration::from_secs(5), async {
            let (inbound, mut peer) = tokio::io::duplex(64);
            let (outbound, mut target) = tokio::io::duplex(64);
            let chain = ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
                    std::sync::Mutex::new(Some(FlushStream {
                        inner: outbound,
                        stalled: false,
                        flushes: Arc::new(AtomicUsize::new(0)),
                    })),
                )))],
                vec![],
            );
            let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                vec![crate::address::NetLocationMask::ANY],
                ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
            )]));
            let resolver: Arc<dyn Resolver> = Arc::new(PendingResolver);
            let handler = Arc::new(Handler(selector.clone()));
            let weak_selector = Arc::downgrade(&selector);
            let weak_resolver = Arc::downgrade(&resolver);
            let weak_handler = Arc::downgrade(&handler);
            drop(selector);
            let relay = tokio::spawn(process_stream(inbound, handler, resolver));
            let mut response = [0; 8];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
            let mut request = [0; 7];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            assert!(weak_selector.upgrade().is_none());
            assert!(weak_resolver.upgrade().is_none());
            assert!(weak_handler.upgrade().is_none());
            assert!(!relay.is_finished());

            peer.write_all(b"live request").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            target.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"live request");
            target.write_all(b"reply after FIN").await.unwrap();
            target.shutdown().await.unwrap();
            bytes.clear();
            peer.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"reply after FIN");
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
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
                vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
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
            super::super::tcp_client_handler_factory::create_test_selector(
                vec![rule],
                resolver.clone(),
            )
            .unwrap(),
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
    async fn reply_gated_socks_and_connect_sniff_route_and_preserve_proxy_ip() {
        use super::super::ingress::tests::{TARGET, socks_target};
        use tokio::io::AsyncReadExt;
        for socks in [true, false] {
            timeout(Duration::from_secs(5), async {
                let mut tasks = tokio::task::JoinSet::new();
                let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
                let (selector, resolver) = socks_target(hello.clone(), &mut tasks).await;
                let handler: Arc<dyn TcpServerHandler> = if socks {
                    Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                        None,
                        false,
                        "0.0.0.0".parse().unwrap(),
                        selector,
                        resolver.clone(),
                    ))
                } else {
                    Arc::new(crate::http_handler::HttpTcpServerHandler::new(
                        None,
                        selector,
                        resolver.clone(),
                    ))
                };
                let (server, mut peer) = tokio::io::duplex(8192);
                tasks.spawn(async move {
                    process_stream(server, handler, resolver).await.unwrap();
                });
                if socks {
                    peer.write_all(&[5, 1, 0]).await.unwrap();
                    let mut method = [0; 2];
                    peer.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 0]);
                    peer.write_all(&[5, 1, 0, 1, 203, 0, 113, 1, 1, 187])
                        .await
                        .unwrap();
                    let mut reply = [0; 10];
                    peer.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                } else {
                    peer.write_all(
                        format!("CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                    let mut reply = Vec::new();
                    while !reply.ends_with(b"\r\n\r\n") {
                        reply.push(peer.read_u8().await.unwrap());
                    }
                    assert!(reply.starts_with(b"HTTP/1.1 200"));
                }
                // No application bytes are sent until the actual protocol success.
                peer.write_all(&hello).await.unwrap();
                peer.shutdown().await.unwrap();
                let mut reply = Vec::new();
                peer.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"greetinglater");
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn coalesced_connect_dns_pipeline_drains_replies_during_prefix_replay() {
        use hickory_resolver::proto::op::{Message, Query};
        use hickory_resolver::proto::rr::{Name, RecordType};
        use tokio::io::AsyncReadExt;

        timeout(Duration::from_secs(5), async {
            let resolver: Arc<dyn Resolver> = Arc::new(PendingResolver);
            let context = Arc::new(
                crate::dns::fake_ip::FakeDnsContext::new(Default::default(), resolver.clone())
                    .unwrap(),
            );
            let selector = Arc::new(
                ClientProxySelector::new(vec![])
                    .with_fake_dns_context(Some(context))
                    .unwrap(),
            );
            let handler = Arc::new(crate::http_handler::HttpTcpServerHandler::new(
                None,
                selector,
                resolver.clone(),
            ));
            let (server, mut peer) = tokio::io::duplex(65536);
            let mut prefix =
                b"CONNECT 192.0.2.1:53 HTTP/1.1\r\nHost: 192.0.2.1:53\r\n\r\n".to_vec();
            for id in 0..1200 {
                let mut query = Message::query();
                query.metadata.id = id;
                query.add_query(Query::query(
                    Name::from_ascii("a.test").unwrap(),
                    RecordType::A,
                ));
                let bytes = query.to_vec().unwrap();
                prefix.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                prefix.extend_from_slice(&bytes);
            }
            assert!(prefix.len() > 30 * 1024 && prefix.len() < 32 * 1024);
            peer.write_all(&prefix).await.unwrap();
            peer.shutdown().await.unwrap();
            let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(process_stream(
                server, handler, resolver,
            )));
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(peer.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"HTTP/1.1 200"));
            for id in 0..1200 {
                let length = peer.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0; length];
                peer.read_exact(&mut bytes).await.unwrap();
                let answer = Message::from_vec(&bytes).unwrap();
                assert_eq!(answer.metadata.id, id);
                assert_eq!(answer.answers.len(), 1);
            }
            task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_wait_does_not_consume_outbound_connect_budget() {
        use tokio::io::AsyncReadExt;
        #[derive(Debug)]
        struct DelayedConnector(std::sync::Mutex<Option<tokio::io::DuplexStream>>);
        #[async_trait]
        impl SocketConnector for DelayedConnector {
            async fn connect(
                &self,
                _: &Arc<dyn Resolver>,
                _: &crate::address::ResolvedLocation,
            ) -> io::Result<Box<dyn AsyncStream>> {
                tokio::time::sleep(Duration::from_millis(900)).await;
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
        let (outbound, mut target) = tokio::io::duplex(64);
        target.write_all(b"ready").await.unwrap();
        target.shutdown().await.unwrap();
        let selector = Arc::new(
            ClientProxySelector::new(vec![ConnectRule::new(
                vec![
                    crate::address::NetLocationMask::from("sniff.example").unwrap(),
                    crate::address::NetLocationMask::ANY,
                ],
                ConnectAction::new_allow(
                    None,
                    ClientChainGroup::new(vec![ClientProxyChain::new(
                        vec![InitialHopEntry::Direct(Arc::new(DelayedConnector(
                            std::sync::Mutex::new(Some(outbound)),
                        )))],
                        vec![],
                    )]),
                ),
            )])
            .with_sniff(true),
        );
        let (server, mut peer) = tokio::io::duplex(64);
        let started = tokio::time::Instant::now();
        let task =
            tokio_util::task::AbortOnDropHandle::new(tokio::spawn(process_stream_with_permit(
                server,
                Arc::new(FlushOnlyHandler(selector)),
                Arc::new(PendingResolver),
                crate::resources::try_stream().unwrap(),
                Duration::from_secs(1),
            )));
        let mut bytes = [0; 5];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ready");
        assert!(started.elapsed() >= Duration::from_millis(1200));
        peer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sniff_failures_close_socks_and_connect_without_a_second_reply() {
        use super::super::ingress::tests::{TARGET, failure_selector};
        use tokio::io::AsyncReadExt;
        for socks in [true, false] {
            for blocked in [true, false] {
                timeout(Duration::from_secs(5), async {
                    let selector = failure_selector(true, blocked);
                    let resolver: Arc<dyn Resolver> =
                        Arc::new(crate::resolver::NativeResolver::new());
                    let handler: Arc<dyn TcpServerHandler> = if socks {
                        Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                            None,
                            false,
                            "0.0.0.0".parse().unwrap(),
                            selector,
                            resolver.clone(),
                        ))
                    } else {
                        Arc::new(crate::http_handler::HttpTcpServerHandler::new(
                            None,
                            selector,
                            resolver.clone(),
                        ))
                    };
                    let (server, mut peer) = tokio::io::duplex(8192);
                    let server = tokio::spawn(process_stream(server, handler, resolver));
                    if socks {
                        peer.write_all(&[5, 1, 0]).await.unwrap();
                        let mut method = [0; 2];
                        peer.read_exact(&mut method).await.unwrap();
                        assert_eq!(method, [5, 0]);
                        peer.write_all(&[5, 1, 0, 1, 203, 0, 113, 1, 1, 187])
                            .await
                            .unwrap();
                        let mut reply = [0; 10];
                        peer.read_exact(&mut reply).await.unwrap();
                        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                    } else {
                        peer.write_all(
                            format!("CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                        let mut reply = Vec::new();
                        while !reply.ends_with(b"\r\n\r\n") {
                            reply.push(peer.read_u8().await.unwrap());
                        }
                        assert!(reply.starts_with(b"HTTP/1.1 200"));
                    }
                    peer.write_all(&crate::sniff::tests::hello(&rustls::version::TLS13, true))
                        .await
                        .unwrap();
                    let mut reply = Vec::new();
                    peer.read_to_end(&mut reply).await.unwrap();
                    assert!(reply.is_empty(), "second reply after optimistic success");
                    let result = server.await.unwrap();
                    if blocked {
                        result.unwrap();
                    } else {
                        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
                    }
                })
                .await
                .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn direct_tcp_startup_rejects_duplicate_fixed_but_allows_automatic_ports() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        for port in [address.port(), 0] {
            let address = SocketAddr::new(address.ip(), port);
            let config =
                format!("- address: ['{address}', '{address}']\n  protocol: {{type: http}}\n");
            let configs =
                crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap())
                    .unwrap();
            let result = start_servers(
                configs.configs.into_iter().next().unwrap(),
                Arc::new(crate::resolver::NativeResolver::new()),
            )
            .await;
            if port == 0 {
                let handles = result.unwrap();
                assert_eq!(handles.len(), 2);
                for handle in &handles {
                    handle.abort();
                }
                for handle in handles {
                    assert!(handle.await.unwrap_err().is_cancelled());
                }
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AddrInUse);
                std::net::TcpListener::bind(address).expect("duplicate bind leaked a listener");
            }
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
    async fn fixed_udp_preserves_transport_permission_denials() {
        #[derive(Debug)]
        struct DeniedConnector;

        #[async_trait]
        impl SocketConnector for DeniedConnector {
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
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transport denied",
                ))
            }

            fn bind_interface(&self) -> Option<&str> {
                None
            }
        }

        for blocked in [true, false] {
            let action = if blocked {
                ConnectAction::Block
            } else {
                ConnectAction::new_allow(
                    None,
                    ClientChainGroup::new(vec![ClientProxyChain::new(
                        vec![InitialHopEntry::Direct(Arc::new(DeniedConnector))],
                        vec![],
                    )]),
                )
            };
            let handler = Arc::new(UdpHandler {
                remote: NetLocation::from_str("192.0.2.1:443", None).unwrap(),
                selector: Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                    vec![crate::address::NetLocationMask::ANY],
                    action,
                )])),
                marker: Arc::new(()),
                shutdowns: Arc::new(AtomicUsize::new(0)),
            });
            let (stream, _peer) = tokio::io::duplex(64);
            let error = process_stream(stream, handler, Arc::new(PendingResolver))
                .await
                .unwrap_err();
            let (kind, message) = if blocked {
                (
                    io::ErrorKind::ConnectionRefused,
                    "Blocked bidirectional udp forward",
                )
            } else {
                (io::ErrorKind::PermissionDenied, "transport denied")
            };
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_setup_and_error_cleanup_have_deadlines() {
        for remote in ["pending.test:53", "192.0.2.1:53"] {
            let marker = Arc::new(());
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let chain = ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Arc::new(PendingConnector))],
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
