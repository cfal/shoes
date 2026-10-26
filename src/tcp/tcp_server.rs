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
mod lifetime_tests;
