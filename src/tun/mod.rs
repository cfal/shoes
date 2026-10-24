//! TUN device support for shoes.
//!
//! This module provides VPN functionality by accepting IP packets from a TUN
//! device and routing TCP/UDP traffic through configured proxy chains.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │   TUN Device    │ ←→  │  shoes/smoltcp  │ ←→  │  Proxy Chain    │
//! │ (IP packets)    │     │ (our TCP stack) │     │ (VLESS, etc.)   │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! The smoltcp stack runs in a dedicated OS thread with direct fd access,
//! using `poll()` for TUN readiness and cross-thread wakeups.
//!
//! # Platform Support
//!
//! - **Linux**: Creates TUN device with specified name/address. Requires root
//!   privileges or `CAP_NET_ADMIN` capability.
//!
//! - **Android**: Accepts raw FD from `VpnService.Builder.establish()`. The
//!   VPN configuration (routes, DNS, etc.) is handled by the Android VpnService.
//!   You must pass the FD via `TunServerConfig::raw_fd()`.
//!
//! - **iOS/macOS**: Accepts raw FD from `NEPacketTunnelProvider.packetFlow`.
//!   Use `TunServerConfig::packet_information(true)` if using the socket FD
//!   directly, or `false` if using the readPackets/writePackets API.

mod offload;
use crate::ip_stack::{packet, tcp_conn, wake};
mod tcp_stack_direct;
#[cfg(test)]
mod tcp_tests;
mod tun_server;
pub(crate) mod udp_handler;
pub(crate) mod udp_manager;

#[cfg(test)]
use crate::ip_stack::test_gate;
#[cfg(test)]
mod udp_tests;

// Platform module only needed for mobile FFI targets
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
#[cfg_attr(
    all(feature = "ffi", not(any(target_os = "android", target_os = "ios"))),
    allow(dead_code)
)]
mod platform;
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
#[cfg_attr(
    all(feature = "ffi", not(any(target_os = "android", target_os = "ios"))),
    allow(unused_imports)
)]
pub use platform::{
    FnSocketProtector, NoOpPlatformCallbacks, NoOpSocketProtector, PlatformCallbacks,
    PlatformInterface, SocketProtector, clear_global_socket_protector,
    clear_global_socket_protector_if_current, get_global_socket_protector, protect_socket,
    set_global_socket_protector,
};

pub use tun_server::TunServerConfig;

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;

use log::{debug, info, warn};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use crate::address::{Address, NetLocation};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::TunConfig;
use crate::config::selection::ConfigSelection;
use crate::resolver::Resolver;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

use packet::PacketBuffer;
use tcp_stack_direct::{PACKET_QUEUE_CAPACITY, TcpStackDirect};
use udp_manager::TunUdpManager;

/// Run the TUN server with the given configuration.
///
/// This function:
/// 1. Creates/wraps a TUN device
/// 2. Sets up our smoltcp-based TCP/IP stack with direct fd access
/// 3. The stack thread reads packets directly from TUN using poll()
/// 4. Handles TCP connections through the proxy chain
/// 5. Handles UDP packets through tokio (forwarded from stack thread)
#[allow(dead_code)]
pub async fn run_tun_server(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    run_tun_server_inner(config, proxy_selector, resolver, shutdown_rx, &mut None).await
}

async fn run_tun_server_inner(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut shutdown_rx: oneshot::Receiver<()>,
    ready: &mut Option<oneshot::Sender<std::io::Result<()>>>,
) -> std::io::Result<()> {
    config.resource_limits.validate()?;
    let offload = config.offload_enabled()?;
    info!(
        "Starting TUN server (direct mode): mtu={}, tcp={}, udp={}, icmp={}",
        config.mtu, config.tcp_enabled, config.udp_enabled, config.icmp_enabled
    );

    let (fd, offload) = if let Some(fd) = config.raw_fd {
        info!("Using provided raw FD: {}", fd);
        // Raw descriptors must be validated before constructing an IO-safety wrapper.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = if config.close_fd_on_drop {
            unsafe { OwnedFd::from_raw_fd(fd) }
        } else {
            unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?
        };
        (fd, false)
    } else {
        let create = |offload| -> std::io::Result<OwnedFd> {
            let device = config.create_device(offload)?;
            #[cfg(target_os = "linux")]
            if offload {
                offload::configure(device.as_raw_fd())?;
            }
            Ok(unsafe { OwnedFd::from_raw_fd(device.into_raw_fd()) })
        };
        match create(offload) {
            Ok(fd) => (fd, offload),
            Err(error) if offload && config.segmentation_offload.is_none() => {
                log::warn!("TUN transmit offload unavailable: {error}; using ordinary packets");
                (create(false)?, false)
            }
            Err(error) => return Err(error),
        }
    };

    // Creates the direct TCP stack in a dedicated thread.
    let mut stack_config = config.clone();
    if config.raw_fd.is_none() && cfg!(any(target_os = "macos", target_os = "ios")) {
        stack_config.packet_information = true;
    }
    let mut tcp_stack = TcpStackDirect::with_offload(fd, stack_config, offload)?;

    // Get UDP receiver (stack thread filters UDP and sends here)
    let udp_from_stack_rx = tcp_stack.take_udp_rx().expect("udp_rx already taken");

    // Channel for sending UDP responses back (stack thread will write to TUN)
    let (udp_to_stack_tx, udp_to_stack_rx) = mpsc::channel::<PacketBuffer>(PACKET_QUEUE_CAPACITY);
    tcp_stack.set_udp_response_tx(udp_to_stack_rx);

    let mut tcp_conn_rx = tcp_stack.take_tcp_rx().expect("tcp_rx already taken");
    tcp_stack.ready().await?;

    let mut tasks = JoinSet::new();
    if config.tcp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();

        tasks.spawn(async move {
            info!("Starting TCP connection handler");
            let mut connections = JoinSet::new();
            loop {
                let new_conn = tokio::select! {
                    conn = tcp_conn_rx.recv() => match conn {
                        Some(conn) => conn,
                        None => break,
                    },
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let proxy_selector = proxy_selector.clone();
                let resolver = resolver.clone();

                connections.spawn(async move {
                    let remote_addr = new_conn.remote_addr;
                    let target = socket_addr_to_net_location(remote_addr);

                    debug!("Handling TCP connection to {:?}", target);

                    if let Err(e) = handle_tcp_connection(
                        new_conn.connection,
                        target,
                        proxy_selector,
                        resolver,
                        Some(new_conn.source_addr),
                    )
                    .await
                    {
                        debug!("TCP connection to {} failed: {}", remote_addr, e);
                    }
                });
            }

            debug!("TCP connection handler ended");
        });
    }

    if config.udp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let limits = config.resource_limits.clone();
        let wake = tcp_stack.wake_handle();

        tasks.spawn(async move {
            handle_udp_packets(
                udp_from_stack_rx,
                udp_to_stack_tx,
                proxy_selector,
                resolver,
                limits,
                wake,
            )
            .await;
        });
    }

    info!("TUN server started successfully");
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }

    // Wait for shutdown signal or stack thread exit
    let result = tokio::select! {
        _ = &mut shutdown_rx => {
            info!("TUN server shutdown requested");
            Ok(())
        }
        result = tcp_stack.finished() => result.and_then(|()| {
            Err(std::io::Error::other("TUN stack stopped unexpectedly"))
        }),
    };

    tasks.shutdown().await;

    // tcp_stack is dropped here, which stops the stack thread

    info!("TUN server stopped");
    result
}

/// Convert a SocketAddr to a NetLocation.
fn socket_addr_to_net_location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

/// Handle a TCP connection by forwarding it through the proxy chain.
pub(crate) async fn handle_tcp_connection(
    mut connection: tcp_conn::TcpConnection,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    source: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    let _permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
    let prepared =
        crate::tcp::ingress::PreparedTcp::new(&proxy_selector, target.clone(), Vec::new())?
            .with_source(source);
    let route = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        prepared.route(&mut connection, &proxy_selector, &resolver),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN routing timed out"))??;
    let connected = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        use tokio::io::AsyncWriteExt;
        let routed = route.connect(&resolver).await?;
        let Some(mut setup) = routed.setup else {
            return Ok(None);
        };
        let flow = setup.client_stream.flow().cloned();
        crate::control::tracked_stream::during_flow(flow.as_deref(), async {
            if let Some(data) = setup.early_data.take() {
                connection.write_all(&data).await?;
                connection.flush().await?;
            }
            if !routed.prefix.is_empty() {
                setup.client_stream.write_all(&routed.prefix).await?;
                setup.client_stream.flush().await?;
            }
            Ok(())
        })
        .await?;
        drop(routed.prefix);
        Ok::<_, std::io::Error>(Some((setup.client_stream, routed.wire_destination)))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN TCP setup timed out"))
    .and_then(|result| result)
    .inspect_err(|error| warn!("Failed to connect to {}: {}", target, error))?;
    drop(proxy_selector);
    drop(resolver);

    let Some((mut remote, wire_destination)) = connected else {
        debug!("TCP connection blocked by rules");
        return Ok(());
    };
    let flow = remote.flow().cloned();
    let result = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut connection, &mut remote) => result,
        _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => Err(crate::control::tracked_stream::cancelled()),
    };
    match result {
        Ok((sent, received)) => debug!(
            "TCP connection to {} completed: {} bytes sent, {} bytes received",
            wire_destination, sent, received,
        ),
        Err(error) => debug!("TCP connection to {} error: {}", wire_destination, error),
    }
    Ok(())
}

/// Handle UDP packets from the stack thread.
///
/// Uses the session-based TunUdpManager which:
/// - Keys sessions by local (app) address, not by destination
/// - Stores the return address in each session
/// - Routes responses using the stored address (no NAT table lookup)
async fn handle_udp_packets(
    from_stack_rx: mpsc::Receiver<PacketBuffer>,
    to_stack_tx: mpsc::Sender<PacketBuffer>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::tun::TunResourceLimits,
    wake: wake::Wake,
) {
    info!("Starting UDP handler (session-based)");

    let udp_handler = udp_handler::UdpHandler::new(from_stack_rx, to_stack_tx, wake);
    let (reader, writer) = udp_handler.split();

    let manager = TunUdpManager::new(reader, writer, proxy_selector, resolver, limits);

    if let Err(e) = manager.run().await {
        warn!("UDP handler error: {}", e);
    }

    info!("UDP handler stopped");
}

/// Start TUN server based on the provided configuration.
pub async fn start_tun_server(
    config: TunConfig,
    resolver: std::sync::Arc<dyn crate::resolver::Resolver>,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    start_tun_server_with_fd_ownership(config, resolver, true).await
}

pub(crate) async fn start_tun_server_with_fd_ownership(
    config: TunConfig,
    resolver: std::sync::Arc<dyn crate::resolver::Resolver>,
    close_fd_on_drop: bool,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let _keep_alive = shutdown_tx;
        let mut ready = Some(ready_tx);
        let result =
            run_tun_from_config_inner(config, shutdown_rx, close_fd_on_drop, resolver, &mut ready)
                .await;
        if let Some(ready) = ready.take() {
            let _ = ready.send(result);
            Ok(())
        } else {
            result
        }
    });
    let handle = tokio_util::task::AbortOnDropHandle::new(handle);
    ready_rx
        .await
        .map_err(|_| std::io::Error::other("TUN task exited before startup completed"))??;
    Ok(handle.detach())
}

/// Run TUN server from config with external shutdown control.
#[allow(dead_code)]
pub async fn run_tun_from_config(
    config: TunConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    run_tun_from_config_inner(config, shutdown_rx, close_fd_on_drop, resolver, &mut None).await
}

async fn run_tun_from_config_inner(
    config: TunConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
    resolver: Arc<dyn Resolver>,
    ready: &mut Option<oneshot::Sender<std::io::Result<()>>>,
) -> std::io::Result<()> {
    let mut tun_server_config = TunServerConfig::new()
        .mtu(config.mtu)
        .tcp_enabled(config.tcp_enabled)
        .udp_enabled(config.udp_enabled)
        .icmp_enabled(config.icmp_enabled)
        .close_fd_on_drop(close_fd_on_drop);
    tun_server_config.resource_limits = config.resource_limits;
    tun_server_config.segmentation_offload = config.segmentation_offload;

    if let Some(ref name) = config.device_name {
        tun_server_config = tun_server_config.tun_name(name.clone());
        println!("Starting TUN server on device {}", name);
    }
    if let Some(fd) = config.device_fd {
        tun_server_config = tun_server_config.raw_fd(fd);
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            tun_server_config = tun_server_config.packet_information(true);
        }
        println!("Starting TUN server from device FD {}", fd);
    }
    if let Some(addr) = config.address {
        tun_server_config = tun_server_config.address(addr);
    }
    if let Some(mask) = config.netmask {
        tun_server_config = tun_server_config.netmask(mask);
    }
    if let Some(dest) = config.destination {
        tun_server_config = tun_server_config.destination(dest);
    }
    if let Some(packet_information) = config.packet_information {
        tun_server_config.packet_information = packet_information;
    }

    let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
    let client_proxy_selector = Arc::new(
        create_tcp_client_proxy_selector(rules, resolver.clone())?.with_sniff(config.sniff),
    );

    run_tun_server_inner(
        tun_server_config,
        client_proxy_selector,
        resolver,
        shutdown_rx,
        ready,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn compiled_config(yaml: &str) -> TunConfig {
        let mut config: TunConfig = serde_yaml::from_str(yaml).unwrap();
        for rule in config.rules.iter_mut() {
            let ConfigSelection::Config(rule) = rule else {
                panic!("test config contains an unexpanded rule group")
            };
            rule.compile(&mut crate::rules::Compiler::default())
                .unwrap();
        }
        config
    }
    #[tokio::test]
    async fn startup_acknowledges_initialization_and_returns_errors() {
        use std::os::fd::IntoRawFd;
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let invalid = compiled_config("resource_limits: {tcp_buffer_size: 0}");
        assert_eq!(
            start_tun_server(invalid, resolver.clone())
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        let (_peer, device) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let fd = device.into_raw_fd();
        let config = compiled_config(&format!("device_fd: {fd}"));
        let task = start_tun_server(config, resolver).await.unwrap();
        assert!(!task.is_finished());
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn invalid_raw_descriptors_return_errors_without_aborting() {
        const CHILD: &str = "SHOES_INVALID_TUN_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tun::tests::invalid_raw_descriptors_return_errors_without_aborting",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed;"),
                "raw descriptor test failed: {}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for fd in [-1, -2, i32::MAX] {
                    for close in [false, true] {
                        let mut config = TunServerConfig::new();
                        config.raw_fd = Some(fd);
                        config.close_fd_on_drop = close;
                        let (_shutdown, stopped) = oneshot::channel();
                        let error = run_tun_server(
                            config,
                            Arc::new(ClientProxySelector::new(Vec::new())),
                            Arc::new(crate::resolver::NativeResolver::new()),
                            stopped,
                        )
                        .await
                        .unwrap_err();
                        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
                    }
                }
            });
    }

    #[tokio::test]
    async fn device_failure_propagates_before_and_after_readiness() {
        use std::os::fd::IntoRawFd;
        for fail_before_start in [false, true] {
            let (peer, tun) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut peer = Some(peer);
            if fail_before_start {
                peer.take();
            }
            let config = compiled_config(&format!("device_fd: {}", tun.into_raw_fd()));
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let error = if fail_before_start {
                start_tun_server(config, resolver).await.unwrap_err()
            } else {
                let (_shutdown, stopped) = oneshot::channel();
                let (ready, started) = oneshot::channel();
                let task = tokio::spawn(async move {
                    run_tun_from_config_inner(config, stopped, true, resolver, &mut Some(ready))
                        .await
                });
                started.await.unwrap().unwrap();
                peer.take();
                tokio::time::timeout(std::time::Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err()
            };
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn proxy_handshake_bytes_reach_the_tun_connection_before_relay_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rule: crate::config::RuleConfig = serde_yaml::from_str(&format!(
            "masks: '0.0.0.0/0'\nclient_proxy:\n  address: '{}'\n  protocol:\n    type: socks\n",
            proxy.local_addr().unwrap()
        ))
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![rule],
                resolver.clone(),
            )
            .unwrap(),
        );
        let control = Arc::new(tcp_conn::TcpConnectionControl::new(1024, 1024));
        let (wake, _wake_rx) = wake::Wake::new().unwrap();
        let connection = tcp_conn::TcpConnection::new(control.clone(), wake);
        let (release, released) = tokio::sync::oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            socket.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            socket.read_exact(&mut request).await.unwrap();
            socket
                .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00greeting")
                .await
                .unwrap();
            released.await.unwrap();
            socket.write_all(b"later").await.unwrap();
            std::future::pending::<()>().await;
        });
        tasks.spawn(async move {
            handle_tcp_connection(
                connection,
                NetLocation::from_str("127.0.0.1:80", None).unwrap(),
                selector,
                resolver,
                None,
            )
            .await
            .unwrap();
        });
        let mut received = Vec::new();
        receive_tun_bytes(&control, &mut received, b"greeting").await;
        release.send(()).unwrap();
        receive_tun_bytes(&control, &mut received, b"greetinglater").await;
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn sniffed_ip_routes_and_replays_through_the_stack_connection() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut tasks = JoinSet::new();
            let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
            let (selector, resolver) =
                crate::tcp::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
            let target = NetLocation::from_str(crate::tcp::ingress::tests::TARGET, None).unwrap();
            let control = Arc::new(tcp_conn::TcpConnectionControl::new(8192, 8192));
            let (wake, _wake_rx) = wake::Wake::new().unwrap();
            let connection = tcp_conn::TcpConnection::new(control.clone(), wake);
            assert_eq!(control.enqueue_recv_data(&hello), hello.len());
            control.set_recv_state(tcp_conn::TcpSocketState::Closed);
            tasks.spawn(async move {
                handle_tcp_connection(connection, target, selector, resolver, None)
                    .await
                    .unwrap();
            });
            let mut received = Vec::new();
            receive_tun_bytes(&control, &mut received, b"greetinglater").await;
            control.set_send_state(tcp_conn::TcpSocketState::Closing);
            control.wake_sender();
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fake_dns_adapter_contract() {
        use crate::tcp::ingress::tests::FakeTcpCase;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for case in [
                FakeTcpCase::Dns,
                FakeTcpCase::Tls,
                FakeTcpCase::Http,
                FakeTcpCase::Plain,
                FakeTcpCase::Unknown,
            ] {
                let mut tasks = JoinSet::new();
                let (selector, resolver, target, payload) = case.fixture(&mut tasks).await;
                let control = Arc::new(tcp_conn::TcpConnectionControl::new(8192, 8192));
                let (wake, _wake_rx) = wake::Wake::new().unwrap();
                let connection = tcp_conn::TcpConnection::new(control.clone(), wake);
                assert_eq!(control.enqueue_recv_data(&payload), payload.len());
                control.set_recv_state(tcp_conn::TcpSocketState::Closed);
                let mut task = tokio::spawn(handle_tcp_connection(
                    connection, target, selector, resolver, None,
                ));
                let mut received = Vec::new();
                loop {
                    let mut bytes = [0; 2048];
                    let count = control.dequeue_send_data(&mut bytes);
                    received.extend_from_slice(&bytes[..count]);
                    control.wake_sender();
                    if task.is_finished() {
                        break;
                    }
                    if case != FakeTcpCase::Unknown && !received.is_empty() {
                        let complete = if case == FakeTcpCase::Dns {
                            received.len() >= 2
                                && received.len()
                                    == 2 + u16::from_be_bytes([received[0], received[1]]) as usize
                        } else {
                            received == b"greetinglater"
                        };
                        if complete {
                            control.set_send_state(tcp_conn::TcpSocketState::Closing);
                            control.wake_sender();
                        }
                    }
                    tokio::task::yield_now().await;
                }
                let result = (&mut task).await.unwrap();
                assert_eq!(result.is_err(), case == FakeTcpCase::Unknown);
                if case == FakeTcpCase::Unknown {
                    assert!(received.is_empty());
                } else {
                    case.assert_reply(&received);
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        })
        .await
        .unwrap();
    }

    async fn receive_tun_bytes(
        control: &tcp_conn::TcpConnectionControl,
        received: &mut Vec<u8>,
        expected: &[u8],
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while received.len() < expected.len() {
                let mut bytes = [0; 64];
                let count = control.dequeue_send_data(&mut bytes);
                received.extend_from_slice(&bytes[..count]);
                control.wake_sender();
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn startup_propagates_required_offload_validation_failure() {
        let (_peer, device) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let config = compiled_config(&format!(
            "device_fd: {}\nsegmentation_offload: true\n",
            device.as_raw_fd()
        ));
        let result =
            start_tun_server(config, Arc::new(crate::resolver::NativeResolver::new())).await;
        match result {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput),
            Ok(handle) => {
                handle.abort();
                let _ = handle.await;
                panic!("TUN startup incorrectly succeeded");
            }
        }
        assert!(unsafe { libc::fcntl(device.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn startup_propagates_device_creation_failure() {
        let config = compiled_config(&format!(
            "device_name: {}\nsegmentation_offload: true\n",
            "x".repeat(libc::IFNAMSIZ + 1)
        ));
        let result =
            start_tun_server(config, Arc::new(crate::resolver::NativeResolver::new())).await;
        match result {
            Err(error) => assert!(error.to_string().contains("Failed to create TUN device")),
            Ok(handle) => {
                handle.abort();
                let _ = handle.await;
                panic!("TUN startup incorrectly succeeded");
            }
        }
    }

    #[tokio::test]
    async fn startup_initializes_device_before_returning_and_abort_releases_it() {
        use std::io::Read;
        let (mut peer, device) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let fd = device.into_raw_fd();
        let config = compiled_config(&format!("device_fd: {fd}\n"));
        let handle = start_tun_server(config, Arc::new(crate::resolver::NativeResolver::new()))
            .await
            .unwrap();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn borrowed_tun_fd_remains_open_after_stop() {
        use std::io::Read;
        let (mut peer, client) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let config = TunServerConfig::new()
            .raw_fd(client.as_raw_fd())
            .close_fd_on_drop(false);
        let (tx, rx) = oneshot::channel();
        tx.send(()).unwrap();
        run_tun_server(
            config,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(crate::resolver::NativeResolver::new()),
            rx,
        )
        .await
        .unwrap();
        assert!(unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(client);
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "stack leaked its duplicate descriptor"
        );
    }

    #[tokio::test]
    async fn explicit_offload_rejects_provided_fd_before_taking_ownership() {
        for close in [false, true] {
            let (_peer, client) = std::os::unix::net::UnixDatagram::pair().unwrap();
            let config = TunServerConfig::new()
                .raw_fd(client.as_raw_fd())
                .close_fd_on_drop(close)
                .segmentation_offload(true);
            let (_tx, rx) = oneshot::channel();
            let error = run_tun_server(
                config,
                Arc::new(ClientProxySelector::new(Vec::new())),
                Arc::new(crate::resolver::NativeResolver::new()),
                rx,
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFD) } >= 0);
        }
    }
}
