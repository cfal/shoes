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
//! using `select()` for efficient event-driven I/O.
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

mod tcp_conn;
mod tcp_stack_direct;
pub mod traffic;
mod tun_server;
mod udp_handler;
mod udp_manager;

pub use tun_server::TunServerConfig;

use std::os::unix::io::IntoRawFd;
use std::sync::Arc;

use log::{debug, info, warn};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::selection::ConfigSelection;
use crate::config::{FakeIpConfig, TunConfig};
use crate::dns::fake_ip::{self, BypassList, FakeIpNetwork, FakeIpPool, FakeIpResponder};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

use tcp_stack_direct::{NewTcpConnection, TcpStackDirect, TcpStackOptions};
use udp_manager::TunUdpManager;

type PacketBuffer = Vec<u8>;

/// Run the TUN server with the given configuration.
///
/// This function:
/// 1. Creates/wraps a TUN device
/// 2. Sets up our smoltcp-based TCP/IP stack with direct fd access
/// 3. The stack thread reads packets directly from TUN using select()
/// 4. Handles TCP connections through the proxy chain
/// 5. Handles UDP packets through tokio (forwarded from stack thread)
pub async fn run_tun_server(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    fake_ip: Option<Arc<FakeIpResponder>>,
    sniff: Option<crate::sniff::SniffSettings>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    info!(
        "Starting TUN server (direct mode): mtu={}, tcp={}, udp={}, icmp={}",
        config.mtu, config.tcp_enabled, config.udp_enabled, config.icmp_enabled
    );

    let fd = if let Some(fd) = config.raw_fd {
        info!("Using provided raw FD: {}", fd);
        fd
    } else {
        let tun_device = config.create_sync_device()?;
        let fd = tun_device.into_raw_fd();
        info!("Created TUN device with FD: {}", fd);
        fd
    };

    let mtu = config.mtu as usize;

    // A buffer smaller than two MTUs cannot hold a single segment plus what
    // arrives behind it, which stalls the connection rather than slowing it.
    let tcp_buffer_size = config.tcp_buffer_size.max(mtu * 2);
    if tcp_buffer_size != config.tcp_buffer_size {
        warn!(
            "tcp_buffer_size {} is below two MTUs, raising it to {}",
            config.tcp_buffer_size, tcp_buffer_size
        );
    }

    info!(
        "TCP stack: buffer={} B/direction, max_connections={} (worst case {} MiB)",
        tcp_buffer_size,
        config.max_connections,
        (tcp_buffer_size * 4 * config.max_connections) / (1024 * 1024)
    );

    // Create the direct TCP stack (runs smoltcp in dedicated thread with select())
    let mut tcp_stack = TcpStackDirect::new(
        fd,
        TcpStackOptions {
            mtu,
            tcp_buffer_size,
            max_connections: config.max_connections,
            // Only meaningful on the raw-fd path: when the device was created
            // here, the `tun` crate owns the descriptor instead.
            close_fd_on_drop: config.close_fd_on_drop,
        },
    );

    // Get UDP receiver (stack thread filters UDP and sends here)
    let udp_from_stack_rx = tcp_stack.take_udp_rx().expect("udp_rx already taken");

    // Channel for sending UDP responses back (stack thread will write to TUN)
    let (udp_to_stack_tx, udp_to_stack_rx) = mpsc::unbounded_channel::<PacketBuffer>();
    tcp_stack.set_udp_response_tx(udp_to_stack_rx);

    let (tcp_conn_tx, mut tcp_conn_rx) = mpsc::unbounded_channel::<NewTcpConnection>();
    tcp_stack.set_new_conn_tx(tcp_conn_tx);

    let tcp_task: Option<JoinHandle<()>> = if config.tcp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let fake_ip_pool = fake_ip.as_ref().map(|responder| responder.pool().clone());

        Some(tokio::spawn(async move {
            info!("Starting TCP connection handler");

            while let Some(new_conn) = tcp_conn_rx.recv().await {
                let proxy_selector = proxy_selector.clone();
                let resolver = resolver.clone();
                let fake_ip_pool = fake_ip_pool.clone();
                let sniff = sniff.clone();

                tokio::spawn(async move {
                    let remote_addr = new_conn.remote_addr;
                    // Restore before routing, so hostname rules see the domain.
                    let target =
                        fake_ip::destination_to_net_location(remote_addr, fake_ip_pool.as_ref());

                    debug!("Handling TCP connection to {:?}", target);

                    if let Err(e) = handle_tcp_connection(
                        new_conn.connection,
                        target,
                        proxy_selector,
                        resolver,
                        sniff.as_ref(),
                    )
                    .await
                    {
                        debug!("TCP connection to {} failed: {}", remote_addr, e);
                    }
                });
            }

            debug!("TCP connection handler ended");
        }))
    } else {
        None
    };

    let udp_task = if config.udp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();

        Some(tokio::spawn(async move {
            handle_udp_packets(
                udp_from_stack_rx,
                udp_to_stack_tx,
                proxy_selector,
                resolver,
                fake_ip,
            )
            .await;
        }))
    } else {
        None
    };

    info!("TUN server started successfully");

    // Periodic traffic stats reporting (every 1 second)
    let traffic_task = tokio::spawn(async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            traffic::report_traffic();
        }
    });

    // Wait for shutdown signal or stack thread exit
    let stack_died = tokio::select! {
        _ = &mut shutdown_rx => {
            info!("TUN server shutdown requested");
            false
        }
        _ = async {
            // Poll until stack stops running
            while tcp_stack.is_running() {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        } => {
            warn!("Stack thread ended unexpectedly");
            true
        }
    };

    traffic_task.abort();

    if let Some(t) = tcp_task {
        t.abort();
    }
    if let Some(t) = udp_task {
        t.abort();
    }

    // tcp_stack is dropped here, which stops the stack thread
    drop(tcp_stack);

    // The read path's buffer pool is process-global, and on mobile the process
    // outlives the tunnel by hours. Nothing reads from it once the stack thread
    // is gone, so hand the memory back.
    tcp_stack_direct::clear_buffer_pool();

    // Freeing the connection buffers does not shrink the process; the allocator
    // keeps the pages. On a phone that leaves an idle tunnel sitting at the
    // high-water mark of the busiest thing the user did with it.
    crate::memory::release_to_os();

    info!("TUN server stopped");

    // An error, not a clean stop: the stack thread only exits on its own when
    // the descriptor died under it. Reporting Ok here left the mobile FFI
    // logging "service stopped normally" and leaving getLastError() empty for
    // what is, from the app's side, the tunnel silently going away.
    if stack_died {
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "TUN stack thread stopped; the device descriptor is no longer usable",
        ));
    }

    Ok(())
}

/// Convert a SocketAddr to a NetLocation.
/// Handle a TCP connection by forwarding it through the proxy chain.
async fn handle_tcp_connection<S>(
    connection: S,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    sniff: Option<&crate::sniff::SniffSettings>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut connection = connection;
    let mut sniffed_prefix: Vec<u8> = Vec::new();
    let mut judged: crate::address::ResolvedLocation = target.clone().into();

    // No reordering is needed here, unlike the inbound path: the TCP handshake
    // completed locally in smoltcp, so the application has already sent its
    // first bytes and there is nothing to write first.
    if let Some(settings) = sniff
        && let Some(addr) = crate::sniff::sniff_target(&target)
    {
        let result = crate::sniff::peek::peek_stream(
            &mut connection,
            &[],
            &settings.protocols,
            settings.timeout,
            crate::sniff::peek::DEFAULT_MAX_BYTES,
        )
        .await;
        sniffed_prefix = result.buffered;
        if let Some(name) = result.sniffed.as_ref().and_then(|s| s.domain.as_deref()) {
            debug!("sniffed {name} for {target}");
            judged = crate::sniff::judged_location(name, addr);
        }
    }

    let decision = proxy_selector.judge(judged, &resolver).await?;

    match decision {
        crate::client_proxy_selector::ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            debug!(
                "TCP: connecting to {} via chain",
                remote_location.location()
            );

            match chain_group
                .connect_tcp(remote_location.clone(), &resolver)
                .await
            {
                Ok(setup_result) => {
                    debug!(
                        "TCP: connected to {}, starting bidirectional copy",
                        remote_location.location()
                    );

                    let crate::tcp::tcp_handler::TcpClientSetupResult {
                        client_stream: mut remote,
                        early_data,
                    } = setup_result;

                    // Wrap the local connection with traffic counting so bytes
                    // are reported in real time, not only after the stream closes.
                    let mut counting = traffic::TrafficCountingStream::new(connection);

                    // The final hop can hand back payload it read while still
                    // completing its own handshake. Dropping it loses the first
                    // bytes the server said, which the inbound path has always
                    // forwarded (src/tcp/tcp_server.rs).
                    if let Some(data) = early_data {
                        use tokio::io::AsyncWriteExt;
                        counting.write_all(&data).await?;
                    }

                    // Whatever sniffing read has to reach the remote before
                    // anything else, in the order the client sent it.
                    if !sniffed_prefix.is_empty() {
                        use tokio::io::AsyncWriteExt;
                        remote.write_all(&sniffed_prefix).await?;
                        remote.flush().await?;
                    }

                    let result = tokio::io::copy_bidirectional(&mut counting, &mut remote).await;

                    match result {
                        Ok((client_to_remote, remote_to_client)) => {
                            debug!(
                                "TCP connection to {} completed: {} bytes sent, {} bytes received",
                                remote_location.location(),
                                client_to_remote,
                                remote_to_client
                            );
                        }
                        Err(e) => {
                            debug!(
                                "TCP connection to {} error: {}",
                                remote_location.location(),
                                e
                            );
                        }
                    }

                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", remote_location.location(), e);
                    Err(e)
                }
            }
        }
        crate::client_proxy_selector::ConnectDecision::Block => {
            debug!("TCP connection blocked by rules");
            Ok(())
        }
    }
}

/// Handle UDP packets from the stack thread.
///
/// Uses the session-based TunUdpManager which:
/// - Keys sessions by local (app) address, not by destination
/// - Stores the return address in each session
/// - Routes responses using the stored address (no NAT table lookup)
async fn handle_udp_packets(
    from_stack_rx: mpsc::UnboundedReceiver<PacketBuffer>,
    to_stack_tx: mpsc::UnboundedSender<PacketBuffer>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    fake_ip: Option<Arc<FakeIpResponder>>,
) {
    info!("Starting UDP handler (session-based)");

    let udp_handler = udp_handler::UdpHandler::new(from_stack_rx, to_stack_tx);
    let (reader, writer) = udp_handler.split();

    let manager = TunUdpManager::new(reader, writer, proxy_selector, resolver, fake_ip);

    if let Err(e) = manager.run().await {
        warn!("UDP handler error: {}", e);
    }

    info!("UDP handler stopped");
}

/// Start TUN server based on the provided configuration.
pub async fn start_tun_server(
    config: TunConfig,
    _resolver: std::sync::Arc<dyn crate::resolver::Resolver>,
) -> std::io::Result<JoinHandle<()>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let _keep_alive = shutdown_tx;
        if let Err(e) = run_tun_from_config(config, shutdown_rx, true).await {
            warn!("TUN server error: {}", e);
        }
    });

    Ok(handle)
}

/// Build the Fake IP responder for one TUN session.
///
/// Errors here are config errors and are reported as such; `validate` already
/// rejects the same inputs, so reaching an error at this point means the config
/// was not validated.
fn build_fake_ip_responder(config: &FakeIpConfig) -> std::io::Result<Arc<FakeIpResponder>> {
    let network = FakeIpNetwork::parse(&config.network)?;
    let pool = Arc::new(FakeIpPool::new(network, config.max_entries)?);
    let bypass = BypassList::new(config.bypass_domains.iter());

    info!(
        "Fake IP enabled: network={}, capacity={}, bypass_patterns={}",
        network,
        pool.capacity(),
        config.bypass_domains.len()
    );

    Ok(Arc::new(FakeIpResponder::new(pool, bypass)))
}

/// Run TUN server from config with external shutdown control.
pub async fn run_tun_from_config(
    config: TunConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
) -> std::io::Result<()> {
    let mut tun_server_config = TunServerConfig::new()
        .mtu(config.mtu)
        .tcp_enabled(config.tcp_enabled)
        .udp_enabled(config.udp_enabled)
        .icmp_enabled(config.icmp_enabled)
        .close_fd_on_drop(close_fd_on_drop);

    if let Some(size) = config.tcp_buffer_size {
        tun_server_config = tun_server_config.tcp_buffer_size(size);
    }
    if let Some(max) = config.max_connections {
        tun_server_config = tun_server_config.max_connections(max);
    }

    if let Some(ref name) = config.device_name {
        tun_server_config = tun_server_config.tun_name(name.clone());
        info!("Starting TUN server on device {}", name);
    }
    if let Some(fd) = config.device_fd {
        tun_server_config = tun_server_config.raw_fd(fd);
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            tun_server_config = tun_server_config.packet_information(true);
        }
        info!("Starting TUN server from device FD {}", fd);
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

    // Built here rather than in run_tun_server so it lives exactly as long as
    // one TUN session. A process-lifetime singleton would carry one VPN
    // session's mappings into the next, which on mobile means a restart could
    // resolve a stale address to the wrong domain.
    let fake_ip_responder = config
        .fake_ip
        .as_ref()
        .map(build_fake_ip_responder)
        .transpose()?;

    // Resolved once per TUN session rather than per connection.
    let sniff = config.sniff.as_ref().and_then(|s| s.to_settings());

    let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));

    run_tun_server(
        tun_server_config,
        client_proxy_selector,
        resolver,
        fake_ip_responder,
        sniff,
        shutdown_rx,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;

    use crate::address::{Address, NetLocation, NetLocationMask};
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::config::{
        ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection,
    };
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::chain_builder::build_client_chain_group;

    use super::*;

    /// A local stream that reports EOF on read and records everything written.
    /// Stands in for the smoltcp-backed TUN connection.
    struct RecordingStream {
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(())) // EOF
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A SOCKS5 server that answers the handshake and then sends the success
    /// reply and some payload in a single write, which is what makes the
    /// client handler report early data.
    async fn spawn_socks_server_with_early_data(payload: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Greeting: version, method count, methods.
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // Request: VER CMD RSV ATYP, then an IPv4 address and port.
            let mut req = [0u8; 4];
            stream.read_exact(&mut req).await.unwrap();
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.unwrap();

            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            reply.extend_from_slice(payload);
            stream.write_all(&reply).await.unwrap();
            stream.flush().await.unwrap();

            // Hold the connection open long enough for the copy to drain.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        addr
    }

    fn selector_through_socks(
        socks_addr: SocketAddr,
        resolver: Arc<dyn Resolver>,
    ) -> Arc<ClientProxySelector> {
        let client_config = ClientConfig {
            address: NetLocation::from_ip_addr(socks_addr.ip(), socks_addr.port()),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let chain = ClientChain {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                client_config,
            ))),
        };
        let group = build_client_chain_group(NoneOrSome::One(chain), resolver);
        let rule = ConnectRule::new(
            vec![NetLocationMask::ANY],
            vec![],
            ConnectAction::new_allow(None, group),
        );
        Arc::new(ClientProxySelector::new(vec![rule]))
    }

    #[tokio::test]
    async fn tun_forwards_early_data_to_the_local_connection() {
        let socks_addr = spawn_socks_server_with_early_data(b"EARLY").await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = selector_through_socks(socks_addr, resolver.clone());

        let written = Arc::new(Mutex::new(Vec::new()));
        let local = RecordingStream {
            written: written.clone(),
        };

        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        handle_tcp_connection(local, target, selector, resolver, None)
            .await
            .unwrap();

        assert_eq!(
            written.lock().unwrap().as_slice(),
            b"EARLY",
            "early data from the final hop must reach the local connection"
        );
    }

    /// A local stream that offers a ClientHello once and then reports EOF,
    /// which is what an application looks like right after the smoltcp
    /// handshake.
    struct HelloThenEof {
        hello: Option<Vec<u8>>,
    }

    impl AsyncRead for HelloThenEof {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(hello) = self.hello.take() {
                buf.put_slice(&hello);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for HelloThenEof {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A SOCKS5 server that records the target address the client asked for,
    /// and everything sent after the reply, then closes.
    async fn spawn_socks_server_recording(
        target_seen: Arc<Mutex<Vec<u8>>>,
        payload_seen: Arc<Mutex<Vec<u8>>>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            // VER CMD RSV ATYP
            let mut req = [0u8; 4];
            stream.read_exact(&mut req).await.unwrap();
            let address = match req[3] {
                0x01 => {
                    let mut v4 = [0u8; 4];
                    stream.read_exact(&mut v4).await.unwrap();
                    v4.to_vec()
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut name = vec![0u8; len[0] as usize];
                    stream.read_exact(&mut name).await.unwrap();
                    name
                }
                other => panic!("unexpected address type {other}"),
            };
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            *target_seen.lock().unwrap() = address;

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.flush().await.unwrap();

            let mut payload = Vec::new();
            let _ = stream.read_to_end(&mut payload).await;
            *payload_seen.lock().unwrap() = payload;
        });

        addr
    }

    #[tokio::test]
    async fn tun_sniffs_the_sni_and_sends_the_name_upstream() {
        let target_seen = Arc::new(Mutex::new(Vec::new()));
        let payload_seen = Arc::new(Mutex::new(Vec::new()));
        let socks_addr =
            spawn_socks_server_recording(target_seen.clone(), payload_seen.clone()).await;

        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = selector_through_socks(socks_addr, resolver.clone());

        let hello = crate::sniff::test_client_hello("ex.com");
        let local = HelloThenEof {
            hello: Some(hello.clone()),
        };

        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let settings = crate::sniff::SniffSettings {
            protocols: vec![crate::sniff::SniffedProtocol::Tls],
            timeout: std::time::Duration::from_millis(300),
        };

        handle_tcp_connection(local, target, selector, resolver, Some(&settings))
            .await
            .unwrap();

        assert_eq!(
            target_seen.lock().unwrap().as_slice(),
            b"ex.com",
            "the sniffed name should be the address sent to the proxy"
        );
        assert_eq!(
            payload_seen.lock().unwrap().as_slice(),
            hello.as_slice(),
            "the bytes read while sniffing must reach the remote unchanged"
        );
    }
}
