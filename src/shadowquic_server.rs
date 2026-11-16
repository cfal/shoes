//! ShadowQuic/JLS transport adapter; forwarding stays in shoes' shared ingress and UDP relay.
use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::{
        BindLocation, ResolvedServerConfig, ResolvedServerProxyConfig,
        server::ShadowQuicServerConfig,
    },
    resolver::Resolver,
    routing::udp_relay::UdpRelay,
};
use bytes::Bytes;
use quinn_jls as quic;
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

// Match the official ShadowQuic transport defaults (400 Mbit/s BDP at 100 ms).
const SHADOWQUIC_STREAM_WINDOW: u64 = 5_000_000;
const SHADOWQUIC_SEND_WINDOW: u64 = 40_000_000;
const SHADOWQUIC_DATAGRAM_WINDOW: usize = 10_000_000;
const SHADOWQUIC_MAX_STREAMS: u32 = 1_000;

type Contexts = Arc<parking_lot::Mutex<ContextStore>>;
#[derive(Default)]
struct ContextStore {
    bound: HashMap<u16, (Arc<UdpRelay>, NetLocation)>,
    pending: HashMap<u16, (std::time::Instant, Vec<Bytes>)>,
    pending_bytes: usize,
    outgoing: std::collections::HashSet<u16>,
}
impl ContextStore {
    fn expire(&mut self) {
        self.pending.retain(|_, (time, packets)| {
            if time.elapsed() < Duration::from_secs(10) {
                true
            } else {
                self.pending_bytes -= packets.iter().map(Bytes::len).sum::<usize>();
                false
            }
        });
    }
}

pub(crate) fn validate(config: &ShadowQuicServerConfig) -> io::Result<()> {
    let mut names = std::collections::HashSet::new();
    if config.users.is_empty() || config.server_name.is_empty() || config.jls_upstream.is_empty() {
        return Err(io::Error::other(
            "ShadowQuic requires users, server_name and jls_upstream",
        ));
    }
    for user in &config.users {
        if user.username.is_empty() || user.password.is_empty() || !names.insert(&user.username) {
            return Err(io::Error::other(
                "ShadowQuic users require unique nonempty usernames and nonempty passwords",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn start(
    config: ResolvedServerConfig,
    resolver: Arc<dyn Resolver>,
) -> io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ResolvedServerProxyConfig::Shadowquic(options) = config.protocol else {
        unreachable!()
    };
    validate(&options)?;
    let selector = Arc::new(
        crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector(
            config.rules.into_vec(),
            resolver.clone(),
        )?
        .with_sniff(config.sniff),
    );
    let BindLocation::Address(addresses) = config.bind_location else {
        return Err(io::Error::other("ShadowQuic requires an IP listener"));
    };
    let server = server_config(&options)?;
    let mut handles = Vec::new();
    // Bind every socket before spawning so a partial bind failure cannot leak listeners.
    let mut endpoints = Vec::new();
    for address in addresses.into_vec() {
        for address in address.to_socket_addrs()? {
            let socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                address.is_ipv6(),
                None,
                Some(address),
                false,
                Some(crate::resources::limits().quic_socket_buffer),
            )?;
            let endpoint = listener::bind(server.clone(), socket.into())?;
            endpoints.push(endpoint);
        }
    }
    for endpoint in endpoints {
        let selector = selector.clone();
        let resolver = resolver.clone();
        let udp_enabled = options.udp_enabled;
        handles.push(tokio::spawn(async move {
            let mut tasks = crate::listener_tasks::ListenerTasks::immediate();
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.endpoint.accept() => incoming,
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                let Some(incoming) = incoming else { break };
                let Some(permit) =
                    crate::resources::try_connection(Some(incoming.remote_address().ip()))
                else {
                    incoming.refuse();
                    continue;
                };
                // Reserve for the protocol's send/stream windows and both datagram queues.
                let bytes = SHADOWQUIC_SEND_WINDOW as usize
                    + SHADOWQUIC_STREAM_WINDOW as usize
                    + 2 * SHADOWQUIC_DATAGRAM_WINDOW;
                let Some(memory) = crate::resources::try_quic_memory(bytes) else {
                    incoming.refuse();
                    continue;
                };
                let Ok(connecting) = incoming.accept() else {
                    continue;
                };
                let selector = selector.clone();
                let resolver = resolver.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _memory = memory;
                    let result = async {
                        // Complete JLS authentication before dispatching even resumed streams.
                        let connection =
                            tokio::time::timeout(Duration::from_secs(10), connecting).await??;
                        if connection.jls_chosen_user().is_none() {
                            connection.close(263u32.into(), b"authentication failed");
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "JLS authentication failed",
                            ));
                        }
                        run_connection(connection, selector, resolver, udp_enabled).await
                    }
                    .await;
                    if let Err(error) = result {
                        log::debug!("ShadowQuic connection ended: {error}");
                    }
                });
            }
        }));
    }
    Ok(handles)
}

fn server_config(config: &ShadowQuicServerConfig) -> io::Result<quic::ServerConfig> {
    use quic::rustls::{self, pki_types::PrivatePkcs8KeyDer};
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .map_err(io::Error::other)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = if config.zero_rtt { u32::MAX } else { 0 };
    tls.send_half_rtt_data = config.zero_rtt;
    let mut jls = rustls::jls::JlsServerConfig::default();
    for user in &config.users {
        jls = jls.add_user(user.password.clone(), user.username.clone());
    }
    tls.jls_config = jls
        .with_server_name(config.server_name.clone())
        .with_upstream_addr(config.jls_upstream.clone())
        .with_rate_limit(u64::MAX)
        .enable(true)
        .into();
    let crypto = quic::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server = quic::ServerConfig::with_crypto(Arc::new(crypto));
    let limits = crate::resources::limits();
    let max_streams = limits
        .max_streams_per_connection
        .unwrap_or(SHADOWQUIC_MAX_STREAMS as usize)
        .min(u32::MAX as usize) as u32;
    let mut mtu_discovery = quic::MtuDiscoveryConfig::default();
    mtu_discovery
        .black_hole_cooldown(Duration::from_secs(120))
        .interval(Duration::from_secs(90))
        .blackhole_reset_mtu(false)
        .black_hole_threshold(15);
    let mut transport = quic::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(max_streams.into())
        .max_concurrent_uni_streams(max_streams.into())
        .send_window(SHADOWQUIC_SEND_WINDOW)
        .stream_receive_window((SHADOWQUIC_STREAM_WINDOW as u32).into())
        // Leave the connection receive window at the upstream transport default.
        .datagram_receive_buffer_size(Some(SHADOWQUIC_DATAGRAM_WINDOW))
        .datagram_send_buffer_size(SHADOWQUIC_DATAGRAM_WINDOW)
        .initial_mtu(1_300)
        .min_mtu(1_290)
        .mtu_discovery_config(Some(mtu_discovery))
        .enable_segmentation_offload(true)
        .congestion_controller_factory(Arc::new(quic::congestion::BbrConfig::default()));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

async fn run_connection(
    connection: quic::Connection,
    selector: Arc<crate::client_proxy_selector::ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp: bool,
) -> io::Result<()> {
    let limits = crate::resources::limits();
    let contexts: Contexts = Default::default();
    let mut tasks = tokio::task::JoinSet::new();
    let mut cleanup = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            bi = connection.accept_bi() => {
                let (send, recv) = bi.map_err(io::Error::other)?;
                if limits.max_streams_per_connection.is_some_and(|n| tasks.len() >= n) { continue; }
                let Some(permit) = crate::resources::try_stream() else { continue };
                let (connection, selector, resolver, contexts) = (connection.clone(), selector.clone(), resolver.clone(), contexts.clone());
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_bi(connection, send, recv, selector, resolver, contexts, udp).await { log::debug!("ShadowQuic stream ended: {e}"); }
                });
            }
            uni = connection.accept_uni(), if udp => {
                let mut recv = uni.map_err(io::Error::other)?;
                if tasks.len() >= limits.max_streams_per_connection.unwrap_or(SHADOWQUIC_MAX_STREAMS as usize) { continue; }
                let Some(permit) = crate::resources::try_stream() else { continue };
                let contexts = contexts.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = async {
                        let id = recv.read_u16().await?;
                        loop {
                            let len = recv.read_u16().await? as usize;
                            let mut data = vec![0; len];
                            AsyncReadExt::read_exact(&mut recv, &mut data).await?;
                            deliver(&contexts, id, data.into());
                        }
                        #[allow(unreachable_code)] Ok::<(), io::Error>(())
                    }.await;
                });
            }
            packet = connection.read_datagram(), if udp => {
                let packet = packet.map_err(io::Error::other)?;
                if packet.len() >= 2 { deliver(&contexts, u16::from_be_bytes([packet[0],packet[1]]), packet.slice(2..)); }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            _ = cleanup.tick() => contexts.lock().expire(),
        }
    }
}
fn deliver(contexts: &Contexts, id: u16, data: Bytes) {
    let mut store = contexts.lock();
    if let Some((relay, dst)) = store.bound.get(&id).cloned() {
        drop(store);
        let _ = relay.send_to(data, dst);
    } else {
        store.expire();
        if store.pending_bytes + data.len() > 1024 * 1024 || store.pending.len() >= 4096 {
            return;
        }
        let entry = store
            .pending
            .entry(id)
            .or_insert_with(|| (std::time::Instant::now(), Vec::new()));
        if entry.1.len() >= 4 {
            return;
        }
        entry.1.push(data.clone());
        store.pending_bytes += data.len();
    }
}

async fn handle_bi(
    connection: quic::Connection,
    mut send: quic::SendStream,
    mut recv: quic::RecvStream,
    selector: Arc<crate::client_proxy_selector::ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    contexts: Contexts,
    udp: bool,
) -> io::Result<()> {
    let (cmd, dst) = tokio::time::timeout(Duration::from_secs(10), async {
        let cmd = recv.read_u8().await?;
        if cmd == 0xff {
            return Ok((cmd, None));
        }
        let dst = crate::socks_handler::read_location_direct(&mut recv).await?;
        Ok::<_, io::Error>((cmd, Some(dst)))
    })
    .await??;
    match cmd {
        1 => {
            let mut stream = Stream {
                send,
                recv,
                peer: connection.remote_address(),
            };
            let target = crate::tcp::ingress::PreparedTcp::new(&selector, dst.unwrap(), vec![])?
                .with_source(Some(stream.peer));
            let routed = crate::util::timeout_stream_setup(async {
                target
                    .route(&mut stream, &selector, &resolver)
                    .await?
                    .connect(&resolver)
                    .await
            })
            .await?;
            if let Some(mut setup) = routed.setup {
                setup.client_stream.write_all(&routed.prefix).await?;
                if let Some(data) = setup.early_data {
                    stream.write_all(&data).await?;
                }
                crate::copy_bidirectional::copy_bidirectional(
                    &mut stream,
                    &mut *setup.client_stream,
                    false,
                    true,
                )
                .await?;
            }
        }
        3 | 4 if udp => {
            let relay = Arc::new(UdpRelay::new(
                selector,
                resolver,
                Some(connection.remote_address()),
            )?);
            let mut session = Association {
                contexts: contexts.clone(),
                ids: Vec::new(),
            };
            let control = async {
                loop {
                    let dst = crate::socks_handler::read_location_direct(&mut recv).await?;
                    let id = recv.read_u16().await?;
                    let mut contexts = contexts.lock();
                    if contexts.bound.len() >= 4096 || contexts.bound.contains_key(&id) {
                        return Err(io::Error::other("ShadowQuic context limit or duplicate ID"));
                    }
                    contexts.bound.insert(id, (relay.clone(), dst.clone()));
                    if let Some((_, packets)) = contexts.pending.remove(&id) {
                        for packet in packets {
                            contexts.pending_bytes -= packet.len();
                            relay.send_to(packet, dst.clone())?;
                        }
                    }
                    session.ids.push(id);
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            let replies = async {
                let mut outgoing = Outgoing {
                    contexts: contexts.clone(),
                    ids: Vec::new(),
                };
                let mut destinations =
                    HashMap::<NetLocation, (u16, Option<quic::SendStream>)>::new();
                loop {
                    let (data, source) = relay.recv().await?;
                    if !destinations.contains_key(&source) {
                        let id = {
                            let mut store = contexts.lock();
                            if store.outgoing.len() >= 4096 {
                                return Err(io::Error::other("ShadowQuic outgoing context limit"));
                            }
                            let id = (0..=u16::MAX)
                                .find(|id| !store.outgoing.contains(id))
                                .unwrap();
                            store.outgoing.insert(id);
                            outgoing.ids.push(id);
                            id
                        };
                        send.write_all(&crate::socks_handler::write_location_to_vec(&source)?)
                            .await?;
                        send.write_u16(id).await?;
                        let uni = if cmd == 4 {
                            let mut stream =
                                connection.open_uni().await.map_err(io::Error::other)?;
                            stream.write_u16(id).await?;
                            Some(stream)
                        } else {
                            None
                        };
                        destinations.insert(source.clone(), (id, uni));
                    }
                    let (id, uni) = destinations.get_mut(&source).unwrap();
                    if let Some(uni) = uni {
                        uni.write_u16(u16::try_from(data.len()).map_err(io::Error::other)?)
                            .await?;
                        uni.write_all(&data).await?;
                    } else {
                        let mut packet = Vec::with_capacity(data.len() + 2);
                        packet.extend_from_slice(&id.to_be_bytes());
                        packet.extend_from_slice(&data);
                        match connection.send_datagram_wait(packet.into()).await {
                            Ok(()) | Err(quic::SendDatagramError::TooLarge) => {}
                            Err(e) => return Err(io::Error::other(e)),
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            tokio::select! { result = control => result?, result = replies => result? }
        }
        0xff => {
            // Extensions use u64 opcode; unsupported operations return Result::Err(NotAvailable).
            let (opcode, sub) = tokio::time::timeout(Duration::from_secs(10), async {
                Ok::<_, io::Error>((recv.read_u64().await?, recv.read_u8().await?))
            })
            .await??;
            if opcode == 1 && sub == 0 {
                let stats = connection.stats();
                send.write_u8(0).await?;
                send.write_u32(26).await?;
                send.write_u64(stats.path.lost_packets).await?;
                send.write_u64(stats.path.sent_packets).await?;
                send.write_f64(connection.rtt().as_secs_f64() * 1000.0)
                    .await?;
                send.write_u16(stats.path.current_mtu).await?;
            } else {
                let denied = opcode == 2
                    && !connection
                        .jls_chosen_user()
                        .is_some_and(|name| name.starts_with("admin"));
                send.write_all(&[1, u8::from(denied)]).await?;
            }
            send.shutdown().await?;
        }
        _ => return Err(io::Error::other("unsupported ShadowQuic command")),
    }
    Ok(())
}
struct Association {
    contexts: Contexts,
    ids: Vec<u16>,
}
impl Drop for Association {
    fn drop(&mut self) {
        let mut contexts = self.contexts.lock();
        for id in &self.ids {
            contexts.bound.remove(id);
        }
    }
}

struct Outgoing {
    contexts: Contexts,
    ids: Vec<u16>,
}
impl Drop for Outgoing {
    fn drop(&mut self) {
        let mut store = self.contexts.lock();
        for id in &self.ids {
            store.outgoing.remove(id);
        }
    }
}

struct Stream {
    send: quic::SendStream,
    recv: quic::RecvStream,
    peer: std::net::SocketAddr,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Stream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.peer)
    }
}

#[cfg(test)]
mod tests;

mod listener;
