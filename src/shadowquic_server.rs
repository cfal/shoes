use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use log::{debug, error};
use shadowquic::config::{
    AuthUser, CongestionControl, JlsUpstream, ShadowQuicServerCfg,
    ShadowQuicServerCfg as UpstreamShadowQuicServerCfg,
};
use shadowquic::msgs::socks5::{AddrOrDomain, SocksAddr};
use shadowquic::shadowquic::inbound::ShadowQuicServer;
use shadowquic::{Inbound, ProxyRequest, UdpRecv, UdpSend};
use tokio::io::ReadBuf;
use tokio::sync::mpsc::{Receiver, channel};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ShadowQuicCongestionControl,
    ShadowQuicServerConfig,
};
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_server::process_stream;

fn socks_addr_to_net_location(addr: SocksAddr) -> std::io::Result<NetLocation> {
    let address = match addr.addr {
        AddrOrDomain::V4(octets) => Address::Ipv4(Ipv4Addr::from(octets)),
        AddrOrDomain::V6(octets) => Address::Ipv6(Ipv6Addr::from(octets)),
        AddrOrDomain::Domain(domain) => {
            let domain = String::from_utf8(domain.contents).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid ShadowQUIC domain: {e}"),
                )
            })?;
            Address::Hostname(domain)
        }
    };

    Ok(NetLocation::new(address, addr.port))
}

fn socket_addr_to_socks_addr(addr: &SocketAddr) -> SocksAddr {
    match addr.ip() {
        IpAddr::V4(ip) => SocksAddr {
            addr: AddrOrDomain::V4(ip.octets()),
            port: addr.port(),
        },
        IpAddr::V6(ip) => SocksAddr {
            addr: AddrOrDomain::V6(ip.octets()),
            port: addr.port(),
        },
    }
}

fn convert_congestion_control(
    congestion_control: ShadowQuicCongestionControl,
) -> CongestionControl {
    match congestion_control {
        ShadowQuicCongestionControl::Bbr => CongestionControl::Bbr,
        ShadowQuicCongestionControl::Cubic => CongestionControl::Cubic,
        ShadowQuicCongestionControl::NewReno => CongestionControl::NewReno,
        ShadowQuicCongestionControl::Bbr3 => CongestionControl::Bbr3,
    }
}

fn convert_config(
    bind_addr: SocketAddr,
    config: ShadowQuicServerConfig,
) -> UpstreamShadowQuicServerCfg {
    ShadowQuicServerCfg {
        bind_addr,
        users: config
            .users
            .into_iter()
            .map(|user| AuthUser {
                username: user.username,
                password: user.password,
            })
            .collect(),
        server_name: config.server_name,
        jls_upstream: JlsUpstream {
            addr: config.jls_upstream.addr,
            rate_limit: config.jls_upstream.rate_limit,
        },
        alpn: config.alpn,
        zero_rtt: config.zero_rtt,
        congestion_control: convert_congestion_control(config.congestion_control),
        initial_mtu: config.initial_mtu,
        min_mtu: config.min_mtu,
        gso: config.gso,
        mtu_discovery: config.mtu_discovery,
        blackhole_detection: config.blackhole_detection,
    }
}

struct ShadowQuicUdpStream {
    inbound: Receiver<std::io::Result<(Bytes, NetLocation)>>,
    outbound: UnboundedSender<(Bytes, SocksAddr)>,
    pending_read: Option<(Bytes, NetLocation)>,
}

impl ShadowQuicUdpStream {
    fn new(mut recv: Box<dyn UdpRecv>, send: Arc<dyn UdpSend>) -> Self {
        let (inbound_tx, inbound_rx) = channel(16);
        let (outbound_tx, mut outbound_rx) = unbounded_channel::<(Bytes, SocksAddr)>();

        tokio::spawn(async move {
            loop {
                let result = recv.recv_from().await.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("ShadowQUIC UDP receive failed: {e}"),
                    )
                });

                let result = match result {
                    Ok((bytes, addr)) => match socks_addr_to_net_location(addr) {
                        Ok(target) => Ok((bytes, target)),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                };

                if inbound_tx.send(result).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some((bytes, addr)) = outbound_rx.recv().await {
                if let Err(e) = send.send_to(bytes, addr).await {
                    error!("ShadowQUIC UDP send failed: {e}");
                    break;
                }
            }
        });

        Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
            pending_read: None,
        }
    }
}

impl AsyncReadTargetedMessage for ShadowQuicUdpStream {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        if self.pending_read.is_none() {
            match Pin::new(&mut self.inbound).poll_recv(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    self.pending_read = Some(packet);
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ShadowQUIC UDP receive channel closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let Some((bytes, target)) = self.pending_read.take() else {
            return Poll::Pending;
        };

        if bytes.len() > buf.remaining() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ShadowQUIC UDP packet exceeds receive buffer",
            )));
        }

        buf.put_slice(&bytes);
        Poll::Ready(Ok(target))
    }
}

impl AsyncWriteSourcedMessage for ShadowQuicUdpStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let bytes = Bytes::copy_from_slice(buf);
        let source = socket_addr_to_socks_addr(source);
        self.outbound.send((bytes, source)).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("ShadowQUIC UDP send channel closed: {e}"),
            )
        })?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for ShadowQuicUdpStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for ShadowQuicUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ShadowQuicUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncTargetedMessageStream for ShadowQuicUdpStream {}

struct ShadowQuicTcpStream {
    inner: Box<dyn shadowquic::TcpTrait>,
}

impl ShadowQuicTcpStream {
    fn new(inner: Box<dyn shadowquic::TcpTrait>) -> Self {
        Self { inner }
    }
}

impl tokio::io::AsyncRead for ShadowQuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ShadowQuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for ShadowQuicTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for ShadowQuicTcpStream {}

async fn handle_request(
    request: ProxyRequest,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    match request {
        ProxyRequest::Tcp(tcp_session) => {
            let remote_location = socks_addr_to_net_location(tcp_session.dst)?;
            let server_handler =
                Arc::new(crate::port_forward_handler::PortForwardServerHandler::new(
                    vec![remote_location],
                    proxy_selector,
                ));
            process_stream(
                ShadowQuicTcpStream::new(tcp_session.stream),
                server_handler,
                resolver,
            )
            .await
        }
        ProxyRequest::Udp(udp_session) => {
            let stream = ShadowQuicUdpStream::new(udp_session.recv, udp_session.send);
            run_udp_routing(
                ServerStream::Targeted(Box::new(stream)),
                proxy_selector,
                resolver,
                false,
            )
            .await
        }
    }
}

async fn run_shadowquic_server(
    mut server: ShadowQuicServer,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    server
        .init()
        .await
        .map_err(|e| std::io::Error::other(format!("failed to initialize ShadowQUIC: {e}")))?;

    loop {
        let request = server.accept().await.map_err(|e| {
            std::io::Error::other(format!("failed to accept ShadowQUIC request: {e}"))
        })?;
        let proxy_selector = Arc::clone(&proxy_selector);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, proxy_selector, resolver).await {
                error!("ShadowQUIC request ended with error: {e}");
            }
        });
    }
}

pub async fn start_shadowquic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} server at {}", &protocol, &bind_location);

    let ServerProxyConfig::Shadowquic(shadowquic_config) = protocol else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ShadowQUIC server starter requires ShadowQUIC protocol config",
        ));
    };

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    assert!(!rules.is_empty());

    let bind_addresses = match bind_location {
        BindLocation::Address(a) => a.to_socket_addrs()?,
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "Cannot listen on path, ShadowQUIC does not have unix domain socket support",
            ));
        }
    };

    let proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));
    let mut handles = Vec::with_capacity(bind_addresses.len());

    for bind_address in bind_addresses {
        let upstream_config = convert_config(bind_address, shadowquic_config.clone());
        let server = ShadowQuicServer::new(upstream_config).await.map_err(|e| {
            std::io::Error::other(format!(
                "failed to create ShadowQUIC server at {bind_address}: {e}"
            ))
        })?;
        let proxy_selector = Arc::clone(&proxy_selector);
        let resolver = Arc::clone(&resolver);

        let handle = tokio::spawn(async move {
            if let Err(e) = run_shadowquic_server(server, proxy_selector, resolver).await {
                error!("ShadowQUIC server at {bind_address} stopped with error: {e}");
            }
        });
        handles.push(handle);
    }

    debug!("Started {} ShadowQUIC endpoint(s)", handles.len());
    Ok(handles)
}
