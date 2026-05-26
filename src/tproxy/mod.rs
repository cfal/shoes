//! Linux transparent proxy (TPROXY) inbound.
//!
//! Accepts TCP and UDP traffic redirected via `iptables -j TPROXY` / `nftables`
//! and `ip rule`. The original destination is recovered from the kernel
//! (TCP: `getsockname` on the IP_TRANSPARENT-bound listener; UDP:
//! `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` ancillary data).
//!
//! Linux-only.

pub mod cmsg;
pub mod listener;
pub mod udp_relay;

use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, error, info};
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, TcpConfig};
use crate::resolver::Resolver;
use crate::socket_util::set_tcp_keepalive;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerSetupResult;
use crate::tcp::tcp_server::process_setup_result;

pub async fn start_tproxy_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let (tcp_enabled, udp_enabled) = match &config.protocol {
        ServerProxyConfig::Tproxy { tcp_enabled, udp_enabled } => (*tcp_enabled, *udp_enabled),
        other => {
            return Err(std::io::Error::other(format!(
                "start_tproxy_servers called with non-tproxy protocol: {other}"
            )));
        }
    };

    let bind_addrs = match &config.bind_location {
        BindLocation::Address(range) => range.to_socket_addrs()?,
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "tproxy cannot use unix socket bind (should have been rejected during validation)",
            ));
        }
    };

    let rules = config
        .rules
        .clone()
        .map(ConfigSelection::unwrap_config)
        .into_vec();
    assert!(!rules.is_empty(), "rules must contain at least the default direct allow");

    let proxy_selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
    let tcp_cfg = config.tcp_settings.clone().unwrap_or_default();

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for bind in bind_addrs {
        if tcp_enabled {
            let resolver = resolver.clone();
            let proxy_selector = proxy_selector.clone();
            let tcp_cfg = tcp_cfg.clone();
            info!("tproxy TCP listening on {bind}");
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_tproxy_tcp_server(bind, tcp_cfg, resolver, proxy_selector).await {
                    error!("tproxy TCP server on {bind} exited: {e}");
                }
            }));
        }
        if udp_enabled {
            let resolver = resolver.clone();
            let proxy_selector = proxy_selector.clone();
            info!("tproxy UDP listening on {bind}");
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_tproxy_udp_server(bind, resolver, proxy_selector).await {
                    error!("tproxy UDP server on {bind} exited: {e}");
                }
            }));
        }
    }

    Ok(handles)
}

async fn run_tproxy_tcp_server(
    bind: SocketAddr,
    tcp_cfg: TcpConfig,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<()> {
    let listener = listener::new_tproxy_tcp_listener(bind)?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("tproxy accept on {bind}: {e}");
                continue;
            }
        };
        let orig_dst = match stream.local_addr() {
            Ok(a) => a,
            Err(e) => {
                error!("tproxy local_addr on accepted {peer}: {e}");
                continue;
            }
        };
        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("tproxy keepalive: {e}");
        }
        if tcp_cfg.no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("tproxy nodelay: {e}");
        }
        let resolver = resolver.clone();
        let proxy_selector = proxy_selector.clone();
        tokio::spawn(async move {
            let setup = TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::from_socket_addr(orig_dst),
                stream: Box::new(stream),
                need_initial_flush: true,
                connection_success_response: None,
                initial_remote_data: None,
                proxy_selector,
            };
            if let Err(e) = process_setup_result(setup, resolver).await {
                debug!("tproxy {peer} -> {orig_dst}: {e}");
            }
        });
    }
}

async fn run_tproxy_udp_server(
    bind: SocketAddr,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<()> {
    let socket = listener::new_tproxy_udp_socket(bind)?;
    let relay = udp_relay::UdpRelay::new(socket, proxy_selector, resolver);
    relay.run().await
}
