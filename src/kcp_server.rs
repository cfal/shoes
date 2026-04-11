use std::net::SocketAddr;
use std::sync::Arc;

use kcp_tokio::{KcpConfig, KcpListener};
use log::{debug, error};
use tokio::task::JoinHandle;

use crate::config::{BindLocation, ConfigSelection, KcpMode, KcpSettings, ServerConfig};
use crate::kcp_stream::KcpStreamWrapper;
use crate::resolver::Resolver;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server::process_stream;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

/// Convert `KcpSettings` from YAML config into a `kcp_tokio::KcpConfig`.
pub fn build_kcp_config(settings: Option<&KcpSettings>) -> KcpConfig {
    let mode = settings
        .map(|s| s.mode.clone())
        .unwrap_or(KcpMode::Normal);

    let mut cfg = match mode {
        KcpMode::Normal => KcpConfig::new(),
        KcpMode::Fast => KcpConfig::new().fast_mode(),
        KcpMode::Turbo => KcpConfig::new().turbo_mode(),
        KcpMode::Gaming => KcpConfig::gaming(),
        KcpMode::FileTransfer => KcpConfig::file_transfer(),
    };

    // Stream mode delivers data as a continuous byte stream without message boundaries.
    // FileTransfer already enables it via KcpConfig::file_transfer().
    // For other modes we leave it at the kcp-tokio default (false = message mode).
    // In message mode KCP delivers data only when a complete segment is received,
    // which is fine for proxy operation since TLS records are self-framed.

    if let Some(s) = settings {
        if let (Some(snd), Some(rcv)) = (s.send_window, s.recv_window) {
            cfg = cfg.window_size(snd, rcv);
        }
        if let Some(mtu) = s.mtu {
            cfg = cfg.mtu(mtu as u32);
        }
    }

    cfg
}

async fn run_kcp_server(
    bind_address: SocketAddr,
    kcp_config: KcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let mut listener = KcpListener::bind(bind_address, kcp_config)
        .await
        .map_err(|e| std::io::Error::other(format!("KCP bind failed: {e}")))?;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("KCP accept failed: {e}");
                continue;
            }
        };

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            let wrapped = KcpStreamWrapper::new(stream);
            if let Err(e) = process_stream(wrapped, cloned_handler, cloned_resolver).await {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

pub async fn start_kcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        kcp_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} KCP server at {}", &protocol, &bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    assert!(!rules.is_empty());

    let bind_addresses = match bind_location {
        BindLocation::Address(a) => a.to_socket_addrs()?,
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "Cannot listen on path: KCP does not support Unix domain sockets",
            ));
        }
    };

    let kcp_config = build_kcp_config(kcp_settings.as_ref());

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

    let bind_ip = bind_addresses.first().map(|addr| addr.ip());
    let tcp_handler: Arc<dyn TcpServerHandler> =
        create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, bind_ip).into();

    let mut handles = vec![];

    for bind_address in bind_addresses {
        let kcp_config = kcp_config.clone();
        let resolver = resolver.clone();
        let tcp_handler = tcp_handler.clone();

        let join_handle = tokio::spawn(async move {
            if let Err(e) = run_kcp_server(bind_address, kcp_config, resolver, tcp_handler).await {
                error!("KCP server at {bind_address} failed: {e}");
            }
        });
        handles.push(join_handle);
    }

    Ok(handles)
}
