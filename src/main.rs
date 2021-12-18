#![feature(hash_drain_filter)]
#![feature(once_cell)]

mod address;
mod async_stream;
mod async_tls;
mod client_proxy;
mod client_proxy_provider;
mod config;
mod copy_bidirectional;
mod http_handler;
mod line_reader;
mod protocol_handler;
mod resolver;
mod shadowsocks;
mod socks_handler;
mod tcp_server;
mod tls_factory;
mod trojan_handler;
mod udp_server;
mod util;
mod vless_handler;
mod vmess;
mod websocket;

use std::sync::Arc;

use futures::future::try_join_all;
use log::{debug, warn};
use tokio::runtime::Builder;
use tokio::task::JoinHandle;

use crate::async_tls::AsyncTlsFactory;
use crate::config::{ServerConfig, ServerProtocol};
use crate::tcp_server::start_tcp_server;
use crate::tls_factory::get_tls_factory;
use crate::udp_server::start_udp_server;

async fn start_servers(
    config: ServerConfig,
    tls_factory: Arc<dyn AsyncTlsFactory>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    debug!("================================================================================");
    debug!("{:#?}", &config);
    debug!("================================================================================");

    let bind_address = config.bind_address.clone();

    let maybe_tcp_handle = if config.server_protocols.contains(&ServerProtocol::Tcp) {
        start_tcp_server(config.clone(), tls_factory).await?
    } else {
        None
    };

    let maybe_udp_handle = if config.server_protocols.contains(&ServerProtocol::Udp) {
        start_udp_server(config).await?
    } else {
        None
    };

    let mut join_handles = Vec::with_capacity(2);

    match maybe_tcp_handle {
        Some(h) => join_handles.push(h),
        None => {
            warn!("Not starting TCP server on {}.", &bind_address);
        }
    }

    match maybe_udp_handle {
        Some(h) => join_handles.push(h),
        None => {
            warn!("Not starting UDP server on {}.", &bind_address);
        }
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to start both tcp and udp",
        ));
    }

    Ok(join_handles)
}

fn print_usage_and_exit(arg0: String) {
    eprintln!("Usage: {} [--threads/-t N] <server uri or config filename> [server uri or config filename] [..]", arg0);
    std::process::exit(1);
}

fn main() {
    env_logger::init();

    let mut args: Vec<String> = std::env::args().collect();
    let arg0 = args.remove(0);
    let mut num_threads = 0usize;

    while args.len() > 0 && args[0].starts_with("-") {
        if args[0] == "--threads" || args[0] == "-t" {
            args.remove(0);
            if args.len() == 0 {
                eprintln!("Missing threads argument.");
                print_usage_and_exit(arg0);
                return;
            }
            num_threads = match args.remove(0).parse::<usize>() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Invalid thread count: {}", e);
                    print_usage_and_exit(arg0);
                    return;
                }
            };
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(arg0);
            return;
        }
    }

    let configs = match ServerConfig::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load server config: {}\n", e);
            print_usage_and_exit(arg0);
            return;
        }
    };

    if num_threads == 0 {
        num_threads = std::cmp::max(
            2,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        );
        debug!("Runtime threads: {}", num_threads);
    } else {
        println!("Using custom thread count ({})", num_threads);
    }

    let runtime = Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not build tokio runtime");

    let tls_factory: Arc<dyn AsyncTlsFactory> = get_tls_factory();

    runtime.block_on(async move {
        println!("\nStarting {} server(s)..", configs.len());

        // Expect tcp and udp join handles for each.
        let mut join_handles = Vec::with_capacity(configs.len() * 2);
        for config in configs {
            join_handles.append(&mut start_servers(config, tls_factory.clone()).await.unwrap());
        }

        // Die on any server error.
        try_join_all(join_handles).await.unwrap();
    });
}
