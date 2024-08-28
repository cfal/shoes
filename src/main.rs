mod address;
mod async_stream;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod copy_multidirectional_message;
mod http_handler;
mod line_reader;
mod option_util;
mod port_forward_handler;
mod quic_server;
mod quic_stream;
mod resolver;
mod rustls_util;
mod salt_checker;
mod shadowsocks;
mod snell;
mod socket_util;
mod socks_handler;
mod tcp;
mod thread_util;
mod timed_salt_checker;
mod tls_handler;
mod trojan_handler;
mod udp_direct_message_stream;
mod util;
mod vless_handler;
mod vmess;
mod websocket;

use std::path::Path;

use log::debug;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tcp_server::start_tcp_server;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

use crate::config::{ServerConfig, Transport};
use crate::quic_server::start_quic_server;
use crate::thread_util::set_num_threads;
use tcp::*;

#[derive(Debug)]
struct ConfigChanged;

fn start_notify_thread(
    config_paths: Vec<String>,
) -> (RecommendedWatcher, UnboundedReceiver<ConfigChanged>) {
    let (tx, rx) = unbounded_channel();

    let mut watcher = notify::recommended_watcher(move |res| match res {
        Ok(_) => {
            tx.send(ConfigChanged {}).unwrap();
        }
        Err(e) => println!("watch error: {:?}", e),
    })
    .unwrap();

    for config_path in config_paths {
        watcher
            .watch(Path::new(&config_path), RecursiveMode::NonRecursive)
            .unwrap();
    }

    (watcher, rx)
}

async fn start_servers(config: ServerConfig) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => match start_tcp_server(config.clone()).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_server(config.clone()).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Udp => todo!(),
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to start servers at {}", &config.bind_location),
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
    let mut dry_run = false;

    while !args.is_empty() && args[0].starts_with("-") {
        if args[0] == "--threads" || args[0] == "-t" {
            args.remove(0);
            if args.is_empty() {
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
        } else if args[0] == "--dry-run" || args[0] == "-d" {
            args.remove(0);
            dry_run = true;
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(arg0);
            return;
        }
    }

    if args.is_empty() {
        println!("No config specified, assuming loading from file config.shoes.yaml");
        args.push("config.shoes.yaml".to_string())
    }

    if dry_run {
        println!("Starting dry run.");
    }

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

    // Used by QUIC to figure out the number of endpoints.
    // TODO: can we pass it in instead?
    set_num_threads(num_threads);

    let mut builder = if num_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        mt.worker_threads(num_threads);
        mt
    };

    let runtime = builder
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not build tokio runtime");

    runtime.block_on(async move {
        let (_watcher, mut config_rx) = start_notify_thread(args.clone());

        loop {
            let configs = match config::load_configs(&args).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load server configs: {}\n", e);
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            for config in configs.iter() {
                debug!("================================================================================");
                debug!("{:#?}", config);
            }
            debug!("================================================================================");

            if dry_run {
                println!("Finishing dry run, config parsed successfully.");
                return;
            }

            println!("\nStarting {} server(s)..", configs.len());

            // Expect tcp and udp join handles for each.
            let mut join_handles = Vec::with_capacity(configs.len() * 2);
            for config in configs {
                join_handles.append(&mut start_servers(config).await.unwrap());
            }

            config_rx.recv().await.unwrap();

            println!("Configs changed, restarting servers in 3 seconds..");

            for join_handle in join_handles {
                join_handle.abort();
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Remove any extra events
            while config_rx.try_recv().is_ok() {}
        }
    });
}
