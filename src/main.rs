mod address;
mod async_stream;
mod buf_reader;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod copy_multidirectional_message;
mod copy_session_messages;
mod crypto;
mod http_handler;
mod hysteria2_server;
mod noop_stream;
mod option_util;
mod port_forward_handler;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod resolver;
mod rustls_config_util;
mod rustls_connection_util;
mod rustls_handshake;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
mod socket_util;
mod socks_handler;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
mod udp_message_stream;
mod udp_multi_message_stream;
mod udp_session_message_stream;
mod uot;
mod util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::io::Write;
use std::path::Path;

use log::debug;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tcp_server::start_tcp_servers;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

use crate::config::{ServerConfig, Transport};
use crate::quic_server::start_quic_servers;
use crate::reality::generate_keypair;
use crate::shadowsocks::ShadowsocksCipher;
use crate::thread_util::set_num_threads;
use tcp::*;

#[derive(Debug)]
struct ConfigChanged;

fn start_notify_thread(
    config_paths: Vec<String>,
) -> (RecommendedWatcher, UnboundedReceiver<ConfigChanged>) {
    let (tx, rx) = unbounded_channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            if matches!(event.kind, EventKind::Modify(..)) {
                tx.send(ConfigChanged {}).unwrap();
            }
        }
        Err(e) => println!("watch error: {e:?}"),
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
        Transport::Tcp => match start_tcp_servers(config.clone()).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_servers(config.clone()).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
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
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            &config.bind_location
        )));
    }

    Ok(join_handles)
}

fn print_usage_and_exit(arg0: String) {
    eprintln!("Usage: {arg0} [--threads/-t N] [--dry-run/-d] [--no-reload] <server uri or config filename> [server uri or config filename] [..]");
    std::process::exit(1);
}

fn main() {
    env_logger::builder()
        .format(|buf, record| {
            let timestamp = buf.timestamp();
            let level_style = buf.default_level_style(record.level());
            let sanitized_args = format!("{}", record.args())
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect::<String>();

            writeln!(
                buf,
                "[{} {level_style}{}{level_style:#} {}] {}",
                timestamp,
                record.level(),
                record.target(),
                sanitized_args
            )
        })
        .init();

    let mut args: Vec<String> = std::env::args().collect();
    let arg0 = args.remove(0);
    let mut num_threads = 0usize;
    let mut dry_run = false;
    let mut no_reload = false;

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
                    eprintln!("Invalid thread count: {e}");
                    print_usage_and_exit(arg0);
                    return;
                }
            };
        } else if args[0] == "--dry-run" || args[0] == "-d" {
            args.remove(0);
            dry_run = true;
        } else if args[0] == "--no-reload" {
            args.remove(0);
            no_reload = true;
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(arg0);
            return;
        }
    }

    if args.iter().any(|s| s == "generate-reality-keypair") {
        let (private_key, public_key) = generate_keypair().unwrap();
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("REALITY private key: {}", private_key);
        println!("REALITY public key: {}", public_key);
        println!(
            "--------------------------------------------------------------------------------"
        );
        return;
    }

    if let Some(pos) = args
        .iter()
        .position(|s| s == "generate-shadowsocks-password")
    {
        let cipher = args.get(pos + 1).map(|s| s.as_str());
        match cipher {
            Some(c) => {
                // Strip 2022-blake3- prefix if present for cipher lookup
                let base_cipher = c.strip_prefix("2022-blake3-").unwrap_or(c);
                match ShadowsocksCipher::try_from(base_cipher) {
                    Ok(cipher) => {
                        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
                        use base64::engine::{general_purpose::STANDARD, Engine as _};

                        let rng = SystemRandom::new();
                        let mut key_bytes = vec![0u8; cipher.key_len()];
                        rng.fill(&mut key_bytes).expect("RNG failed");
                        let password = STANDARD.encode(&key_bytes);
                        println!(
                            "--------------------------------------------------------------------------------"
                        );
                        println!("Cipher: {}", c);
                        println!("Password: {}", password);
                        println!(
                            "--------------------------------------------------------------------------------"
                        );
                    }
                    Err(_) => {
                        eprintln!("Unknown cipher: {}", c);
                        eprintln!("Supported ciphers:");
                        eprintln!("  aes-128-gcm");
                        eprintln!("  aes-256-gcm");
                        eprintln!("  chacha20-ietf-poly1305");
                        eprintln!("  2022-blake3-aes-128-gcm");
                        eprintln!("  2022-blake3-aes-256-gcm");
                        eprintln!("  2022-blake3-chacha20-poly1305");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!("Usage: {} generate-shadowsocks-password <cipher>", arg0);
                eprintln!("Supported ciphers:");
                eprintln!("  aes-128-gcm");
                eprintln!("  aes-256-gcm");
                eprintln!("  chacha20-ietf-poly1305");
                eprintln!("  2022-blake3-aes-128-gcm");
                eprintln!("  2022-blake3-aes-256-gcm");
                eprintln!("  2022-blake3-chacha20-poly1305");
                std::process::exit(1);
            }
        }
        return;
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
        debug!("Runtime threads: {num_threads}");
    } else {
        println!("Using custom thread count ({num_threads})");
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
        let mut reload_state = if no_reload {
            None
        } else {
            let (watcher, rx) = start_notify_thread(args.clone());
            Some((watcher, rx))
        };

        loop {
            let configs = match config::load_configs(&args).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load server configs: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            let (configs, load_file_count) = match config::convert_cert_paths(configs).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load cert files: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            if load_file_count > 0 {
                    println!("Loaded {load_file_count} certs/keys from files");
            }

            for config in configs.iter() {
                debug!("================================================================================");
                debug!("{config:#?}");
            }
            debug!("================================================================================");

            if dry_run {
                if let Err(e) = config::create_server_configs(configs).await {
                    eprintln!("Dry run failed, could not create server configs: {e}\n");
                } else {
                    println!("Finishing dry run, config parsed successfully.");
                }
                return;
            }

            let mut join_handles = vec![];

            let server_configs = match config::create_server_configs(configs).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to create server configs: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            println!("\nStarting {} server(s)..", server_configs.len());

            for server_config in server_configs {
                join_handles.extend(start_servers(server_config).await.unwrap());
            }

            match reload_state.as_mut() {
                Some((_watcher, rx)) => {
                    // Wait for config change
                    rx.recv().await.unwrap();

                    println!("Configs changed, restarting servers in 3 seconds..");

                    for join_handle in join_handles {
                        join_handle.abort();
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                    // Remove any extra events
                    while rx.try_recv().is_ok() {}
                }
                None => {
                    // No reload mode - wait forever
                    // TODO: signal handling?
                    futures::future::pending::<()>().await;
                    unreachable!();
                }
            }
        }
    });
}
