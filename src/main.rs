mod address;
mod anytls;
mod async_stream;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod dns;
mod h2mux;
mod http_handler;
mod hysteria2_client;
mod hysteria2_server;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod resolver;
mod routing;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_client;
mod tuic_server;
#[cfg(unix)]
mod tun;
mod udp_hop_socket;
mod udp_message_stream;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;
mod logging;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Spawn a background task that dumps jemalloc memory stats on SIGUSR1.
/// Usage: `kill -USR1 <pid>` to trigger a heap profile dump.
#[cfg(all(unix, not(any(target_env = "msvc", target_os = "ios"))))]
fn spawn_memory_profiler() {
    tokio::spawn(async move {
        let mut sigusr1 = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::user_defined1(),
        )
        .expect("Failed to register SIGUSR1 handler");

        let mut dump_count = 0u32;
        loop {
            sigusr1.recv().await;
            dump_count += 1;

            // Advance jemalloc epoch to get fresh stats
            tikv_jemalloc_ctl::epoch::advance().unwrap();

            let allocated = tikv_jemalloc_ctl::stats::allocated::read().unwrap();
            let active = tikv_jemalloc_ctl::stats::active::read().unwrap();
            let resident = tikv_jemalloc_ctl::stats::resident::read().unwrap();
            let mapped = tikv_jemalloc_ctl::stats::mapped::read().unwrap();
            let retained = tikv_jemalloc_ctl::stats::retained::read().unwrap();

            eprintln!("======== jemalloc memory stats (dump #{}) ========", dump_count);
            eprintln!("  allocated: {:>10.2} MB  (app is using this)", allocated as f64 / 1_048_576.0);
            eprintln!("  active:    {:>10.2} MB  (pages with live data)", active as f64 / 1_048_576.0);
            eprintln!("  resident:  {:>10.2} MB  (RSS, mapped + in RAM)", resident as f64 / 1_048_576.0);
            eprintln!("  mapped:    {:>10.2} MB  (total mmap'd)", mapped as f64 / 1_048_576.0);
            eprintln!("  retained:  {:>10.2} MB  (freed but not returned to OS)", retained as f64 / 1_048_576.0);

            // Try to dump heap profile (requires _RJEM_MALLOC_CONF=prof:true)
            let filename = format!("shoes_heap.{}.heap", dump_count);
            let c_filename = std::ffi::CString::new(filename.clone()).unwrap();
            let c_filename_ptr = c_filename.as_ptr();
            let result = unsafe {
                tikv_jemalloc_ctl::raw::write(
                    b"prof.dump\0",
                    c_filename_ptr,
                )
            };
            match result {
                Ok(_) => eprintln!("  heap profile dumped to: {}", filename),
                Err(e) => eprintln!("  heap profile dump failed (run with _RJEM_MALLOC_CONF=prof:true): {}", e),
            }
            eprintln!("==================================================");
        }
    });
}

#[cfg(not(all(unix, not(any(target_env = "msvc", target_os = "ios")))))]
fn spawn_memory_profiler() {
    // No-op on unsupported platforms
}

use std::path::Path;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::{Engine as _, general_purpose::STANDARD};
use log::debug;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tcp_server::start_servers;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

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

fn print_usage_and_exit(arg0: String) {
    eprintln!("{arg0} [OPTIONS] <config.yaml> [config.yaml...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -t, --threads NUM    Set the number of worker threads (default: CPU count)");
    eprintln!("    -l, --log-file PATH  Log to file (repeatable; \"-\" means stderr; default: stderr)");
    eprintln!("    -d, --dry-run        Parse the config and exit");
    eprintln!("    --no-reload          Disable automatic config reloading on file changes");
    eprintln!("    -V, --version        Print version information and exit");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!(
        "    generate-reality-keypair                       Generate a new Reality X25519 keypair"
    );
    eprintln!("    generate-shadowsocks-2022-password <cipher>    Generate a Shadowsocks password");
    eprintln!(
        "    generate-vless-user-id                         Generate a random VLESS/VMESS user ID (UUID v4)"
    );
    std::process::exit(1);
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let arg0 = args.remove(0);
    let mut num_threads = 0usize;
    let mut dry_run = false;
    let mut no_reload = false;
    let mut log_files: Vec<String> = Vec::new();

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
        } else if args[0] == "--log-file" || args[0] == "-l" {
            args.remove(0);
            if args.is_empty() {
                eprintln!("Missing log-file argument.");
                print_usage_and_exit(arg0);
                return;
            }
            log_files.push(args.remove(0));
        } else if args[0] == "--dry-run" || args[0] == "-d" {
            args.remove(0);
            dry_run = true;
        } else if args[0] == "--no-reload" {
            args.remove(0);
            no_reload = true;
        } else if args[0] == "--version" || args[0] == "-V" {
            println!("shoes {}", env!("CARGO_PKG_VERSION"));
            return;
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(arg0);
            return;
        }
    }

    let directives = logging::resolve_directives();
    let mut writers: Vec<Box<dyn logging::LogWriter>> = Vec::new();

    if log_files.is_empty() || log_files.iter().any(|p| p == "-") {
        writers.push(Box::new(logging::StderrWriter));
    }
    for path in &log_files {
        if path == "-" {
            continue;
        }
        match logging::FileLogWriter::new(path) {
            Ok(w) => writers.push(Box::new(w)),
            Err(e) => {
                eprintln!("Failed to open log file {path}: {e}");
                std::process::exit(1);
            }
        }
    }

    logging::init_multi_logger(writers, directives);

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
        .position(|s| s == "generate-shadowsocks-2022-password")
    {
        let cipher = args.get(pos + 1).map(|s| s.as_str());
        match cipher {
            Some(c) => {
                // Strip 2022-blake3- prefix if present for cipher lookup
                let base_cipher = match c.strip_prefix("2022-blake3-") {
                    Some(b) => b,
                    None => {
                        eprintln!(
                            "Password generation is only necessary for shadowsocks 2022 ciphers."
                        );
                        std::process::exit(1);
                    }
                };
                match ShadowsocksCipher::try_from(base_cipher) {
                    Ok(cipher) => {
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
                        eprintln!("Supported shadowsocks 2022 ciphers:");
                        eprintln!("  2022-blake3-aes-128-gcm");
                        eprintln!("  2022-blake3-aes-256-gcm");
                        eprintln!("  2022-blake3-chacha20-poly1305");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!(
                    "Usage: {} generate-shadowsocks-2022-password <cipher>",
                    arg0
                );
                eprintln!("Supported shadowsocks 2022 ciphers:");
                eprintln!("  2022-blake3-aes-128-gcm");
                eprintln!("  2022-blake3-aes-256-gcm");
                eprintln!("  2022-blake3-chacha20-poly1305");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.iter().any(|s| s == "generate-vless-user-id") {
        let uuid = uuid_util::generate_uuid();
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("VLESS/VMESS User ID: {}", uuid);
        println!(
            "--------------------------------------------------------------------------------"
        );
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
                if let Err(e) = config::create_server_configs(configs) {
                    eprintln!("Dry run failed, could not create server configs: {e}\n");
                } else {
                    println!("Finishing dry run, config parsed successfully.");
                }
                return;
            }

            let mut join_handles = vec![];

            let server_configs = match config::create_server_configs(configs) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to create server configs: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            let config::ValidatedConfigs {
                configs: server_configs,
                dns_groups,
            } = server_configs;

            // Build DNS registry from expanded groups (async - resolves hostnames)
            let mut dns_registry = match dns::build_dns_registry(dns_groups).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to build DNS registry: {e}\n");
                    print_usage_and_exit(arg0);
                    return;
                }
            };

            println!("\nStarting {} server(s)..", server_configs.len());

            // Start memory profiler (dump stats with: kill -USR1 <pid>)
            spawn_memory_profiler();

            for server_config in server_configs {
                // Get the resolver for this server from the registry
                let dns_ref = match &server_config {
                    config::Config::Server(s) => s.dns.as_ref(),
                    config::Config::TunServer(t) => t.dns.as_ref(),
                    _ => None,
                };
                let resolver = dns_registry.get_for_server(dns_ref);
                join_handles.extend(start_servers(server_config, resolver).await.unwrap());
            }

            match reload_state.as_mut() {
                Some((_watcher, rx)) => {
                    #[cfg(unix)]
                    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                    #[cfg(not(unix))]
                    let mut sigterm = futures::future::pending::<()>();

                    tokio::select! {
                        _ = rx.recv() => {
                            println!("Configs changed, restarting servers in 3 seconds..");

                            for join_handle in join_handles {
                                join_handle.abort();
                            }

                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                            // Remove any extra events
                            while rx.try_recv().is_ok() {}
                        }
                        _ = tokio::signal::ctrl_c() => {
                            println!("Received Ctrl-C, shutting down gracefully...");
                            break;
                        }
                        _ = async {
                            #[cfg(unix)]
                            sigterm.recv().await;
                            #[cfg(not(unix))]
                            sigterm.await;
                        } => {
                            println!("Received SIGTERM, shutting down gracefully...");
                            break;
                        }
                    }
                }
                None => {
                    #[cfg(unix)]
                    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                    #[cfg(not(unix))]
                    let mut sigterm = futures::future::pending::<()>();

                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            println!("Received Ctrl-C, shutting down gracefully...");
                            break;
                        }
                        _ = async {
                            #[cfg(unix)]
                            sigterm.recv().await;
                            #[cfg(not(unix))]
                            sigterm.await;
                        } => {
                            println!("Received SIGTERM, shutting down gracefully...");
                            break;
                        }
                    }
                }
            }
        }
    });
}
