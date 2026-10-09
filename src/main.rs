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
mod hysteria2_server;
mod listener_tasks;
mod logging;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod prepend_stream;
mod process;
mod quic_endpoint;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod resolver;
mod resources;
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
#[cfg(target_os = "linux")]
mod splice;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
#[cfg(unix)]
mod tun;
mod udp_fragments;
mod udp_message_stream;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::{Engine as _, general_purpose::STANDARD};
use log::debug;
use tokio::runtime::Builder;

use crate::reality::generate_keypair;
use crate::shadowsocks::ShadowsocksCipher;
use crate::thread_util::set_num_threads;

fn print_usage_and_exit(arg0: String) {
    eprintln!("{arg0} [OPTIONS] <config.yaml> [config.yaml...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -t, --threads NUM    Set the number of worker threads (default: CPU count)");
    eprintln!(
        "    -l, --log-file PATH  Log to file (repeatable; \"-\" means stderr; default: stderr)"
    );
    eprintln!("    -d, --dry-run        Parse the config and exit");
    eprintln!("    --no-reload          Disable automatic config reloading on file changes");
    eprintln!(
        "    global_limits.reload_grace_secs sets the TCP reload drain deadline (default: 300)"
    );
    eprintln!("    QUIC connections disconnect immediately on reload.");
    eprintln!("    -V, --version        Print version information and exit");
    eprintln!();
    eprintln!("RESOURCE LIMITS:");
    eprintln!("    Optional YAML entry: - global_limits: {{ max_connections: 1024 }}");
    eprintln!(
        "    Admission is unlimited unless configured. Only one global_limits entry is allowed."
    );
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("    check <config.yaml>                            Validate configuration and exit");
    eprintln!("    version                                        Print version information");
    eprintln!("    SIGHUP reloads configuration even with --no-reload.");
    eprintln!("    SIGINT/SIGTERM stop listeners and exit without waiting for TCP reload drains.");
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
    if args.first().is_some_and(|arg| arg == "check") {
        args[0] = "--dry-run".into();
    } else if args.first().is_some_and(|arg| arg == "version") {
        args[0] = "--version".into();
    }
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

    let code = match runtime.block_on(process::run(args, dry_run, no_reload)) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("shoes: {error}");
            1
        }
    };
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    log::logger().flush();
    std::process::exit(code);
}
