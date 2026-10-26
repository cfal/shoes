use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::{Engine as _, general_purpose::STANDARD};
use log::debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Builder;

use crate::reality::generate_keypair;
use crate::shadowsocks::ShadowsocksCipher;
use crate::thread_util::set_num_threads;
use crate::{logging, process, uuid_util};

fn print_usage_and_exit(arg0: String) -> ! {
    eprintln!("{arg0} [OPTIONS] <config.yaml> [config.yaml...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -t, --threads NUM    Set the number of worker threads (default: CPU count)");
    eprintln!(
        "    -l, --log-file PATH  Log to file (repeatable; \"-\" means stderr; default: stderr)"
    );
    eprintln!(
        "    -d, --dry-run        Validate config and certificates without starting listeners"
    );
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
    #[cfg(target_os = "linux")]
    eprintln!(
        "    cleanup-tun                                    Recover owned managed-TUN state in this network namespace"
    );
    eprintln!("    SIGHUP reloads configuration even with --no-reload.");
    eprintln!("    SIGINT/SIGTERM stop listeners and exit without waiting for TCP reload drains.");
    eprintln!(
        "    generate-reality-keypair                       Generate a new Reality X25519 keypair"
    );
    eprintln!("    generate-shadowsocks-2022-password <cipher>    Generate a Shadowsocks password");
    eprintln!(
        "    generate-reality-mldsa65-keypair                Generate optional REALITY ML-DSA-65 keys"
    );
    eprintln!(
        "    generate-vless-user-id                         Generate a random VLESS/VMESS user ID (UUID v4)"
    );
    eprintln!(
        "    generate-vless-encryption [options]             Generate matched VLESS encryption credentials"
    );
    eprintln!("      --auth x25519|mlkem768 (repeatable), --mode native|xorpub|random");
    eprintln!("      --rtt 0rtt|1rtt, --lifetime 600s|N-Ms|0s");
    std::process::exit(1);
}

pub fn main() {
    std::process::exit(run());
}

struct FileLogShutdownGuard {
    writers: Vec<Arc<logging::FileLogWriter>>,
}

impl Drop for FileLogShutdownGuard {
    fn drop(&mut self) {
        let deadline = Instant::now() + logging::FILE_LOG_FLUSH_TIMEOUT;
        for writer in &self.writers {
            let _ = writer.shutdown_timeout(deadline.saturating_duration_since(Instant::now()));
        }
    }
}

fn run() -> i32 {
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
        match args.remove(0).as_str() {
            "--threads" | "-t" => {
                if args.is_empty() {
                    eprintln!("Missing threads argument.");
                    print_usage_and_exit(arg0);
                }
                num_threads = match args.remove(0).parse::<usize>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Invalid thread count: {e}");
                        print_usage_and_exit(arg0);
                    }
                };
            }
            "--log-file" | "-l" => {
                if args.is_empty() {
                    eprintln!("Missing log-file argument.");
                    print_usage_and_exit(arg0);
                }
                log_files.push(args.remove(0));
            }
            "--dry-run" | "-d" => dry_run = true,
            "--no-reload" => no_reload = true,
            "--version" | "-V" => {
                println!("shoes {}", env!("CARGO_PKG_VERSION"));
                return 0;
            }
            other => {
                eprintln!("Invalid argument: {other}");
                print_usage_and_exit(arg0);
            }
        }
    }

    let directives = logging::resolve_directives();
    let mut writers: Vec<Box<dyn logging::LogWriter>> = Vec::new();
    let mut file_log_guard = FileLogShutdownGuard {
        writers: Vec::new(),
    };
    writers.push(Box::new(crate::control::logs::Writer));

    if log_files.is_empty() || log_files.iter().any(|p| p == "-") {
        writers.push(Box::new(logging::StderrWriter));
    }
    for path in &log_files {
        if path == "-" {
            continue;
        }
        match logging::FileLogWriter::new(path) {
            Ok(writer) => {
                let writer = Arc::new(writer);
                file_log_guard.writers.push(writer.clone());
                writers.push(Box::new(writer));
            }
            Err(e) => {
                eprintln!("Failed to open log file {path}: {e}");
                return 1;
            }
        }
    }

    if let Err(error) = logging::init_multi_logger(writers, directives) {
        eprintln!("Failed to initialize logger: {error}");
        return 1;
    }

    if args
        .first()
        .is_some_and(|s| s == "generate-vless-encryption")
    {
        match crate::vless::encryption::generator::generate(&args[1..]) {
            Ok((encryption, decryption)) => {
                println!("encryption: {encryption}");
                println!("decryption: {}", *decryption);
            }
            Err(error) => {
                eprintln!("VLESS encryption generation failed: {error}");
                return 1;
            }
        }
        return 0;
    }

    if args.iter().any(|s| s == "generate-reality-mldsa65-keypair") {
        match crate::reality::generate_mldsa65_keypair() {
            Ok((seed, verify)) => {
                println!("mldsa65_seed: {seed}");
                println!("mldsa65_verify: {verify}");
            }
            Err(error) => {
                eprintln!("ML-DSA-65 key generation failed: {error}");
                return 1;
            }
        }
        return 0;
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
        return 0;
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
                        return 1;
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
                        return 1;
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
                return 1;
            }
        }
        return 0;
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
        return 0;
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

    let result = runtime.block_on(async {
        #[cfg(target_os = "linux")]
        if !dry_run && args.len() == 1 && args[0] == "cleanup-tun" {
            return crate::desktop::cleanup().await;
        }
        process::run(args, dry_run, no_reload).await
    });
    let code = match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("shoes: {error}");
            1
        }
    };
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    code
}
