//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use log::{LevelFilter, Log, Metadata, Record, info};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, convert_cert_paths, create_server_configs, load_config_str};
use crate::dns::build_dns_registry;
use crate::tcp::tcp_server::start_servers;
use crate::tun::run_tun_from_config;

/// Global log file handle for file-based logging.
pub static LOG_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// Global flag to track if logger has been initialized.
pub static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global state for the TUN service.
pub static TUN_SERVICE: OnceLock<parking_lot::Mutex<Option<TunServiceHandle>>> = OnceLock::new();

/// Global flag to track initialization.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Handle to a running TUN service.
pub struct TunServiceHandle {
    /// Tokio runtime running the service.
    pub runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    pub running: Arc<AtomicBool>,
}

/// Parse log level string to LevelFilter.
pub fn parse_log_level(level_str: &str) -> LevelFilter {
    match level_str.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

/// Set up log file for file-based logging.
///
/// Returns 0 on success, -1 on error.
pub fn setup_log_file(path_str: &str) -> i32 {
    let file_mutex = LOG_FILE.get_or_init(|| Mutex::new(None));

    match OpenOptions::new().create(true).append(true).open(path_str) {
        Ok(file) => {
            let result = if let Ok(mut guard) = file_mutex.lock() {
                *guard = Some(file);
                true
            } else {
                false
            };
            if result {
                info!("Log file set to: {}", path_str);
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Write a log message to the log file if configured.
pub fn write_to_log_file(level: log::Level, target: &str, message: &str) {
    if let Some(file_mutex) = LOG_FILE.get() {
        if let Ok(mut guard) = file_mutex.lock() {
            if let Some(ref mut file) = *guard {
                let _ = writeln!(file, "{} [{}] {}", level, target, message);
                let _ = file.flush();
            }
        }
    }
}

/// Flush the log file.
pub fn flush_log_file() {
    if let Some(file_mutex) = LOG_FILE.get() {
        if let Ok(mut guard) = file_mutex.lock() {
            if let Some(ref mut file) = *guard {
                let _ = file.flush();
            }
        }
    }
}

/// Base logger that handles file logging.
/// Platform-specific loggers can wrap this and add their own output.
pub struct FileLogger {
    level: LevelFilter,
}

impl FileLogger {
    pub fn new(level: LevelFilter) -> Self {
        Self { level }
    }
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            write_to_log_file(
                record.level(),
                record.target(),
                &format!("{}", record.args()),
            );
        }
    }

    fn flush(&self) {
        flush_log_file();
    }
}

/// Stop the TUN service and wait for shutdown.
///
/// This is the common shutdown logic used by both iOS and Android.
pub fn stop_service() {
    info!("Stopping TUN service");

    let handle = if let Some(service) = TUN_SERVICE.get() {
        service.lock().take()
    } else {
        None
    };

    if let Some(mut handle) = handle {
        if let Some(tx) = handle.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait up to 5 seconds for service to stop
        let running = handle.running.clone();
        for i in 0..50 {
            if !running.load(Ordering::SeqCst) {
                info!("TUN service stopped after {}ms", i * 100);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        drop(handle.runtime);
        info!("TUN runtime dropped");
    }

    info!("TUN service stop completed");
}

/// Check if the TUN service is running.
pub fn is_service_running() -> bool {
    if let Some(service) = TUN_SERVICE.get() {
        let guard = service.lock();
        if let Some(ref handle) = *guard {
            return handle.running.load(Ordering::SeqCst);
        }
    }
    false
}

/// Start the service from a config YAML string.
///
/// This parses the config YAML and starts both TUN and any Server configs
/// (like mixed HTTP+SOCKS5 servers) that are defined in the config.
/// The config YAML must already have device_fd set in the TUN config.
pub async fn start_from_config(
    config_yaml: &str,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    info!("Parsing config for TUN server");

    let configs: Vec<Config> = load_config_str(config_yaml)?;

    let (configs, pem_count) = convert_cert_paths(configs).await?;
    if pem_count > 0 {
        info!("Loaded {} PEM files", pem_count);
    }

    let crate::config::ValidatedConfigs {
        configs: validated_configs,
        dns_groups,
    } = create_server_configs(configs)?;

    // Build DNS registry from expanded groups
    let mut dns_registry = build_dns_registry(dns_groups).await?;

    // Separate TUN config from server configs, validate exactly one TUN with device_fd
    let mut tun_config = None;
    let mut server_configs = Vec::new();

    for config in validated_configs {
        match config {
            Config::TunServer(tc) => {
                if tun_config.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Multiple TUN configs found - only one is allowed for mobile",
                    ));
                }
                if tc.device_fd.is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TUN config missing device_fd - must be injected by caller",
                    ));
                }
                info!(
                    "TUN config: fd={}, mtu={}, tcp={}, udp={}, icmp={}",
                    tc.device_fd.unwrap(),
                    tc.mtu,
                    tc.tcp_enabled,
                    tc.udp_enabled,
                    tc.icmp_enabled
                );
                tun_config = Some(tc);
            }
            Config::Server(sc) => {
                server_configs.push(sc);
            }
            _ => {}
        }
    }

    let tun_config = tun_config.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "No TUN config found")
    })?;

    // Start TCP servers (like mixed)
    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles.extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // Run TUN server (blocks until shutdown). close_fd_on_drop = false because mobile owns the FD
    let result = run_tun_from_config(tun_config, shutdown_rx, false).await;

    // Cleanup any servers when TUN stops
    for handle in join_handles {
        handle.abort();
    }

    result
}
