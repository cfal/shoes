//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use log::{error, info, warn};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, convert_cert_paths, create_server_configs, load_config_str};
use crate::dns::build_dns_registry;
use crate::tcp::tcp_server::start_servers;
#[cfg(unix)]
use crate::tun::run_tun_from_config;

/// Global log file handle for file-based logging.
pub static LOG_FILE: OnceLock<parking_lot::Mutex<Option<File>>> = OnceLock::new();

/// Global flag to track if logger has been initialized.
pub static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global state for the TUN service.
pub static TUN_SERVICE: OnceLock<parking_lot::Mutex<Option<TunServiceHandle>>> = OnceLock::new();

/// Global flag to track initialization.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Last error message from the service. Set when `start_from_config` fails
/// or the service stops with an error. Read via `shoes_get_last_error()`.
pub static LAST_ERROR: OnceLock<parking_lot::Mutex<Option<String>>> = OnceLock::new();

/// Handle to a running TUN service.
pub struct TunServiceHandle {
    /// Tokio runtime running the service.
    pub runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    pub running: Arc<AtomicBool>,
}

/// Set up log file for file-based logging.
///
/// Returns 0 on success, -1 on error.
pub fn setup_log_file(path_str: &str) -> i32 {
    let file_mutex = LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

    match OpenOptions::new().create(true).append(true).open(path_str) {
        Ok(file) => {
            *file_mutex.lock() = Some(file);
            info!("Log file set to: {}", path_str);
            0
        }
        Err(_) => -1,
    }
}

/// Write a log message to the log file if configured.
pub fn write_to_log_file(level: log::Level, target: &str, message: &str) {
    if let Some(file_mutex) = LOG_FILE.get() {
        let mut guard = file_mutex.lock();
        if let Some(ref mut writer) = *guard {
            let _ = writeln!(writer, "{} [{}] {}", level, target, message);
        }
    }
}

/// Flush the log file.
pub fn flush_log_file() {
    if let Some(file_mutex) = LOG_FILE.get() {
        let mut guard = file_mutex.lock();
        if let Some(ref mut writer) = *guard {
            let _ = writer.flush();
        }
    }
}

/// How long `stop_service` waits for the service task to finish.
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often it looks while waiting.
const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Stop the TUN service and wait for shutdown.
///
/// This is the common shutdown logic used by both iOS and Android.
///
/// Returns `true` if the service confirmed it stopped, `false` if the wait
/// timed out. The wait is the part that cannot be skipped: it is what
/// guarantees the stack thread has released the TUN descriptor, so the app can
/// close its own copy without racing a thread that is still reading from it.
/// In practice it costs a few milliseconds — the old version polled in 100 ms
/// steps and so paid at least that much every time.
///
/// Dropping the runtime, on the other hand, waits on tasks that no longer hold
/// anything the app needs back, so it happens on a thread of its own and the
/// caller does not pay for it.
pub fn stop_service() -> bool {
    info!("Stopping TUN service");

    let handle = if let Some(service) = TUN_SERVICE.get() {
        service.lock().take()
    } else {
        None
    };

    let Some(mut handle) = handle else {
        info!("TUN service was not running");
        crate::socket_protector::clear_global_socket_protector();
        return true;
    };

    if let Some(tx) = handle.shutdown_tx.take() {
        let _ = tx.send(());
    }

    let started = std::time::Instant::now();
    let mut stopped = false;
    while started.elapsed() < STOP_TIMEOUT {
        if !handle.running.load(Ordering::SeqCst) {
            stopped = true;
            break;
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }

    if stopped {
        info!(
            "TUN service stopped after {}ms",
            started.elapsed().as_millis()
        );
    } else {
        error!(
            "TUN service did not stop within {}s; the TUN descriptor may still be in use",
            STOP_TIMEOUT.as_secs()
        );
    }

    // The protector holds a reference to the platform's VPN service object.
    // Released here rather than in the platform modules so that neither one can
    // forget.
    crate::socket_protector::clear_global_socket_protector();

    // shutdown_timeout, not drop: a task wedged in a blocking call would
    // otherwise keep this thread — the app's main thread, in the sample code
    // both platforms ship — parked indefinitely.
    let runtime = Arc::new(parking_lot::Mutex::new(Some(handle.runtime)));
    let shutdown_runtime = runtime.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("shoes-runtime-shutdown".to_owned())
        .spawn(move || {
            if let Some(runtime) = shutdown_runtime.lock().take() {
                runtime.shutdown_timeout(std::time::Duration::from_secs(5));
                info!("TUN runtime dropped");
            }
        })
    {
        warn!("Could not spawn the runtime shutdown thread ({e}); dropping inline");
        // Falling back to an inline drop is worse than a background one, but it
        // is much better than leaking the runtime and its threads.
        drop(runtime.lock().take());
    }

    info!("TUN service stop completed");
    stopped
}

/// Store an error message.
pub fn set_last_error(error: String) {
    let err = LAST_ERROR.get_or_init(|| parking_lot::Mutex::new(None));
    *err.lock() = Some(error);
}

/// Clear the last error message (called on successful start).
pub fn clear_last_error() {
    if let Some(err) = LAST_ERROR.get() {
        *err.lock() = None;
    }
}

/// Get the last error message, if any.
pub fn get_last_error() -> Option<String> {
    LAST_ERROR.get().and_then(|m| m.lock().clone())
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

/// A config that has been parsed, validated, and had its DNS resolvers built.
///
/// Preparing is separate from running so that the FFI can do it on the calling
/// thread and answer `start` with a real verdict. Everything that a bad config
/// can fail at — YAML syntax, missing `device_fd`, an unusable key, a resolver
/// that will not build — fails here, in front of the caller, instead of inside
/// a spawned task whose error the app only learns about by polling
/// `isRunning()` and finding it already false.
pub struct PreparedService {
    tun_config: crate::config::TunConfig,
    server_configs: Vec<crate::config::ServerConfig>,
    dns_registry: crate::dns::DnsRegistry,
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
    let prepared = prepare_from_config(config_yaml).await?;
    run_prepared(prepared, shutdown_rx).await
}

/// Parse and validate a config, and build its resolvers. See [`PreparedService`].
pub async fn prepare_from_config(config_yaml: &str) -> std::io::Result<PreparedService> {
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
    let dns_registry = build_dns_registry(dns_groups).await?;

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

    Ok(PreparedService {
        tun_config,
        server_configs,
        dns_registry,
    })
}

/// Run a service that [`prepare_from_config`] has already validated.
///
/// Returns when the TUN stops, either because `shutdown_rx` fired or because
/// the stack died.
pub async fn run_prepared(
    prepared: PreparedService,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let PreparedService {
        tun_config,
        server_configs,
        mut dns_registry,
    } = prepared;

    // Start TCP servers (like mixed)
    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles.extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // Run TUN server (blocks until shutdown). close_fd_on_drop = false because mobile owns the FD
    #[cfg(unix)]
    let result = run_tun_from_config(tun_config, shutdown_rx, false).await;
    #[cfg(not(unix))]
    let result = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TUN is not supported on this platform",
    ));

    // Cleanup any servers when TUN stops
    for handle in join_handles {
        handle.abort();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that mutate shared LAST_ERROR state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_set_and_get_last_error() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_last_error();

        assert!(get_last_error().is_none());

        set_last_error("connection refused".to_string());
        assert_eq!(get_last_error().as_deref(), Some("connection refused"));
    }

    #[test]
    fn test_clear_last_error() {
        let _guard = TEST_LOCK.lock().unwrap();

        set_last_error("some error".to_string());
        assert!(get_last_error().is_some());

        clear_last_error();
        assert!(get_last_error().is_none());
    }

    #[test]
    fn test_set_overwrites_previous_error() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_last_error();

        set_last_error("first error".to_string());
        set_last_error("second error".to_string());
        assert_eq!(get_last_error().as_deref(), Some("second error"));
    }
}
