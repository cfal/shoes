//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use log::info;
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
pub static SERVICE_LIFECYCLE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Handle to a running TUN service.
pub struct TunServiceHandle {
    /// Tokio runtime running the service.
    pub runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    pub running: Arc<AtomicBool>,
    pub task: JoinHandle<std::io::Result<()>>,
}

struct ServiceRunGuard {
    running: Arc<AtomicBool>,
    #[cfg(unix)]
    protector: Arc<dyn crate::tun::SocketProtector>,
}

impl Drop for ServiceRunGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        #[cfg(unix)]
        crate::tun::clear_global_socket_protector_if_current(&self.protector);
    }
}

pub fn spawn_service(
    runtime: &tokio::runtime::Runtime,
    config: String,
    shutdown: oneshot::Receiver<()>,
    running: Arc<AtomicBool>,
) -> JoinHandle<std::io::Result<()>> {
    let guard = ServiceRunGuard {
        running,
        #[cfg(unix)]
        protector: crate::tun::get_global_socket_protector(),
    };
    runtime.spawn(async move {
        let _guard = guard;
        let result = start_from_config(&config, shutdown).await;
        if let Err(e) = &result {
            log::error!("Shoes service failed: {e}");
        }
        result
    })
}

struct ServerTasks(Vec<JoinHandle<()>>);

impl Drop for ServerTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
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

/// Stop the TUN service and wait for shutdown.
///
/// This is the common shutdown logic used by both iOS and Android.
pub fn stop_service() {
    let _lifecycle = SERVICE_LIFECYCLE.lock();
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

        match handle.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle.task).await
        }) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log::error!("TUN service task failed: {e}"),
            Err(_) => handle.task.abort(),
        }
        handle
            .runtime
            .shutdown_timeout(std::time::Duration::from_secs(5));
        handle.running.store(false, Ordering::SeqCst);
        #[cfg(unix)]
        crate::tun::clear_global_socket_protector();
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
        global_limits,
    } = create_server_configs(configs)?;
    crate::resources::configure(global_limits)?;
    let _resource_reporter = crate::resources::ResourceReporter::start();

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
    let mut join_handles = ServerTasks(Vec::new());

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles
            .0
            .extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // Run TUN server (blocks until shutdown). close_fd_on_drop = false because mobile owns the FD
    #[cfg(unix)]
    let result = {
        let resolver = dns_registry.get_for_server(tun_config.dns.as_ref());
        run_tun_from_config(tun_config, shutdown_rx, false, resolver).await
    };
    #[cfg(not(unix))]
    let result = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TUN is not supported on this platform",
    ));

    // Cleanup any servers when TUN stops
    drop(join_handles);

    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn start_test_service(
        config: String,
        protector: Arc<dyn crate::tun::SocketProtector>,
    ) -> (Arc<AtomicBool>, tokio::task::AbortHandle) {
        let _lifecycle = SERVICE_LIFECYCLE.lock();
        crate::tun::set_global_socket_protector(protector);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let running = Arc::new(AtomicBool::new(true));
        let task = spawn_service(&runtime, config, shutdown_rx, running.clone());
        let abort_handle = task.abort_handle();
        *TUN_SERVICE
            .get_or_init(|| parking_lot::Mutex::new(None))
            .lock() = Some(TunServiceHandle {
            runtime,
            shutdown_tx: Some(shutdown_tx),
            running: running.clone(),
            task,
        });
        (running, abort_handle)
    }

    #[test]
    fn timed_out_service_cannot_clear_replacement_socket_protector() {
        if std::env::var_os("SHOES_FFI_RESTART_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ffi::common::tests::timed_out_service_cannot_clear_replacement_socket_protector",
                    "--nocapture",
                ])
                .env("SHOES_FFI_RESTART_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let (_old_peer, old_fd) = UnixDatagram::pair().unwrap();
        let (_new_peer, new_fd) = UnixDatagram::pair().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = parking_lot::Mutex::new(release_rx);
        let old_protector = Arc::new(crate::tun::FnSocketProtector::new(move |_| {
            entered_tx.send(()).unwrap();
            release_rx
                .lock()
                .recv_timeout(Duration::from_secs(30))
                .unwrap();
            Ok(())
        }));
        let old_config = format!(
            r#"
- device_fd: {}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "127.0.0.1:9"
          transport: quic
          quic_settings:
            verify: false
          protocol:
            type: socks
"#,
            old_fd.as_raw_fd(),
        );
        let (old_running, old_task) = start_test_service(old_config, old_protector);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        stop_service();
        assert!(started.elapsed() >= Duration::from_secs(9));
        assert!(!old_running.load(Ordering::SeqCst));
        assert!(!is_service_running());
        assert_eq!(
            crate::tun::protect_socket(-1).unwrap_err().kind(),
            std::io::ErrorKind::NotConnected,
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let protector = Arc::new(crate::tun::FnSocketProtector::new(move |_| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        let config = format!("- device_fd: {}\n", new_fd.as_raw_fd());
        let (new_running, _) = start_test_service(config, protector);
        crate::tun::protect_socket(-1).unwrap();
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !old_task.is_finished() {
            assert!(
                Instant::now() < deadline,
                "old service did not finish after release"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let protection = crate::tun::protect_socket(-1);
        let replacement_running = is_service_running();
        stop_service();
        assert!(replacement_running);
        assert!(
            protection.is_ok(),
            "old cleanup removed the replacement protector: {protection:?}"
        );
        assert!(calls.load(Ordering::SeqCst) >= 2);
        assert!(!new_running.load(Ordering::SeqCst));
        assert_eq!(
            crate::tun::protect_socket(-1).unwrap_err().kind(),
            std::io::ErrorKind::NotConnected,
        );

        let (failed_running, _) =
            start_test_service("[]".into(), Arc::new(crate::tun::NoOpSocketProtector));
        let handle = TUN_SERVICE.get().unwrap().lock().take().unwrap();
        assert!(handle.runtime.block_on(handle.task).unwrap().is_err());
        assert!(!failed_running.load(Ordering::SeqCst));
        assert_eq!(
            crate::tun::protect_socket(-1).unwrap_err().kind(),
            std::io::ErrorKind::NotConnected,
        );
    }
}
