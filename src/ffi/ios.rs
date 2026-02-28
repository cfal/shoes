//! iOS FFI bindings for shoes.
//!
//! This module provides C-compatible functions that can be called from Swift
//! via the iOS Network Extension (PacketTunnelProvider).
//!
//! # Usage from Swift
//!
//! ```swift
//! // Initialize logging
//! shoes_init("info")
//!
//! // Set log file (optional, for debugging)
//! shoes_set_log_file("/path/to/log.txt")
//!
//! // Start VPN with config YAML and packet tunnel fd
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```

use std::ffi::{CStr, c_char, c_int, c_long};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use log::{error, info};
use parking_lot::Mutex;
use std::sync::OnceLock;
use tokio::sync::oneshot;

use crate::logging::{DynamicFileLogWriter, LogWriter};

use super::common::{
    self, INITIALIZED, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, TunServiceHandle, setup_log_file,
};

/// Socket protector callback type.
/// Called from Rust to protect sockets from VPN routing.
/// The callback receives a file descriptor and should return true if protected successfully.
pub type ProtectSocketCallback = extern "C" fn(fd: c_int) -> bool;

/// Global socket protector callback.
static PROTECT_CALLBACK: OnceLock<Mutex<Option<ProtectSocketCallback>>> = OnceLock::new();

/// Socket protector implementation for iOS.
struct IosSocketProtector;

impl crate::tun::SocketProtector for IosSocketProtector {
    fn protect(&self, fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
        let callback_guard = PROTECT_CALLBACK.get_or_init(|| Mutex::new(None)).lock();

        if let Some(callback) = *callback_guard {
            if callback(fd as c_int) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Socket protection failed",
                ))
            }
        } else {
            Ok(())
        }
    }
}

/// Initialize the shoes library.
///
/// # Arguments
/// * `log_level` - Log level string: "error", "warn", "info", "debug", "trace"
///
/// # Returns
/// * 0 on success
/// * -1 on error
///
/// # Safety
/// `log_level` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shoes_init(log_level: *const c_char) -> c_int {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return 0;
    }

    let level_str = if log_level.is_null() {
        "info"
    } else {
        match CStr::from_ptr(log_level).to_str() {
            Ok(s) => s,
            Err(_) => "info",
        }
    };

    let filter = crate::logging::parse_log_level(level_str)
        .unwrap_or(log::LevelFilter::Info);

    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

        // File-only logging on iOS (no stderr output)
        let writers: Vec<Box<dyn LogWriter>> =
            vec![Box::new(DynamicFileLogWriter::new(&LOG_FILE))];
        let directives = vec![crate::logging::Directive { name: None, level: filter }];
        crate::logging::init_multi_logger(writers, directives);
    }

    TUN_SERVICE.get_or_init(|| Mutex::new(None));
    PROTECT_CALLBACK.get_or_init(|| Mutex::new(None));

    info!("shoes iOS initialized with log level: {}", level_str);
    0
}

/// Start the shoes VPN service.
///
/// # Arguments
/// * `config_yaml` - YAML configuration string (must include device_fd in TUN config)
/// * `protect_callback` - Callback function to protect sockets from VPN routing
///
/// # Returns
/// * Handle (> 0) on success
/// * -1 on error
///
/// # Safety
/// `config_yaml` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shoes_start(
    config_yaml: *const c_char,
    protect_callback: ProtectSocketCallback,
) -> c_long {
    if config_yaml.is_null() {
        error!("shoes_start: config_yaml is null");
        return -1;
    }

    let config_str = match CStr::from_ptr(config_yaml).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            error!("shoes_start: invalid UTF-8 in config_yaml: {}", e);
            return -1;
        }
    };

    info!("shoes_start: config length = {} bytes", config_str.len());

    {
        let mut callback_guard = PROTECT_CALLBACK.get_or_init(|| Mutex::new(None)).lock();
        *callback_guard = Some(protect_callback);
    }

    crate::tun::set_global_socket_protector(Arc::new(IosSocketProtector));

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("shoes_start: failed to create runtime: {}", e);
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    runtime.spawn(async move {
        match common::start_from_config(&config_str, shutdown_rx).await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => error!("shoes service error: {}", e),
        }
        running_clone.store(false, Ordering::SeqCst);
    });

    let handle = TunServiceHandle {
        shutdown_tx: Some(shutdown_tx),
        running,
        runtime,
    };

    let mut guard = TUN_SERVICE.get().unwrap().lock();
    *guard = Some(handle);

    1
}

/// Stop the shoes VPN service.
///
/// # Arguments
/// * `handle` - Handle returned by shoes_start (currently unused, we use global state)
#[unsafe(no_mangle)]
pub extern "C" fn shoes_stop(_handle: c_long) {
    common::stop_service();

    if let Some(callback) = PROTECT_CALLBACK.get() {
        let mut guard = callback.lock();
        *guard = None;
    }
}

/// Check if the shoes service is running.
///
/// # Returns
/// * true if running
/// * false if not running
#[unsafe(no_mangle)]
pub extern "C" fn shoes_is_running() -> bool {
    common::is_service_running()
}

/// Get the shoes library version.
///
/// # Returns
/// A static string containing the version. Do not free this pointer.
#[unsafe(no_mangle)]
pub extern "C" fn shoes_get_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Set the log file path for file-based logging.
///
/// # Arguments
/// * `path` - Absolute path to the log file
///
/// # Returns
/// * 0 on success
/// * -1 on error
///
/// # Safety
/// `path` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shoes_set_log_file(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    setup_log_file(path_str)
}
