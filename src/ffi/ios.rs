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

use std::ffi::{CStr, CString, c_char, c_int, c_long};
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

/// Traffic statistics callback type.
/// Called about once a second with cumulative byte counts since `shoes_start`.
///
/// * `upload_bytes` - total bytes sent from the device to the proxy.
/// * `download_bytes` - total bytes received from the proxy to the device.
///
/// Invoked from a Rust worker thread, not the caller's thread.
pub type ShoesTrafficCallback = extern "C" fn(upload_bytes: u64, download_bytes: u64);

/// Global socket protector callback.
static PROTECT_CALLBACK: OnceLock<Mutex<Option<ProtectSocketCallback>>> = OnceLock::new();

/// Socket protector implementation for iOS.
struct IosSocketProtector;

impl crate::socket_protector::SocketProtector for IosSocketProtector {
    fn protect(&self, fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
        let callback_guard = PROTECT_CALLBACK.get_or_init(|| Mutex::new(None)).lock();

        if let Some(callback) = *callback_guard {
            if callback(fd as c_int) {
                Ok(())
            } else {
                Err(std::io::Error::other("Socket protection failed"))
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
        // SAFETY: the caller guarantees a valid null-terminated C string,
        // and we checked for null above.
        unsafe { CStr::from_ptr(log_level) }
            .to_str()
            .unwrap_or("info")
    };

    let filter = crate::logging::parse_log_level(level_str).unwrap_or(log::LevelFilter::Info);

    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

        // File-only logging on iOS (no stderr output)
        let writers: Vec<Box<dyn LogWriter>> = vec![Box::new(DynamicFileLogWriter::new(&LOG_FILE))];
        let directives = vec![crate::logging::Directive {
            name: None,
            level: filter,
        }];
        crate::logging::init_multi_logger(writers, directives);
        crate::logging::install_panic_hook();
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
/// * `traffic_callback` - Callback invoked about once a second with cumulative
///   upload and download byte counts
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
    traffic_callback: ShoesTrafficCallback,
) -> c_long {
    if config_yaml.is_null() {
        error!("shoes_start: config_yaml is null");
        return -1;
    }

    // Overwriting a live handle would drop its Runtime on this thread, which
    // blocks until the old tasks finish while they still own the TUN fd.
    if common::is_service_running() {
        error!("shoes_start: service already running, call shoes_stop first");
        common::set_last_error("service already running".to_string());
        return -1;
    }

    // SAFETY: the caller guarantees a valid null-terminated C string, and we
    // checked for null above.
    let config_str = match unsafe { CStr::from_ptr(config_yaml) }.to_str() {
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

    // Store traffic callback and reset counters
    crate::tun::traffic::reset_traffic_counters();
    crate::tun::traffic::set_traffic_callback(Arc::new(move |upload, download| {
        traffic_callback(upload, download);
    }));

    crate::socket_protector::set_global_socket_protector(Arc::new(IosSocketProtector));

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

    common::clear_last_error();

    // Prepared here, on the caller's thread, so that a config this process
    // cannot run is reported as a failed start. Doing it inside the spawned
    // task meant shoes_start() returned success and the app had to discover
    // the failure by noticing shoes_is_running() had gone false on its own.
    let prepared = match runtime.block_on(common::prepare_from_config(&config_str)) {
        Ok(prepared) => prepared,
        Err(e) => {
            let msg = e.to_string();
            error!("shoes_start: invalid config: {}", msg);
            common::set_last_error(msg);
            crate::tun::traffic::clear_traffic_callback();
            crate::socket_protector::clear_global_socket_protector();
            *PROTECT_CALLBACK.get_or_init(|| Mutex::new(None)).lock() = None;
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    runtime.spawn(async move {
        match common::run_prepared(prepared, shutdown_rx).await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                common::set_last_error(msg);
            }
        }
        running_clone.store(false, Ordering::SeqCst);
    });

    let handle = TunServiceHandle {
        shutdown_tx: Some(shutdown_tx),
        running,
        runtime,
    };

    // get_or_init, not get().unwrap(): a caller that reaches shoes_start
    // without shoes_init would otherwise panic across the FFI boundary.
    let mut guard = TUN_SERVICE.get_or_init(|| Mutex::new(None)).lock();
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
    crate::tun::traffic::clear_traffic_callback();

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

    // SAFETY: the caller guarantees a valid null-terminated C string, and we
    // checked for null above.
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    setup_log_file(path_str)
}

/// Change the log level of a running library.
///
/// `shoes_init` reads the level once and ignores it on every later call, so
/// without this a support workflow of "turn on debug logging and reproduce"
/// means killing the app first. Takes effect immediately, for every subsequent
/// record.
///
/// Note that release builds are compiled with `release_max_level_info`, so
/// "debug" and "trace" only differ from "info" in a build that keeps them.
///
/// # Arguments
/// * `log_level` - "error", "warn", "info", "debug", "trace", or "off"
///
/// # Returns
/// * 0 on success
/// * -1 if the level was not recognised
///
/// # Safety
/// `log_level` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shoes_set_log_level(log_level: *const c_char) -> c_int {
    if log_level.is_null() {
        return -1;
    }

    // SAFETY: the caller guarantees a valid null-terminated C string, and we
    // checked for null above.
    let Ok(level_str) = (unsafe { CStr::from_ptr(log_level) }).to_str() else {
        return -1;
    };

    match crate::logging::parse_log_level(level_str) {
        Some(level) => {
            crate::logging::set_log_level(level);
            info!("log level set to {}", level_str);
            0
        }
        None => {
            error!("shoes_set_log_level: unrecognised level {:?}", level_str);
            -1
        }
    }
}

/// Tell the library the device's network changed.
///
/// Call this from `NWPathMonitor`'s update handler. A UDP tunnel bound to an
/// address that no longer exists does not fail — it goes silent — so without
/// this the only recovery is a full stop and start, which tears down the TUN
/// interface and every connection through it. This rebinds the tunnel's socket
/// in place instead.
///
/// Safe to call at any time, including when no tunnel is running. It does no
/// I/O on the calling thread.
///
/// # Returns
/// The number of tunnel endpoints that were told to rebind.
#[unsafe(no_mangle)]
pub extern "C" fn shoes_network_changed() -> c_int {
    crate::amneziawg::notify_network_change() as c_int
}

/// Get the last error message from the shoes service.
///
/// Returns a null-terminated C string containing the error message,
/// or NULL if no error has occurred. The caller must free the returned
/// string using `shoes_free_string()`.
///
/// Thread-safe. The returned string is a copy — safe to use after
/// subsequent shoes API calls.
#[unsafe(no_mangle)]
pub extern "C" fn shoes_get_last_error() -> *mut c_char {
    match common::get_last_error() {
        Some(msg) => match CString::new(msg) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by `shoes_get_last_error()`.
///
/// # Safety
/// `ptr` must be a pointer returned by `shoes_get_last_error()`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shoes_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: the caller guarantees `ptr` came from `into_raw` in
        // `shoes_get_last_error` and has not already been freed.
        drop(unsafe { CString::from_raw(ptr) });
    }
}
