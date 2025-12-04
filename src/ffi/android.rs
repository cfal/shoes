//! Android JNI bindings for shoes TUN service.
//!
//! This module provides JNI-compatible functions for Android integration.
//!
//! # JNI Function Naming
//!
//! JNI function names follow the pattern:
//! `Java_<package>_<class>_<method>`
//!
//! For example, if your Kotlin class is:
//! ```kotlin
//! package com.shoesproxy
//!
//! class ShoesNative {
//!     external fun init(logLevel: String): Int
//! }
//! ```
//!
//! The JNI function would be:
//! `Java_com_shoesproxy_ShoesNative_init`

use std::sync::Arc;
use std::sync::atomic::Ordering;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use log::{LevelFilter, Log, Metadata, Record, error, info};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::tun::{FnSocketProtector, set_global_socket_protector};

use super::common::{
    self, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, TunServiceHandle, flush_log_file,
    parse_log_level, setup_log_file,
};

/// Android logger that writes to both logcat and file.
struct AndroidLogger {
    level: LevelFilter,
}

impl AndroidLogger {
    fn new(level: LevelFilter) -> Self {
        Self { level }
    }
}

impl Log for AndroidLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level = record.level();
        let target = record.target();
        let message = format!("{}", record.args());

        // Write to Android logcat
        #[cfg(target_os = "android")]
        {
            use std::ffi::CString;
            let tag = CString::new("shoes").unwrap_or_default();
            let msg = CString::new(message.as_str()).unwrap_or_default();
            let priority = match level {
                log::Level::Error => 6, // ANDROID_LOG_ERROR
                log::Level::Warn => 5,  // ANDROID_LOG_WARN
                log::Level::Info => 4,  // ANDROID_LOG_INFO
                log::Level::Debug => 3, // ANDROID_LOG_DEBUG
                log::Level::Trace => 2, // ANDROID_LOG_VERBOSE
            };
            unsafe {
                ndk_sys::__android_log_write(priority as i32, tag.as_ptr(), msg.as_ptr());
            }
        }

        // Write to log file if configured (with timestamp for Android)
        if let Some(file_mutex) = LOG_FILE.get() {
            if let Ok(mut guard) = file_mutex.lock() {
                if let Some(ref mut file) = *guard {
                    use std::io::Write;
                    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                    let _ = writeln!(file, "{} {} [{}] {}", timestamp, level, target, message);
                    let _ = file.flush();
                }
            }
        }
    }

    fn flush(&self) {
        flush_log_file();
    }
}

/// Initialize the shoes library.
///
/// # Arguments
/// * `env` - JNI environment
/// * `_class` - Java class (unused)
/// * `log_level` - Log level string ("error", "warn", "info", "debug", "trace")
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_init(
    mut env: JNIEnv,
    _class: JClass,
    log_level: JString,
) -> jint {
    let level_str: String = match env.get_string(&log_level) {
        Ok(s) => s.into(),
        Err(e) => {
            eprintln!("Failed to get log level string: {}", e);
            return -1;
        }
    };

    let level = parse_log_level(&level_str);

    // Initialize logger (only once)
    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| std::sync::Mutex::new(None));

        let logger = AndroidLogger::new(level);
        if log::set_boxed_logger(Box::new(logger)).is_ok() {
            log::set_max_level(level);
        }
    }

    info!("shoes initialized with log level: {}", level_str);
    0
}

/// Get the shoes library version.
///
/// # Returns
/// * Version string from Cargo.toml (e.g., "0.1.0")
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_getVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    let version = env!("CARGO_PKG_VERSION");
    env.new_string(version)
        .unwrap_or_else(|_| JObject::null().into())
}

/// Set the log file path for file-based logging.
///
/// # Arguments
/// * `env` - JNI environment
/// * `_class` - Java class (unused)
/// * `log_path` - Absolute path to the log file
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_setLogFile(
    mut env: JNIEnv,
    _class: JClass,
    log_path: JString,
) -> jint {
    let path_str: String = match env.get_string(&log_path) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get log path string: {}", e);
            return -1;
        }
    };

    setup_log_file(&path_str)
}

/// Start the shoes service.
///
/// # Arguments
/// * `env` - JNI environment
/// * `_class` - Java class (unused)
/// * `config_yaml` - YAML configuration string (includes TUN config with device_fd and optional Server configs like mixed)
/// * `protect_callback` - Java object with protect(int fd) method
///
/// # Returns
/// * Handle (> 0) on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_start<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_yaml: JString<'local>,
    protect_callback: JObject<'local>,
) -> jlong {
    info!("Starting shoes service");

    let config_str: String = match env.get_string(&config_yaml) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get config string: {}", e);
            return -1;
        }
    };

    let callback_ref = match env.new_global_ref(protect_callback) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create global ref for callback: {}", e);
            return -1;
        }
    };

    let jvm = match env.get_java_vm() {
        Ok(vm) => Arc::new(vm),
        Err(e) => {
            error!("Failed to get JavaVM: {}", e);
            return -1;
        }
    };

    // Socket protector calls VpnService.protect() to exempt sockets from VPN routing
    let callback_ref = Arc::new(callback_ref);
    let jvm_clone = jvm.clone();
    let callback_clone = callback_ref.clone();

    let protector = FnSocketProtector::new(move |fd: i32| {
        let mut env = match jvm_clone.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to attach to JVM: {}", e),
                ));
            }
        };

        let result = env.call_method(&*callback_clone, "protect", "(I)Z", &[JValue::Int(fd)]);

        match result {
            Ok(v) => {
                if v.z().unwrap_or(false) {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "VpnService.protect() returned false",
                    ))
                }
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to call protect(): {}", e),
            )),
        }
    });

    set_global_socket_protector(Arc::new(protector));

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    runtime.spawn(async move {
        info!("Shoes service task started");

        match common::start_from_config(&config_str, shutdown_rx).await {
            Ok(()) => info!("Shoes service stopped normally"),
            Err(e) => error!("Shoes service error: {}", e),
        }

        running_clone.store(false, Ordering::SeqCst);
    });

    let handle = TunServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
    };

    let service = TUN_SERVICE.get_or_init(|| parking_lot::Mutex::new(None));
    *service.lock() = Some(handle);

    info!("TUN service started successfully");
    1
}

/// Stop the TUN service.
///
/// # Arguments
/// * `env` - JNI environment
/// * `_class` - Java class (unused)
/// * `handle` - Handle returned by startTun (currently unused, we use global state)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_stop(
    _env: JNIEnv,
    _class: JClass,
    _handle: jlong,
) {
    common::stop_service();
}

/// Check if the TUN service is running.
///
/// # Returns
/// * JNI_TRUE if running
/// * JNI_FALSE if not running
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_isRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if common::is_service_running() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
