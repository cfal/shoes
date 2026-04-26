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

use jni::objects::{Global, JClass, JObject, JString, JValue};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use jni::{EnvUnowned, Outcome};
use log::{Record, error, info};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::logging::{DynamicFileLogWriter, LogWriter};
use crate::tun::{FnSocketProtector, set_global_socket_protector};

use super::common::{
    self, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, TunServiceHandle, setup_log_file,
};

/// Writes to Android logcat. Uses the `record` arg for level mapping;
/// logcat has its own formatting so the pre-formatted string is ignored.
struct LogcatWriter;

impl LogWriter for LogcatWriter {
    fn write_log(&self, record: &Record, _formatted: &str) {
        #[cfg(target_os = "android")]
        {
            use std::ffi::CString;
            let tag = CString::new("shoes").unwrap_or_default();
            let msg = CString::new(format!("{}", record.args())).unwrap_or_default();
            let priority = match record.level() {
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
        #[cfg(not(target_os = "android"))]
        let _ = record;
    }

    fn flush(&self) {}
}

/// Initialize the shoes library.
///
/// # Arguments
/// * `unowned` - JNI environment
/// * `_class` - Java class (unused)
/// * `log_level` - Log level string ("error", "warn", "info", "debug", "trace")
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_init<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    log_level: JString<'local>,
) -> jint {
    let level_str: String = match unowned
        .with_env(|env| env.get_string(&log_level).map(|s| s.to_string()))
        .into_outcome()
    {
        Outcome::Ok(s) => s,
        Outcome::Err(e) => {
            eprintln!("Failed to get log level string: {}", e);
            return -1;
        }
        Outcome::Panic(_) => return -1,
    };

    let level = crate::logging::parse_log_level(&level_str).unwrap_or(log::LevelFilter::Info);

    // Initialize logger (only once)
    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

        let writers: Vec<Box<dyn LogWriter>> = vec![
            Box::new(LogcatWriter),
            Box::new(DynamicFileLogWriter::new(&LOG_FILE)),
        ];
        let directives = vec![crate::logging::Directive { name: None, level }];
        crate::logging::init_multi_logger(writers, directives);
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
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    let version = env!("CARGO_PKG_VERSION");
    match unowned
        .with_env(|env| env.new_string(version))
        .into_outcome()
    {
        Outcome::Ok(s) => s,
        // Can fail under JVM OOM; return null to avoid panicking across FFI.
        _ => JString::null(),
    }
}

/// Set the log file path for file-based logging.
///
/// # Arguments
/// * `unowned` - JNI environment
/// * `_class` - Java class (unused)
/// * `log_path` - Absolute path to the log file
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_setLogFile<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    log_path: JString<'local>,
) -> jint {
    let path_str: String = match unowned
        .with_env(|env| env.get_string(&log_path).map(|s| s.to_string()))
        .into_outcome()
    {
        Outcome::Ok(s) => s,
        Outcome::Err(e) => {
            error!("Failed to get log path string: {}", e);
            return -1;
        }
        Outcome::Panic(_) => return -1,
    };

    setup_log_file(&path_str)
}

/// Start the shoes service.
///
/// # Arguments
/// * `unowned` - JNI environment
/// * `_class` - Java class (unused)
/// * `config_yaml` - YAML configuration string (includes TUN config with device_fd and optional Server configs like mixed)
/// * `protect_callback` - Java object with protect(int fd) method
///
/// # Returns
/// * Handle (> 0) on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_start<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    config_yaml: JString<'local>,
    protect_callback: JObject<'local>,
) -> jlong {
    info!("Starting shoes service");

    let result = unowned
        .with_env(
            |env| -> jni::errors::Result<(String, Global<JObject<'static>>, jni::JavaVM)> {
                let config_str: String = env.get_string(&config_yaml).map(|s| s.to_string())?;
                let callback_ref = env.new_global_ref(protect_callback)?;
                let jvm = env.get_java_vm()?;
                Ok((config_str, callback_ref, jvm))
            },
        )
        .into_outcome();

    let (config_str, callback_ref, jvm) = match result {
        Outcome::Ok(v) => v,
        Outcome::Err(e) => {
            error!("Failed to extract JNI values for start: {}", e);
            return -1;
        }
        Outcome::Panic(_) => return -1,
    };
    let jvm: Arc<jni::JavaVM> = Arc::new(jvm);

    // Socket protector calls VpnService.protect() to exempt sockets from VPN routing
    let callback_ref: Arc<Global<JObject<'static>>> = Arc::new(callback_ref);
    let jvm_clone = jvm.clone();
    let callback_clone = callback_ref.clone();

    let protector = FnSocketProtector::new(move |fd: i32| {
        let protect_ok = jvm_clone
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<bool> {
                let v = env.call_method(
                    &*callback_clone,
                    jni::jni_str!("protect"),
                    jni::jni_sig!("(I)Z"),
                    &[JValue::Int(fd)],
                )?;
                Ok(v.z().unwrap_or(false))
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;

        if protect_ok {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "VpnService.protect() returned false",
            ))
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
/// * `_env` - JNI environment (unused)
/// * `_class` - Java class (unused)
/// * `handle` - Handle returned by startTun (currently unused, we use global state)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_stop(
    _env: EnvUnowned,
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
    _env: EnvUnowned,
    _class: JClass,
) -> jboolean {
    if common::is_service_running() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
