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

use crate::logging::{DynamicFileLogWriter, LogWriter};
use crate::socket_protector::{FnSocketProtector, set_global_socket_protector};

use super::common::{self, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, setup_log_file};

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
                ndk_sys::__android_log_write(priority, tag.as_ptr(), msg.as_ptr());
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
        .with_env(|env| log_level.try_to_string(env))
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
        crate::logging::install_panic_hook();
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
        .with_env(|env| log_path.try_to_string(env))
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
    traffic_callback: JObject<'local>,
) -> jlong {
    info!("Starting shoes service");

    // Overwriting a live handle would drop its Runtime on this thread, which
    // blocks until the old tasks finish while they still own the TUN fd.
    if common::is_service_running() {
        error!("start: service already running, call stop first");
        common::set_last_error("service already running".to_string());
        return -1;
    }

    let result = unowned
        .with_env(
            |env| -> jni::errors::Result<(
                String,
                Global<JObject<'static>>,
                Global<JObject<'static>>,
                jni::JavaVM,
            )> {
                let config_str: String = config_yaml.try_to_string(env)?;
                let protect_ref = env.new_global_ref(protect_callback)?;
                let traffic_ref = env.new_global_ref(traffic_callback)?;
                let jvm = env.get_java_vm()?;
                Ok((config_str, protect_ref, traffic_ref, jvm))
            },
        )
        .into_outcome();

    let (config_str, protect_ref, traffic_ref, jvm) = match result {
        Outcome::Ok(v) => v,
        Outcome::Err(e) => {
            error!("Failed to extract JNI values for start: {}", e);
            return -1;
        }
        Outcome::Panic(_) => return -1,
    };
    let jvm: Arc<jni::JavaVM> = Arc::new(jvm);

    // Socket protector calls VpnService.protect() to exempt sockets from VPN routing
    let protect_ref: Arc<Global<JObject<'static>>> = Arc::new(protect_ref);
    let jvm_clone = jvm.clone();
    let protect_clone = protect_ref.clone();

    let protector = FnSocketProtector::new(move |fd: i32| {
        let protect_ok = jvm_clone
            .attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<bool> {
                let v = env.call_method(
                    &*protect_clone,
                    jni::jni_str!("protect"),
                    jni::jni_sig!("(I)Z"),
                    &[JValue::Int(fd)],
                )?;
                Ok(v.z().unwrap_or(false))
            })
            .map_err(|e| std::io::Error::other(format!("{}", e)))?;

        if protect_ok {
            Ok(())
        } else {
            Err(std::io::Error::other("VpnService.protect() returned false"))
        }
    });

    set_global_socket_protector(Arc::new(protector));

    // Traffic callback calls TrafficListener.onTrafficUpdate(long, long)
    let traffic_ref: Arc<Global<JObject<'static>>> = Arc::new(traffic_ref);
    let jvm_traffic = jvm.clone();
    crate::tun::traffic::reset_traffic_counters();
    crate::tun::traffic::set_traffic_callback(Arc::new(move |upload: u64, download: u64| {
        let _ =
            jvm_traffic.attach_current_thread(|env: &mut jni::Env| -> jni::errors::Result<()> {
                env.call_method(
                    &*traffic_ref,
                    jni::jni_str!("onTrafficUpdate"),
                    jni::jni_sig!("(JJ)V"),
                    &[JValue::Long(upload as i64), JValue::Long(download as i64)],
                )?;
                Ok(())
            });
    }));

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    };

    common::clear_last_error();

    // Prepared here, on the caller's thread, so that a config this process
    // cannot run is reported as a failed start. Doing it inside the spawned
    // task meant start() returned success and the app had to discover the
    // failure by noticing isRunning() had gone false on its own.
    let prepared = match runtime.block_on(common::prepare_from_config(&config_str)) {
        Ok(prepared) => prepared,
        Err(e) => {
            let msg = e.to_string();
            error!("start: invalid config: {}", msg);
            common::set_last_error(msg);
            crate::tun::traffic::clear_traffic_callback();
            crate::socket_protector::clear_global_socket_protector();
            return -1;
        }
    };

    // Runtime::new() above, not a pinned worker count: Android has no Network
    // Extension memory limit to stay under, so it takes the cores it can get.
    // That is why control::start receives a runtime rather than building one.
    let handle = crate::control::start(runtime, prepared, common::set_last_error);

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
    crate::tun::traffic::clear_traffic_callback();
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

/// Change the log level of a running library.
///
/// `init` reads the level once and ignores it on every later call, so without
/// this a support workflow of "turn on debug logging and reproduce" means
/// killing the app first.
///
/// Note that release builds are compiled with `release_max_level_info`, so
/// "debug" and "trace" only differ from "info" in a build that keeps them.
///
/// # Returns
/// * 0 on success
/// * -1 if the level was not recognised
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_setLogLevel<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    log_level: JString<'local>,
) -> jint {
    let level_str: String = match unowned
        .with_env(|env| log_level.try_to_string(env))
        .into_outcome()
    {
        Outcome::Ok(s) => s,
        Outcome::Err(e) => {
            error!("Failed to get log level string: {}", e);
            return -1;
        }
        Outcome::Panic(_) => return -1,
    };

    match crate::logging::parse_log_level(&level_str) {
        Some(level) => {
            crate::logging::set_log_level(level);
            info!("log level set to {}", level_str);
            0
        }
        None => {
            error!("setLogLevel: unrecognised level {:?}", level_str);
            -1
        }
    }
}

/// Tell the library the device's network changed.
///
/// Call this from `ConnectivityManager.NetworkCallback`. A UDP tunnel bound to
/// an address that no longer exists does not fail — it goes silent — so without
/// this the only recovery is a full stop and start, which tears down the TUN
/// interface and every connection through it. This rebinds the tunnel's socket
/// in place instead.
///
/// Safe to call at any time, including when no tunnel is running, and from any
/// thread: it does no I/O itself.
///
/// # Returns
/// The number of tunnel endpoints that were told to rebind.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_networkChanged(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    crate::amneziawg::notify_network_change() as jint
}

/// Get the last error message from the shoes service.
///
/// # Returns
/// * Error message string, or null if no error has occurred.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_shoesproxy_ShoesNative_getLastError<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    match common::get_last_error() {
        Some(msg) => match unowned.with_env(|env| env.new_string(&msg)).into_outcome() {
            Outcome::Ok(s) => s,
            _ => JString::null(),
        },
        None => JString::null(),
    }
}
