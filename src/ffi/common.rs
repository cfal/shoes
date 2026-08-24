//! Common FFI utilities shared between iOS and Android.
//!
//! This module contains platform-independent code that both iOS and Android use.
//!
//! The service lifecycle itself lives in [`crate::control`]. What stays here is
//! the part that is genuinely about the C and JNI boundary: global singletons,
//! because a caller on the far side addresses its service by an integer rather
//! than by holding a value, and the log-file plumbing those callers configure.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::OnceLock;

use log::info;

// Only what ios.rs and android.rs actually name. `mod common` is private, so
// re-exporting more than that is an unused import rather than a public API --
// and the Android clippy job builds with -D warnings.
pub use crate::control::{ServiceHandle as TunServiceHandle, prepare_from_config};

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
///
/// Returns `true` if the service confirmed it stopped, `false` if the wait
/// timed out. See [`crate::control::stop_handle`] for what that distinction
/// costs the caller.
pub fn stop_service() -> bool {
    info!("Stopping TUN service");

    let handle = if let Some(service) = TUN_SERVICE.get() {
        service.lock().take()
    } else {
        None
    };

    let Some(handle) = handle else {
        info!("TUN service was not running");
        crate::socket_protector::clear_global_socket_protector();
        return true;
    };

    let stopped = crate::control::stop_handle(handle);

    // The protector holds a reference to the platform's VPN service object.
    // Released here rather than in the platform modules so that neither one can
    // forget.
    crate::socket_protector::clear_global_socket_protector();

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
            return handle.is_running();
        }
    }
    false
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
