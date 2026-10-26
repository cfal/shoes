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
use tokio::sync::oneshot;

use crate::logging::{DynamicFileLogWriter, LogWriter};

use super::common::{
    self, INITIALIZED, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, TunServiceHandle, setup_log_file,
};

/// Socket protector callback type.
/// Called from Rust to protect sockets from VPN routing.
/// The callback receives a file descriptor and should return true if protected successfully.
pub type ProtectSocketCallback = extern "C" fn(fd: c_int) -> bool;

/// Socket protector implementation for iOS.
struct IosSocketProtector(ProtectSocketCallback);

impl crate::tun::SocketProtector for IosSocketProtector {
    fn protect(&self, fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
        if (self.0)(fd as c_int) {
            Ok(())
        } else {
            Err(std::io::Error::other("Socket protection failed"))
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
    let _setup = common::LOGGER_SETUP.lock();
    if INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let level_str = if log_level.is_null() {
        "info"
    } else {
        unsafe { CStr::from_ptr(log_level) }
            .to_str()
            .unwrap_or("info")
    };

    let filter = crate::logging::parse_log_level(level_str).unwrap_or(log::LevelFilter::Info);

    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

        // File-only logging on iOS (no stderr output)
        let writers: Vec<Box<dyn LogWriter>> = vec![Box::new(DynamicFileLogWriter::new(&LOG_FILE))];
        let directives = vec![crate::logging::Directive {
            name: None,
            level: filter,
        }];
        if crate::logging::init_multi_logger(writers, directives).is_err() {
            return -1;
        }
        LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
    }

    TUN_SERVICE.get_or_init(|| Mutex::new(None));
    INITIALIZED.store(true, Ordering::SeqCst);

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
    if !common::is_lifecycle_thread() {
        return -1;
    }
    let _lifecycle = common::SERVICE_LIFECYCLE.lock();
    if TUN_SERVICE
        .get()
        .is_some_and(|service| service.lock().is_some())
    {
        error!("Stop the previous shoes service before starting another");
        return -1;
    }
    if config_yaml.is_null() {
        error!("shoes_start: config_yaml is null");
        return -1;
    }

    let config_str = match unsafe { CStr::from_ptr(config_yaml) }.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            error!("shoes_start: invalid UTF-8 in config_yaml: {}", e);
            return -1;
        }
    };

    info!("shoes_start: config length = {} bytes", config_str.len());

    crate::tun::set_global_socket_protector(Arc::new(IosSocketProtector(protect_callback)));

    crate::thread_util::set_num_threads(2);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("shoes_start: failed to create runtime: {}", e);
            crate::tun::clear_global_socket_protector();
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let task = common::spawn_service(&runtime, config_str, shutdown_rx, running.clone());

    let handle = TunServiceHandle {
        shutdown_tx: Some(shutdown_tx),
        running,
        runtime,
        task,
    };

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

    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    setup_log_file(path_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::SocketProtector;

    // Logger installation is process-global, so these cases need isolated children.
    fn run_in_subprocess(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(marker, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "subprocess {test_name} failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
            "subprocess did not execute exactly one test: {test_name}\n{stdout}\n{stderr}"
        );
        true
    }

    #[test]
    #[should_panic(expected = "subprocess did not execute exactly one test")]
    fn subprocess_rejects_missing_test() {
        run_in_subprocess(
            "ffi::ios::tests::__missing_subprocess_case__",
            "SHOES_FILE_LOG_MISSING_CHILD",
        );
    }

    #[test]
    fn file_logging_stop_flushes_buffered_records_without_closing_sink() {
        if run_in_subprocess(
            "ffi::ios::tests::file_logging_stop_flushes_buffered_records_without_closing_sink",
            "SHOES_FILE_LOG_BUFFERED_CHILD",
        ) {
            return;
        }
        struct BufferedOutput {
            pending: Vec<u8>,
            visible: Arc<Mutex<Vec<u8>>>,
        }
        impl std::io::Write for BufferedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.pending.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.visible.lock().append(&mut self.pending);
                Ok(())
            }
        }

        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, 0);
        let visible = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::new(
            crate::logging::FileLogWriter::with_test_writer(BufferedOutput {
                pending: Vec::new(),
                visible: visible.clone(),
            })
            .unwrap(),
        );
        *LOG_FILE.get().unwrap().lock() = Some(writer.clone());
        info!("buffered before stop");
        assert!(visible.lock().is_empty());

        shoes_stop(0);

        let contents = String::from_utf8(visible.lock().clone()).unwrap();
        assert!(
            contents.contains("buffered before stop"),
            "stop must flush pending file records"
        );
        assert!(contents.contains("TUN service stop completed"));
        assert!(!writer.is_finished());
        assert!(Arc::ptr_eq(
            &writer,
            LOG_FILE.get().unwrap().lock().as_ref().unwrap()
        ));
        let stats = writer.stats();
        assert_eq!(stats.written_records, stats.accepted_records);
        assert_eq!(stats.pending_records, 0);

        LOG_FILE.get().unwrap().lock().take();
        writer
            .shutdown_timeout(crate::logging::FILE_LOG_FLUSH_TIMEOUT)
            .unwrap();
    }

    #[test]
    fn file_logging_stalled_replacement_retains_one_worker() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        if run_in_subprocess(
            "ffi::ios::tests::file_logging_stalled_replacement_retains_one_worker",
            "SHOES_FILE_LOG_STALL_CHILD",
        ) {
            return;
        }
        struct Gate {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }
        impl std::io::Write for Gate {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replacement.log");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, 0);
        let writer = Arc::new(
            crate::logging::FileLogWriter::with_test_writer(Gate {
                entered: entered_tx,
                release: release_rx,
            })
            .unwrap(),
        );
        *LOG_FILE.get().unwrap().lock() = Some(writer.clone());
        info!("blocked write");
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..2 {
            let started = Instant::now();
            assert_eq!(setup_log_file(path.to_str().unwrap()), -1);
            assert!(started.elapsed() < Duration::from_secs(3));
            assert!(Arc::ptr_eq(
                &writer,
                LOG_FILE.get().unwrap().lock().as_ref().unwrap()
            ));
        }
        info!("dropped after failed replacement");
        assert_eq!(writer.stats().dropped_records, 1);
        release_tx.send(()).unwrap();
        writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(setup_log_file(path.to_str().unwrap()), 0);
        let current = LOG_FILE.get().unwrap().lock().take().unwrap();
        assert_ne!(current.stats().sink_id, writer.stats().sink_id);
        current.shutdown_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn file_logging_repeated_init_replacement_and_stop() {
        if run_in_subprocess(
            "ffi::ios::tests::file_logging_repeated_init_replacement_and_stop",
            "SHOES_FILE_LOG_TEST_CHILD",
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.log");
        let second = directory.path().join("second.log");
        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, 0);
        assert_eq!(setup_log_file(first.to_str().unwrap()), 0);
        let writer = LOG_FILE.get().unwrap().lock().clone().unwrap();
        info!("before stop");
        shoes_stop(0);
        assert!(
            std::fs::read_to_string(&first)
                .unwrap()
                .contains("before stop")
        );
        assert!(!writer.is_finished());
        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, 0);
        assert!(Arc::ptr_eq(
            &writer,
            LOG_FILE.get().unwrap().lock().as_ref().unwrap()
        ));
        info!("after repeated init");
        assert_eq!(setup_log_file(directory.path().to_str().unwrap()), -1);
        assert!(Arc::ptr_eq(
            &writer,
            LOG_FILE.get().unwrap().lock().as_ref().unwrap()
        ));
        assert_eq!(setup_log_file(second.to_str().unwrap()), 0);
        assert!(writer.is_finished());
        assert!(
            std::fs::read_to_string(&first)
                .unwrap()
                .contains("after repeated init")
        );
        common::write_to_log_file(log::Level::Info, "test", "new\n\u{1b}[31m record");
        shoes_stop(0);
        assert!(
            std::fs::read_to_string(&second)
                .unwrap()
                .contains("new\\n\\u{1b}[31m record")
        );
        let writer = LOG_FILE.get().unwrap().lock().take().unwrap();
        writer
            .shutdown_timeout(crate::logging::FILE_LOG_FLUSH_TIMEOUT)
            .unwrap();
    }

    #[test]
    fn file_logging_init_failure_does_not_mark_initialized() {
        if run_in_subprocess(
            "ffi::ios::tests::file_logging_init_failure_does_not_mark_initialized",
            "SHOES_FILE_LOG_FAILURE_CHILD",
        ) {
            return;
        }
        let _capture = crate::logging::test_capture::Capture::new();
        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, -1);
        assert_eq!(unsafe { shoes_init(std::ptr::null()) }, -1);
        assert!(!INITIALIZED.load(Ordering::SeqCst));
        assert!(!LOGGER_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn protectors_keep_their_own_callback_across_replacement() {
        extern "C" fn old(fd: c_int) -> bool {
            fd == 1
        }
        extern "C" fn new(fd: c_int) -> bool {
            fd == 2
        }
        let old = Arc::new(IosSocketProtector(old));
        let new = IosSocketProtector(new);
        old.protect(1).unwrap();
        assert!(old.protect(2).is_err());
        drop(old);
        new.protect(2).unwrap();
        assert!(new.protect(1).is_err());
    }
}
