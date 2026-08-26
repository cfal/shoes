//! Service lifecycle: prepare a config, run it, stop it.
//!
//! Extracted from `src/ffi/common.rs` so that non-mobile hosts — a macOS
//! Network Extension, a Windows service, a Linux daemon — can drive a tunnel
//! without going through the C or JNI boundary. The FFI keeps its global
//! singletons, because a C caller addresses its service by an integer, and
//! delegates the work here.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{error, info, warn};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

mod device;
#[cfg(feature = "control-logs")]
pub mod logs;
#[cfg(feature = "control-stats")]
pub mod stats;
mod stop;

pub use device::DevicePolicy;
pub use stop::StopOutcome;

// Not on Android or iOS. This is not a feature a mobile host might want and
// currently declines -- it is API a mobile host structurally cannot use, since
// a C or JNI caller has no way to receive a StatusSnapshot and reads the same
// facts through shoes_is_running() and shoes_get_last_error() instead. Worth
// 1824 bytes of the arm64 .so, measured.
//
// macOS is deliberately on the near side of this: the desktop Network
// Extension provider is a target_os = "macos" build and does want it.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod status;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use status::{Status, StatusSnapshot, StopReason};

use crate::config::{Config, convert_cert_paths, create_server_configs, load_config_str};
use crate::dns::build_dns_registry;
use crate::tcp::tcp_server::start_servers;
#[cfg(unix)]
use crate::tun::run_tun_from_config;

/// Handle to a running service.
///
/// # Do not drop this from async code
///
/// Prefer [`ServiceHandle::stop`], and call it from a blocking context —
/// `tokio::task::spawn_blocking` from a Tauri command or an async handler.
///
/// Two reasons, and they apply to a plain `drop` as much as to `stop`. The
/// handle owns a [`tokio::runtime::Runtime`], and dropping a runtime inside
/// another runtime's context panics with "Cannot drop a runtime in a context
/// where blocking is not allowed". And `stop` waits, by design, up to
/// [`STOP_TIMEOUT`] on the calling thread — on an async worker that stalls
/// every other task sharing it.
///
/// Dropping also skips the wait entirely, which is the wait that tells a host
/// whether it may close a descriptor it lent. That answer only comes back from
/// `stop`, as a [`StopOutcome`].
pub struct ServiceHandle {
    /// Tokio runtime running the service.
    runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    running: Arc<AtomicBool>,
    /// When `start` spawned the service, for `uptime`.
    started_at: std::time::Instant,
    /// Set if the stack stopped with an error, so `status` can tell a failure
    /// from a stop the host asked for. The FFI gets the same string through
    /// its `on_error` callback, because a C caller cannot receive an enum
    /// carrying a String.
    failure: Arc<parking_lot::Mutex<Option<String>>>,
}

/// How long `stop_handle` waits for the service task to finish.
pub const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often it looks while waiting.
const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Stop a running service and wait for it to release the TUN descriptor.
///
/// Call this from a blocking context — see the warning on [`ServiceHandle`].
/// It sleeps the calling thread in a poll loop for up to [`STOP_TIMEOUT`], and
/// if the shutdown thread cannot be spawned it drops the runtime inline, which
/// panics inside an async context.
///
/// The wait is the part that cannot be skipped: it is what
/// guarantees the stack thread has released the TUN descriptor, so the app can
/// close its own copy without racing a thread that is still reading from it.
/// In practice it costs a few milliseconds — the old version polled in 100 ms
/// steps and so paid at least that much every time.
///
/// Dropping the runtime, on the other hand, waits on tasks that no longer hold
/// anything the app needs back, so it happens on a thread of its own and the
/// caller does not pay for it.
pub fn stop_handle(mut handle: ServiceHandle) -> StopOutcome {
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

    let waited = started.elapsed();
    let outcome = if stopped {
        info!("TUN service stopped after {}ms", waited.as_millis());
        StopOutcome::Released
    } else {
        error!(
            "TUN service did not stop within {}s; the TUN descriptor may still be in use",
            STOP_TIMEOUT.as_secs()
        );
        StopOutcome::TimedOut { waited }
    };

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

    outcome
}

impl ServiceHandle {
    /// Whether the service task is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop this service and wait for it to release the device.
    ///
    /// Consumes the handle, because a stopped service has nothing left to
    /// answer and a second stop has no meaning.
    ///
    /// Call this from a blocking context — see the warning on this type.
    pub fn stop(self) -> StopOutcome {
        stop_handle(self)
    }

    /// A point-in-time reading of this service.
    ///
    /// Note that the byte counters are process-global — see the note on
    /// [`start`] about one service per process.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn status(&self) -> StatusSnapshot {
        let running = self.is_running();

        let status = if running {
            Status::Running
        } else {
            Status::Stopped {
                reason: match self.failure.lock().clone() {
                    Some(msg) => StopReason::Failed(msg),
                    None => StopReason::Requested,
                },
            }
        };

        // The counters live behind cfg(unix) with the TUN module. On Windows
        // there is no tunnel to count yet, and a host still wants a snapshot.
        #[cfg(unix)]
        let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
        #[cfg(not(unix))]
        let (upload_bytes, download_bytes) = (0, 0);

        StatusSnapshot {
            status,
            uptime: running.then(|| self.started_at.elapsed()),
            upload_bytes,
            download_bytes,
        }
    }
}

/// Start a prepared service on `runtime`, and hand back a handle to it.
///
/// The runtime is the caller's rather than ours: iOS pins it to two worker
/// threads to stay inside a Network Extension's memory limit, while Android
/// takes `Runtime::new()` and all the cores it can get. That is a policy this
/// module has no business deciding, and folding the two into one default would
/// quietly change one of them.
///
/// `on_error` is called from the service task if the stack stops with an error.
/// The FFI uses it to fill `LAST_ERROR`, which is how a C caller — which cannot
/// receive a Rust enum carrying a String — learns what happened.
///
/// # One service per process
///
/// The traffic counters in `crate::tun::traffic` are process-global statics, so
/// a second concurrent `ServiceHandle` in one process would report the sum of
/// both services. Each privileged host runs exactly one tunnel, so this costs
/// nothing in practice — but it is an invariant this API depends on rather than
/// an accident.
pub fn start(
    runtime: tokio::runtime::Runtime,
    prepared: PreparedService,
    on_error: impl Fn(String) + Send + 'static,
) -> ServiceHandle {
    // From zero, so a second session does not report the first one's bytes
    // against a fresh uptime. Both FFI platforms already do this in their own
    // start path; a Rust host had no equivalent.
    #[cfg(unix)]
    crate::tun::traffic::reset_traffic_counters();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let failure = Arc::new(parking_lot::Mutex::new(None));
    let failure_clone = failure.clone();

    runtime.spawn(async move {
        info!("shoes service task started");

        match run_prepared(prepared, shutdown_rx).await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                // Recorded for status() as well as handed to the caller: a
                // Rust host wants StopReason::Failed, the FFI wants a string
                // for LAST_ERROR, and neither should have to read the other's
                // channel to get it.
                *failure_clone.lock() = Some(msg.clone());
                on_error(msg);
            }
        }

        running_clone.store(false, Ordering::SeqCst);
    });

    ServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
        started_at: std::time::Instant::now(),
        failure,
    }
}

/// A config that has been parsed, validated, and had its DNS resolvers built.
///
/// Preparing is separate from running so that the host can do it on the calling
/// thread and answer `start` with a real verdict. Everything that a bad config
/// can fail at — YAML syntax, a device the host cannot provide, an unusable
/// key, a resolver that will not build — fails here, in front of the caller,
/// instead of inside
/// a spawned task whose error the app only learns about by polling
/// `isRunning()` and finding it already false.
pub struct PreparedService {
    tun_config: crate::config::TunConfig,
    server_configs: Vec<crate::config::ServerConfig>,
    dns_registry: crate::dns::DnsRegistry,
    policy: DevicePolicy,
}

/// Start the service from a config YAML string.
///
/// This parses the config YAML and starts both TUN and any Server configs
/// (like mixed HTTP+SOCKS5 servers) that are defined in the config.
///
/// What the TUN section must contain depends on `policy`: under
/// [`DevicePolicy::BorrowedFd`] it needs a `device_fd` the host already owns,
/// and under [`DevicePolicy::Owned`] it must not have one, because the service
/// creates the device itself.
pub async fn start_from_config(
    config_yaml: &str,
    policy: DevicePolicy,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let prepared = prepare_from_config(config_yaml, policy).await?;
    run_prepared(prepared, shutdown_rx).await
}

/// Parse and validate a config, and build its resolvers. See [`PreparedService`].
pub async fn prepare_from_config(
    config_yaml: &str,
    policy: DevicePolicy,
) -> std::io::Result<PreparedService> {
    info!("Parsing config for TUN server");

    let configs: Vec<Config> = load_config_str(config_yaml)?;

    let (configs, pem_count) = convert_cert_paths(configs).await?;
    if pem_count > 0 {
        info!("Loaded {} PEM files", pem_count);
    }

    let crate::config::ValidatedConfigs {
        configs: validated_configs,
        dns_groups,
        outbounds,
    } = create_server_configs(configs)?;

    // Replace, not add: a reload through this path must not carry the
    // previous config's servers into the new list.
    #[cfg(feature = "control-stats")]
    crate::outbound_stats::install(&outbounds);
    #[cfg(not(feature = "control-stats"))]
    let _ = outbounds;


    // Build DNS registry from expanded groups
    let dns_registry = build_dns_registry(dns_groups).await?;

    // Separate TUN config from server configs, and check the one TUN against
    // what this host can provide -- see DevicePolicy.
    let mut tun_config = None;
    let mut server_configs = Vec::new();

    for config in validated_configs {
        match config {
            Config::TunServer(tc) => {
                if tun_config.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Multiple TUN configs found - only one is allowed",
                    ));
                }
                device::validate(&tc, policy)?;
                // unwrap_or(-1) rather than {:?} on the Option: an Owned host
                // has no descriptor to report, and -1 says so without pulling
                // Option<i32>'s Debug impl into a mobile build.
                info!(
                    "TUN config: fd={}, mtu={}, tcp={}, udp={}, icmp={}",
                    tc.device_fd.unwrap_or(-1),
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
        policy,
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
        policy,
    } = prepared;

    // Start TCP servers (like mixed)
    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    for server_config in server_configs {
        let resolver = dns_registry.get_for_server(server_config.dns.as_ref());
        join_handles.extend(start_servers(Config::Server(server_config), resolver).await?);
    }

    // Runs until shutdown. Who closes the descriptor follows from the policy:
    // whoever created the device closes it, and nobody else.
    #[cfg(unix)]
    let result = run_tun_from_config(tun_config, shutdown_rx, policy.close_fd_on_drop()).await;
    #[cfg(not(unix))]
    let result = {
        // Consumed only by the TUN branch, which this platform does not have.
        let _ = policy;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is not supported on this platform",
        ))
    };

    // Cleanup any servers when TUN stops
    for handle in join_handles {
        handle.abort();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn prepare(yaml: &str) -> std::io::Result<PreparedService> {
        current_thread_runtime().block_on(prepare_from_config(yaml, DevicePolicy::BorrowedFd))
    }

    /// A config with no TUN section must fail before anything is spawned, so
    /// the caller gets a verdict instead of a handle that dies moments later.
    #[test]
    fn test_prepare_rejects_a_config_with_no_tun() {
        let err = prepare("---\n[]\n").map(|_| ()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("No TUN config found"));
    }

    /// A TUN section is recognised by device_name or device_fd, so this one is
    /// a TUN config that names no descriptor. The descriptor is the caller's,
    /// so that cannot be run and must be said here rather than inside a task.
    #[test]
    fn test_prepare_rejects_a_tun_without_a_descriptor() {
        let err = prepare("---\n- device_name: tun0\n  address: 10.0.0.2\n")
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.to_string().contains("device_fd"),
            "expected a device_fd complaint, got: {err}"
        );
    }

    /// Two TUN sections have no defined meaning, and silently taking the first
    /// would route a user's traffic somewhere they did not ask for.
    #[test]
    fn test_prepare_rejects_two_tun_configs() {
        let err = prepare("---\n- device_fd: 3\n- device_fd: 4\n")
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.to_string().contains("Multiple TUN configs"),
            "expected a multiple-TUN complaint, got: {err}"
        );
    }
}

#[cfg(all(test, feature = "control-stats"))]
mod outbound_install_tests {
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};

    /// Preparing a service is the commitment to running it, so this is where
    /// the registry is replaced — and where a host's list appears at zero.
    #[tokio::test]
    async fn preparing_a_service_installs_its_outbounds() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        // A TUN section is required, and BorrowedFd is the policy that takes
        // a descriptor from the config. Nothing opens it here -- the device is
        // touched in run_prepared, not in prepare_from_config.
        let yaml = r#"
- device_fd: 3
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Frankfurt
        address: "fra1.example:443"
        protocol: {type: socks}
"#;
        let _prepared = super::prepare_from_config(yaml, super::DevicePolicy::BorrowedFd)
            .await
            .unwrap();

        let names: Vec<String> = snapshot_all().into_iter().map(|o| o.name).collect();
        assert!(names.contains(&"Frankfurt".to_string()), "got {names:?}");
        assert!(names.contains(&"direct".to_string()), "got {names:?}");
    }
}
