# Desktop control API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the service lifecycle now locked inside `src/ffi/common.rs` as a public `shoes::control` module, so a desktop GUI's privileged host can start, stop, observe and stream logs from a tunnel.

**Architecture:** The lifecycle code moves rather than being rewritten — `src/ffi/common.rs` keeps its globals and its C-boundary projections and delegates to `control`. Mobile behaviour is unchanged by construction, and a CI byte-size check on the Android `.so` enforces that the move costs nothing. Additions that hold runtime state (log ring, connection counter) go behind Cargo features that are off by default, because RSS is the budget mobile cannot spare.

**Tech Stack:** Rust 2024 edition, tokio, `parking_lot`, `tokio::sync::broadcast`, existing `crate::logging::LogWriter` sink interface.

**Spec:** `docs/specs/2026-08-24-desktop-control-api.md`

## Global Constraints

- **Cargo is not on `PATH` in the dev environment.** Every task's commands assume you first run:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"`
- **No mobile FFI symbol may be added, removed, or change signature.** `MOBILE.md` lists the contract: 9 `Java_com_shoesproxy_ShoesNative_*` JNI symbols, 10 `shoes_*` C symbols in `include/shoes.h`.
- **New runtime state goes behind a feature, off by default.** `default = []` stays empty. A plain `cargo build` and every mobile build must produce today's bytes.
- **Errors are `std::io::Result`.** Do not introduce a crate error enum.
- **Comments explain *why*, not *what*.** Match the surrounding style: the existing code documents the reasoning behind non-obvious choices (see the `STOP_TIMEOUT` comment in `src/ffi/common.rs`). Preserve every such comment you move.
- **Run the full suite, both feature states, before every commit:**
  `cargo test --locked && cargo test --locked --features ffi`

---

### Task 1: Extract the lifecycle into `shoes::control`

A pure move. No behaviour changes, no new API, no signature changes. The deliverable is that `shoes::control` exists and compiles on every platform, and that the Android `.so` is byte-identical.

**Files:**
- Create: `src/control/mod.rs`
- Modify: `src/lib.rs:110-127` (add `pub mod control;`)
- Modify: `src/ffi/common.rs` (delegate; keep globals)
- Create: `mobile-size-baseline.txt`
- Modify: `.github/workflows/mobile.yml` (add the size check to the `android` job)

**Interfaces:**
- Consumes: nothing.
- Produces: `shoes::control::{PreparedService, ServiceHandle, prepare_from_config, run_prepared, stop_handle}`. `ServiceHandle` has public fields `runtime: tokio::runtime::Runtime`, `shutdown_tx: Option<oneshot::Sender<()>>`, `running: Arc<AtomicBool>` — the same shape as today's `TunServiceHandle`, renamed. Task 2 replaces the public fields with a constructor.

- [ ] **Step 1: Create the module and move the code**

Create `src/control/mod.rs`. Move these items out of `src/ffi/common.rs` **verbatim, including every doc comment**:

- `TunServiceHandle` → rename to `ServiceHandle`
- `STOP_TIMEOUT`, `STOP_POLL_INTERVAL`
- `PreparedService`, `prepare_from_config`, `run_prepared`, `start_from_config`

The stop logic needs one change, because it currently reads a global. Split it: `control::stop_handle(handle: ServiceHandle) -> bool` contains everything after the handle is taken, and `ffi::common::stop_service()` keeps the global-taking half.

```rust
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

use crate::config::{Config, convert_cert_paths, create_server_configs, load_config_str};
use crate::dns::build_dns_registry;
use crate::tcp::tcp_server::start_servers;
#[cfg(unix)]
use crate::tun::run_tun_from_config;

/// Handle to a running service.
pub struct ServiceHandle {
    /// Tokio runtime running the service.
    pub runtime: tokio::runtime::Runtime,
    /// Channel to signal shutdown.
    pub shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flag indicating if service is running.
    pub running: Arc<AtomicBool>,
}

/// How long `stop_handle` waits for the service task to finish.
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often it looks while waiting.
const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
```

Then move `PreparedService`, `prepare_from_config`, `run_prepared` and `start_from_config` across unchanged, and write `stop_handle` as the body of today's `stop_service` from the `if let Some(tx) = handle.shutdown_tx.take()` line onward — including the `shoes-runtime-shutdown` thread and both of its explanatory comments, which encode findings that cost real debugging.

- [ ] **Step 2: Declare the module**

In `src/lib.rs`, after the `pub mod logging;` block at line 118:

```rust
/// Service lifecycle for embedding hosts.
pub mod control;
```

No cfg attribute. This module must exist on every target.

- [ ] **Step 3: Make `ffi::common` delegate**

`src/ffi/common.rs` keeps `LOG_FILE`, `LOGGER_INITIALIZED`, `TUN_SERVICE`, `INITIALIZED`, `LAST_ERROR`, the log-file helpers, and the error helpers. Replace the moved items with re-exports and a thin `stop_service`:

```rust
pub use crate::control::{
    PreparedService, ServiceHandle as TunServiceHandle, prepare_from_config, run_prepared,
    start_from_config,
};

/// Stop the TUN service and wait for shutdown.
///
/// Returns `true` if the service confirmed it stopped, `false` if the wait
/// timed out. The wait is the part that cannot be skipped: it is what
/// guarantees the stack thread has released the TUN descriptor, so the app can
/// close its own copy without racing a thread that is still reading from it.
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
```

The `ServiceHandle as TunServiceHandle` alias means `ios.rs:35` and `android.rs:35` keep importing the name they already import. Do not touch either file in this task.

- [ ] **Step 4: Verify the move changed nothing**

```bash
cargo test --locked && cargo test --locked --features ffi
```

Expected: PASS, including the three existing tests in `src/ffi/common.rs`'s test module (`test_set_and_get_last_error`, `test_clear_last_error`, `test_set_overwrites_previous_error`). Those tests passing unmodified is the direct evidence that mobile behaviour did not change.

```bash
cargo clippy --locked --all-targets -- -D warnings
```

Expected: no new warnings. Note the two pre-existing macOS-only `unused variable: interface` warnings at `src/socket_util.rs:132` and `:234`; those are not yours.

- [ ] **Step 5: Record the size baseline**

Build the Android arm64 library and record its stripped size:

```bash
cargo ndk -t arm64-v8a build --profile release-mobile --lib
stat -f %z target/aarch64-linux-android/release-mobile/libshoes.so
```

Write that number, alone on a line, to `mobile-size-baseline.txt`:

```
# Bytes in target/aarch64-linux-android/release-mobile/libshoes.so.
# CI fails if the built library exceeds this. Raise it deliberately, in a
# commit that says what bought the bytes -- see MOBILE.md for why this budget
# is defended: download size and RSS are separate budgets, and this is the
# download one.
<the number from stat>
```

- [ ] **Step 6: Enforce it in CI**

In `.github/workflows/mobile.yml`, in the `android` job, immediately after the "Build AAR" step, add:

```yaml
      # The desktop control API is meant to cost mobile nothing. This is what
      # turns that intention into something CI can reject, modelled on the AAR
      # verification below: a checked-in number, raised deliberately.
      - name: Check the arm64 library against the size baseline
        run: |
          set -euo pipefail
          so=$(find target -name libshoes.so -path '*aarch64-linux-android*' | head -1)
          [ -n "$so" ] || { echo "libshoes.so not found"; exit 1; }
          actual=$(stat -c %s "$so")
          baseline=$(grep -v '^#' mobile-size-baseline.txt | tr -d '[:space:]')
          echo "arm64 libshoes.so: $actual bytes (baseline $baseline)"
          if [ "$actual" -gt "$baseline" ]; then
            over=$((actual - baseline))
            echo "Over the baseline by $over bytes."
            echo "If the growth is intended, raise mobile-size-baseline.txt in a"
            echo "commit that says what bought the bytes."
            exit 1
          fi
```

Note `stat -c` here and `stat -f` in step 5: the CI runner is Linux, your dev machine is macOS, and the flags differ.

- [ ] **Step 7: Commit**

```bash
git add src/control/mod.rs src/lib.rs src/ffi/common.rs mobile-size-baseline.txt .github/workflows/mobile.yml
git commit -m "control: extract the service lifecycle from the FFI

Moves the lifecycle verbatim into a public shoes::control, so a desktop
host can drive a tunnel without going through the C or JNI boundary. The
FFI keeps its globals and delegates.

No behaviour change, and the size baseline is there to prove it: the
arm64 .so must not grow."
```

---

### Task 2: `control::start()`

`ios.rs` and `android.rs` currently duplicate the whole start sequence — build a runtime, `block_on(prepare_from_config(..))`, spawn `run_prepared`, assemble the handle. This task moves that block into `control` and leaves both FFI files calling it.

**Files:**
- Modify: `src/control/mod.rs`
- Modify: `src/ffi/ios.rs:170-240`
- Modify: `src/ffi/android.rs:274-320`

**Interfaces:**
- Consumes: `control::{PreparedService, ServiceHandle, prepare_from_config, run_prepared}` from Task 1.
- Produces: `control::start(prepared: PreparedService, on_error: impl Fn(String) + Send + 'static) -> std::io::Result<ServiceHandle>`. `ServiceHandle`'s fields become private.

- [ ] **Step 1: Write the failing test**

Add to `src/control/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A config with no TUN section must fail before anything is spawned, so
    /// the caller gets a verdict instead of a handle that dies moments later.
    #[test]
    fn test_prepare_rejects_a_config_with_no_tun() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime
            .block_on(prepare_from_config("---\n- {}\n"))
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// start() owns the runtime it creates, so a handle it returns reports
    /// running until it is stopped.
    #[test]
    fn test_start_reports_running_then_stops() {
        let prepared = prepared_noop_service();
        let handle = start(prepared, |_| {}).unwrap();
        assert!(handle.is_running());
        assert!(stop_handle(handle));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --locked control::tests
```

Expected: FAIL — `cannot find function 'start'`, `cannot find function 'prepared_noop_service'`, `no method named 'is_running'`.

- [ ] **Step 3: Implement `start` and `is_running`**

In `src/control/mod.rs`:

```rust
impl ServiceHandle {
    /// Whether the service task is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Start a prepared service on a runtime of its own.
///
/// `on_error` is called from the service task if the stack stops with an
/// error. The FFI uses it to fill `LAST_ERROR`, which is how a C caller —
/// which cannot receive a Rust enum carrying a String — learns what happened.
///
/// Both FFI platforms built this block themselves and had to keep the two
/// copies in step; it lives here now so there is one of it.
pub fn start(
    prepared: PreparedService,
    on_error: impl Fn(String) + Send + 'static,
) -> std::io::Result<ServiceHandle> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    runtime.spawn(async move {
        match run_prepared(prepared, shutdown_rx).await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                on_error(msg);
            }
        }
        running_clone.store(false, Ordering::SeqCst);
    });

    Ok(ServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
    })
}
```

Add the test helper, in the same `mod tests`:

```rust
    /// A prepared service whose TUN config points at a descriptor that is
    /// valid but carries nothing: enough to exercise the lifecycle without a
    /// real device.
    fn prepared_noop_service() -> PreparedService {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        use std::os::unix::io::IntoRawFd;
        let fd = a.into_raw_fd();
        let yaml = format!(
            "---\n- type: tun\n  device_fd: {fd}\n  address: 10.0.0.2\n  netmask: 255.255.255.0\n"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(prepare_from_config(&yaml)).unwrap()
    }
```

Then make `ServiceHandle`'s three fields private, since `start` is now the only constructor.

- [ ] **Step 4: Run the tests**

```bash
cargo test --locked control::tests
```

Expected: PASS.

- [ ] **Step 5: Rewrite the two FFI call sites**

In `src/ffi/ios.rs`, replace everything from `let runtime = match tokio::runtime::Builder::new_multi_thread()` through the `*guard = Some(handle);` line with:

```rust
    common::clear_last_error();

    // Prepared on the caller's thread, so that a config this process cannot
    // run is reported as a failed start. Doing it inside the spawned task
    // meant shoes_start() returned success and the app had to discover the
    // failure by noticing shoes_is_running() had gone false on its own.
    let prepare_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("shoes_start: failed to create runtime: {}", e);
            return -1;
        }
    };

    let prepared = match prepare_runtime.block_on(common::prepare_from_config(&config_str)) {
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

    let handle = match crate::control::start(prepared, common::set_last_error) {
        Ok(handle) => handle,
        Err(e) => {
            error!("shoes_start: failed to start: {}", e);
            common::set_last_error(e.to_string());
            crate::tun::traffic::clear_traffic_callback();
            crate::socket_protector::clear_global_socket_protector();
            return -1;
        }
    };

    // get_or_init, not get().unwrap(): a caller that reaches shoes_start
    // without shoes_init would otherwise panic across the FFI boundary.
    let mut guard = TUN_SERVICE.get_or_init(|| Mutex::new(None)).lock();
    *guard = Some(handle);

    1
```

Apply the identical change to the corresponding block in `src/ffi/android.rs` (currently lines 274-320), keeping that file's JNI-specific error reporting around it.

- [ ] **Step 6: Verify both FFI surfaces still build and pass**

```bash
cargo test --locked && cargo test --locked --features ffi
cargo clippy --locked --all-targets --features ffi -- -D warnings
```

Expected: PASS, no new warnings.

- [ ] **Step 7: Commit**

```bash
git add src/control/mod.rs src/ffi/ios.rs src/ffi/android.rs
git commit -m "control: own the start sequence

iOS and Android each built the runtime, prepared the config, spawned the
service and assembled the handle themselves, and the two copies had to be
kept in step by hand. control::start() does it once."
```

---

### Task 3: Structured status

Replace "a bool plus a string" with a type a GUI can render.

**Files:**
- Create: `src/control/status.rs`
- Modify: `src/control/mod.rs`
- Modify: `src/tun/traffic.rs:162-169` (un-gate `get_traffic_counters`)

**Interfaces:**
- Consumes: `ServiceHandle` from Task 2.
- Produces: `control::{Status, StopReason, StatusSnapshot}`, and `ServiceHandle::status() -> StatusSnapshot`.

- [ ] **Step 1: Write the failing test**

Add to `src/control/status.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A GUI renders a failure differently from a requested stop, so the two
    /// must not both arrive as "stopped".
    #[test]
    fn test_a_failure_is_distinguishable_from_a_requested_stop() {
        let requested = Status::Stopped {
            reason: StopReason::Requested,
        };
        let failed = Status::Stopped {
            reason: StopReason::Failed("bind: address in use".to_string()),
        };
        assert_ne!(requested, failed);
        assert!(matches!(failed, Status::Stopped { reason: StopReason::Failed(ref m) } if m.contains("address in use")));
    }

    /// Starting is not running: a GUI that cannot tell them apart shows a
    /// connected state while the tunnel is still coming up.
    #[test]
    fn test_starting_is_not_running() {
        assert_ne!(Status::Starting, Status::Running);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --locked control::status
```

Expected: FAIL — `file not found for module 'status'`.

- [ ] **Step 3: Implement the types**

`src/control/status.rs`:

```rust
//! What a host asks the service about itself.
//!
//! The FFI answers with a bool and an optional string, which cannot separate
//! starting from running, or a stop the user asked for from a stack that died.
//! A GUI needs that separation to decide whether to show a red banner.

/// Why a service is no longer running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The host asked it to stop.
    Requested,
    /// The stack returned an error. Carries the message the host displays.
    Failed(String),
}

/// Where a service is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Starting,
    Running,
    Stopping,
    Stopped { reason: StopReason },
}

/// A point-in-time reading. Cheap enough to poll at a GUI's frame rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub status: Status,
    pub uptime: Option<std::time::Duration>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}
```

- [ ] **Step 4: Run the tests**

```bash
cargo test --locked control::status
```

Expected: PASS.

- [ ] **Step 5: Un-gate the traffic getter**

In `src/tun/traffic.rs`, the getter is `#[cfg(test)]` and so does not exist in a real build. Remove that attribute so `StatusSnapshot` can read it:

```rust
/// Get current traffic counters.
///
/// Process-global, not per-service: see the note on `control::start`.
pub fn get_traffic_counters() -> (u64, u64) {
    (
        UPLOAD_BYTES.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
    )
}
```

This is inside `#[cfg(unix)] pub mod tun`, so `ServiceHandle::status()` must fall back to `(0, 0)` on a non-unix target.

- [ ] **Step 6: Wire it to the handle**

In `src/control/mod.rs`, add `mod status; pub use status::{StatusSnapshot, Status, StopReason};` and give `ServiceHandle` two more fields: `started_at: std::time::Instant` and `failure: Arc<parking_lot::Mutex<Option<String>>>`.

`start` must write that field as well as calling the caller's `on_error`, so wrap it rather than passing it straight through. Replace the `on_error(msg)` line inside `start`'s spawned task:

```rust
    let failure = Arc::new(parking_lot::Mutex::new(None));
    let failure_clone = failure.clone();

    runtime.spawn(async move {
        match run_prepared(prepared, shutdown_rx).await {
            Ok(()) => info!("shoes service stopped normally"),
            Err(e) => {
                let msg = e.to_string();
                error!("shoes service error: {}", msg);
                // Recorded for status() as well as handed to the caller: the
                // FFI wants it as a string for LAST_ERROR, a Rust host wants
                // it as StopReason::Failed, and neither should have to poll
                // the other's channel for it.
                *failure_clone.lock() = Some(msg.clone());
                on_error(msg);
            }
        }
        running_clone.store(false, Ordering::SeqCst);
    });
```

Then add:

```rust
impl ServiceHandle {
    /// A point-in-time reading of this service.
    ///
    /// Note that the byte counters are process-global — see the note on
    /// `start` about one service per process.
    pub fn status(&self) -> StatusSnapshot {
        let status = if self.is_running() {
            Status::Running
        } else {
            Status::Stopped {
                reason: match self.failure.lock().clone() {
                    Some(msg) => StopReason::Failed(msg),
                    None => StopReason::Requested,
                },
            }
        };

        #[cfg(unix)]
        let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
        #[cfg(not(unix))]
        let (upload_bytes, download_bytes) = (0, 0);

        StatusSnapshot {
            uptime: self.is_running().then(|| self.started_at.elapsed()),
            status,
            upload_bytes,
            download_bytes,
        }
    }
}
```

Add a doc comment on `start` recording the invariant:

```rust
/// # One service per process
///
/// The traffic counters in `src/tun/traffic.rs` are process-global statics, and
/// `status()` reads them. A second concurrent `ServiceHandle` in one process
/// would therefore report the sum of both. Each privileged host runs exactly
/// one tunnel, so this costs nothing in practice — but it is an invariant this
/// API depends on rather than an accident.
```

- [ ] **Step 7: Run everything and commit**

```bash
cargo test --locked && cargo test --locked --features ffi
```

Expected: PASS.

```bash
git add src/control/status.rs src/control/mod.rs src/tun/traffic.rs
git commit -m "control: report status as a type, not a bool and a string

A host polling is_running() plus get_last_error() cannot tell starting
from running, or a stop it asked for from a stack that died. Both are
things a GUI renders differently."
```

---

### Task 4: `StopOutcome`

`stop_handle` returns `bool`. The two values mean "safe to close your descriptor" and "do not touch that descriptor", which is too much meaning for a bool to carry safely.

**Files:**
- Modify: `src/control/status.rs`
- Modify: `src/control/mod.rs`

**Interfaces:**
- Consumes: `stop_handle` from Task 1.
- Produces: `control::StopOutcome`; `stop_handle(handle: ServiceHandle) -> StopOutcome`; `ServiceHandle::stop(self) -> StopOutcome`.

- [ ] **Step 1: Write the failing test**

Add to `src/control/status.rs`'s test module:

```rust
    /// The two outcomes carry different obligations, so a caller must not be
    /// able to treat them alike by accident.
    #[test]
    fn test_only_released_permits_closing_a_borrowed_descriptor() {
        assert!(StopOutcome::Released.device_released());
        assert!(
            !StopOutcome::TimedOut {
                waited: std::time::Duration::from_secs(5)
            }
            .device_released()
        );
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --locked control::status
```

Expected: FAIL — `cannot find type 'StopOutcome'`.

- [ ] **Step 3: Implement**

In `src/control/status.rs`:

```rust
/// What happened when a service was asked to stop.
///
/// This is not a `Result`. `TimedOut` is a successful report of an unwelcome
/// fact, and typing it as an error would invite a host to `?` it and skip the
/// descriptor decision it exists to force.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// The stack confirmed it released the device. Safe to close a borrowed
    /// descriptor.
    Released,
    /// The wait expired. The device may still be in use, so a borrowed
    /// descriptor must not be closed.
    TimedOut { waited: std::time::Duration },
}

impl StopOutcome {
    /// Whether the host may now close a descriptor it lent to the service.
    pub fn device_released(&self) -> bool {
        matches!(self, StopOutcome::Released)
    }
}
```

Change `stop_handle` to return `StopOutcome`, replacing its `stopped` bool: `StopOutcome::Released` where it currently returns `true`, and `StopOutcome::TimedOut { waited: started.elapsed() }` where it returns `false`. Keep both `info!`/`error!` lines and the `shoes-runtime-shutdown` thread untouched. Add `ServiceHandle::stop(self) -> StopOutcome` that calls it.

- [ ] **Step 4: Keep the FFI boolean**

In `src/ffi/common.rs`, `stop_service()` still returns `bool` — a C caller receives an int. Adapt at the boundary:

```rust
    let stopped = crate::control::stop_handle(handle).device_released();
```

- [ ] **Step 5: Run and commit**

```bash
cargo test --locked && cargo test --locked --features ffi
```

Expected: PASS.

```bash
git add src/control/status.rs src/control/mod.rs src/ffi/common.rs
git commit -m "control: make the stop outcome a type

true and false meant 'safe to close your descriptor' and 'do not touch
that descriptor'. #[must_use] on a named type makes the obligation hard
to discard by accident."
```

---

### Task 5: `DevicePolicy`

The last piece of mobile policy becomes a parameter, so Linux and Windows — which create their own device — can use the same code path.

**Files:**
- Create: `src/control/device.rs`
- Modify: `src/control/mod.rs`
- Modify: `src/ffi/common.rs`

**Interfaces:**
- Consumes: `prepare_from_config` from Task 1.
- Produces: `control::DevicePolicy`; `control::prepare_from_config(config_yaml: &str, policy: DevicePolicy)`; `DevicePolicy::close_fd_on_drop(&self) -> bool`.

- [ ] **Step 1: Write the failing tests**

`src/control/device.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TunConfig;

    /// `TunConfig` derives only Debug/Clone/Deserialize/Serialize -- there is
    /// no Default impl, and several fields get their defaults from serde
    /// attributes rather than from Rust. So build it the way the real code
    /// does, by deserializing.
    fn tun_config(device_fd: Option<i32>) -> TunConfig {
        let fd_line = match device_fd {
            Some(fd) => format!("  device_fd: {fd}\n"),
            None => String::new(),
        };
        let yaml = format!("type: tun\n{fd_line}  address: 10.0.0.2\n");
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn test_borrowed_fd_requires_a_descriptor() {
        let err = validate(&tun_config(None), DevicePolicy::BorrowedFd).unwrap_err();
        assert!(err.to_string().contains("device_fd"));
    }

    #[test]
    fn test_owned_refuses_a_descriptor() {
        // A host that creates its own device but also names a descriptor has
        // two sources and no way to say which wins.
        let err = validate(&tun_config(Some(7)), DevicePolicy::Owned).unwrap_err();
        assert!(err.to_string().contains("device_fd"));
    }

    #[test]
    fn test_each_policy_accepts_its_own_shape() {
        assert!(validate(&tun_config(Some(7)), DevicePolicy::BorrowedFd).is_ok());
        assert!(validate(&tun_config(None), DevicePolicy::Owned).is_ok());
    }

    /// The descriptor is closed by whoever created it. Deriving this from the
    /// policy is the point: as a free parameter it was a constant that one
    /// caller could get wrong, leaking a descriptor or closing a live one.
    #[test]
    fn test_ownership_decides_who_closes() {
        assert!(!DevicePolicy::BorrowedFd.close_fd_on_drop());
        assert!(DevicePolicy::Owned.close_fd_on_drop());
    }
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --locked control::device
```

Expected: FAIL — `file not found for module 'device'`.

- [ ] **Step 3: Implement**

`src/control/device.rs`:

```rust
//! Where the TUN device comes from.
//!
//! Two hosts, two answers. A macOS Network Extension, iOS and Android are each
//! handed a descriptor by the platform and keep ownership of it. Linux and
//! Windows are handed nothing and create the device themselves.
//!
//! `TunConfig` already describes a device, so this is not another description
//! of one — it is which shapes of `TunConfig` a given host can honour.

/// Who owns the TUN device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePolicy {
    /// The host hands over a descriptor it owns and will close itself.
    /// macOS Network Extension, iOS, Android.
    BorrowedFd,
    /// shoes creates the device and owns it. Linux, and Windows once the
    /// wintun backend lands.
    Owned,
}

impl DevicePolicy {
    /// Whether the service closes the descriptor when it is done with it.
    ///
    /// Derived rather than configured: the owner closes, and nobody else.
    pub fn close_fd_on_drop(&self) -> bool {
        matches!(self, DevicePolicy::Owned)
    }
}

/// Check a TUN config against what this host can provide.
pub fn validate(
    config: &crate::config::TunConfig,
    policy: DevicePolicy,
) -> std::io::Result<()> {
    match policy {
        DevicePolicy::BorrowedFd if config.device_fd.is_none() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN config missing device_fd - must be injected by caller",
        )),
        DevicePolicy::Owned if config.device_fd.is_some() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN config sets device_fd, but this host creates its own device",
        )),
        _ => Ok(()),
    }
}
```

- [ ] **Step 4: Run the tests**

```bash
cargo test --locked control::device
```

Expected: PASS.

- [ ] **Step 5: Thread the policy through**

In `src/control/mod.rs`, give `prepare_from_config` the second parameter, replace its inline `device_fd.is_none()` check with `device::validate(&tc, policy)?`, keep the multiple-TUN rejection exactly as it is (it applies under both policies — a second TUN has no defined meaning either way), and store the policy on `PreparedService`. In `run_prepared`, replace the hard-coded `false`:

```rust
    #[cfg(unix)]
    let result = run_tun_from_config(tun_config, shutdown_rx, policy.close_fd_on_drop()).await;
```

In `src/ffi/common.rs`, keep the FFI's own zero-argument shape so `ios.rs` and `android.rs` need no edit:

```rust
/// Parse and validate a config for a mobile host, which is always handed a
/// descriptor by the platform.
pub async fn prepare_from_config(config_yaml: &str) -> std::io::Result<PreparedService> {
    crate::control::prepare_from_config(config_yaml, crate::control::DevicePolicy::BorrowedFd).await
}
```

- [ ] **Step 6: Update the call sites Task 2 wrote**

`prepare_from_config` gained a parameter, so the two tests added in Task 2 no longer compile. In `src/control/mod.rs`'s test module, pass the policy explicitly:

```rust
        let err = runtime
            .block_on(prepare_from_config("---\n- {}\n", DevicePolicy::BorrowedFd))
            .unwrap_err();
```

and in `prepared_noop_service`:

```rust
        runtime
            .block_on(prepare_from_config(&yaml, DevicePolicy::BorrowedFd))
            .unwrap()
```

- [ ] **Step 7: Run and commit**

```bash
cargo test --locked && cargo test --locked --features ffi
```

Expected: PASS. The mobile path is byte-for-byte the same decisions it made before, now spelled as `BorrowedFd`.

```bash
git add src/control/device.rs src/control/mod.rs src/ffi/common.rs
git commit -m "control: make device ownership a parameter

prepare_from_config demanded a device_fd because mobile always has one,
and run_prepared passed close_fd_on_drop = false as a constant. Linux and
Windows invert both. Deriving the flag from the policy also closes the
case where a caller sets it wrong and either leaks a descriptor or closes
a live one."
```

---

### Task 6: The macOS C API

**Files:**
- Modify: `src/ffi/mod.rs:50-56`
- Modify: `.github/workflows/mobile.yml`

**Interfaces:**
- Consumes: everything above.
- Produces: the ten `shoes_*` symbols on macOS targets.

- [ ] **Step 1: Widen the cfg**

In `src/ffi/mod.rs`, both the module declaration and its re-export:

```rust
// macOS as well as iOS: a Network Extension provider on macOS receives its
// descriptor from packetFlow exactly as on iOS, so it wants the same C API.
// The desktop GUI's privileged host is that provider.
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::*;
```

- [ ] **Step 2: Verify it builds on macOS**

```bash
cargo build --locked --features ffi
nm -gU target/debug/libshoes.dylib | grep -c '_shoes_'
```

Expected: builds; the count is 10.

If the build fails on an iOS-only assumption inside `ios.rs`, fix it there and note it in the commit — the module has never been compiled for macOS, so this step is a real check rather than a formality.

- [ ] **Step 3: Add the CI job**

In `.github/workflows/mobile.yml`, add alongside the `ios` job:

```yaml
  macos:
    name: Build macOS staticlib
    runs-on: macos-latest
    timeout-minutes: 45

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable
        with:
          targets: aarch64-apple-darwin

      - name: Cache Rust build
        uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2
        with:
          key: macos

      # The Network Extension provider for the desktop client is Swift, so it
      # consumes the same C API as iOS. Building it here means a change to the
      # FFI cannot break the macOS host without CI noticing.
      - name: Build staticlib
        run: cargo build --locked --release --features ffi --target aarch64-apple-darwin

      - name: Verify the C symbols are present
        run: |
          set -euo pipefail
          lib=target/aarch64-apple-darwin/release/libshoes.a
          count=$(nm -gU "$lib" | grep -c '_shoes_' || true)
          echo "$count shoes_* symbols"
          [ "$count" -ge 10 ] || { echo "Expected at least 10, found $count"; exit 1; }
```

- [ ] **Step 4: Commit**

```bash
git add src/ffi/mod.rs .github/workflows/mobile.yml
git commit -m "ffi: build the C API for macOS too

A macOS Network Extension provider gets its descriptor from packetFlow
exactly as iOS does, so it wants the same ten symbols. No new code: the
consuming path at src/tun/mod.rs:470 already has a macos arm."
```

---

### Task 7: Log streaming behind `control-logs`

**Files:**
- Create: `src/control/logs.rs`
- Modify: `src/control/mod.rs`
- Modify: `Cargo.toml:20-23`
- Modify: `.github/workflows/test.yml` (desktop feature column, plus a Windows check job)

**Interfaces:**
- Consumes: `crate::logging::LogWriter`.
- Produces: `control::logs::{BroadcastLogWriter, LogLine}` under `feature = "control-logs"`. `BroadcastLogWriter::new(capacity: usize)`, `subscribe(&self) -> (Vec<LogLine>, broadcast::Receiver<LogLine>)`.

- [ ] **Step 1: Add the features**

In `Cargo.toml`:

```toml
[features]
default = []
ffi = []  # Enable FFI module for non-Android builds
# Both of these hold runtime state, and RSS is the budget a phone cannot
# spare -- see MOBILE.md, where the per-connection figures are measured. They
# are separate flags rather than one `desktop` so each cost stays attributable:
# an iOS extension could take stats without inheriting a log buffer.
control-stats = []
control-logs = []
desktop = ["control-stats", "control-logs"]
```

- [ ] **Step 2: Write the failing tests**

`src/control/logs.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;

    fn line(message: &str) -> LogLine {
        LogLine {
            level: Level::Info,
            target: "shoes".to_string(),
            message: message.to_string(),
            at: std::time::SystemTime::now(),
        }
    }

    /// A GUI that attaches after the tunnel started still needs to see why it
    /// failed, so the backlog is retained rather than only streamed.
    #[test]
    fn test_a_late_subscriber_receives_the_backlog() {
        let writer = BroadcastLogWriter::new(4);
        writer.push(line("first"));
        writer.push(line("second"));

        let (backlog, _rx) = writer.subscribe();
        assert_eq!(backlog.len(), 2);
        assert_eq!(backlog[0].message, "first");
    }

    /// The ring is what makes the RSS cost a number the host chose, so it must
    /// not grow past it.
    #[test]
    fn test_the_ring_does_not_grow_past_its_capacity() {
        let writer = BroadcastLogWriter::new(2);
        for i in 0..10 {
            writer.push(line(&format!("line {i}")));
        }

        let (backlog, _rx) = writer.subscribe();
        assert_eq!(backlog.len(), 2);
        assert_eq!(backlog[1].message, "line 9");
    }

    /// write_log runs on arbitrary threads, including inside the packet path.
    /// A subscriber that stops reading must lose lines rather than stall it.
    #[test]
    fn test_a_stalled_subscriber_does_not_block_the_writer() {
        let writer = BroadcastLogWriter::new(2);
        let (_backlog, _rx) = writer.subscribe();
        for i in 0..1000 {
            writer.push(line(&format!("line {i}")));
        }
        // Reaching here without blocking is the assertion.
    }
}
```

- [ ] **Step 3: Run to verify they fail**

```bash
cargo test --locked --features control-logs control::logs
```

Expected: FAIL — `file not found for module 'logs'`.

- [ ] **Step 4: Implement**

`src/control/logs.rs`:

```rust
//! A log sink a host can subscribe to.
//!
//! `MultiLogger` already dispatches each formatted line to a list of
//! `LogWriter`s, so this is one more sink rather than a change to logging.
//!
//! Note what this sink is not: a privileged view. It sees exactly what the
//! `Directive` filtering lets every other sink see, and enabling it must not
//! raise the global level. Anything that must not reach a log file must not
//! reach a log line at all -- redaction belongs at the call site, not here.

use std::collections::VecDeque;

use log::{Level, Record};
use parking_lot::Mutex;
use tokio::sync::broadcast;

/// One log line, already formatted, with its metadata kept separate so a GUI
/// can filter by level without parsing text back out.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: Level,
    pub target: String,
    pub message: String,
    pub at: std::time::SystemTime,
}

/// Retains a bounded backlog and broadcasts to live subscribers.
pub struct BroadcastLogWriter {
    ring: Mutex<VecDeque<LogLine>>,
    capacity: usize,
    tx: broadcast::Sender<LogLine>,
}

impl BroadcastLogWriter {
    /// `capacity` lines are retained for subscribers that attach later.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            tx,
        }
    }

    /// The retained backlog, and a receiver for everything after it.
    pub fn subscribe(&self) -> (Vec<LogLine>, broadcast::Receiver<LogLine>) {
        // Subscribe before copying the backlog, so a line written between the
        // two arrives on the receiver rather than falling in the gap.
        let rx = self.tx.subscribe();
        let backlog = self.ring.lock().iter().cloned().collect();
        (backlog, rx)
    }

    pub(crate) fn push(&self, line: LogLine) {
        {
            let mut ring = self.ring.lock();
            if ring.len() == self.capacity {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        // Ignored deliberately: no subscribers, or a subscriber that has
        // fallen behind, must not stall a thread that is moving packets.
        let _ = self.tx.send(line);
    }
}

impl crate::logging::LogWriter for BroadcastLogWriter {
    fn write_log(&self, record: &Record, formatted: &str) {
        self.push(LogLine {
            level: record.level(),
            target: record.target().to_string(),
            message: formatted.to_string(),
            at: std::time::SystemTime::now(),
        });
    }

    fn flush(&self) {}
}
```

In `src/control/mod.rs`:

```rust
#[cfg(feature = "control-logs")]
pub mod logs;
```

- [ ] **Step 5: Run the tests**

```bash
cargo test --locked --features control-logs control::logs
```

Expected: PASS, and the stalled-subscriber test returns rather than hanging.

- [ ] **Step 6: Prove the feature is off by default**

```bash
cargo test --locked && cargo build --locked
```

Expected: PASS, and `src/control/logs.rs` is not compiled.

- [ ] **Step 7: Add the CI columns**

In `.github/workflows/test.yml`, after the FFI step:

```yaml
      # The desktop host builds with these; nothing else should. Running both
      # ends of the matrix is what keeps `default = []` honest.
      - name: Run tests with the desktop control surface enabled
        run: cargo test --locked --features desktop
```

Then add a Windows job to the same file. This is not optional polish: `src/lib.rs:123` gates the TUN module on `cfg(unix)`, so the `#[cfg(not(unix))]` fallbacks in `ServiceHandle::status` and `stats::snapshot` are compiled by **nothing** in CI today — `build.yml` has both Windows targets commented out. An untested `cfg` branch is an unwritten one.

```yaml
  windows-check:
    name: Check Windows build
    runs-on: windows-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable

      - name: Cache Rust build
        uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2
        with:
          key: windows-check

      # cargo check, not test: TUN is unsupported on Windows until the wintun
      # backend lands, so there is nothing to run yet. What matters now is that
      # shoes::control and its cfg(not(unix)) arms compile at all -- they are
      # the reason the desktop GUI can target Windows before the tunnel can.
      - name: Check with the desktop control surface
        run: cargo check --locked --features desktop
```

- [ ] **Step 8: Commit**

```bash
git add src/control/logs.rs src/control/mod.rs Cargo.toml .github/workflows/test.yml
git commit -m "control: add a subscribable log sink behind control-logs

MultiLogger already takes a list of sinks, so this is one more of them.
Bounded, because that is what makes the memory cost a number the host
picked; non-blocking, because write_log runs on the packet path.

Off by default: it holds runtime state, and RSS is the budget mobile
cannot spare."
```

---

### Task 8: Active connections behind `control-stats`

**Files:**
- Create: `src/control/stats.rs`
- Modify: `src/control/mod.rs`
- Modify: `src/tun/tcp_stack_direct.rs:700` and `:871`

**Interfaces:**
- Consumes: `StatusSnapshot` from Task 3.
- Produces: `control::stats::{StatsSnapshot, snapshot}` under `feature = "control-stats"`.

- [ ] **Step 1: Write the failing test**

`src/control/stats.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The count has to come back down, or a GUI shows a number that only
    /// ever grows and means nothing after an hour.
    #[test]
    fn test_the_count_rises_and_falls() {
        reset_active_connections();
        assert_eq!(snapshot().active_connections, 0);

        connection_opened();
        connection_opened();
        assert_eq!(snapshot().active_connections, 2);

        connection_closed();
        assert_eq!(snapshot().active_connections, 1);

        connection_closed();
        assert_eq!(snapshot().active_connections, 0);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --locked --features control-stats control::stats
```

Expected: FAIL — `file not found for module 'stats'`.

- [ ] **Step 3: Implement**

`src/control/stats.rs`:

```rust
//! Counters a host displays.
//!
//! Deliberately thin. The figure a GUI server list really wants is bytes per
//! configured outbound, and there is no key to hang that on: outbound client
//! configs carry no name or label field, so the only candidate is an address,
//! which is neither stable across config edits nor meaningful to a user.
//! Adding outbound labels is a config schema change that reaches mobile and
//! belongs in its own spec.

use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// A point-in-time reading of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
}

pub(crate) fn connection_opened() {
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn connection_closed() {
    // saturating, not wrapping: a close without a matching open would
    // otherwise show a GUI 18 quintillion live connections.
    let _ = ACTIVE_CONNECTIONS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(1))
    });
}

#[cfg(test)]
pub(crate) fn reset_active_connections() {
    ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);
}

/// Read the counters.
pub fn snapshot() -> StatsSnapshot {
    #[cfg(unix)]
    let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
    #[cfg(not(unix))]
    let (upload_bytes, download_bytes) = (0, 0);

    StatsSnapshot {
        upload_bytes,
        download_bytes,
        active_connections: ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
    }
}
```

In `src/control/mod.rs`:

```rust
#[cfg(feature = "control-stats")]
pub mod stats;
```

- [ ] **Step 4: Run the test**

```bash
cargo test --locked --features control-stats control::stats
```

Expected: PASS.

- [ ] **Step 5: Call it from the stack**

The stack already tracks this set; these two sites are where it changes. In `src/tun/tcp_stack_direct.rs`, after the insert at line 700:

```rust
                                        active_connections.insert((src_addr, dst_addr));
                                        #[cfg(feature = "control-stats")]
                                        crate::control::stats::connection_opened();
```

and after the remove at line 871:

```rust
                active_connections.remove(&(socket_info.src_addr, socket_info.dst_addr));
                #[cfg(feature = "control-stats")]
                crate::control::stats::connection_closed();
```

Both sites are already off the per-packet path — one runs on a SYN, the other on cleanup — so a relaxed atomic there is not measurable.

- [ ] **Step 6: Verify both feature states**

```bash
cargo test --locked && cargo test --locked --features ffi && cargo test --locked --features desktop
cargo clippy --locked --all-targets --features desktop -- -D warnings
```

Expected: PASS, no new warnings.

- [ ] **Step 7: Commit**

```bash
git add src/control/stats.rs src/control/mod.rs src/tun/tcp_stack_direct.rs
git commit -m "control: count active connections behind control-stats

The stack already maintains the set; this exposes its size. Per-outbound
bytes would need a stable key per outbound, and client configs carry no
label field -- that is a schema change, and its own spec."
```

---

## Verification of the whole

After Task 8, confirm the plan's central claim — that mobile paid nothing:

```bash
cargo ndk -t arm64-v8a build --profile release-mobile --lib
stat -f %z target/aarch64-linux-android/release-mobile/libshoes.so
```

Expected: at or below the number in `mobile-size-baseline.txt`. If it is above, the growth came from a task that was supposed to be feature-gated — find it before raising the baseline.

Then confirm the FFI contract is intact, per `MOBILE.md`:

```bash
cargo build --locked --features ffi
nm -gU target/debug/libshoes.dylib | grep '_shoes_' | wc -l   # expect 10
```

And that the three feature states all build, which is the whole matrix this
plan supports:

```bash
cargo test --locked                      # default: mobile's bytes
cargo test --locked --features ffi       # the mobile FFI surface
cargo test --locked --features desktop   # the desktop host surface
```
