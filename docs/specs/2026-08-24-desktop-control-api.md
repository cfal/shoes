# Desktop control API

Promote the service lifecycle now locked inside `src/ffi/common.rs` into a
first-class `shoes::control` module, so that a desktop GUI's privileged host —
a macOS Network Extension, a Windows service, a Linux daemon — can start, stop,
observe and stream logs from a tunnel through one supported surface.

Written 2026-08-24 against `mobile` at `367cff0`. Sub-project #1 of the desktop
client; see [Deliberately out of scope](#deliberately-out-of-scope) for the
other six.

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [Why the GUI never links the runtime](#why-the-gui-never-links-the-runtime)
- [Module layout](#module-layout)
- [Size discipline](#size-discipline)
- [ServiceHandle](#servicehandle)
- [Status and stop outcomes](#status-and-stop-outcomes)
- [Device-source policy](#device-source-policy)
- [Statistics](#statistics)
- [Log streaming](#log-streaming)
- [What the FFI keeps](#what-the-ffi-keeps)
- [macOS C API](#macos-c-api)
- [Error handling](#error-handling)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Order of work](#order-of-work)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

The library cannot start a proxy. `start_servers` is `pub`, but it lives at
`src/tcp/tcp_server.rs:275` behind `mod tcp;` — private, declared at
`src/lib.rs:101`. An external crate that depends on `shoes` can parse and
validate a config and can do nothing with the result.

The lifecycle that a host actually needs does exist, and it is good code. It
is in `src/ffi/common.rs`: `prepare_from_config` parses, validates and builds
DNS resolvers on the calling thread so a bad config fails in front of the
caller; `run_prepared` starts the TCP servers and then the TUN; `stop_service`
signals shutdown, waits for the stack thread to confirm it released the TUN
descriptor, and drops the runtime on a thread of its own so a wedged blocking
task cannot park the caller's main thread.

Three things keep that code away from a desktop host.

**It is compiled out.** `src/ffi/mod.rs` gates the module as
`#[cfg(any(target_os = "android", target_os = "ios", test))]`. On a desktop
target it does not exist.

**Its policy is mobile's.** `prepare_from_config` rejects a config whose TUN
section has no `device_fd` — "must be injected by caller" — and rejects more
than one TUN because "only one is allowed for mobile". `run_prepared` passes
`close_fd_on_drop = false` as a constant, commented "mobile owns the FD".
Linux and Windows invert the first rule: nobody hands them a descriptor, so
shoes creates the device and must close it.

**It answers questions a GUI cannot use.** State is a `bool` from
`is_service_running()` plus an `Option<String>` from `get_last_error()`. A
caller polling that pair cannot distinguish starting from running, or a
requested stop from a stack that died. There is no way to subscribe to logs,
and the only traffic figures are two process-global counters.

## Scope

In scope, all of it inside this repository:

- a `src/control/` module holding the lifecycle, public on every platform;
- `ServiceHandle`, an owned handle replacing global singletons for non-FFI
  callers;
- structured `Status` and `StopOutcome` types;
- `DevicePolicy`, making the borrowed-versus-owned descriptor question a
  parameter instead of a hard-coded mobile assumption;
- feature-gated statistics and log streaming, off by default;
- widening the cfg on `src/ffi/ios.rs` so macOS builds the same C API the
  Swift Network Extension provider will call.

Out of scope is listed at the end, and includes two things that are shoes-side
and genuinely needed later: the Windows wintun backend, and share-link parsing.

## Why the GUI never links the runtime

Worth stating up front, because it removes a decision people expect to make.

The desktop client uses a macOS Network Extension. An NE provider is a separate
process by Apple's design, and the TUN descriptor arrives inside it — the GUI
process can never hold it. Windows is the same shape: the descriptor belongs to
the service running as SYSTEM. Linux likewise.

So on all three platforms the proxy runs in the privileged host, never in the
Tauri process. This module's consumers are those three hosts. The GUI links
`shoes` only for `config::load_config_str` and `config::create_server_configs`,
which are already public (`src/config/mod.rs:97`, `src/config/validate.rs:54`)
and need no runtime, no privilege and no changes.

One consequence shapes the API: the macOS consumer is Swift, so it consumes the
C FFI, while the Windows and Linux consumers are Rust and want typed calls.
`shoes::control` is the Rust surface; `src/ffi/ios.rs` is the C projection of
it.

## Module layout

```
src/control/
  mod.rs      ServiceHandle, start(), prepare(), DevicePolicy   unconditional
  status.rs   Status, StopReason, StopOutcome, StatusSnapshot   unconditional
  stats.rs    counters beyond the existing two                  feature control-stats
  logs.rs     BroadcastLogWriter and subscriptions              feature control-logs
```

`src/lib.rs` gains `pub mod control;` with no cfg attribute. `src/ffi/common.rs`
keeps its file, its globals and its mobile policy checks, and delegates each of
them to `control`.

The lifecycle code moves rather than being rewritten. In particular the
shutdown sequence — the `STOP_TIMEOUT` poll and the named
`shoes-runtime-shutdown` thread — is transplanted unchanged. It encodes two
findings that cost real debugging, and reimplementing it would lose them.

## Size discipline

`MOBILE.md` already established the two budgets this module has to respect, and
they behave differently:

- **Download size.** Code bytes. `MOBILE.md` measured that dropping every
  protocol an awg+vless client cannot reach frees about 1.0 MiB of a 9.4 MB
  `libshoes.so`, and declined it because the feature-combination CI matrix cost
  more than the megabyte was worth.
- **RSS.** Dominated by per-connection buffers, not code — about 1.31 MB per
  TCP connection, roughly 35 connections inside an iOS extension's ~50 MB
  jetsam limit.

Relocating `ffi::common` touches neither: it is the same code in a different
file. The additions are what need care, and they split cleanly. `Status`,
`StopOutcome` and `DevicePolicy` are plain enums over state that already
exists, costing a handful of bytes and no allocation. Per-outbound statistics
and a log ring buffer hold **runtime state**, and therefore cost RSS on exactly
the platform that cannot afford it.

So: relocation is unconditional, anything with runtime state is gated.

```toml
[features]
default = []
ffi = []
control-stats = []            # counters beyond the existing two; costs RSS
control-logs = []             # bounded in-memory log ring; costs RSS
desktop = ["control-stats", "control-logs"]
```

Two features rather than one `desktop` flag, so each RSS cost stays
individually attributable — if the iOS extension ever wants per-outbound
figures it can take them without inheriting a log buffer. Supported
combinations remain few: mobile builds `--no-default-features`, desktop hosts
build `--features desktop`, and CI covers those two plus the existing default.
That is two extra columns, not the combinatorial matrix `MOBILE.md` warned
about.

The precedent for gating this way is already in the tree: `feature = "ffi"`
guards `src/lib.rs:126` and `src/config/mod.rs:95`.

**Acceptance criterion.** Build the `release-mobile` arm64 `.so` before and
after the relocation and require a delta of zero bytes. The relocation should
not move a single byte, so any delta is a signal that something leaked into the
mobile build, and CI should say so rather than leaving it to inspection.

## ServiceHandle

```rust
/// A running service. Dropping the handle stops the service, but prefer
/// `stop()` — a drop cannot report whether the TUN descriptor was released.
pub struct ServiceHandle { /* runtime, shutdown_tx, running, started_at */ }

/// Parse, validate, and build resolvers. Fails in front of the caller.
pub async fn prepare(
    config_yaml: &str,
    policy: DevicePolicy,
) -> std::io::Result<PreparedService>;

/// Start a prepared service. Returns once the servers are bound and the
/// stack thread is running.
pub fn start(prepared: PreparedService) -> std::io::Result<ServiceHandle>;

impl ServiceHandle {
    pub fn status(&self) -> StatusSnapshot;
    /// Consumes the handle. See `StopOutcome`.
    pub fn stop(self) -> StopOutcome;
}
```

Splitting `prepare` from `start` is not new — it is the existing
`PreparedService` contract, whose doc comment explains the reasoning: every
failure a bad config can produce, from YAML syntax to an unusable key to a
resolver that will not build, happens in front of the caller rather than inside
a spawned task whose error the host learns about only by polling and finding
the service already stopped. That property is preserved verbatim.

### One service per process

`StatusSnapshot` reads the traffic counters in `src/tun/traffic.rs`, which are
process-global statics (`UPLOAD_BYTES`, `DOWNLOAD_BYTES`). A second concurrent
`ServiceHandle` in one process would therefore report the sum of both services.

Each privileged host runs exactly one tunnel, so this costs nothing in
practice, but it is an invariant the API depends on rather than an accident.
It is documented on `start()`. Making the counters per-handle would touch every
call site on the hot path and is not done here.

## Status and stop outcomes

```rust
pub enum Status {
    Starting,
    Running,
    Stopping,
    /// Down. `reason` separates a requested stop from a stack that died on
    /// its own: the GUI shows a red banner for the second and nothing for
    /// the first.
    Stopped { reason: StopReason },
}

pub enum StopReason {
    Requested,
    /// The stack returned an error. Carries the message the host displays.
    Failed(String),
}

pub struct StatusSnapshot {
    pub status: Status,
    pub uptime: Option<std::time::Duration>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}
```

`StopOutcome` preserves a distinction the current code already draws and that a
host must not lose. `stop_service` returns `bool`: `true` means the stack
thread confirmed it released the TUN descriptor, `false` means the five-second
wait expired and, in the existing code's own words, "the TUN descriptor may
still be in use."

That is the difference between *safe to close your descriptor* and *do not
touch that descriptor*, so it stays a two-variant type rather than collapsing
into `Result<()>`:

```rust
pub enum StopOutcome {
    /// The stack confirmed it released the device. Safe to close a borrowed
    /// descriptor.
    Released,
    /// The wait expired. The device may still be in use; a borrowed
    /// descriptor must not be closed.
    TimedOut { waited: std::time::Duration },
}
```

`StopOutcome` is marked `#[must_use]`. It carries a safety obligation rather
than merely a result, so discarding it silently is the mistake the type exists
to prevent.

## Device-source policy

The two mobile assumptions become one parameter. `TunConfig`
(`src/config/types/tun.rs:52`) already carries `device_name`, `device_fd`,
`address`, `netmask`, `destination` and `mtu`, so no new type is needed to
*describe* a device — config stays the single source of truth. What varies per
host is only which shapes of `TunConfig` are acceptable.

```rust
pub enum DevicePolicy {
    /// The host hands over a descriptor it owns and will close itself.
    /// macOS Network Extension, iOS, Android.
    ///
    /// `device_fd` is required; exactly one TUN config is allowed.
    BorrowedFd,
    /// shoes creates the device and owns it. Linux, and Windows once the
    /// wintun backend lands.
    ///
    /// `device_fd` must be absent. `address` and `netmask` become
    /// load-bearing rather than informational.
    Owned,
}
```

The payoff is that `close_fd_on_drop` stops being a constant and falls out of
the policy — `BorrowedFd` implies `false`, `Owned` implies `true`. That closes
a real bug class: today a caller passing the wrong flag either leaks a
descriptor or closes one the host still holds, and nothing objects.

Validation moves out of `prepare_from_config`'s body and into a function over
`(TunConfig, DevicePolicy)`, which makes it directly testable without starting
anything. The FFI passes `BorrowedFd` and gets byte-identical behaviour to
today, single-TUN check included.

Wintun attaches here later, either as a third variant or as an `Owned`
sub-case, without reopening `start()` or `ServiceHandle`.

## Statistics

Behind `control-stats`. Scope here is deliberately narrow, because the obvious
richer version is blocked on something that does not exist yet.

**What ships.** An active-connection count alongside the two byte totals.
`src/tun/tcp_stack_direct.rs:612` already maintains an
`active_connections: HashSet<(SocketAddr, SocketAddr)>` and inserts and removes
from it at `:700` and `:871`; exposing its length costs one atomic store at two
sites already on a cold path, and no new allocation.

```rust
pub struct StatsSnapshot {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
}
```

**What does not ship, and why.** A per-outbound breakdown — bytes per
configured server, which is what a GUI server list wants — needs a stable key
per outbound. There is none: outbound client configs in
`src/config/types/client.rs` carry no name or label field, so the only
available key is an address, which is neither stable across config edits nor
meaningful to show a user.

Adding outbound labels is a config schema change that reaches mobile and
deserves its own spec. Until then a per-outbound breakdown would either invent
a key that changes under the user or ship a schema change through the back
door. It is deferred, and the GUI shows totals.

## Log streaming

Behind `control-logs`. `src/logging.rs` makes this small: `MultiLogger`
dispatches each pre-formatted line to a list of `LogWriter` sinks, and
`init_multi_logger(writers, directives)` takes that list. A GUI stream is one
more sink, not a change to the logging core.

```rust
pub struct BroadcastLogWriter { /* bounded ring + broadcast sender */ }

impl BroadcastLogWriter {
    /// `capacity` lines are retained for late subscribers.
    pub fn new(capacity: usize) -> Self;
    /// Returns the retained backlog and a receiver for subsequent lines.
    pub fn subscribe(&self) -> (Vec<LogLine>, tokio::sync::broadcast::Receiver<LogLine>);
}

impl crate::logging::LogWriter for BroadcastLogWriter { /* ... */ }
```

Three constraints come from where `write_log` runs. It is called from arbitrary
threads, including inside the packet path, so it must not block: the broadcast
send is non-blocking and a receiver that falls behind loses lines rather than
stalling the writer. The ring is **bounded**, which is what makes the RSS cost
a number the host picks rather than a leak. And `LogWriter::write_log` receives
an already-formatted `&str`, so this sink does no formatting of its own.

`LogLine` carries level, target, message and a timestamp, so a GUI can filter
by level without re-parsing text — the failure mode JBCentralGUI lives with,
where the data path parses ANSI-coloured CLI output.

## What the FFI keeps

`src/ffi/common.rs` is not deleted. Mobile addresses its service by an integer
handle across a C boundary, so it needs its `OnceLock` singletons; they stay
exactly where they are. `TUN_SERVICE` comes to hold a `control::ServiceHandle`
instead of the local `TunServiceHandle`, and each of `start_from_config`,
`stop_service`, `is_service_running` and `get_last_error` becomes a thin
adapter over `control`.

`LAST_ERROR` also stays, as the C-boundary projection of `StopReason::Failed`:
a C caller cannot receive an enum with a `String` payload, so the FFI keeps
flattening it into a retrievable message.

The contract this preserves is checkable rather than asserted. `MOBILE.md`
lists the entry points — nine `Java_com_shoesproxy_ShoesNative_*` JNI symbols
and ten `shoes_*` C symbols declared in `include/shoes.h`. None is added,
removed or changed in signature.

## macOS C API

`src/ffi/mod.rs` gates the iOS module as `#[cfg(target_os = "ios")]`. macOS
gets the same treatment: `#[cfg(any(target_os = "ios", target_os = "macos"))]`.

This is nearly the whole macOS story. An NE provider on macOS receives a
descriptor from `packetFlow` exactly as on iOS, and the code that consumes it
— `TunServerConfig::raw_fd`, and the `#[cfg(any(target_os = "ios", target_os
= "macos"))]` arm already present at `src/tun/mod.rs:470` — is written and
shipping. What is required is the cfg widening, a macOS entry in the cbindgen
run that produces `include/shoes.h`, and a CI job that builds the macOS
`staticlib`.

Note what is *not* required: a macOS arm in `create_sync_device`
(`src/tun/tun_server.rs:247`, today `linux`/`ios`/`android`). That function
creates a device, and under `DevicePolicy::BorrowedFd` macOS never does.

## Error handling

Errors stay `std::io::Result`, matching the rest of the crate; introducing a
crate error enum here would be a change of a different kind, applied to one
module.

Failures divide by when they happen, and the division is the reason `prepare`
exists:

- **Before start.** Config parse, validation, device-policy mismatch, resolver
  construction. Returned from `prepare` as `Err`, on the caller's thread,
  with nothing started.
- **During start.** A port already bound, a device that will not open.
  Returned from `start` as `Err`; any servers already started are aborted
  before returning, as `run_prepared` does today.
- **After start.** The stack thread dies. Surfaced through
  `Status::Stopped { reason: StopReason::Failed(msg) }` on the next
  `status()`, and to C callers through `LAST_ERROR` unchanged.

`TimedOut` from `stop` is not an error. It is a successful report of an
unwelcome fact, and typing it as `Err` would invite a host to `?` it and skip
the descriptor-handling decision it exists to force.

## Security notes

Log streaming is a new exposure path and should be treated as one. Lines that
were previously written to a file readable only by a privileged process will
now cross an IPC boundary to a user-session GUI. This fork has already had to
fix REALITY key material reaching the log, so the risk is demonstrated rather
than hypothetical.

Two rules follow, and they belong in the IPC spec as much as this one:

- The broadcast sink is subject to the same `Directive` level filtering as
  every other sink. It does not get a privileged view, and in particular
  enabling it must not raise the global level.
- Whatever must not appear in a log file must not appear in a log line, full
  stop. The sink is not the place to add redaction; a line that needs
  redacting is a bug at its call site.

## Testing

The relocation's correctness argument is that behaviour is unchanged, so the
tests are mostly about pinning behaviour that exists.

- **Device policy**, unit tests over `(TunConfig, DevicePolicy)` with nothing
  started: `BorrowedFd` without `device_fd` is refused; `Owned` with
  `device_fd` is refused; two TUN configs are refused under both; the derived
  `close_fd_on_drop` is `false` for `BorrowedFd` and `true` for `Owned`.
- **Status transitions**: a service reports `Running` after `start`, and
  `Stopped { Requested }` after `stop`. A prepare-time failure leaves nothing
  started and returns `Err` rather than transitioning at all.
- **Stop outcome**: `Released` on a clean stop. `TimedOut` is asserted against
  a stack stub that ignores the shutdown signal, so the five-second path is
  covered without a five-second test — the timeout is a constant the test can
  shorten.
- **The existing FFI tests keep passing unmodified.** `src/ffi/common.rs`'s
  test module runs under `cfg(test)` on the host today; that it still passes
  after the lifecycle moves is the direct evidence that mobile behaviour did
  not change.
- **Log sink** (feature-gated): a subscriber receives lines; a late subscriber
  receives the retained backlog; the ring does not grow past its capacity; a
  receiver that stops reading loses lines and does not block the writer.
- **Stats** (feature-gated): the active-connection count rises and falls with
  connections and returns to zero after they close.
- **Size**: the `release-mobile` arm64 `.so` byte-size delta across the
  relocation is zero, checked in CI.
- **Feature matrix**: `--no-default-features` and `--features desktop` both
  build and pass on Linux, macOS and Windows. Windows is expected to build
  with TUN unsupported until wintun lands; that it *builds* is the point,
  since `src/lib.rs:123` gates the TUN module on `cfg(unix)`.

## Order of work

1. Extract the lifecycle into `src/control/`, `ffi::common` delegating. No
   behaviour change, no new API. Land the zero-byte size check with it.
2. `Status`, `StopReason`, `StopOutcome`, `StatusSnapshot`; FFI keeps
   projecting them onto its bool and its `LAST_ERROR` string.
3. `DevicePolicy` and its validation; FFI passes `BorrowedFd`.
4. Widen the `ffi::ios` cfg to macOS; add the cbindgen and CI entries.
5. `control-logs` and the broadcast sink.
6. `control-stats` and the active-connection count.

Steps 1 through 3 are the ones everything else waits on. Step 4 unblocks the
macOS provider, and 5 and 6 can land after the GUI exists, since a GUI can ship
without a log pane.

## Deliberately out of scope

Six sibling sub-projects, each its own spec:

- **Windows wintun backend.** A new `src/tun/` backend on a ring-buffer
  session API rather than a descriptor and `select()`. Shoes-side and
  required; large enough to design separately. This spec's job is the seam.
- **macOS Network Extension provider.** Swift, plus post-processing the
  `.app` bundle to embed the extension, which Tauri's bundler does not do.
- **Privileged helper and IPC contract.** One protocol over three mechanisms:
  `SMAppService`, a Windows service, systemd with polkit.
- **The Tauri GUI.** Tray, popover, dashboard, config editor.
- **Packaging, signing, notarization, updater.**
- **Share-link parsing** (`vless://` and siblings). Nothing in `src/` parses
  one today; the sole mention is a doc comment at
  `src/config/types/client.rs:238`. It belongs in the GUI repository, since no
  mobile caller wants it and it would cost mobile bytes for no mobile benefit.

Also out of scope, and noted where they arise above: per-outbound statistics,
which need an outbound label the config schema does not have; and making the
traffic counters per-handle rather than process-global.
