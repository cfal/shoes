# Windows TUN backend

Give Windows a TUN backend so that `run_prepared` stops returning
`ErrorKind::Unsupported` there, using wintun's ring-buffer session API behind
the same dedicated-thread design the Unix backend already has.

Written 2026-08-27 against `windows-tun` at `7791cc6`. This is sub-project #2
of the desktop client (ROADMAP.md, "Desktop clients"); the control API it
attaches to is sub-project #1 and is merged.

Windows 11 only, by decision. Nothing here checks for older versions, and the
APIs used — wintun, netioapi via `wintun-bindings`' helpers,
`WaitForMultipleObjects` — are used without legacy fallbacks.

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [What the reference implementations do](#what-the-reference-implementations-do)
- [Why not upstream PR #102](#why-not-upstream-pr-102)
- [Design](#design)
- [Module layout](#module-layout)
- [The stack loop becomes generic over its device](#the-stack-loop-becomes-generic-over-its-device)
- [The wintun device](#the-wintun-device)
- [Device creation and adapter configuration](#device-creation-and-adapter-configuration)
- [Configuration surface](#configuration-surface)
- [Dependencies](#dependencies)
- [Error handling](#error-handling)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Order of work](#order-of-work)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

`src/lib.rs` gates the TUN module on `cfg(unix)`, so on Windows
`control::run_prepared` returns `ErrorKind::Unsupported`
(`src/control/mod.rs:409`) and the binary refuses a TUN config at
`start_servers` (`src/tcp/tcp_server.rs:284`). The crate builds on Windows —
CI checks it — so this is a missing backend, not a port.

The backend cannot be a straight recompile because the Unix design is built on
a file descriptor. `TcpStackDirect` (`src/tun/tcp_stack_direct.rs`) runs
smoltcp on a dedicated OS thread that `poll()`s the TUN fd, reads it with
`libc::read`, writes it with `libc::write`, and is woken for shutdown through a
pipe. Wintun has none of those: a session hands out packets from a shared
ring buffer (`WintunReceivePacket`), takes sends the same way
(`WintunAllocateSendPacket`/`WintunSendPacket`), and signals readability
through an event handle (`WintunGetReadWaitEvent`).

What must survive the port is the shape: one dedicated stack thread, batching,
the pooled read buffers, the bounded-error backstop that stops a dead device
from busy-looping a core, and shutdown that wakes an idle thread rather than
waiting for a packet that never comes.

## Scope

In scope:

- the smoltcp stack loop extracted so both backends share it, with the Unix
  behaviour unchanged;
- a wintun-backed device: adapter creation, session I/O, event-based waiting,
  shutdown;
- adapter configuration from `TunConfig` — name, address, netmask, gateway,
  MTU — through `wintun-bindings`' netioapi-backed helpers;
- config validation for the Windows shape of `TunConfig`, refusing
  `device_fd` loudly;
- widening the `cfg(unix)` gates in `src/lib.rs`, `src/main.rs`,
  `src/tcp/tcp_server.rs` and `src/control/` to `cfg(any(unix, windows))`;
- documentation and an example.

Out of scope is listed at the end. The two entries worth flagging up front:
host route and DNS configuration (the privileged-helper sub-project owns
those), and any change to mobile behaviour — the refactor must leave the Unix
backend equivalent in behaviour, with the existing Unix test suite as the
check. Two deliberate exceptions to that equivalence were made after the live
run measured them, both improvements shipped to every platform: the UDP
response waker (below), and enabling smoltcp's `auto-icmp-echo-reply` feature
— without which `icmp_enabled` had never actually answered a ping anywhere.

## What the reference implementations do

**wireguard-go** (`tun/tun_windows.go`, read 2026-08-27) is the canonical
wintun consumer, written by wintun's own authors:

- Session ring capacity is `0x800000` — 8 MiB — passed to `StartSession`.
  We take the same value; the ring is shared by all flows, unlike our
  per-connection buffers, so mobile's sizing arithmetic does not apply.
- The read loop blocks on the handle from `ReadWaitEvent()` via
  `WaitForSingleObject` when `ReceivePacket` reports no data. (It spins
  briefly at high rates first; we do not copy the spin, because our loop
  already amortises through `MAX_PACKET_BATCH` and the 10 ms poll cap.)
- Shutdown sets a flag and then sets the read-wait event, so the blocked
  reader wakes, observes the flag, and exits. This is exactly the job the
  Unix backend's wake pipe does.

**wintun-bindings 0.7.40** (the crate the `tun` dependency already uses on
Windows, so it is in `Cargo.lock` today) exposes what the loop needs:
`Session::try_receive()` (non-blocking), `Session::get_read_wait_event()`,
`Session::get_shutdown_event()`, `Session::shutdown()`,
`Session::allocate_send_packet(len)` + `send_packet`, and adapter
helpers `Adapter::create/set_mtu/set_network_addresses_tuple` implemented
over netioapi rather than `netsh`. Sessions are internally reference-counted
and their handles are `Send + Sync`, which is what lets the stack thread own
the I/O while `Drop` on another thread signals shutdown.

**Upstream PR cfal/shoes#102** was read for which knobs matter (ring
capacity, the read-wait event, MTU on the adapter) and rejected as a base —
see the next section.

## Why not upstream PR #102

Recorded in ROADMAP.md and repeated here because it shapes the design: the PR
converts the stack to `AsyncDevice` and `.await`, which deletes the
dedicated-thread design that MOBILE.md's buffer and connection tuning rests
on, and it removes the `phy_wait_error_count` / `MAX_PHY_WAIT_ERRORS` guard
that stops a dead descriptor busy-looping a core. This spec keeps the thread
and keeps the guard; the only thing that changes per platform is how the
thread reads, writes, and waits.

## Design

One sentence: the stack loop in `tcp_stack_direct.rs` becomes a function
generic over a small device trait, the existing fd device implements it, and
a new wintun device implements it too.

```text
                 ┌────────────────────────────────────────────┐
                 │ run_stack_loop<D: StackDevice>             │
                 │ (batching, smoltcp, socket servicing,      │
                 │  error backstop — shared, unchanged)       │
                 └────────────┬──────────────┬────────────────┘
                              │              │
                    ┌─────────┴───┐    ┌─────┴──────────┐
                    │ FdDevice    │    │ WintunDevice   │
                    │ read/write/ │    │ try_receive /  │
                    │ poll + wake │    │ send_packet /  │
                    │ pipe (unix) │    │ WaitForMultiple│
                    └─────────────┘    │ Objects (win)  │
                                       └────────────────┘
```

## Module layout

```
src/tun/
  mod.rs               platform arms where the device is created   any(unix, windows)
  stack_common.rs      PooledBuffer + pool, TcpStackOptions,       unconditional
                       SharedState, NewTcpConnection, packet
                       classification, create_tcp_connection,
                       run_stack_loop<D>, StackDevice trait,
                       StackHandle (the shared manager: thread,
                       channels, accessors, signal/join)
  tcp_stack_direct.rs  FdDevice, wake pipe, poll(), TcpStackDirect unix
  tcp_stack_wintun.rs  WintunDevice, event wait, TcpStackWintun    windows
  wintun_device.rs     dll load, adapter create + configure,       windows
                       session start
  tun_server.rs        TunServerConfig; create_sync_device stays   any(unix, windows)
                       unix-only inside it
  tcp_conn.rs          unchanged                                   unconditional
  traffic.rs           unchanged                                   unconditional
  udp_handler.rs       unchanged                                   unconditional
  udp_manager.rs       unchanged                                   unconditional
```

`TcpStackWintun` presents the same four methods `run_tun_server` uses on
`TcpStackDirect` — `take_udp_rx`, `set_udp_response_tx`, `set_new_conn_tx`,
`is_running` — so `run_tun_server` keeps one body with a platform arm only
where the stack is constructed.

The `tun` crate dependency moves to `[target.'cfg(unix)'.dependencies]`: its
Windows half wraps wintun behind a blocking `Read`, which is exactly the
double-buffered shape this backend exists to avoid, and compiling it on
Windows would be dead weight.

## The stack loop becomes generic over its device

```rust
/// What the shared stack loop needs from a platform device, beyond
/// smoltcp's `Device` (which supplies the RxToken/TxToken pair).
pub(super) trait StackDevice: smoltcp::phy::Device {
    /// Non-blocking read of one packet into a pooled buffer.
    /// Ok(None) means nothing available; Err means the device is gone.
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>>;
    /// Park a packet for the next smoltcp poll to consume.
    fn store_packet(&mut self, pkt: PooledBuffer);
    /// Whether a parked packet is waiting.
    fn has_pending(&self) -> bool;
    /// Write one packet, dropping it (Ok) when the device queue is full.
    fn write_packet(&self, data: &[u8]) -> io::Result<()>;
    /// Sleep until readable, woken for shutdown, or `duration` elapses;
    /// `None` sleeps the loop's idle maximum.
    fn wait(&self, duration: Option<SmolDuration>) -> io::Result<()>;
}
```

`run_direct_stack_thread` moves to `stack_common.rs` as
`run_stack_loop<D: StackDevice>` with two mechanical substitutions —
`wait_readable(fd, wake_fd, d)` becomes `device.wait(d)`, and
`device.pending_rx.is_none()` becomes `!device.has_pending()` — and no other
change. In particular `MAX_PACKET_BATCH`, the `phy_wait_error_count`
backstop, the 10 ms poll cap, the 1000 ms idle cap, and the
`control-stats` counter reset on exit all stay in the shared body, so both
platforms get them by construction.

Both devices return `PooledBuffer` from `try_recv`. On Unix that is the
`read()` destination as today; on Windows it is one copy out of the ring
(`packet.bytes()` into the pooled buffer), which costs the same single copy
the Unix `read()` performs and lets the RxToken, the pool, and the batching
stay shared. `set_nonblocking` stays in the Unix constructor: it is fd
preparation, not loop logic.

## The wintun device

```rust
/// Windows TUN device over a wintun session.
struct WintunDevice {
    session: Arc<Session>,
    /// Handle from WintunGetReadWaitEvent: signalled while the receive
    /// ring is non-empty.
    read_wait: HANDLE,
    /// Session shutdown event; Drop on the owner sets it via
    /// Session::shutdown(), which is this backend's wake pipe.
    shutdown_event: HANDLE,
    mtu: usize,
    pending_rx: Option<PooledBuffer>,
}
```

- `try_recv`: `session.try_receive()`. `Ok(None)` maps to `Ok(None)`;
  a packet is copied into a `PooledBuffer`; `Err` maps to an
  `io::Error` so the shared loop's fatal-read path (stop the thread, report
  `BrokenPipe` from `run_tun_server`) fires exactly as on a Unix EOF.
- `write_packet`: `allocate_send_packet(len)` + copy + `send_packet`. A
  **full ring** (`ERROR_BUFFER_OVERFLOW`, per wintun.h) is logged at trace
  and dropped, the way the Unix path drops on `ENOBUFS`/`EAGAIN` — for a
  UDP-shaped device, dropping is what a full queue does. Any **other**
  allocation error is a session dying underneath us and is surfaced as
  `Err`, so the loop warns the way the Unix path warns on a failed
  `write()`; conflating the two would let a removed adapter blackhole
  traffic behind trace-level "ring full" lines.
- Received packets larger than the device MTU (the ring can carry up to
  64 KiB whatever the adapter was told) are dropped rather than grown into
  the pooled buffers, whose global pool budget is sized in MTUs; the Unix
  backend's fixed-size read truncates the same packets into unparseable
  fragments with the same outcome.
- `TxToken::consume`: allocates the ring packet first and lets smoltcp emit
  straight into `bytes_mut()`, so the TX path has no scratch copy at all.
  If allocation fails the token still calls `f` on a plain buffer and drops
  the result, because smoltcp's contract is that `consume` runs the closure
  — a rare, lossy path, so it does not carry the Unix token's thread-local
  scratch machinery.
- `wait`: `WaitForMultipleObjects` on `[read_wait, shutdown_event,
  wake_event]` with the same timeout arithmetic as the Unix `wait_readable` —
  smoltcp's delay capped at 10 ms, 1000 ms when idle. `WAIT_FAILED` returns
  an error so the shared backstop counts it; a shutdown or wake signal
  returns `Ok` and the loop observes `running` and the response channel on
  its next pass, matching how the wake pipe behaves.

### The UDP response waker

Found by the live run: a UDP response queued by tokio while the stack thread
was idle sat until the 1000 ms wait timed out, because nothing woke the
thread on enqueue — `Thread::unpark` does not interrupt `poll()` or
`WaitForMultipleObjects`. Measured at ~500 ms average on every cold DNS
lookup, against the microseconds Fake IP takes to produce the answer, and
just as real on the Unix backends, where the same loop had the same gap.

Each backend now exposes `udp_waker() -> StackWaker` (an `Arc<dyn Fn()>`),
which the UDP writer fires after every enqueue. On Unix it writes a byte to
the wake pipe through a duplicated descriptor (`dup`, owned by the closure,
so a waker outliving the stack cannot write to a reused descriptor number),
and `wait_readable` now drains the pipe so repeated wakes cannot turn the
poll into a busy loop. On Windows it sets a dedicated auto-reset event that
the device waits on as a third handle — auto-reset, so one `SetEvent` is one
wakeup with nothing to drain. A prompt-delivery test pins the Unix path; the
Windows path is pinned by the live run's DNS timing.

`TcpStackWintun` mirrors `TcpStackDirect`: it spawns
`shoes-smoltcp-wintun`, holds the `running` flag and the shared state, and
its `Drop` stores `running = false`, calls `session.shutdown()` — the
event-set that wireguard-go performs by hand — and joins the thread. There is
no descriptor-ownership question on Windows: the session and adapter are
always ours, created in `wintun_device.rs` and released when the last `Arc`
drops after the join, so `TcpStackOptions::close_fd_on_drop` is simply unused
there.

## Device creation and adapter configuration

`wintun_device.rs` does, in order:

1. **Load the driver library.** `wintun_bindings::load()`, with the crate's
   `verify_binary_signature` feature enabled so a planted `wintun.dll` on the
   search path is refused rather than loaded. A load failure produces an
   error that says where to get the DLL (wintun.net) and where to put it
   (next to `shoes.exe`, or `System32`).
2. **Create the adapter.** `Adapter::create(&wintun, name, "shoes", guid)`
   with `name` from `device_name`. The GUID is derived deterministically —
   `blake3("shoes-wintun:" + name)` truncated to a `u128` — so recreating
   the adapter reuses the same Windows network profile instead of
   accumulating "Network 2, Network 3" profiles run after run.
   `ERROR_ACCESS_DENIED` is rephrased: creating a wintun adapter requires
   Administrator, and the raw error does not say so.
3. **Configure it.** `set_mtu(mtu)`, then
   `set_network_addresses_tuple(address, netmask, None)` — address and
   netmask from the config (required and IPv4-only on Windows, see below).
   The gateway parameter is never passed: wintun-bindings implements these
   helpers as `netsh` invocations, and `gateway=` would install a system
   default route through the adapter, which is the host's decision, not
   shoes'. For the same reason the config's `destination` is refused on
   Windows rather than forwarded — on Linux it is only the point-to-point
   peer address, and silently promoting it to a default route would hijack
   the routing of anyone porting a config. IPv6 addresses are refused at
   validation because the crate's netsh ipv6 arm emits parameters that
   context does not accept.
4. **Start the session.** `start_session(0x800000)` — wireguard-go's ring
   size, cited above.

A failure after the adapter exists tears the adapter down before returning
(dropping the `Arc<Adapter>` deletes it); a half-configured adapter left
behind would shadow the next run's create.

## Configuration surface

The Windows shape of a TUN section is the Linux create-it-yourself shape:

```yaml
- device_name: shoes0        # wintun adapter name
  address: 10.99.0.2
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
```

`src/config/validate.rs` gains a `target_os = "windows"` arm beside the
Linux/Android/iOS ones:

- `device_name`, `address` and `netmask` are required. A wintun adapter
  without an address is reachable by nothing and fails silently; requiring
  the address is the refuse-loudly rule applied to a whole platform.
- `address` and `netmask` must be IPv4: wintun-bindings 0.7 configures the
  adapter through `netsh interface ipv4`, and its ipv6 arm cannot work, so
  an IPv6 address would pass `--dry-run` and fail opaquely at start.
- `destination` is refused: the only place the crate could put it is netsh's
  `gateway=`, which installs a system default route, and routes are the
  host's.
- `device_fd` is refused with a message that says why: Windows has no
  descriptor to inject — the wintun handle model does not survive a process
  boundary the way an fd does — and shoes creates the device itself.

The runtime arm in `run_tun_server` re-checks the same shape with the same
rules for callers that bypass YAML validation; it deliberately invents no
looser rule of its own (no defaulted adapter name), so the two sites cannot
disagree about what a valid Windows TUN config is.

`DevicePolicy` needs no new variant: Windows attaches at `Owned` exactly as
the control-API spec planned, and `device::validate`'s `Owned` arm already
refuses a `device_fd`. `run_tun_from_config`'s `close_fd_on_drop` parameter
is accepted and unused on Windows, where ownership is structural.

The gates that widen from `cfg(unix)` to `cfg(any(unix, windows))`:
`src/lib.rs:131`, `src/main.rs:63`, `src/tcp/tcp_server.rs:280`,
`src/control/mod.rs:43/188/229/407`, `src/control/stats.rs:33/38`. The
`cfg(not(...))` fallbacks stay, widened to match, so a hypothetical third
platform still gets the explicit `Unsupported` error rather than a compile
break.

## Dependencies

```toml
[target.'cfg(unix)'.dependencies]
tun = { version = "*", features = ["async"] }      # moved, not added

[target.'cfg(windows)'.dependencies]
wintun-bindings = { version = "0.7", features = ["verify_binary_signature"] }
windows-sys = { version = "0.61", features = [
    "Win32_Foundation",
    "Win32_System_Threading",
] }
```

Both Windows crates are already in `Cargo.lock` (via `tun`), so this changes
what compiles where, not what the tree depends on. `windows-sys` is needed
directly only for `WaitForMultipleObjects` and its constants.

## Error handling

Failures divide the way the control API divides them:

- **Prepare/validate time.** Missing `device_name`/`address`/`netmask`, or a
  `device_fd`, fail in `validate.rs` in front of the caller.
- **Start time.** DLL missing, signature refused, adapter creation denied
  (Administrator), session start failure. Returned as `Err` from
  `run_tun_server` before anything is spawned, each with a message naming
  the action the operator must take.
- **Run time.** `try_receive` failing or `WaitForMultipleObjects` failing
  repeatedly stops the stack thread through the shared backstop, and
  `run_tun_server` reports `BrokenPipe` exactly as on Unix, so
  `Status::Stopped { reason: Failed }` and the FFI's `LAST_ERROR` behave
  identically across platforms.

## Security notes

- **DLL loading is an attack surface.** `wintun.dll` is resolved by the
  loader's search order, and the process runs elevated. The
  `verify_binary_signature` feature checks the binary's signature before
  loading; without it, a writable directory on the search path is a
  privilege escalation. This is the "do not hand back something the platform
  refused" rule applied to code rather than sockets.
- **No socket protector on Windows.** The Android-style route exclusion does
  not apply: outbound sockets bind to real interfaces chosen by the host's
  routing table, and keeping the physical default route preferred is the
  helper/GUI's job (out of scope here). Nothing in this backend loops
  traffic back into its own tunnel unless the operator routes it there.

## Testing

The refactor's correctness argument is that the Unix behaviour is unchanged,
and the new code's argument is the shared loop plus a thin device.

- **The existing Unix stack tests keep passing unmodified** —
  `test_stack_shutdown_on_eof`, `test_stack_exits_promptly`,
  `stack_leaves_a_borrowed_fd_open`, the connection-count reset, the
  `write_all` EAGAIN test. They are the direct evidence the extraction
  changed nothing. CI runs them on Linux and macOS.
- **The shared loop gets a scripted device**, a channel-backed
  `StackDevice` double in `stack_common.rs` tests, so the loop's behaviour
  — shutdown on device error, prompt exit, SYN handling, the counter reset —
  is asserted on every platform including Windows, with no driver and no
  privileges. This is coverage the Unix-only tests could never give the
  shared code.
- **Windows unit tests without the driver**: GUID derivation is
  deterministic and distinct across names; validation of the Windows config
  shape (missing address, present `device_fd`) under `cfg(windows)`.
- **An `#[ignore]`d integration test** creates a real adapter, starts a
  session, and round-trips one packet. It needs Administrator and
  `wintun.dll`, so it is run by hand (`--ignored`) rather than in CI, the
  same posture as the tproxy plans in ROADMAP.md.
- **A live run on this machine**: shoes with a TUN config and a route for a
  test prefix pointed at the adapter, traffic through a rule to a real
  outbound, verifying TCP, UDP/DNS and Fake IP end to end. Recorded in the
  plan, not automated.

## Order of work

1. Extract `stack_common.rs`; `tcp_stack_direct.rs` keeps the fd device and
   its tests. No behaviour change; the Unix suite is the check.
2. The scripted-device tests over the shared loop.
3. `wintun_device.rs` and `tcp_stack_wintun.rs`.
4. Platform arms in `tun/mod.rs` and `tun_server.rs`; move the `tun` dep;
   add the Windows deps.
5. `validate.rs` Windows arm; widen the `cfg` gates in `lib.rs`, `main.rs`,
   `tcp_server.rs`, `control/`.
6. Docs: CONFIG.md, README platform list, ROADMAP desktop section,
   CHANGELOG; `examples/tun_windows.yaml`.
7. The `#[ignore]`d integration test, then the live run.

## Deliberately out of scope

- **Host routes and DNS.** shoes moves packets; the host owns the network.
  On Windows that means the operator (or, later, the privileged-helper
  sub-project) adds routes into the adapter and points DNS at it. The
  example and CONFIG.md show the manual commands.
- **The Windows service, IPC, GUI, packaging.** Sub-projects #4–#6 of the
  desktop client.
- **Windows-on-ARM and Windows 10.** Windows 11 x64 only for now; nothing
  checks a version, but nothing older is tested or promised.
- **BorrowedFd on Windows.** A future host handing over an existing adapter
  (by name or handle) would be a new `DevicePolicy` shape; nothing needs it
  yet.
- **The read-rate spin optimisation** wireguard-go performs before blocking
  on the read event. Batching plus the 10 ms cap already amortises the
  wakeups; add the spin only if a measured gap appears.
