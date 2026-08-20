# Mobile integration notes

State of the `mobile` branch as a core library for an Android/iOS VPN app, and
what still stands between it and a shipping product.

Everything in "What works" is verified on this branch. Every finding cites the
line that produced it. Findings marked *fixed* have landed; the rest are still
open and are ordered at the end. Line references were last checked against
`037018e`; if one has drifted, trust the symbol name over the number.

## What works

| | Android | iOS |
|---|---|---|
| Builds | `cargo ndk -t arm64-v8a -t armeabi-v7a` clean | `cargo build --target aarch64-apple-ios` clean |
| Packaging | AAR via `scripts/build-android.sh` | XCFramework via `scripts/build-ios.sh` |
| Entry points | 9 `Java_com_shoesproxy_ShoesNative_*` JNI symbols | 10 `shoes_*` C symbols |
| Socket protection | `VpnService.protect` via `SocketProtector` | `IosSocketProtector` |
| Traffic stats | `TrafficListener.onTrafficUpdate` | `ShoesTrafficCallback` |
| Error reporting | `getLastError()`, and `start` returns -1 on a bad config | same, via `shoes_get_last_error()` |
| Network change | `networkChanged()` | `shoes_network_changed()` |
| Live log level | `setLogLevel()` | `shoes_set_log_level()` |
| AmneziaWG 2.0/3.0 | yes | yes |
| Fake IP / DNS leak | yes, via TUN interception | yes, via TUN interception |

The iOS build needs `IPHONEOS_DEPLOYMENT_TARGET=16.0`; `aws-lc-sys` references
`___chkstk_darwin`, which is iOS 13+. `scripts/build-ios.sh` sets it, but a
plain `cargo build --target aarch64-apple-ios` fails at link time without it.

---

# Orientation

Read this part first if you are picking the branch up cold. It is the contract
the findings below assume.

## Where things live

| Path | What |
|---|---|
| `src/ffi/common.rs` | Platform-independent FFI core: globals, `start_from_config`, `stop_service` |
| `src/ffi/android.rs` | JNI entry points, `FnSocketProtector`, traffic callback into the JVM |
| `src/ffi/ios.rs` | C entry points, `IosSocketProtector`, traffic callback into Swift |
| `src/ffi/stub.rs` | No-op build for desktop targets |
| `src/tun/mod.rs` | TUN server entry (`run_tun_server`, `run_tun_from_config`) and the 1 s traffic timer |
| `src/tun/tcp_stack_direct.rs` | smoltcp stack on the raw fd; buffer sizes and connection cap live here |
| `src/tun/tcp_conn.rs` | Per-connection ring buffers (`TcpConnectionControl`) |
| `src/tun/udp_manager.rs` | UDP session table (`MAX_SESSIONS`) |
| `src/socket_protector.rs` | `SocketProtector` trait, global protector, `protect_socket` |
| `src/tun/platform.rs` | `PlatformCallbacks`, `PlatformInterface`; re-exports the protector for the FFI |
| `src/tun/traffic.rs` | Byte counters, `report_traffic`, `TrafficCountingStream` |
| `src/amneziawg/` | AmneziaWG 2.0/3.0 client: `config.rs`, `tunnel.rs`, `netstack.rs`, `connector.rs` |
| `src/amneziawg/endpoint.rs` | The rebindable endpoint socket and the network-change registry |
| `src/dns/fake_ip/` | Fake IP: `pool.rs`, `responder.rs`, `bypass.rs` |
| `src/tcp/socket_connector_impl.rs` | Where outbound proxy TCP/UDP sockets are actually created |
| `src/config/validate.rs` | `create_server_configs` — config validation and group expansion |
| `src/config/types/redacted.rs` | `Redacted<T>` — keeps secrets out of `Debug` output |
| `include/shoes.h` | Generated C header; the authoritative iOS signature list |
| `android/src/main/java/com/shoesproxy/ShoesNative.kt` | Kotlin JNI bridge, KDoc'd |

## Building and testing

```bash
# Android AAR -> output/android/shoes-release.aar
# Needs ANDROID_NDK_HOME, ANDROID_HOME and gradle on PATH.
bash scripts/build-android.sh

# iOS XCFramework -> output/ios/Shoes.xcframework
# macOS + Xcode only. Regenerates include/shoes.h via cbindgen if installed.
bash scripts/build-ios.sh

# Native libs only, skipping Gradle
cargo ndk -t arm64-v8a -t armeabi-v7a -P 21 \
    -o android/src/main/jniLibs -- build --profile release-mobile --lib

# iOS device slice by hand — the deployment target is not optional
IPHONEOS_DEPLOYMENT_TARGET=16.0 \
    cargo build --profile release-mobile --target aarch64-apple-ios

# Tests run on the host. `src/ffi/common.rs` compiles under
# cfg(test) already, so plain `cargo test` covers it. The `ffi` feature is what
# pulls in the socket-protector plumbing (`src/tun/platform.rs`, and the
# protect call in `src/amneziawg/tunnel.rs:79`) on a desktop target — build with
# it when you are changing that path.
cargo test
cargo test --features ffi
```

Both build scripts ship only `arm64-v8a` and `armeabi-v7a`. There is no x86 or
x86_64 slice, so the Android emulator needs an arm64 image.

CI (`.github/workflows/mobile.yml`) triggers on `master` and on PRs into
`master` only. Pushes to `mobile` build nothing — verify locally before relying
on a green tick that was never produced.

## FFI surface

Android — 9 symbols, all `Java_com_shoesproxy_ShoesNative_*`, mirrored by
`ShoesNative.kt`:

| Kotlin | Rust | Returns |
|---|---|---|
| `init(logLevel: String)` | `android.rs:79` | 0 ok, -1 error |
| `getVersion()` | `android.rs:119` | version string |
| `setLogFile(logPath: String)` | `android.rs:145` | 0 ok, -1 error |
| `setLogLevel(logLevel: String)` | `android.rs` | 0 ok, -1 unrecognised |
| `networkChanged()` | `android.rs` | tunnels notified |
| `start(configYaml, protectCallback, trafficCallback)` | `android.rs:177` | `1` on success, -1 on error |
| `stop(handle: Long)` | `android.rs:317` | — |
| `isRunning()` | `android.rs:332` | boolean |
| `getLastError()` | `android.rs:348` | string or null |

iOS — 10 symbols, declared in `include/shoes.h`:

```c
int   shoes_init(const char *log_level);
long  shoes_start(const char *config_yaml, /* protect cb */, /* traffic cb */);
void  shoes_stop(long _handle);
bool  shoes_is_running(void);
const char *shoes_get_version(void);
int   shoes_set_log_file(const char *path);
int   shoes_set_log_level(const char *log_level);
int   shoes_network_changed(void);
char *shoes_get_last_error(void);   // caller frees
void  shoes_free_string(char *ptr);
```

`shoes_get_last_error` returns an owned string. Pass it back to
`shoes_free_string` or it leaks.

## Lifecycle contract

1. `init` once. Idempotent; use `setLogLevel` / `shoes_set_log_level` to
   change verbosity afterwards, since `init` reads the level only the first
   time.
2. Open the TUN yourself — `VpnService.Builder.establish()` on Android,
   `NEPacketTunnelProvider` on iOS — and put the fd into the config YAML as
   `device_fd`. The library never opens the device. Hold the descriptor open:
   do not `detachFd()` and forget it, and do not close it while the tunnel runs.
3. `start(configYaml, ...)`. The config must contain **exactly one** TUN entry
   and it must carry `device_fd`; both are enforced in `common.rs`. Server
   entries (a `mixed` listener, say) may sit alongside it and are started too,
   then aborted when the TUN stops. A -1 means the config was rejected and
   `getLastError()` says why — parsing, validation and resolver construction all
   happen before `start` returns, so it is a real verdict rather than a deferred
   failure.
4. `stop(...)`. Signals shutdown, then blocks until the engine has released the
   TUN descriptor — milliseconds in practice, bounded at 5 s. Not from the main
   thread. Close your descriptor after it returns.
5. Forward network changes while the tunnel runs: `networkChanged()` /
   `shoes_network_changed()`. See finding 3.

The fd stays yours, and now actually is: the flag that says so
(`close_fd_on_drop = false`) was only honoured on the path that *creates* the
device, so on the raw-fd path — every mobile start — the stack closed the app's
descriptor on shutdown regardless. An app that also closed its own, as this
document told it to, was double-closing, which in a process that is opening
sockets constantly means closing whichever socket has since taken the number.
Close it yourself after `stop` returns.

There is one tunnel per process. All state lives in the `TUN_SERVICE` global in
`common.rs`, and starting over a running service is refused rather than
permitted.

## Threading contract

- `init`, `stop`, `isRunning`, `getLastError`, `setLogLevel` and
  `networkChanged` are safe from any thread. `stop` is the one that blocks, and
  it must not be on the main thread.
- `start` spawns its own multi-threaded Tokio runtime and returns once the
  config has been accepted; the service then runs on that runtime, not on the
  caller's thread. It does parse and validate on the caller's thread, so a
  config with a large certificate to load costs the caller that much.
- `SocketProtector.protect(fd)` is invoked from whichever runtime thread is
  creating the socket. It must be safe to call off the main thread and should
  not block. On Android it is delivered through `FnSocketProtector`
  (`android.rs:226`), which attaches to the JVM as needed.
- `TrafficListener.onTrafficUpdate` fires from a dedicated Tokio task on a 1 s
  interval — never the main thread. Marshal to the UI thread yourself. It fires
  once at the start of a session and then only on a tick where a counter moved,
  so an idle tunnel is silent rather than reporting the same numbers 3,600 times
  an hour.
- Both callbacks are stored in globals and cleared inside `stop`, along with the
  socket protector — which on Android holds a JNI global reference to the
  `VpnService`, so leaving it installed kept a destroyed service and its
  `Context` alive. Do not retain objects across a stop/start cycle and assume
  they are still wired.

## Example configs

`examples/tun_fake_ip.yaml` and `examples/amneziawg_client.yaml` are the two
shapes a mobile app actually sends. Take either, inject `device_fd`, and it is a
valid argument to `start`. `CONFIG.md` is the full reference.

---

# Findings

## 1. Per-connection memory will get the iOS extension killed — fixed

`tcp_stack_direct.rs` set both TCP buffers to `0x3FFF * 20` (~320 KB) as
constants, and each connection allocated **four** of them eagerly — two smoltcp
socket buffers and two ring buffers in `TcpConnectionControl::new`. That was
~1.31 MB per TCP connection, taken at SYN, regardless of what the connection
carried, against a `MAX_CONCURRENT_CONNECTIONS` of 1024: a ceiling of ~1.34 GB,
or about 35 connections inside an iOS extension's ~50 MB jetsam limit. A single
page load in Safari opens more than that.

It was also only half the bill. The AmneziaWG virtual stack
(`src/amneziawg/netstack.rs`) allocates its own four buffers per connection, at
256 KiB each, and on a mobile VPN the two stacks are in series: a browser
connection is accepted by the TUN stack and initiated through the netstack, so
it paid 1.31 MB *plus* 1 MiB. Its UDP sockets took another 128 KiB of payload
buffer per session.

But the two stacks must not be sized alike, and finding out why cost a
benchmark. The TUN stack's buffers face an application on the same device, and
both stacks keep ring buffers between their smoltcp half and their async half —
nothing there spans a round trip, so those only need to cover scheduling jitter.
The AmneziaWG stack's *socket* buffers are the receive window and in-flight send
data of a connection whose far end is a server on the internet. Cutting those to
32 KiB cost 6x the throughput; see finding 10 for the measurement. They keep
their size, and `src/buffer_sizing.rs` names the two roles separately so the
distinction survives the next person who sees two constants that look alike.

Both are configuration now — `tcp_buffer_size` and `max_connections` on the TUN
config, carried through `TunServerConfig` and `TcpStackOptions` — and both
default by platform, the way `mtu` already did:

| | local buffer | remote window | max connections | worst case, both stacks |
|---|---|---|---|---|
| iOS, Android | 32 KiB | 256 KiB | 256 | 176 MiB |
| everywhere else | 64 KiB | 256 KiB | 1024 | 1 GiB |

A connection through both stacks costs four local buffers in the TUN stack and
two window buffers plus two local ones in the AmneziaWG stack: 704 KiB on
mobile, against 2.3 MB before. Those are ceilings on what a connection
*allocates*; what it costs resident is about a third — see finding 10.

Neither buffer spans a network round trip: both sit between the device and a
proxy connection inside this process, so their size buys burst tolerance rather
than throughput, and the old value was sized for a desktop 10 GbE path. The
ceiling is logged at startup (`TCP stack: buffer=... max_connections=...`), and
a value below two MTUs is raised to two MTUs.

What is still worth doing: allocate lazily and grow, rather than taking the full
four buffers at SYN. The ceiling is now survivable, but a connection that
carries one HTTP request still pays for a connection that carries a video.

Two neighbouring allocations were already sized for this budget: the AnyTLS
outgoing channel is bounded at `OUTGOING_CHANNEL_CAPACITY = 256`
(`src/anytls/anytls_client_session.rs:30`), and the UDP session table is an LRU
capped at 256 (`udp_manager.rs:36`).

## 2. Only the AmneziaWG socket is excluded from the tunnel — fixed

`protect_socket` used to have exactly one caller in the whole tree:
`src/amneziawg/tunnel.rs:82`, guarding the AmneziaWG endpoint's UDP socket. The
comment there stated the hazard correctly — an unprotected socket is captured by
the TUN it feeds, and every packet loops back into itself — but every other
outbound socket was created without it. A `client_chain` that was not AmneziaWG
opened its upstream connection inside its own tunnel, and a working Android
setup was working because of `Builder.addDisallowedApplication`, an app-side
workaround nothing here required or documented.

The protector now lives in `src/socket_protector.rs`, which compiles on every
target rather than only on mobile, and `socket_util::new_tcp_socket` and
`new_udp_socket` consult it. Protection follows from where a socket is created
rather than from whoever created it having remembered, which is what let five
call sites drift in the first place. The socket2 constructors are the
listener-side primitives and are deliberately left alone; the three outbounds
that build their own socket — the AmneziaWG endpoint and the two DNS paths —
call `socket_util::protect_outbound` themselves.

Both DNS paths also used to bypass our constructors entirely when no
`bind_interface` was set, binding through tokio directly, so upstream queries
leaked even after the outbound sockets were fixed. They protect explicitly now.

Covered by tests in `src/socket_util.rs` that install a recording protector and
assert the file descriptor reached it, including that a refused protection fails
socket creation rather than handing back a socket that would loop.

## 3. Nothing handles a network change — fixed

There was no API to tell the library the network moved, and nothing that
noticed on its own. On mobile the default route changes constantly, and when it
does the AmneziaWG endpoint's UDP socket is still bound to an address that no
longer exists. It does not error. It goes quiet, and stays quiet, and the only
recovery was stop-and-start — which tears down the TUN interface and every
connection through it.

The endpoint socket is replaceable now (`src/amneziawg/endpoint.rs`). The three
tunnel tasks hold an `EndpointSocket` instead of a `UdpSocket`, read the live
socket through a `watch` channel, and are woken when it is swapped underneath
them. A rebind binds a fresh socket, protects it, and connects it to the same
peer; no new handshake is needed, because WireGuard peers roam — the server
updates the endpoint it holds for us as soon as an authenticated packet arrives
from the new address.

Two things trigger it:

- **The app tells us.** `shoes_network_changed()` on iOS, `networkChanged()` on
  Android — call them from `NWPathMonitor` and from
  `ConnectivityManager.NetworkCallback`. Safe from any thread and when nothing
  is running; they do no I/O on the calling thread.
- **We notice.** A send that fails with `ENETUNREACH`, `EHOSTUNREACH`,
  `ENETDOWN`, `EADDRNOTAVAIL` or `EINVAL` schedules a rebind by itself, so an
  app that never wires up the callback still recovers, one failed send later.
  `ECONNREFUSED` and `ECONNRESET` deliberately do not: on a connected UDP socket
  those are the peer's ICMP replies and say nothing about our own address.

Still not handled: pooled TCP connections through a non-AmneziaWG chain, and
resolver state. Both fail and re-establish on their own, where the UDP tunnel
could not.

## 4. `stop` blocks the calling thread for up to five seconds — mostly fixed

`stop_service` polled a flag in 100 ms sleeps up to 50 times and then dropped
the Runtime, which itself blocks until every task finishes. Called from
`onDestroy` on the main thread — which is what the KDoc sample did — that is an
ANR waiting to happen, and it paid at least 100 ms even when the service had
already stopped.

Two changes. The poll is 5 ms now, so a stop costs what it actually takes rather
than rounding up to a tenth of a second. And the Runtime is shut down on a
thread of its own, with a timeout, because waiting for tasks to drop gets the
caller nothing.

The wait that remains cannot be skipped: it is what guarantees the stack thread
has released the TUN descriptor, so the app can close its own copy without
racing a thread still reading from it. `stop` returns `true` when it confirmed
the stop and `false` on timeout. It must still be called off the main thread,
and the KDoc sample now does that, closes the descriptor afterwards, and checks
`start`'s return value.

## 5. The handle returned by `start` is not a handle

`shoes_start` returns the literal `1` (`src/ffi/ios.rs:224`,
`src/ffi/android.rs:307`), and `shoes_stop(_handle)` ignores its argument
entirely — all state lives in the `TUN_SERVICE` global. That is fine as long as
there is exactly one tunnel, which the code enforces ("Multiple TUN configs
found - only one is allowed for mobile", `common.rs:181`).

It is worth either making the handle real or dropping it from the signature.
As it stands the API implies a multi-instance model it does not have, and a
caller that stores two handles will silently operate on one tunnel.

The double-start hazard this created is now fixed — both platforms refuse to
start over a running service rather than dropping a live Runtime on the caller's
thread.

## 6. The log level is fixed at first init — fixed

`shoes_init` returns 0 immediately if `INITIALIZED` was already set, before it
reads `log_level`, so a second call with `"debug"` did nothing and reported
success while doing it. For a support workflow — "turn on debug logging and
reproduce" — the user had to kill the app.

`shoes_set_log_level` / `ShoesNative.setLogLevel` change the level of a running
library. They set an override that `MultiLogger` consults ahead of its
directives, so the change applies to every target immediately.

The caveat from before still stands: `log` is built with
`release_max_level_info` (`Cargo.toml:55`), so `debug` and `trace` are compiled
out of release builds. Raising the level past `info` only does something in a
build that keeps them.

## 7. Traffic stats wake the device once a second regardless of traffic — fixed

`report_traffic` loaded both counters and invoked the callback unconditionally,
so an idle tunnel crossed into the JVM, or into Swift, 3,600 times an hour to
repeat numbers that had not changed. It now compares against what the last tick
reported and returns without calling when neither counter moved.

The interval is still a fixed 1 s. Making it configurable, so an app can back
off when its UI is not in the foreground, is still worth doing.

The JNI side itself is fine: `attach_current_thread` in jni 0.22 is the
permanent-attach variant, documented as a thread-local check with no JNI call
once the thread is attached.

## 8. Smaller items

- **`libboringtun-*.so` shipped in the AAR.** `cargo-ndk` copies every cdylib in
  the dependency graph. Nothing loads it — the hashed filename is not a valid
  `System.loadLibrary` name — so it was 315 KB of dead weight per ABI.
  `scripts/build-android.sh:66` now deletes it. The dependency has since been
  renamed to awgtun, so the file is `libawgtun-*.so` today; the script deletes
  everything except `libshoes.so`, so the rename does not resurrect it.
- **Secrets in logs are handled, mostly.** `Redacted<T>`
  (`src/config/types/redacted.rs`) gives keys and passwords a `Debug` that
  prints a placeholder, so a config dump into the log file is safe to hand to
  support. Worth confirming that any new secret-bearing config field is wrapped
  in it — the type only helps where it is used.
- **`minSdk = 21`, `compileSdk = 35`** (`android/build.gradle.kts:8,11`). Play
  Store now requires targeting API 35+ for new submissions; `compileSdk` is fine
  but confirm the consuming app's `targetSdk`. `minSdk 21` is very generous —
  raising it to 24 or 26 would let the NDK drop some compatibility shims.
- **~~Stale ABI comment in CI.~~ Fixed.** The `android` job's header comment
  now names the ABIs it actually builds.
- **A line per connection at `info`.** The stack logged every accepted SYN at
  `info`, which in a release build — where `info` is the maximum level — meant a
  page load's worth of source and destination addresses in logcat and in the log
  file the user hands to support. It is `debug` now.
- **No `android:extractNativeLibs` guidance.** For a 9.4 MB `libshoes.so`,
  leaving it uncompressed in the APK (`useLegacyPackaging = false`, the default
  on AGP 9) is right, but it doubles the on-disk footprint. Worth measuring.
- **~~Release binary size is unmeasured.~~ Done — see the `release-mobile`
  profile.** Measured on `aarch64-linux-android`, `--lib`, stripped:

  | profile | raw | zipped |
  |---|---|---|
  | `release` (`opt-level = 3`, unwind) | 14,575,384 | 6,038,573 |
  | `+ panic = "abort"` | 11,854,920 | 5,029,063 |
  | `opt-level = 2` + abort | 11,393,592 | 4,890,541 |
  | **`release-mobile`** (`opt-level = "s"` + abort) | **9,415,728** | **3,734,628** |

  `panic = "abort"` is worth 2.7 MB by itself: it deletes `.eh_frame` and
  `.gcc_except_table`, which are 2 MiB of the baseline. `opt-level = "s"` beats
  `"z"` on zipped size despite being larger raw, and beats `2` by 1.16 MB
  zipped. Cost, measured over 11 × 50 MiB transfers through a real AmneziaWG
  3.0 peer: throughput unchanged (6.55 vs 6.36 MB/s mean, link-bound either
  way), CPU up ~15% (0.72 s vs 0.62 s per 50 MiB) — about 2 ms per MB.
- **Feature-gating the protocols would be worth ~17%, for a much larger tax.**
  Dropping every protocol an awg+vless client cannot reach frees ~1.0 MiB of
  dependency `.text` (h2, hyper, the quinn/h3 stack, argon2, notify) and
  ~0.5 MiB of shoes' own — against 15 + 15 serde-derived config variants
  needing `#[cfg]`, 28 match arms in `validate.rs` alone, and a permanent
  feature-combination CI matrix. The profile change above got more for two
  lines. Note also that `.text` is file-backed and demand-paged, so unused
  protocol code costs essentially no RSS — this is a download-size lever, not
  a finding-1 lever.
- **The stack thread's panic guard does nothing on mobile.**
  `TcpStackDirect::new` wraps the thread body in `catch_unwind` and logs what it
  catches, but the `release-mobile` profile sets `panic = "abort"`, so a panic
  there ends the process before the handler runs. The panic hook in
  `src/logging.rs` still records it, which is the part that matters; the
  `catch_unwind` is simply inert in shipping builds and should not be read as
  containment.
- **No jemalloc on mobile.** Deliberate (`Cargo.toml:95` excludes iOS and
  Android) and correct — but it means the system allocator's fragmentation
  behaviour is what you get, so the real footprint sits above the ceiling
  finding 1 computes.

## 9. Platform wiring Fake IP still expects

Fake IP is implemented and intercepts DNS inside the TUN, so it works without
the app configuring anything. Two things still make it behave better:

- **Point the tunnel's DNS at an address you route.** Android
  `Builder.addDnsServer(...)` / iOS `NEDNSSettings`. Interception matches on
  port rather than address, so this is not required for correctness — but
  without it the OS may decide there is no resolver and skip queries entirely
  on some networks.
- **Route the fake range.** The pool address must arrive at the TUN for the
  connection to be restored. A default route covers it; a split tunnel needs
  `198.18.0.0/16` (or whatever `network` is set to) added explicitly.

## 10. Memory: what the audit measured

Three questions, since none of the arithmetic above is worth much unmeasured.

**Does anything leak?** No. The whole suite under `leaks --atExit` reports 30
unreachable allocations of 16 bytes each, all of them `Box::leak` in test
scaffolding for the TUIC and Hysteria2 servers. Nothing in the TUN stack, the
tunnel, or the FFI leaks by construction: every socket table has a removal path,
the endpoint registry holds weak references and sweeps them, and the globals the
FFI keeps are single values rather than collections.

```bash
cargo test --lib --no-run
MallocStackLogging=1 leaks --atExit -- ./target/debug/deps/shoes-<hash>
```

**What does a connection actually cost?** Less than it allocates, because
`vec![0u8; n]` gets zero pages the kernel only faults in when they are written.
Measured with `measure_memory_per_connection` (ignored by default; run it with
`--ignored --nocapture`), 200 connections at 32 KiB buffers:

| | |
|---|---|
| allocated per connection | 128 KiB |
| resident per connection | ~40 KiB, about a third |

So the 128 MiB ceiling above is a ceiling on address space, and the resident
figure for 256 saturated mobile connections is nearer 40 MiB — still the
dominant term inside an iOS extension, which is why the ceiling matters, but not
the number to quote.

**Does the smaller sizing cost throughput?** For the local buffers, no. For the
window, catastrophically — which is how the distinction above got found. 50 MiB
per transfer through the real AmneziaWG peer at ~40 ms RTT, arms rotated:

| AmneziaWG socket buffer | throughput | CPU per transfer |
|---|---|---|
| 256 KiB | 6.2 MB/s | 0.6-1.6 s |
| 64 KiB | 2.1 MB/s | 1.1-2.5 s |
| 32 KiB | 1.05 MB/s | 1.7-3.6 s |

Throughput linear in the buffer is what a receive-window limit looks like, and
note that the smaller windows burn *more* CPU, because the same bytes take five
times as long to move. With the window back at 256 KiB and only the ring buffers
cut, all three configurations — including the 32 KiB mobile one — measure ~6.2
MB/s, matching the baseline this branch had before any of this work.

**Does it come back?** Not on its own. After dropping every connection and the
stack, resident size stayed within 150 KiB of its peak: freeing does not shrink
a process, because no general-purpose allocator returns spans eagerly. On a
phone that leaves an idle tunnel parked at the high-water mark of the busiest
thing the user did with it. `src/memory.rs` now asks the allocator to purge when
a tunnel stops — `mallopt(M_PURGE_ALL)` on bionic, `malloc_zone_pressure_relief`
on Apple's libmalloc — alongside dropping the read path's buffer pool.

Be careful what you expect from that: on macOS the purge did not move RSS in
this measurement, which is consistent with libmalloc marking pages reclaimable
rather than unmapping them. Whether it helps an iOS extension's `phys_footprint`
— the number jetsam actually reads — is unverified here and worth checking under
Instruments before relying on it. On bionic, scudo documents `M_PURGE_ALL` as
releasing to the OS.

**Allocation churn.** The AmneziaWG data path allocated per packet: a `to_vec()`
of every datagram leaving `decapsulate`, `encapsulate` and the timer, plus a
`Vec<Vec<u8>>` per send to hold decoys that are only present during a handshake.
At the ~4,600 packets/s a 6.5 MB/s tunnel carries, that was tens of thousands of
allocations a second, which on mobile is battery and fragmentation rather than
throughput. Those are reusable scratch buffers now, and the decoy list does not
allocate when there are no decoys. The same went for the TUN write path, where
every segment and every ACK allocated a fresh buffer; it now uses a thread-local
one.

What still allocates per packet, deliberately: the two channels that carry IP
packets between the stacks own their `Vec<u8>`, so a packet crossing them is one
allocation. Removing that means changing the channel element type to something
poolable, which is a larger change than it looks and was not worth folding into
this pass.

## Suggested order

What is left, in the order it is worth doing:

1. Lazy buffer growth (1). The ceiling is survivable now, but a connection that
   carries one HTTP request still pays the full window a video connection needs,
   and the resident figure above says a third of that is real. Growing the
   window from small toward 256 KiB as a connection proves it can use it is the
   change that gets both numbers.
2. Confirm the allocator purge does something for `phys_footprint` on a real
   iOS extension (10). If it does not, the lever is (1) instead.
3. Handle semantics (5). The API implies a multi-instance model it does not
   have.
4. Configurable traffic-report interval (7), so an app can back off when its UI
   is not in the foreground.
5. The packaging items in 8, and the Fake IP platform wiring in 9.
