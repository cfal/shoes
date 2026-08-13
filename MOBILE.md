# Mobile integration notes

State of the `mobile` branch as a core library for an Android/iOS VPN app, and
what still stands between it and a shipping product.

Everything in "What works" is verified on this branch. Every finding cites the
line that produced it — none of it is speculative, but the fixes are not written
yet. Line references were last checked against `037018e`; if one has drifted,
trust the symbol name over the number.

## What works

| | Android | iOS |
|---|---|---|
| Builds | `cargo ndk -t arm64-v8a -t armeabi-v7a` clean | `cargo build --target aarch64-apple-ios` clean |
| Packaging | AAR via `scripts/build-android.sh` | XCFramework via `scripts/build-ios.sh` |
| Entry points | 7 `Java_com_shoesproxy_ShoesNative_*` JNI symbols | 8 `shoes_*` C symbols |
| Socket protection | `VpnService.protect` via `SocketProtector` | `IosSocketProtector` |
| Traffic stats | `TrafficListener.onTrafficUpdate` | `ShoesTrafficCallback` |
| Error reporting | `getLastError()` | `shoes_get_last_error()` |
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

# Tests (849 of them) run on the host. `src/ffi/common.rs` compiles under
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

Android — 7 symbols, all `Java_com_shoesproxy_ShoesNative_*`, mirrored by
`ShoesNative.kt`:

| Kotlin | Rust | Returns |
|---|---|---|
| `init(logLevel: String)` | `android.rs:79` | 0 ok, -1 error |
| `getVersion()` | `android.rs:119` | version string |
| `setLogFile(logPath: String)` | `android.rs:145` | 0 ok, -1 error |
| `start(configYaml, protectCallback, trafficCallback)` | `android.rs:177` | `1` on success, -1 on error |
| `stop(handle: Long)` | `android.rs:317` | — |
| `isRunning()` | `android.rs:332` | boolean |
| `getLastError()` | `android.rs:348` | string or null |

iOS — 8 symbols, declared in `include/shoes.h`:

```c
int   shoes_init(const char *log_level);
long  shoes_start(const char *config_yaml, /* protect cb */, /* traffic cb */);
void  shoes_stop(long _handle);
bool  shoes_is_running(void);
const char *shoes_get_version(void);
int   shoes_set_log_file(const char *path);
char *shoes_get_last_error(void);   // caller frees
void  shoes_free_string(char *ptr);
```

`shoes_get_last_error` returns an owned string. Pass it back to
`shoes_free_string` or it leaks.

## Lifecycle contract

1. `init` once. Idempotent, and see finding 6 for what that costs you.
2. Open the TUN yourself — `VpnService.Builder.establish().detachFd()` on
   Android, `NEPacketTunnelProvider` on iOS — and put the fd into the config
   YAML as `device_fd`. The library never opens the device.
3. `start(configYaml, ...)`. The config must contain **exactly one** TUN entry
   and it must carry `device_fd`; both are enforced in `common.rs:178-189`.
   Server entries (a `mixed` listener, say) may sit alongside it and are started
   too, then aborted when the TUN stops.
4. `stop(...)`. Signals shutdown, then blocks — see finding 4.

The fd stays yours. `start_from_config` passes `close_fd_on_drop = false`
(`common.rs:221`) precisely so the library does not close a descriptor the
platform owns. Close it yourself after `stop` returns.

There is one tunnel per process. All state lives in the `TUN_SERVICE` global in
`common.rs`, and starting over a running service is refused rather than
permitted.

## Threading contract

- `init`, `stop`, `isRunning`, `getLastError` are safe from any thread. `stop`
  is the one that blocks, and it must not be on the main thread.
- `start` spawns its own multi-threaded Tokio runtime and returns immediately;
  the service runs on that runtime, not on the caller's thread.
- `SocketProtector.protect(fd)` is invoked from whichever runtime thread is
  creating the socket. It must be safe to call off the main thread and should
  not block. On Android it is delivered through `FnSocketProtector`
  (`android.rs:226`), which attaches to the JVM as needed.
- `TrafficListener.onTrafficUpdate` fires from a dedicated Tokio task on a 1 s
  interval (`tun/mod.rs:171-179`) — never the main thread. Marshal to the UI
  thread yourself.
- Both callbacks are stored in globals and cleared inside `stop`
  (`clear_traffic_callback`, and the protect callback on iOS). Do not retain
  objects across a stop/start cycle and assume they are still wired.

## Example configs

`examples/tun_fake_ip.yaml` and `examples/amneziawg_client.yaml` are the two
shapes a mobile app actually sends. Take either, inject `device_fd`, and it is a
valid argument to `start`. `CONFIG.md` is the full reference.

---

# Findings

## 1. Per-connection memory will get the iOS extension killed

This is the one blocking issue.

`src/tun/tcp_stack_direct.rs:374-375` sets both TCP buffers to `0x3FFF * 20`
(~320 KB), and each connection allocates **four** of them eagerly — two smoltcp
socket buffers at `tcp_stack_direct.rs:756-757` and two ring buffers in
`TcpConnectionControl::new` at `tcp_conn.rs:60`. That is **~1.31 MB per TCP
connection**, allocated at SYN, regardless of how much the connection carries.

`MAX_CONCURRENT_CONNECTIONS` is 1024 (`tcp_stack_direct.rs:377`), so the stack's
own ceiling is about **1.34 GB**.

An iOS `NEPacketTunnelProvider` runs under a hard ~50 MB memory limit. The
extension is jetsam'd, not warned, when it crosses it. That works out to **~35
concurrent connections** — a single page load in Safari opens more than that.
Android is more forgiving but a 1024-connection burst still means an OOM kill.

What to do:

- Make the buffer sizes configurable in `TunServerConfig` rather than constants,
  and default them far lower on mobile. 32-64 KB per direction is enough to keep
  a mobile radio busy; the current value is sized for a desktop 10 GbE path.
- Allocate lazily and grow, instead of taking 1.31 MB at SYN.
- Set `MAX_CONCURRENT_CONNECTIONS` from config too, and pick a mobile default
  (256 matches the UDP `MAX_SESSIONS` already in `udp_manager.rs:36`).

Until this is addressed, measure before shipping: run the extension under
Instruments' Allocations with 50 concurrent connections and watch the footprint.

Two neighbouring allocations have already been sized for this budget and are
not part of the problem: the AnyTLS outgoing channel is bounded at
`OUTGOING_CHANNEL_CAPACITY = 256` (`src/anytls/anytls_client_session.rs:30`,
with the iOS limit named in the comment above it), and the UDP session table is
an LRU capped at 256.

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

## 3. Nothing handles a network change

There is no API to tell the library the network moved — no `on_network_change`,
no rebind, no reconnect. `rg -n 'network_change|rebind|path_monitor' src/`
returns nothing at all.

On mobile the default route changes constantly: Wi-Fi to cellular, cellular to
Wi-Fi, IP change on the same interface, doze wake-up. When it does:

- Every UDP socket, including the AmneziaWG endpoint socket in
  `src/amneziawg/tunnel.rs`, is still bound to the old local address. It stops
  receiving, silently. The tunnel does not error; it goes quiet.
- Resolver state and any pooled TCP connections point at an interface that no
  longer carries traffic.

Both platforms already deliver the signal — `ConnectivityManager.NetworkCallback`
on Android, `NWPathMonitor` on iOS. What is missing is somewhere to deliver it
to. The minimum useful surface is one FFI call that rebinds the AmneziaWG
endpoint socket and forces a fresh handshake; a fuller version also drains the
proxy connection pools and re-resolves.

Today the only recovery is stop-and-start, which tears down the TUN interface
and every connection through it.

## 4. `stop` blocks the calling thread for up to five seconds

`stop_service` in `src/ffi/common.rs:85` polls a flag in 100 ms sleeps up to 50
times, then drops the Runtime — which itself blocks until every task finishes.

On Android, calling `ShoesNative.stop()` from `onDestroy` on the main thread is
an ANR waiting to happen: the system allows about 5 seconds before it kills the
app for not responding, and this can consume all of it. The KDoc on
`ShoesNative.stop` says it "blocks until the service has fully stopped" but does
not say for how long, and the sample in the KDoc calls it from `onDestroy`.

On iOS, `stopTunnel(with:completionHandler:)` has a similar budget before the
extension is killed.

What to do: make the shutdown wait asynchronous, or at minimum document a hard
requirement to call it off the main thread and fix the KDoc sample. A callback
or a `shoes_stop_async` that signals and returns immediately, with completion
delivered through the existing error/status channel, fits both platforms better.

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

## 6. The log level is fixed at first init

`shoes_init` returns 0 immediately if `INITIALIZED` was already set
(`ios.rs:89-91`), before it reads `log_level`. A second call with `"debug"` does
nothing, and returns success while doing so.

For a support workflow — "turn on debug logging and reproduce" — that means the
user has to kill the app. A `shoes_set_log_level` that updates the filter on a
live logger is a small addition and removes the restart.

Note that `log` is built with `release_max_level_info` (`Cargo.toml:51`), so
`debug` and `trace` are compiled out of release builds entirely. A live log
level switch is only useful together with a build that keeps those levels.

## 7. Traffic stats wake the device once a second regardless of traffic

`report_traffic` (`src/tun/traffic.rs:57`) loads both counters and invokes the
callback unconditionally; the timer task in `tun/mod.rs:171-179` calls it on a
1-second interval. An idle tunnel therefore crosses into the JVM, or into Swift,
3,600 times an hour to report numbers that have not changed.

Skipping the call when neither counter moved since the last tick is a few lines
and lets an idle device stay idle. Consider also making the interval
configurable, so the app can back off when its UI is not in the foreground.

The JNI side itself is fine: `attach_current_thread` in jni 0.22 is the
permanent-attach variant, which is documented as a thread-local check with no
JNI call once the thread is attached. No change needed there.

## 8. Smaller items

- **`libboringtun-*.so` shipped in the AAR.** `cargo-ndk` copies every cdylib in
  the dependency graph. Nothing loads it — the hashed filename is not a valid
  `System.loadLibrary` name — so it was 315 KB of dead weight per ABI.
  `scripts/build-android.sh:66` now deletes it.
- **Secrets in logs are handled, mostly.** `Redacted<T>`
  (`src/config/types/redacted.rs`) gives keys and passwords a `Debug` that
  prints a placeholder, so a config dump into the log file is safe to hand to
  support. Worth confirming that any new secret-bearing config field is wrapped
  in it — the type only helps where it is used.
- **`minSdk = 21`, `compileSdk = 35`** (`android/build.gradle.kts:8,11`). Play
  Store now requires targeting API 35+ for new submissions; `compileSdk` is fine
  but confirm the consuming app's `targetSdk`. `minSdk 21` is very generous —
  raising it to 24 or 26 would let the NDK drop some compatibility shims.
- **Stale ABI comment in CI.** The header comment on the `android` job in
  `.github/workflows/mobile.yml` claims x86_64 and x86 slices; the job builds
  arm64-v8a and armeabi-v7a, same as the script.
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
- **No jemalloc on mobile.** Deliberate (`Cargo.toml:95` excludes iOS and
  Android) and correct — but it means the system allocator's fragmentation
  behaviour is what you get, which makes finding 1 worse than the arithmetic
  suggests.

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

## Suggested order

1. Buffer sizing and connection limits (1). Nothing else matters if the
   extension is being killed.
2. Socket protection coverage (2). Cheap to fix, and it removes a silent
   dependency on an app-side workaround nobody wrote down.
3. Network-change handling (3). This is the difference between a VPN that
   survives walking out of the house and one that does not.
4. Async stop (4) and live log level (6). Both small, both remove a rough
   edge users will hit.
5. Idle traffic ticks (7), handle semantics (5), packaging (8).
