# Runtime stats through the FFI

Written 2026-08-27 against `mobile` at `e116f43` (v0.2.13), in answer to the
KVN request at `/tmp/kvn-handoff/shoes-stats-ffi-request.md`.

## The answer first

**Build it, and ship it on in both mobile artifacts.** The request asked for
the cost of "a counter table" at 256 connections and said to drop the feature
if that cost is not small. Read from the source, there is no table keyed by
connection. `control-stats` adds:

| State | Where | Size | Scales with |
| --- | --- | --- | --- |
| `ACTIVE_CONNECTIONS` | `src/tun/traffic.rs:29` | 8 B | nothing |
| Registry: one `Entry` per configured outbound | `src/outbound_stats.rs`, `mod registry` | ~200 B each (two `String`s, an `Arc<OutboundCounters>` of 3 atomics, a `HashMap` slot) | outbounds in the config — KVN has two: its chain and the built-in `direct` |
| Counter handles carried by `ClientProxyChain` | `src/client_proxy_chain.rs:92-107` | 8 B per hop | hops in the config |
| One `Arc` per live outbound stream | `src/outbound_counting_stream.rs:27` | 8 B | live connections: 2 KiB at the 256 ceiling |

Everything else the feature adds is code, which is the download budget
(`mobile-size-baseline.txt`), not RSS. `src/tun/traffic.rs:28` already
measured the connection counter at 720 bytes of code; the registry and the
counting adapters were added in v0.2.13 and have not been measured on the
arm64 profile yet — the plan measures them and raises the baseline in a commit
that says so. The RSS side is settled by the table above: it is within the
noise of a single 32 KiB connection buffer. The design below keeps the option
to ship without the feature (the symbol exists either way and returns NULL),
but nothing in the numbers argues for using it.

## Scope

One new entry point per platform, returning `control::stats::snapshot()` as
JSON, and the build changes that put `control-stats` into the published AAR
and XCFramework. Nothing else: no change to `ShoesTrafficCallback`, no change
to any existing symbol's signature or behaviour, no `control-logs` anywhere
near mobile.

## Sources

| What | Where |
| --- | --- |
| The snapshot being exposed | `src/control/stats.rs:20-49` |
| Counter storage and cost | `src/tun/traffic.rs:17-46`, `src/outbound_stats.rs` (`mod registry`) |
| Per-stream cost | `src/outbound_counting_stream.rs:22-36` |
| The owned-string convention to reuse | `src/ffi/ios.rs:353-374` (`shoes_get_last_error`, `shoes_free_string`) |
| JNI string return convention | `src/ffi/android.rs:403-414` (`getLastError`) |
| Kotlin mirror | `android/src/main/java/com/shoesproxy/ShoesNative.kt` |
| Header generation | `cbindgen.toml`, `scripts/build-ios.sh:21-26` |
| Header/symbol parity check | `.github/workflows/mobile.yml`, job `macos`, "Verify the C surface" |
| Size gate | `.github/workflows/mobile.yml`, job `android`; `mobile-size-baseline.txt` |
| AAR content gate | `.github/workflows/mobile.yml`, "Verify AAR ships only libshoes.so" |
| Feature policy | `Cargo.toml:27-37`, `MOBILE.md` §10 |
| Where the registry is installed | `src/control/mod.rs:369` (`prepare_from_config`) |
| Where the count resets | `src/tun/tcp_stack_direct.rs:939` (stack exit) |

## What is actually true today

**`snapshot()` compiles only with `control-stats`.** `src/control/mod.rs:19`
gates the module; `src/lib.rs:80` and `src/main.rs:25` gate
`outbound_stats`. A default build has no `StatsSnapshot` type at all, so an
FFI function that returns one has to either be gated itself or carry a stub
body.

**The macOS CI job builds `--features ffi` only** and fails if the number of
exported `shoes_*` symbols differs from the number declared in
`include/shoes.h`. A symbol that exists only under `control-stats` would make
that check fail unless the job also enabled the feature, and would make the
header's contents depend on which features the header was generated with.
That is the wrong property for a header KVN diffs to decide whether a bump is
drop-in.

**`serde_json` is a dev-dependency only** (`Cargo.toml:112`). The library
has no JSON serializer, and the snapshot has four scalar fields and a list of
four-field records. Adding a serializer for that would spend more of the
download budget than the feature itself.

**Two different things are called `active_connections`.** The top-level one
is device-side TCP connections through the smoltcp stack
(`tcp_stack_direct.rs:704`, `:877`). The per-outbound one counts live
`OutboundCountingStream`s, which wrap the stream to the *exit* hop of a chain
(`outbound_counting_stream.rs:40`). They can differ: a UDP session has no
outbound stream; a device connection that failed before its chain connected
has no outbound stream; a chain whose stream is dropped after the device side
has already been cleaned up briefly counts on one side only. The header
documents both so a host does not assert they are equal.

**The registry survives `stop`.** `install` runs in `prepare_from_config`
and replaces the set; nothing clears it on stop. Byte totals are reset in
`control::start` (`src/control/mod.rs`, "From zero"), and the device-side
count is zeroed when the stack thread exits. So between a stop and the next
start a snapshot shows the previous session's outbounds with their final
byte counts and zero connections. That matches what the traffic callback's
last values mean and is left as is.

## Design

### The C entry point

```c
/**
 * Read the runtime counters as a JSON document.
 *
 * Returns a null-terminated UTF-8 string the caller must free with
 * `shoes_free_string()`, or NULL if this library was built without the
 * `control-stats` feature. It is never NULL for any other reason: before
 * `shoes_start` every number is zero and `outbounds` is empty; after
 * `shoes_stop` it holds the final figures of the session that just ended,
 * and the next `shoes_start` resets them.
 *
 * Safe from any thread, and safe to call when nothing is running. It does no
 * I/O; it takes a short read lock on the outbound registry and allocates the
 * string.
 *
 * The document has this shape, and fields may be added to it in a later
 * release; a host should ignore keys it does not know:
 *
 *   {"upload_bytes":0,"download_bytes":0,"active_connections":0,
 *    "outbounds":[{"name":"Frankfurt","upload_bytes":0,"download_bytes":0,
 *                  "active_connections":0}]}
 *
 * `upload_bytes` and `download_bytes` at the top level are the same two
 * totals `ShoesTrafficCallback` delivers, measured at the TUN edge.
 * `active_connections` at the top level is live TCP connections through the
 * tunnel. Each `outbounds` entry is measured at the proxy instead: its bytes
 * are application payload to and from that server, and its
 * `active_connections` is streams open to it. The two measurements do not
 * agree to the byte and are not meant to; see src/control/stats.rs.
 * `outbounds` is sorted by name and lists every outbound in the running
 * config, including ones with no traffic yet.
 */
char *shoes_get_stats(void);
```

`shoes_free_string`'s comment widens from "a pointer returned by
`shoes_get_last_error()`" to "a pointer returned by `shoes_get_last_error()`
or `shoes_get_stats()`, or NULL". That is the only edit to an existing
declaration, and it is a comment.

The symbol is **unconditional**: the function exists in every build. Its
body is `#[cfg(feature = "control-stats")]` and the alternative arm returns
`null_mut()`. This keeps `include/shoes.h` identical regardless of features,
keeps the macOS parity check counting the same list in both configurations,
and means a host built against the header cannot fail to link.

### The JNI entry point

```kotlin
/**
 * Read the runtime counters as a JSON string.
 *
 * Returns null only if the native library was built without stats support.
 * Otherwise it is always a document; before [start] the numbers are zero and
 * `outbounds` is empty. Safe from any thread. The document's shape is
 * described on `shoes_get_stats` in include/shoes.h.
 */
external fun getStats(): String?
```

Rust side: `Java_com_shoesproxy_ShoesNative_getStats`, shaped exactly like
`getLastError` (`env.new_string`, `JString::null()` on failure).

### Serialisation

`impl StatsSnapshot { pub fn to_json(&self) -> String }` in
`src/control/stats.rs`, hand-written with `write!` into a `String`, plus a
private `fn write_json_string(out: &mut String, s: &str)` that escapes `"`,
`\`, and control characters below U+0020 as `\uXXXX` (with the short forms
`\n`, `\r`, `\t`, `\b`, `\f`), per RFC 8259 §7. Names come from user config
and can contain anything; this is the one place a bad escape becomes a
malformed document on a phone. Integers are emitted bare; `usize` is written
as a decimal like the `u64`s. No floats, no nulls, no optional fields.

Lives in `control::stats` rather than `ffi::common` because it is a property
of the snapshot, testable on the host with `--features control-stats`, and
the two FFI modules are compiled only on their targets.

### Build and CI

- `scripts/build-android.sh` and `scripts/build-ios.sh` pass
  `--features control-stats` to cargo. `default = []` in `Cargo.toml` stays:
  a library consumer still opts in, and the Cargo.toml comment gains a line
  saying the mobile artifacts turn `control-stats` on and why.
- `mobile.yml`, job `macos`: build with `--features ffi,control-stats` so the
  real body is compiled and its symbol counted. The parity check itself does
  not change.
- `lint.yml`, "Run clippy for Android": add `--features control-stats` so the
  JNI body that calls `snapshot()` is linted on its target.
- `mobile-size-baseline.txt`: raised to the measured arm64 figure with the
  feature on, with a history line naming what bought the bytes and the
  before/after pair.
- `cbindgen.toml`: no change. The function is unconditional, so no `cfg`
  reaches the header.

### Documentation

- `include/shoes.h` regenerated by cbindgen (`scripts/build-ios.sh` does it;
  the committed copy must match).
- `MOBILE.md`: FFI tables go to 10 JNI / 11 C symbols; `getStats` row and
  `shoes_get_stats` line; a paragraph in §10 recording the measured code and
  RSS cost of `control-stats` so the next person asking KVN's question finds
  the number.
- `AGENTS.md`, "Where the known debt is written down": "9 JNI and 10 C entry
  points" becomes 10 and 11 — the `catch_unwind` finding applies to the new
  one too.
- `CHANGELOG.md`: an entry under the next version.

## Alternatives considered

**A scalar `shoes_active_connections(void)` returning `int64_t`.** The
cheapest possible mechanism, and exactly the one datum KVN needs today. Not
chosen because it would be the second stats surface (after the callback) and
per-outbound would need a third when KVN grows chains or per-app routing —
each an ABI addition KVN must re-pin against. JSON lets the document grow
without a new symbol. The cost of choosing JSON over the scalar is one
allocation and a parse per poll, on a poll a host runs about once a second.

**A struct-out `int shoes_get_stats(ShoesStats *out)`.** Avoids the
allocation, but `outbounds` is variable-length with string names, so the
struct would need either a caller-provided buffer protocol or a second
ownership convention (free the array, free each name). The request said not
to add a new ownership convention; JSON through the existing
`shoes_free_string` does not.

**Extending `ShoesTrafficCallback` with a third parameter.** Forbidden by the
request: KVN's traffic UI is built on that signature.

**A gated symbol (`#[cfg(feature = "control-stats")]` on the `extern` fn).**
Rejected above: it makes the header depend on features and breaks the parity
check in the `--features ffi` job.

**Adding `serde_json` as a dependency.** Rejected above: a serializer for one
flat document is download-budget spend with no payoff, and hand-written JSON
for four integer fields and an escaped string is small enough to test
exhaustively.

**Keeping `control-stats` opt-in for mobile and shipping two artifacts.** The
combinatorial matrix `MOBILE.md` warned off, for an RSS cost measured in
kilobytes. Rejected. A host that does not want stats does not call the
function and pays only the download bytes the baseline records.

## Error handling

- Built without the feature: NULL / Kotlin `null`. Not an error; nothing is
  written to `LAST_ERROR`, which is for service failures.
- `CString::new` failing on an interior NUL: impossible by construction (the
  escaper turns U+0000 into `\u0000`), but the C function still maps it to
  NULL rather than unwrapping, as `shoes_get_last_error` does.
- JNI `new_string` failing under JVM OOM: `JString::null()`, as `getVersion`
  and `getLastError` do.
- Registry lock poisoned: `snapshot_all` already `unwrap`s the `RwLock`; a
  poisoned lock means a panic while holding it, which on the mobile profile
  is already an abort. No new handling.

## Testing

Host tests, run with `--features control-stats` (and under
`--features desktop` in CI, which includes it):

- `to_json` of a zero snapshot with no outbounds is byte-exact:
  `{"upload_bytes":0,"download_bytes":0,"active_connections":0,"outbounds":[]}`.
- `to_json` of a snapshot with two outbounds parses with `serde_json`
  (dev-dependency) into a `Value` whose fields round-trip the input, and the
  outbound order in the array matches the input order.
- Escaping: a name containing `"`, `\`, a newline, a tab and U+0001 produces
  a document `serde_json` parses back to the original name. A name with an
  interior NUL is escaped as `\u0000` and the result contains no raw NUL
  byte.
- Large values: `u64::MAX` for a byte count is emitted as the full decimal.

Target verification (the plan carries the commands):

- Android: `cargo ndk` build with the feature; `nm -D` on the arm64 `.so`
  shows `Java_com_shoesproxy_ShoesNative_getStats`; the AAR content check
  passes unchanged.
- macOS `--features ffi,control-stats` dylib: `nm -gj` lists 11 `shoes_`
  symbols and the header declares 11.
- Default-feature build: the same 11 symbols are exported and
  `shoes_get_stats` returns NULL — verified on the macOS dylib, since that is
  the build CI can run.
- Size: arm64 `.so` measured with and without the feature; the difference is
  the code cost and goes into `mobile-size-baseline.txt`'s history.
- RSS: `measure_memory_per_connection` (`src/tun/tcp_stack_direct.rs:1328`)
  run with and without the feature at `CONNECTIONS = 256` on the host; the
  difference is reported in `MOBILE.md` §10 alongside the analytic table
  above. This test exercises the device-side stack, so it captures
  `ACTIVE_CONNECTIONS` but not `OutboundCountingStream`; that one is
  `size_of` arithmetic (8 bytes) and a unit test asserts it stays 8.

## Out of scope

- A configurable traffic-report interval, or folding a connection count into
  the callback (MOBILE.md item 7 is the place for that).
- `control-logs` on any mobile artifact.
- Per-connection listings, DNS or UDP session counts — nothing that would
  need a table keyed by connection.
- `catch_unwind` at the FFI boundary. The new entry point inherits the
  existing gap, which `AGENTS.md` records; fixing it is a change to all 21
  symbols, not this one.
- Handle semantics (MOBILE.md item 5). `shoes_get_stats` takes no handle
  because the counters are process-global, as `control::start` documents.
