# Test Suites

Tests are grouped by runtime prerequisites, not just protocol. Cargo has
`autotests = false`: register new test targets in `Cargo.toml`, and add new case
modules to the appropriate target's `.rs` file. An unreferenced file under
`tests/cases/` is not compiled or run.

## Local Checks

Run from the repository root. Limit Rust build concurrency on small machines:

```sh
export CARGO_BUILD_JOBS=1
cargo test --workspace --locked --lib --bins
cargo test -p shoes --locked --lib --features ffi -- --test-threads=1
cargo test -p shoes --locked --test process_contract -- --test-threads=1
cargo test -p shoes --locked --test rule_allocation
cargo test -p shoes --locked --test retention_allocation --test matcher_invariants -- --nocapture
cargo test -p shoes --locked --test rule_properties -- --test-threads=1
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Library tests cover protocol parsers and adapters, authentication, routing and
configuration, resource limits, deterministic backpressure, and rootless TUN and
WireGuard paths. Binary and process-contract tests cover startup, validation,
signals, reload rejection, listener replacement, and cleanup. The FFI feature
enables host-side service and socket-protection tests; it does not simulate an
Android or iOS VPN service.

Clippy's `--all-features` compiles optional tests but does not execute them.
Likewise, a filtered `cargo test` command that matches zero tests succeeds; check
the reported test count when renaming modules or changing CI filters.

## Integration Targets

| Target | Feature | Prerequisites and scope |
| --- | --- | --- |
| `integration` | `integration-tests` | Local endpoints, Shoes subprocesses, and sing-box for peer cases. Includes TCP/UDP protocols, chaining, sniffing, Fake DNS, resource lifecycle, and userspace WireGuard. |
| `process_contract` | None | Shoes subprocesses; Unix-only cases exercise signals and filesystem reloads. |
| `rule_allocation` | None | Local rule compilation and allocation limits. |
| `retention_allocation` | None | Isolated requested-heap retention across failed compilation, generation replacement, retained owners, and final destruction. |
| `matcher_invariants` | None | Fixed-seed port-range membership against a linear oracle, including Boolean composition and boundary cases. |
| `rule_properties` | None | Bounded deterministic rule parser mutations and cross-format properties; no peers or network. |
| `optional_peer` | `optional-peer-tests` | sing-box, Mihomo, Xray, shadowsocks-rust, and Naive Caddy as required by each case. Includes carrier sharing and idle reuse. |
| `xhttp_interop` | `integration-tests` | Local-only filters or pinned Xray and Mihomo; see [XHTTP.md](XHTTP.md). |
| `reality_interop` | `optional-peer-tests` | Pinned Xray and local TLS camouflage endpoints. |
| `vless_encryption_interop` | `optional-peer-tests` | Pinned Xray, Mihomo, and sing-box; see the [fixture guide](fixtures/vless_encryption/README.md). |
| `external_network` | `external-network-tests` | Internet access and sing-box for DNS, external REALITY, and proxy cases. |
| `privileged` | `privileged-tests` | Select a case explicitly. Kernel TUN needs Linux, `/dev/net/tun`, `ip`, IPv6 loopback, and passwordless sudo. Kernel WireGuard also needs `wg` and namespace tools. Native Naive cases have separate binary, libcronet, and CA prerequisites. |
| `stress` | `stress-tests` | Sustained traffic and benchmarks; some cases are ignored and require explicit selection. |

Examples:

```sh
# Local relay contract, without an external peer binary.
cargo test --locked --features integration-tests --test integration plain_tcp_relay:: -- --test-threads=1

# The full local-protocol suite also requires sing-box.
SHOES_TEST_SING_BOX_BIN=/absolute/path/to/sing-box \
  cargo test --locked --features integration-tests --test integration -- --test-threads=1

# Includes same-name device replacement and active-flow teardown.
cargo test --locked --features privileged-tests --test privileged tun_kernel:: -- --test-threads=1

# SS2022 client identity headers: Xray, shadowsocks-rust, and sing-box UoT.
SHOES_TEST_XRAY_BIN=/absolute/path/to/xray \
SHOES_TEST_SSSERVER_BIN=/absolute/path/to/ssserver \
SHOES_TEST_SING_BOX_BIN=/absolute/path/to/sing-box \
  cargo test --locked --features optional-peer-tests --test optional_peer \
    shadowsocks_identity:: -- --test-threads=1
```

Use absolute peer paths to avoid accidentally testing a different installed
version. Most fixtures accept `SHOES_TEST_SING_BOX_BIN`, `SHOES_TEST_MIHOMO_BIN`,
`SHOES_TEST_XRAY_BIN`, `SHOES_TEST_SSSERVER_BIN`, or `SHOES_TEST_NAIVE_CADDY_BIN`.
The dedicated VLESS/REALITY fixtures additionally use `XRAY_BINARY` and
`MIHOMO_BINARY`; their fixture guide and workflow specify the exact pins.
Requested but unavailable peers should fail, not silently skip.

The SS2022 identity tests use Xray 26.10.21, shadowsocks-rust `ssserver` 1.25.0,
and sing-box 1.14.1 with multi-user Shadowsocks and SagerNet UoT. They cover
both AES key sizes, concurrent users, ordered relays, wrong/missing/reordered
identity rejection, large bidirectional transfers, half-close, server-first data,
and TCP/UoT behind an HTTP proxy hop. CI installs all three peers for this suite;
`ssserver` uses `SHOES_TEST_SSSERVER_BIN` locally.
Xray and shadowsocks-rust must return the complete payload after client upload
EOF. sing-box uses reply-first exchanges: the pinned build truncates replies
after early upload EOF even with a single-key SS2022 configuration. All three
peers must deliver server-first data and clean EOF after the acknowledged exchange.

## Measuring Coverage

The manual `Advisory verification evidence` workflow collects Linux unit/process
coverage with Rust 1.99.1, `llvm-tools-preview`, and `cargo-llvm-cov` 0.9.1. It has
no percentage gate. `smoke` selects one rule-loader unit test and one process
test that verifies a child actually flushes a nonempty LLVM profile. `full` runs
the library and process-contract suites, without optional features. Each command
uses the existing nonzero-test guard. Run locally with the same pinned tooling:

```sh
export CARGO_BUILD_JOBS=1
bash scripts/coverage-linux.sh NEW_OUTPUT_DIRECTORY smoke BASE_REVISION
```

In the recommendation batch VM, hold the shared foreground build lock around the
entire script and use its dedicated target, as specified in `EXECUTION_RULES.md`.
The script uses a fresh, named coverage target under `CARGO_TARGET_DIR`, refuses
reuse, and never cleans shared artifacts. Tool installation, if needed, is
`cargo install cargo-llvm-cov --version 0.9.1 --locked`; do not install another
toolchain just to manufacture local success evidence.

The output retains test logs, commands, toolchain and skip information, LCOV,
changed-line JSON and profile paths. Raw profiles remain in the named target.
The changed-line report compares the chosen local base revision to the tracked
working tree, includes uncovered line numbers, and reports `null` rather than
100% for no executable changed lines. Untracked files are outside `git diff`;
missing source instrumentation is distinguished from uncovered executable lines.
Unknown/non-executable lines are never implicitly called covered.

On Linux, `SHOES_TEST_GRACEFUL_STOP` makes both shared guards and process-contract
guards send SIGTERM before bounded SIGKILL fallback. The coverage script sets it
and preserves per-process profile filenames. Forced exits or failed startup can
still lack profiles; successful smoke verifies a normal server shutdown, not
every error path. Inline unit-test code can be included, while standalone test
and support paths may be excluded by cargo-llvm-cov's default report filters.
Inspect per-file results rather than a headline percentage. Peers, privileged/kernel tests,
external-network suites, FFI, device and non-Linux coverage remain separate,
unmeasured categories, not silent skips or part of this percentage.

## Bounded Rule Properties

`rule_properties` is explicitly registered because `autotests = false`. It uses
the public `load_source` and compiler budget APIs without exposing private
protocol parsers or adding dependencies. Three existing JSON/SRS/text fixtures
seed 288 deterministic truncation/bit-flip/insertion/trailing-byte mutations.
Each is loaded twice with a fresh compiler to compare rejection or predicate
results; untouched seeds must parse successfully. The fixed seed is
`0x726c7365745f3234`; failures identify format, case and bytes. Retain a minimal
reproducer, not a growing generated corpus.

Inputs are capped at 4 KiB. Each mutation has a 72 MiB accounting budget (the
existing regex compiler conservatively reserves 64 MiB even for small patterns).
A separate 2 MiB compressed expansion must hit a 4 MiB accounting budget before
full inflation; generated exact-domain rules compare the shared JSON/text subset
with normalized queries and Mihomo's pattern case/trailing-dot normalization.
Sing-box's intentionally different uppercase-literal behavior is not treated as
a cross-format equivalence. Existing allocator regressions remain authoritative for actual peak
allocations; accounting budgets are not RSS guarantees. Linux CI bounds the test
executable to 30 seconds via Cargo's host runner and adds a ten-minute outer
deadline including compilation, not a timing performance assertion. For
already-built smoke binaries use `timeout --kill-after=5s 30s TEST_BINARY
--test-threads=1`. No unbounded randomized runner or stress workload is enabled.

Follow-ups: MRS/DAT, YAML aliases/depth, DNS/HTTP/TLS framing and protocol state
machines need their own small seeds, decompression/window caps and cancellation
properties. Broader differential cases must only compare intentionally shared
semantics with pinned peers and preserve fixture licensing. No new peer or
libFuzzer toolchain is required for this first surface.

## CI And Remaining Gaps

The workflows run Linux unit, process, FFI, local-protocol, external-network,
kernel TUN/WireGuard, and pinned-peer suites. macOS runs rootless TUN, WireGuard,
process-watcher unit tests, and selected FFI/process contracts. Android and iOS
jobs cross-compile the native libraries but do not exercise device VPN lifecycles.
Only selected bounded stress cases run in CI; long-duration and performance tests
remain explicit opt-ins. Filtered test steps run through
`.github/require-tests.sh`, which fails a step whose filter selects no tests.

Retain the existing suite boundaries. Prefer deterministic in-process tests for
fragmentation, cancellation, credit accounting, and parser rejection; use
process/kernel tests for descriptor ownership, real routing, and reload behavior.
Bound network waits, assert exact payloads and EOF/error outcomes, and propagate
fixture-task failures rather than accepting a timeout as proof of rejection.

The `process::retention_tests::` library case launches an exact-filter child to
isolate process-global budgets and descriptor counts from parallel tests. The
child must run exactly one passing test, so a stale filter cannot silently pass.
The case repeats partial listener startup failures, malformed and cancelled SOCKS
handshakes, TCP generation retirement with live and stalled sessions, owner
destruction, and QUIC endpoint/stream ownership. Every cycle must restore its
known baseline within five seconds, including Tokio live tasks and active
connection/stream/QUIC reservations. Linux also gates FD recovery; other
platforms explicitly report FD/RSS as unavailable (`None`). RSS is informational.
These are lifecycle primitives, not a replacement for process activation tests.
The real SIGHUP datapath measurement remains in `benches/reload_memory.mjs`.

`shoes_test_support::measure` supplies the shared counting system allocator,
Linux process samples, and bounded state polling. Do not use process-wide
samples in concurrently running tests. Allocation tests have one test per
executable, warm up first, and sample equivalent owner states before printing.
The allocator counts successful allocations/reallocations and requested live
bytes/blocks, not jemalloc arenas, foreign allocations, or RSS. Retention checks
require exact return to baseline; compilation peak budgets remain enforced.

Important remaining limitations:

- Coverage is manual and Linux unit/process only; see [Measuring Coverage](#measuring-coverage).
  Passing suites or increased percentages do not establish exhaustive coverage.
- Android/iOS device execution and macOS Network Extension kernel-device behavior
  remain separate from host-side tests and cross-compilation.
- Windows build entries are disabled; ARM and musl builds do not establish
  runtime coverage. macOS does not run the full Linux protocol and IP-stack suite.
- The legacy `privileged` target's `tun::` cases are not selected by CI; the
  `tun_kernel::` cases are. Native Naive and most sustained multi-GiB stress tests
  remain manual.
- The historical Naive/sing-box idle timeout remains unattributed. Progress
  diagnostics and deterministic H2 credit tests do not prove its cause.
- Mihomo and sing-box early-half-close limitations retain ignored strict tests.
  Their enabled reply-first cases still require exact payloads and clean TLS EOF.
  A passing non-injected run is not proof that the timing-sensitive Mihomo issue
  is fixed; see the fixture guide.
- WebSocket Close frames are skipped rather than answered as RFC 6455 requires.
  Xray, sing-box and mihomo close the TCP connection right after sending Close,
  so reads still end at EOF.
- Internet-dependent failures and manual native Naive prerequisites require
  separate investigation; they are not covered by a local-only test run.
