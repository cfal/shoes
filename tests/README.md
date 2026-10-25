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
| `optional_peer` | `optional-peer-tests` | sing-box, Mihomo, Xray, and Naive Caddy as required by each case. Includes carrier sharing and idle reuse. |
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
```

Use absolute peer paths to avoid accidentally testing a different installed
version. Most fixtures accept `SHOES_TEST_SING_BOX_BIN`, `SHOES_TEST_MIHOMO_BIN`,
`SHOES_TEST_XRAY_BIN`, or `SHOES_TEST_NAIVE_CADDY_BIN`. The dedicated VLESS/REALITY
fixtures additionally use `XRAY_BINARY` and `MIHOMO_BINARY`; their fixture guide
and workflow specify the exact pins. Requested but unavailable peers should
fail, not silently skip.

## Measuring Coverage

CI does not collect coverage. To measure it locally with
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov), collect the unit,
integration, and process-contract suites into one profile set and report once:

```sh
export CARGO_BUILD_JOBS=1 SHOES_TEST_GRACEFUL_STOP=1
export SHOES_TEST_SING_BOX_BIN=/absolute/path/to/sing-box
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace --lib --bins --locked -- --test-threads=2
cargo llvm-cov --no-report --locked --features integration-tests \
  --test integration --test process_contract -- --test-threads=1
cargo llvm-cov report --summary-only
```

On Linux, `SHOES_TEST_GRACEFUL_STOP` makes test guards send SIGTERM before
SIGKILL, so instrumented Shoes subprocesses write their profiles. Without it,
and on other platforms, which ignore it, code reached only through integration
subprocesses is reported as uncovered. Totals include test modules and
test-support code, so compare per-file figures rather than the headline
percentage.

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

- CI does not measure coverage; see [Measuring Coverage](#measuring-coverage).
  Passing suites do not establish exhaustive coverage.
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
