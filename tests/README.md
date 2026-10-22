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

## CI And Remaining Gaps

The workflows run Linux unit, process, FFI, local-protocol, external-network,
kernel TUN/WireGuard, and pinned-peer suites. macOS runs rootless TUN, WireGuard,
process-watcher unit tests, and selected FFI/process contracts. Android and iOS
jobs cross-compile the native libraries but do not exercise device VPN lifecycles.
Only selected bounded stress cases run in CI; long-duration and performance tests
remain explicit opt-ins.

Retain the existing suite boundaries. Prefer deterministic in-process tests for
fragmentation, cancellation, credit accounting, and parser rejection; use
process/kernel tests for descriptor ownership, real routing, and reload behavior.
Bound network waits, assert exact payloads and EOF/error outcomes, and propagate
fixture-task failures rather than accepting a timeout as proof of rejection.

Important remaining limitations:

- No measured whole-project line or branch coverage is maintained by these
  workflows; passing suites do not establish exhaustive coverage.
- Android/iOS device execution and macOS Network Extension kernel-device behavior
  remain separate from host-side tests and cross-compilation.
- Windows build entries are disabled; ARM and musl builds do not establish
  runtime coverage. macOS does not run the full Linux protocol and IP-stack suite.
- Global resource-budget changes across rejected and accepted reload generations
  need a combined process contract; separate budget and reload tests do not cover
  their interaction.
- Graceful message-stream EOF with a permanently pending shutdown needs an
  explicit shutdown policy and regression. Error-path cleanup already has a
  deadline; changing the graceful path is not merely a test improvement. The
  association idle timer also lacks deterministic paused-clock coverage.
- Pre-auth ClientHello negative cases, credential rejection for VLESS fallback,
  Hysteria2 and TUIC, and broader WebSocket length/control-frame boundaries need
  focused tests. Multi-record ClientHello support and extension-length handling
  need separate protocol review.
- The legacy `privileged` target's `tun::` cases are not selected by CI; the
  `tun_kernel::` cases are. Native Naive and most sustained multi-GiB stress tests
  remain manual. Several local ShadowTLS handshake cases still live in the
  Internet-dependent target.
- Filtered CI invocations can still select zero tests after a rename. The
  resource-limit and raw-descriptor subprocess tests explicitly require one
  passed child test, but that guard is not applied to every workflow filter.
- The historical Naive/sing-box idle timeout remains unattributed. Progress
  diagnostics and deterministic H2 credit tests do not prove its cause.
- Mihomo and sing-box early-half-close limitations retain ignored strict tests.
  Their enabled reply-first cases still require exact payloads and clean TLS EOF.
  A passing non-injected run is not proof that the timing-sensitive Mihomo issue
  is fixed; see the fixture guide.
- Internet-dependent failures and manual native Naive prerequisites require
  separate investigation; they are not covered by a local-only test run.
