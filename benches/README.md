# Benchmark Tools

These are opt-in measurements, not standalone Cargo benches. The Rust helpers are
ignored library tests so they can exercise private production code; the JavaScript
and shell tools collect and compare their output. CI runs the tooling regression
tests, not shared-runner timing gates.

- [Sudoku](#sudoku-measurements): codec and stream costs.
- [Selector](#selector-measurements): routing and cache costs.
- [Reload](#reload-memory-and-lifetime): memory, descriptor and generation lifetime.
- [Whole paths](#whole-path-measurements): composition preparation, selection and churn.
- [Advisory collection](ADVISORY.md): bounded selector/reload collection and comparison.

Keep generated logs, manifests and binaries outside the source tree or in the
ignored `benches/results/` directory. Historical
[selector and reload snapshots](https://github.com/cfal/shoes/tree/5a4954463cbe016960843012580e44d470fdd440/benches/results)
and their [original interpretation](https://github.com/cfal/shoes/blob/5a4954463cbe016960843012580e44d470fdd440/benches/README.md#retained-run-2026-10-20)
remain in Git history; they describe those revisions and hosts, not current performance.

## Sudoku Measurements

The ignored `sudoku_measurement` unit test exercises the production codec and
`SudokuStream` with 3 KiB plaintext writes, entropy/ASCII/custom/three-layout rotation,
classic/packed directions, and 0%/10% padding. Build and run it explicitly:

```sh
CARGO_BUILD_JOBS=1 cargo test --release --locked --lib sudoku_measurement --no-run
SUDOKU_BENCH_MS=500 SUDOKU_BENCH_SAMPLES=7 taskset -c 0 \
  target/release/deps/shoes-TEST_HASH sudoku_measurement --ignored --nocapture
```

Use the test executable reported by Cargo. `SUDOKU_BENCH_FILTER` selects case
names by substring. `SUDOKU_BENCH_BYTES` selects 1-3640 plaintext bytes per write
(default 3072). Output rows are `SUDOKU,case,sample,iterations,ns,MiB/s`;
`ns` is per iteration and throughput counts plaintext bytes. `codec_decode`
iterations cover three writes (9 KiB by default), restoring the three-layout rotation
position; other cases cover one write (3 KiB by default). Compare normalized MiB/s, not
nanoseconds across different batch sizes. Optional
`SUDOKU_BENCH_WIRE_DIR` supplies identical `entropy-classic-pad0.bin`-style wire
files for entropy/ASCII comparisons; each must decode to the benchmark's
deterministic plaintext. Otherwise, wire inputs use a fixed ChaCha12 seed so
baseline and candidate decode identical bytes when encoder RNG ordering is unchanged.

Stream cases use a repeating in-memory source and discard sink, not sockets,
TLS, or a Tokio scheduler. Setup and allocation occur outside timed iterations;
the production ChaCha12 RNG is retained. These numbers measure codec and wrapper
cost, not network throughput. Compare separately built baseline/candidate
executables on the same pinned CPU, alternate their run order, retain raw
samples and binary/source hashes, and use isolated Cargo targets to prevent
stale artifacts from another source tree. Go comparisons must disclose RNG and
wrapper differences rather than imply equivalent end-to-end workloads.

This library test uses the system allocator, not the application's jemalloc.

## Selector Measurements

For the small, advisory selector/reload collection and comparison workflow, see
[ADVISORY.md](ADVISORY.md). It retains raw runs and rejects invalid artifacts;
it does not reuse the historical comparator's timing gates. The manual
`Advisory verification evidence` workflow publishes one revision's measurements.

The selector measurement is an ignored unit test so it can exercise the real
private ingress, cache and routing paths. It is not a standalone Cargo bench.

```sh
CARGO_BUILD_JOBS=1 cargo test --release --lib measurement_bench --no-run
BENCH_CPU=2 BENCH_REPEATS=3 bash benches/run_selector.sh \
  target/release/deps/shoes-TEST_HASH "$HOME/tmp/selector-results.log"
```

Use the test executable printed by Cargo, not the production `shoes` binary.
The runner refuses to overwrite results. Each case runs in a fresh process and
checks all 4,096 deterministic queries before timing. Entry selection, hit/miss,
case variation and port guards are independently randomized. Timings are the
median and p95 of 15 batch averages, not individual request tails. DNS uses an
immediately ready counted stub, not Fake DNS or network resolution.

For old/new comparisons, copy this helper into a detached baseline checkout at
`benches/selector_measurement.rs`, run `git add -N` on the copy, and include it in
`src/client_proxy_selector.rs` with `#[path = "../benches/selector_measurement.rs"]`.
The resulting patch must contain the helper bytes, not an external absolute path.
Pin both source revisions,
hash this helper and each lockfile/diff, rebuild both test executables, and record
their hashes. Use identical Rust flags, allocator, CPU pinning and workload.
Compare medians across processes; preserve individual samples and outliers.

The matrix covers 16/100k/1M entries, homogeneous and mixed port guards, and
128/1,024 ordered policies with early/late/missing hits. `BENCH_MODE=warm` and
`cold` are also available for cache experiments. Cold mode cycles 32,768 unique
hostname keys through a 10,000-entry cache, including small and early-hit cases;
`floor` measures the ready
future, runtime entry and cloned-location wrapper. No cache policy change is
implied by these measurements. Host measurements do not establish mobile memory,
concurrent cache contention or network throughput.

The library test uses the system allocator, not the server binary's jemalloc.
Both sides use the production release profile (fat LTO, default 16 codegen units,
strip enabled, non-incremental release builds).
The baseline matrix runs before the candidate matrix; repeated fresh processes
and retained min/max values expose noise, but do not remove run-order effects.

```sh
node benches/compare_selector.mjs RESULTS/old.log RESULTS/new.log
node benches/selector_manifest.mjs BASELINE_WORKTREE RESULTS CANDIDATE_REVISION COMMANDS_JSON
```

`COMMANDS_JSON` must contain the actual `baseline_build`, `candidate_build`,
`profile`, `run` and `aggregate` strings for that measurement. The generator does
not infer build commands or flags from the current checkout.

The comparator requires exactly three processes for each of 58 cases. Its 57
routing gates cover a small-rule/many-policy regression budget of the greater of
25% or 250 ns, plus 100k/1M scaling. The remaining case calibrates the harness floor. The manifest
records the exact baseline patch/lockfile, candidate tree/source hashes, helper,
executables, raw logs, toolchain and commands. Keep these artifacts together in
the chosen results directory, without committing generated output. These synthetic
membership workloads are not a general routing-throughput claim: many-policy
evaluation remains ordered and scales with policies visited. The comparator's
250 ns allowance is not a no-regression guarantee for small workloads.

## Reload Memory And Lifetime

`reload_memory.mjs` exercises the real server with a domain YAML and two SRS files.
By default, four live TCP streams retain four selector generations across three
SIGHUP reloads and must continue echoing exact bytes. The server uses jemalloc;
RSS includes allocator retention and does not measure live heap allocations.

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --bin shoes
export BENCH_BUILD_COMMAND='CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --bin shoes'
BENCH_PROFILE=debug BENCH_WORKERS=1 node benches/reload_memory.mjs \
  SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
BENCH_PROFILE=debug BENCH_WORKERS=8 node benches/reload_memory.mjs \
  SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
```

Run from the source checkout used to build the binary. `BENCH_BUILD_COMMAND`
records that command; the harness does not rebuild or infer binary provenance.
Tracked-tree cleanliness excludes untracked files. Harness regressions run with
`node --test benches/*.test.mjs`.

The reload harness records a warmed idle sample, a post-payload sample per
pinned generation, and a drained sample after all test connections close.
`BENCH_GENERATIONS` selects 2-16 generations (default 4). The 60-second
whole-run deadline and reload grace apply. Each committed generation
alternates between two local upstreams: exact payload echo is necessary but not
sufficient; the new connection must reach the newly configured upstream. Old
connections must keep echoing exact bytes. FDs must return to the pre-connection
idle ceiling within five seconds after warmup and final drain.
A fresh post-drain connection must still reach the final committed upstream and
echo exact bytes before the final idle sample is taken.
The asynchronous toolchain probe has a five-second deadline and also observes
whole-run cancellation. The reported RSS peak includes every recorded sample.

The measurement requires Linux `/proc`; missing metrics are errors, never zero.
RSS/HWM and reload time are informational, without slope or nanosecond gates.
RSS includes allocator retention and cannot establish that live allocations
leak. The report records source revision/tree, tracked patch, untracked Rust
source hashes, lockfile, binary, harness, inputs, server log, toolchain, supplied
build command, and command arguments. `source.patch_base64` preserves raw patch
bytes, with color, external diffs and text conversions disabled, fixed path
prefixes and three context lines; `source.patch_sha256` hashes the decoded bytes.
`BENCH_CONTENTION` records observed outside
load; its default is explicitly `not recorded`. Use a fresh output directory:
the harness refuses to overwrite `server.log`.

For a small reproducible correctness/measurement cycle, without downloading a
large corpus, use a YAML file containing `payload: [blocked.invalid]` and the
committed `tests/fixtures/rule_sets/singbox-v2.srs` for both SRS arguments. That
fixture run does not represent large-rule-set memory costs.
Preserve stdout JSON and the output directory's `server.log` together.

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --lib process::retention_tests:: -- --nocapture
CARGO_BUILD_JOBS=1 cargo test --locked --test retention_allocation --test matcher_invariants -- --nocapture
CARGO_BUILD_JOBS=1 cargo test --locked --test rule_allocation -- --nocapture
TMPDIR="$PWD/target/tmp" node --test benches/reload_memory.test.mjs
```

Create `target/tmp` first when using the last command. On shared hosts, run builds,
heavy tests, and measurements under the same exclusive `flock`, with one Cargo
build job and worktree-local target/scratch paths. Release the lock between
commands. Do not compare timing/RSS across contested runs as if they were isolated.

The isolated Rust lifetime case samples live Tokio tasks, active resource
reservations, and Linux FDs at matching lifecycle states. Its TCP tests use a
one-second drain grace and five-second cleanup deadline, including stalled
handshakes and live exact-byte sessions; QUIC checks that application handles
retain memory reservations until destruction. The separate system-allocator
test performs 64 generation/failed-compilation cycles after eight warmups,
checking exact live-byte/allocation-count recovery with four temporary owners.
This models immutable predicate ownership, not full daemon heap retention.
`rule_allocation` enforces adversarial compilation peak budgets.
`matcher_invariants` adds 128 fixed-seed port-range cases with linear membership,
boundary, negation, and composition checks; production domain storage is untouched.

Linux CI gates these correctness and bounded-retention tests. Full daemon live
heap, asynchronous task counts in the subprocess, mobile devices, and arbitrary
long-lived generation overlap remain outside these measurements. Other isolated
tests can reuse the sampling helpers without adding production metrics.

## Whole-Path Measurements

`path_measurement` measures JSON parsing, validation/expansion and connector
construction together, then selection separately without dialing. Cases cover
one/four fixed hops, 16-way round-robin, nested selector/URL-test compositions
with 64/1,024 leaves, 48 nested choices, a 16,000-member selector, and a 64-leaf
group referenced by 64 rules. URL-test samples are seeded; no probes run here.
Preparation excludes dropping the result. Selection includes releasing the
selected path and uses warmed, unchanged manual choices.

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --release --lib path_measurement --no-run
PATH_BUILD_COMMAND='CARGO_BUILD_JOBS=1 cargo test --locked --release --lib path_measurement --no-run' \
PATH_REVISION="$(git rev-parse HEAD)" PATH_PROFILE=release PATH_SOURCE_ROOT="$PWD" \
node benches/run_paths.mjs TEST_BINARY NEW_OUTPUT_DIRECTORY
```

The collector pins CPU 2 by default (`BENCH_CPU`), runs three fresh processes
per case (`BENCH_REPEATS`), and records seven preparation samples and seven
75-ms selection batches per transport/process. Reported selection extrema and
medians are batch averages, not individual-flow latency percentiles. It retains
raw logs, toolchain/build command, source and executable hashes. Use `fixed`
as the final argument for a pre-feature comparison; its harness needs only
source/resolved enum-name adaptations, unwrapping resolved `ConfigSelection`
rules, and `select_indices` instead of `select`.
Baseline selection measures decisions (indices); candidate selection includes
path materialization and release. Neither measures the complete per-flow setup.
Archive both harness versions and use identical profiles/toolchains. Alternate
baseline/candidate runs on an otherwise idle host with the same exclusive lock.
Set `PATH_SOURCE_ROOT` to the source tree used for that binary, especially for
baseline runs. The collector validates the binary's debug-assertions metadata
against `PATH_PROFILE` and rejects missing or duplicate samples.

Debug builds additionally report thread-local requested Rust heap and allocation
counts using the existing test allocator. They assert that warmed selection
retains no allocations and that dropping a prepared result releases its live
bytes. Debug timings are not performance evidence; release timings use the
uninstrumented system allocator. Neither measures the daemon's jemalloc arenas,
TLS handshakes, concurrent selection contention, or network throughput.

The Linux `path_lifecycle_churn_releases_generations_tasks_and_sockets` test runs
in an isolated child: 12 cycles of four control-generation publications and 16
selector updates per generation, with real local one/two-hop SOCKS paths and
automatic probes. Existing streams and retained prefix dialers must keep using
their selected routes; retired compositions/generations must be released.
After each cycle, live Tokio tasks, FDs and connection/stream reservations must
return to baseline within five seconds; reservations stay zero in these
client-only paths. RSS is informational. This exercises
control-generation replacement, not listener reload or every pooled protocol;
run the existing process-retention test alongside it for listener reload/drain.
