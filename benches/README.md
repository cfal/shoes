# Selector measurements

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
executables, raw logs, toolchain and commands. Executables stay local rather than
being committed; raw logs and aggregate results are retained in `results/`.

## Retained Run (2026-10-20)

`results/manifest.json` identifies baseline `76df520c` and candidate `d8c44452`.
All 57 routing gates passed across 348 fresh processes. Ordinary uncached medians:

| Workload | Baseline | Indexed |
| --- | ---: | ---: |
| 16 members | 0.432 us | 0.476 us |
| 100k members | 711.62 us | 0.508 us |
| 1M members | 8,995.17 us | 0.556 us |
| 1,024 policies, late hit | 944.72 us | 123.72 us |

The budget is not a no-regression guarantee: all nine 16-member cases and all six
unguarded many-policy early-hit cases slowed by 44-150 ns (up to 41%). At these
baselines, the 250 ns allowance dominates. Thirteen of those cases have
non-overlapping per-process ranges.

The historical baseline patch used an external absolute helper path. It is kept
unchanged in the manifest as build evidence; `results/baseline-reproduction.patch`
reconstructs a portable patch with the exact measured helper from `d8c44452`.
This reconstruction was not used to build the retained executable. The retained
manifest's profile metadata corrects an earlier unsupported codegen-units=1 claim;
its tooling hashes still identify the original measurement scripts.

These synthetic membership workloads are not a general routing-throughput
claim. Many-policy evaluation remains ordered and scales with policies visited.
The full distributions, including occasional process outliers, are in
`results/{old,new}.log`; `results/selector.json` contains aggregates and gates.

`reload_memory.mjs` exercises the real server with the 197,553-entry Loyalsoldier
reject YAML plus sing-geoip CN/US SRS. Four live TCP streams retain four selector
generations across three SIGHUP reloads and must continue echoing exact bytes.
The debug server at `82556016` used jemalloc and includes the final YAML and
decompression allocation fixes. Initial load/reload took 2.37-2.50 seconds;
sampled peak RSS was 102.2 MiB with one worker and 103.7 MiB with eight.
These replace the older `d8c44452` decoder measurements. Raw RSS/HWM samples,
source revision/tree, tracked-tree cleanliness, build command and input/binary
hashes are in `results/reload*.json`.
This is a measured four-generation overlap, not a bound on arbitrary draining
connections or a mobile memory guarantee. Requested heap and concurrent routing
latency were not measured. Android/iOS device validation remains outstanding.

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --bin shoes
export BENCH_BUILD_COMMAND='CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --bin shoes'
BENCH_PROFILE=debug BENCH_WORKERS=1 node benches/reload_memory.mjs \
  SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
BENCH_PROFILE=debug BENCH_WORKERS=8 taskset -c 0,1,3-7 \
  node benches/reload_memory.mjs SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
```

Run from the source checkout used to build the binary. `BENCH_BUILD_COMMAND`
records that command; the harness does not rebuild or infer binary provenance.
Tracked-tree cleanliness excludes untracked files. Harness regressions run with
`node --test benches/*.test.mjs`.

The one-worker run had no affinity restriction; the eight-worker run excluded
CPU 2 to avoid the selector benchmark. Both ran in the shared VM.
Corpus revisions: Loyalsoldier/clash-rules `335129e29eb0b32bb783d4164bcce1d35b53d9e1`
(`reject.txt`), SagerNet/sing-geoip `eb32cd6ed4a16fcb3bf9a36ccebf28e45716ae84`
(`geoip-cn.srs`, `geoip-us.srs`). The large corpus files are not committed.

## Lifetime Regressions

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
fixture run is not comparable to the historical 197,553-entry results above.
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
