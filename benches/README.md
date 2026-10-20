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

For old/new comparisons, inject this same file as a test module in a detached
checkout of the baseline's `client_proxy_selector.rs`. Pin both source revisions,
hash this helper and each lockfile/diff, rebuild both test executables, and record
their hashes. Use identical Rust flags, allocator, CPU pinning and workload.
Compare medians across processes; preserve individual samples and outliers.

The matrix covers 16/100k/1M entries, homogeneous and mixed port guards, and
128/1,024 ordered policies with early/late/missing hits. `BENCH_MODE=warm` and
`cold` are also available for cache experiments; `floor` measures the ready
future, runtime entry and cloned-location wrapper. No cache policy change is
implied by these measurements. Host measurements do not establish mobile memory,
concurrent cache contention or network throughput.

The library test uses the system allocator, not the server binary's jemalloc.
Both sides use the production release profile (fat LTO, one codegen unit).
The baseline matrix runs before the candidate matrix; repeated fresh processes
and retained min/max values expose noise, but do not remove run-order effects.

```sh
node benches/compare_selector.mjs RESULTS/old.log RESULTS/new.log
node benches/selector_manifest.mjs BASELINE_WORKTREE RESULTS CANDIDATE_REVISION
```

The comparator requires exactly three processes for each of 58 cases. Its 57
routing gates cover small-rule no-regression, 100k/1M scaling, and many-policy
no-regression. The remaining case calibrates the harness floor. The manifest
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

These synthetic membership workloads are not a general routing-throughputput
claim. Many-policy evaluation remains ordered and scales with policies visited.
The full distributions, including occasional process outliers, are in
`results/{old,new}.log`; `results/selector.json` contains aggregates and gates.

`reload_memory.mjs` exercises the real server with the 197,553-entry Loyalsoldier
reject YAML plus sing-geoip CN/US SRS. Four live TCP streams retain four selector
generations across three SIGHUP reloads and must continue echoing exact bytes.
The debug server used jemalloc. Initial load/reload took roughly 1.9-2.0 seconds;
peak RSS was approximately 116 MiB with one worker and 122 MiB with eight.
Raw RSS/HWM samples and input/binary hashes are in `results/reload*.json`.
This is a measured four-generation overlap, not a bound on arbitrary draining
connections or a mobile memory guarantee. Requested heap and concurrent routing
latency were not measured. Android/iOS device validation remains outstanding.

```sh
BENCH_PROFILE=debug BENCH_WORKERS=1 node benches/reload_memory.mjs \
  SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
BENCH_PROFILE=debug BENCH_WORKERS=8 taskset -c 0,1,3-7 \
  node benches/reload_memory.mjs SHOES_BINARY SCRATCH_DIR REJECT_YAML CN_SRS US_SRS
```

The one-worker run had no affinity restriction; the eight-worker run excluded
CPU 2 to avoid the selector benchmark. Both ran in the shared VM.
Corpus revisions: Loyalsoldier/clash-rules `335129e29eb0b32bb783d4164bcce1d35b53d9e1`
(`reject.txt`), SagerNet/sing-geoip `eb32cd6ed4a16fcb3bf9a36ccebf28e45716ae84`
(`geoip-cn.srs`, `geoip-us.srs`). The large corpus files are not committed.
