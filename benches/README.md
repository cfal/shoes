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
