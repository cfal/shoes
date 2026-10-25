# Advisory Performance Evidence

This is an opt-in extension of `selector_measurement.rs` and `reload_memory.mjs`,
not a replacement for allocation, cancellation, process or pinned-peer tests.
No throughput or timing threshold gates a shared-runner build.
Collection is Linux-only: the existing reload harness and affinity metadata use
`/proc`. Saved reports can be compared without launching either binary.

## Collect And Compare

The manual `Advisory verification evidence` workflow's `performance` choice
builds release executables and uploads raw evidence for its selected revision.
It never checks out a second revision or claims a speedup from one measurement.
Download independently collected baseline and candidate artifacts and compare:

```sh
node benches/advisory_report.mjs BASELINE_DIRECTORY CANDIDATE_DIRECTORY > advisory.json
```

For a local measurement, supply the library test executable emitted by Cargo,
the server binary, and a new output directory. Keep build flags in the environment
through collection; the runner records them but cannot infer historical flags
from a binary. Build commands must describe the actual binaries, not desired ones.

```sh
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export BENCH_PROFILE=release
export BENCH_SELECTOR_BUILD_COMMAND='cargo test --locked --release --lib measurement_bench --no-run --message-format=json'
export BENCH_BUILD_COMMAND='cargo build --locked --release --bin shoes'
cargo test --locked --release --lib measurement_bench --no-run --message-format=json
cargo build --locked --release --bin shoes
node benches/run_advisory.mjs SELECTOR_TEST_BINARY SHOES_BINARY NEW_OUTPUT_DIRECTORY
```

Use `debug` and the actual debug build commands for a tooling smoke only. Do not
compare debug and release runs. In the recommendation batch VM, wrap **all**
builds, tests and collection in the foreground flock from `EXECUTION_RULES.md`,
with its shared target and `CARGO_BUILD_JOBS=1`. Do not follow the older baseline
patch/staging instructions in `README.md` for this workstream.

The bounded matrix is six selector processes (16 members and 128 policies with
12,800 members, three repeats each) plus three reload processes. Selector runs
verify 4,096 queries before collecting 15 batch averages. Each reload process
retains four live connections through three SIGHUPs and checks exact echoes.
The collector fixes `BENCH_GENERATIONS=4`, irrespective of the parent environment.
Upstream's harness is unchanged: alternating upstream targets verify committed
routing, and warmup/drain phases check return to the initial FD count. Initial
startup timing is separate from the three reload-readiness timings; the first
pinned generation has no additional readiness timing.
The reload inputs are a tiny generated domain YAML and the existing pinned SRS
fixture passed in both SRS argument positions. Duplicate source caching is
intentional here: this smoke is not the historical large-corpus RSS workload.
Every selector process has a 15-second deadline; each reload harness has its
existing 60-second deadline plus a 70-second outer bound. Failures remain in the
manifest and raw logs, and invalidate comparison rather than disappearing.

`measurement.json` schema 2 records revision/tree, dirty-state and patch digest, source
and tooling hashes, binary and lockfile hashes, build commands/profile, Rust and
Node versions, OS/CPU/affinity, selected build flags, inputs, commands, exit
statuses and raw-log hashes. `source.diff` preserves tracked changes; `sources`
also hashes untracked verification code. HEAD is not a claim of a clean measured
tree. Keep the source patch and raw runs with the manifest. Neither the collector
nor a self-comparison establishes baseline-versus-candidate improvement.

## Interpretation And Invalid Runs

Comparison requires three successful fresh processes for every declared case,
nonzero executed selector tests, finite positive samples and RSS, all four reload
generations, warmup/drain samples, and matching raw-artifact hashes and reload provenance. Missing,
malformed, zero-sample, failed or partial artifacts produce `status: invalid`,
no metrics, and a nonzero exit. Different toolchain/environment, workload, helper
hashes or profile produce `status: incomparable`, also without deltas.
Historical schema-1/four-sample reports are rejected, not silently converted into
evidence of upstream's newer lifecycle checks. Recollect both revisions with the
same current harness to compare them.

Valid reports retain raw process values, min/median/max, and percentage deltas.
Overlapping ranges or changes below 5% are `noise-unresolved`. Disjoint ranges
outside that band are labelled `candidate-higher`/`candidate-lower`, not proven
regressions/improvements. All recorded metrics are lower-is-better, but three
processes, fixed run order, frequency scaling and shared-host interference do
not establish statistical confidence. Timing changes never cause a nonzero exit.
The original 58-case comparator and its explicit opt-in gates remain separate.

Tooling regressions:

```sh
node --test benches/*.test.mjs scripts/coverage-lines.test.mjs scripts/require-tests.test.mjs
```

## Deferred Matrix

The following remain separately opt-in follow-ups, not implied by a passing smoke:

| Workload | Prerequisites and evidence before automation |
| --- | --- |
| Direct/encrypted TCP and multiplexed transport | Pinned independent peers, setup latency and sustained throughput, exact payload verification, CPU/RSS/FD/allocation measurements |
| QUIC | Peer pins, stable connection accounting, packet captures for framing failures; no migration claim from reload tests |
| TUN and WireGuard | Explicit root/kernel/device availability, namespace isolation, separate userspace/kernel reports; never silently skip prerequisites |
| Large rule sets | Retained corpus revisions/hashes and large-corpus runs; the tiny fixture smoke is insufficient |
| Loss/latency/small MTU | Dedicated controlled host, explicit impairment setup and teardown, repeated interleaved baseline/candidate runs |
| Mobile/platform memory | Real device VPN lifecycles and platform-specific RSS/heap instrumentation |

Do not add a shared-runner hard gate before establishing repeatability, noise
budgets and clean baseline/candidate artifact provenance. Reload correctness and
generation lifetime expansion belong to the lifecycle workstream; extend the
measurement matrix after those contracts settle rather than duplicating them.
