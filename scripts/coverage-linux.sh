#!/usr/bin/env bash
set -euo pipefail

output=${1:?usage: coverage-linux.sh NEW_OUTPUT_DIR smoke|full BASE_REVISION}
mode=${2:?missing smoke or full}
base=${3:?missing base revision}
[[ $(uname -s) == Linux ]] || { echo 'Linux coverage only' >&2; exit 1; }
[[ $mode == smoke || $mode == full ]] || { echo 'Expected smoke or full' >&2; exit 1; }
[[ $(cargo llvm-cov --version) == 'cargo-llvm-cov 0.9.1' ]] || { echo 'Requires cargo-llvm-cov 0.9.1' >&2; exit 1; }
base=$(git rev-parse --verify "${base}^{commit}")
mkdir "$output"
output=$(realpath "$output")
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
export SHOES_TEST_GRACEFUL_STOP=1
# Each invocation owns fresh profiles. Never clean or reuse another run's profiles.
CARGO_LLVM_COV_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}/verification-coverage-$(basename "$output")"
export CARGO_LLVM_COV_TARGET_DIR
[[ ! -e $CARGO_LLVM_COV_TARGET_DIR ]] || { echo 'Coverage target already exists; use a new output name' >&2; exit 1; }
mkdir -p "$CARGO_LLVM_COV_TARGET_DIR" "$output/tmp"
export TMPDIR="$output/tmp"
{
    printf 'scope=Linux unit/process\nmode=%s\nbase=%s\n' "$mode" "$base"
    git rev-parse HEAD
    git status --short
    rustc -Vv
    cargo -V
    cargo llvm-cov --version
    rustup component list --installed
    printf 'CARGO_BUILD_JOBS=%s\nCARGO_INCREMENTAL=%s\nRUSTFLAGS=%s\nCARGO_ENCODED_RUSTFLAGS=%s\n' \
        "$CARGO_BUILD_JOBS" "$CARGO_INCREMENTAL" "${RUSTFLAGS:-}" "${CARGO_ENCODED_RUSTFLAGS:-}"
    printf 'Skipped: peers, privileged/kernel, external network, FFI, macOS/Windows, mobile devices, stress\n'
} > "$output/environment.txt"
git diff --no-ext-diff --no-renames --unified=0 "$base" -- src tests > "$output/changes.diff"
unit_filter=()
process_filter=()
if [[ $mode == smoke ]]; then
    unit_filter=(rule_set::tests::detected_binary_sources_still_require_valid_payloads)
    process_filter=(coverage_process_graceful_stop)
fi
run() {
    local label=$1
    shift
    printf '%q ' "$@" >> "$output/commands.txt"
    printf '\n' >> "$output/commands.txt"
    .github/require-tests.sh "$@" 2>&1 | tee "$output/$label.log"
}
run unit cargo llvm-cov test --locked --no-report -p shoes --lib "${unit_filter[@]}" -- --test-threads=1
run process cargo llvm-cov test --locked --no-report -p shoes --test process_contract "${process_filter[@]}" -- --test-threads=1
cargo llvm-cov report --locked --lcov --output-path "$output/coverage.lcov" 2>&1 | tee "$output/report.log"
node scripts/coverage-lines.mjs "$output/changes.diff" "$output/coverage.lcov" > "$output/changed-lines.json"
find "$CARGO_LLVM_COV_TARGET_DIR" -maxdepth 1 -name '*.profraw' -type f -size +0c -print > "$output/profiles.txt"
test -s "$output/profiles.txt"
printf 'Coverage artifacts: %s\n' "$output"
