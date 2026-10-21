#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: run_selector.sh TEST_BINARY OUTPUT.log}
output=${2:?usage: run_selector.sh TEST_BINARY OUTPUT.log}
[[ ! -e "$output" ]] || { printf 'Refusing to overwrite %s\n' "$output" >&2; exit 1; }
runner=()
if [[ -n ${BENCH_CPU:-} ]]; then runner=(taskset -c "$BENCH_CPU"); fi

run_case() {
    BENCH_COUNT=$1 BENCH_POLICIES=$2 BENCH_MODE=$3 BENCH_WORKLOAD=$4 BENCH_PORTS=$5 \
        "${runner[@]}" "$binary" \
        client_proxy_selector::measurement_bench::selector_measurement \
        --ignored --exact --nocapture --test-threads=1 >> "$output"
}

for ((round=0; round<${BENCH_REPEATS:-3}; round++)); do
    modes=(ordinary sniff dns)
    if ((round % 2)); then modes=(dns sniff ordinary); fi
    for mode in "${modes[@]}"; do
        for ports in none fixed mixed; do
            for count in 16 100000; do run_case "$count" 1 "$mode" mixed "$ports"; done
        done
        run_case 1000000 1 "$mode" mixed none
        for policies in 128 1024; do
            for workload in early late miss; do
                for ports in none mixed; do
                    run_case "$((policies * 100))" "$policies" "$mode" "$workload" "$ports"
                done
            done
        done
    done
    run_case 16 1 floor mixed none
done
