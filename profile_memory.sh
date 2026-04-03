#!/bin/bash
# Memory profiling script for shoes
# Usage: ./profile_memory.sh anytls_client.yaml

export _RJEM_MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:17,prof_final:true,prof_prefix:shoes_heap"
export MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:17,prof_final:true,prof_prefix:shoes_heap"

echo "Starting shoes with jemalloc heap profiling..."
echo "  _RJEM_MALLOC_CONF=$_RJEM_MALLOC_CONF"
echo ""
echo "After speed test:"
echo "  1. Close browser, wait 15s"
echo "  2. kill -USR1 \$(pgrep -x shoes)   # check allocated MB"
echo "  3. kill \$(pgrep -x shoes)          # creates heap dump"
echo "  4. jeprof --text ./target/release/shoes shoes_heap.*.heap"
echo ""

exec ./target/release/shoes "${@:-anytls_client.yaml}"
