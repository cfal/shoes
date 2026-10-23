#!/usr/bin/env bash
# Runs a filtered test command and fails if it ran no tests, e.g. after a rename.
set -euo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed' "$log"; then
    echo "::error::No tests ran: $*" >&2
    exit 1
fi
