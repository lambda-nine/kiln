#!/bin/sh
# Warm start: latency of running `true` in a sandbox that already exists
# (`kiln exec` into a `kiln create` sandbox, `docker exec`, `runc exec`,
# `crun exec`). Needs bench/setup.sh first.
#
#   sudo bench/warm.sh [label]     # results go to bench/results/<label>/
#
# RUNS, WARMUP and GAP work as in coldstart.sh.
set -eu
cd "$(dirname "$0")"
. ./lib.sh
RUNS=${RUNS:-100}
WARMUP=${WARMUP:-10}
GAP=${GAP:-0.1}
out="results/${1:-warm}"
mkdir -p "$out"

ids=""
trap 'for pair in $ids; do stop_idle "${pair%%=*}" "${pair#*=}"; done' EXIT
for runtime in kiln kiln-net docker docker-net runc crun; do
    id=$(start_idle "$runtime" "kiln-warm-$runtime")
    ids="$ids $runtime=$id"
    echo "== $runtime"
    hyperfine -N --style basic --warmup "$WARMUP" --runs "$RUNS" --prepare "sleep $GAP" \
        --export-json "$out/exec-$runtime.json" "$(exec_cmd "$runtime" "$id")" >/dev/null
done
python3 -I summarize.py "$out"/exec-*.json | tee "$out/summary.md"
