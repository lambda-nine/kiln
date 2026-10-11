#!/bin/sh
# Compares kiln builds against each other: cold-start time of `kiln run --
# true`, with and without a network, for every binary given.
#
#   sudo bench/compare.sh label /path/to/kiln-a /path/to/kiln-b ...
#
# Results go to bench/results/<label>/. RUNS, WARMUP and GAP work as in
# coldstart.sh. Each binary is benchmarked in the same session, so a busy
# host affects them all alike.
set -eu
cd "$(dirname "$0")"
RUNS=${RUNS:-100}
WARMUP=${WARMUP:-10}
GAP=${GAP:-0.1}
label=$1
shift
BINARIES="$*"
out="results/$label"

if pgrep -f review-regressions >/dev/null; then
    echo "review-regressions.sh is running; measure later" >&2
    exit 1
fi
mkdir -p "$out"
for net in none full; do
    set --
    for kiln in $BINARIES; do
        set -- "$@" "$kiln run --net $net -- true"
    done
    hyperfine -N --style basic --warmup "$WARMUP" --runs "$RUNS" \
        --prepare "sleep $GAP" --export-json "$out/net-$net.json" "$@" >/dev/null
done
python3 -I summarize.py "$out"/*.json | tee "$out/summary.md"
