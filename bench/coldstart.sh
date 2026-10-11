#!/bin/sh
# Cold-start benchmark: how long it takes to start a sandbox, run `true` in it
# and tear it down again, end to end, for kiln, Docker, runc and crun. Every
# runtime starts the same Alpine tree with the same limits as kiln's defaults
# (512 MiB, 1 CPU, 128 PIDs). Needs bench/setup.sh first.
#
#   sudo bench/coldstart.sh [label]     # results go to bench/results/<label>/
#
# KILN=path picks the kiln binary (default /usr/local/bin/kiln), RUNS and
# WARMUP the number of timed and untimed runs, ONLY=regex a subset of cases.
#
# GAP is an untimed pause before every run (default 0.1 s). Without it, runs
# follow each other within microseconds and some kernel paths stay "warm":
# moving a process into a cgroup waits for an RCU grace period unless another
# move happened just before (see docs/benchmarks.md). GAP=0 measures that
# back-to-back case.
set -eu
cd "$(dirname "$0")"
KILN=${KILN:-/usr/local/bin/kiln}
RUNS=${RUNS:-100}
WARMUP=${WARMUP:-10}
ONLY=${ONLY:-.}
GAP=${GAP:-0.1}
out="results/${1:-latest}"
bundle=/var/lib/kiln-bench/bundle
limits="--memory 512m --cpus 1 --pids-limit 128"

if pgrep -f review-regressions >/dev/null; then
    echo "review-regressions.sh is running; measure later" >&2
    exit 1
fi
mkdir -p "$out"

# name|command. hyperfine -N runs each command directly (no shell), so only
# the runtime's own time is measured.
cases="
kiln-none|$KILN run -- true
docker-none|docker run --rm --network none $limits kiln-alpine true
runc-none|runc run --bundle $bundle kiln-bench
crun-none|crun run --bundle $bundle kiln-bench
kiln-net|$KILN run --net full -- true
docker-net|docker run --rm $limits kiln-alpine true
"

echo "$cases" | grep -E "^($ONLY)" | grep '|' | while IFS='|' read -r name cmd; do
    echo "== $name: $cmd"
    hyperfine -N --style basic --warmup "$WARMUP" --runs "$RUNS" \
        --prepare "sleep $GAP" --export-json "$out/$name.json" "$cmd" >/dev/null
done
python3 -I summarize.py "$out"/*.json | tee "$out/summary.md"
