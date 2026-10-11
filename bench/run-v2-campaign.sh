#!/usr/bin/env bash
# Run replicated lifecycle latency measurements across fresh Lima VM boots.
#
# Usage: bench/run-v2-campaign.sh [output-directory]
# Environment: SESSIONS (default 5), RUNS (100), WARMUPS (10), GAP_MS (100),
#              SEED (20261011), LIMA_INSTANCE (kiln).
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

OUT=${1:-bench/results/v2/macbook-air-2026-10-11}
SESSIONS=${SESSIONS:-5}
RUNS=${RUNS:-100}
WARMUPS=${WARMUPS:-10}
GAP_MS=${GAP_MS:-100}
SEED=${SEED:-20261011}
LIMA_INSTANCE=${LIMA_INSTANCE:-kiln}

if [[ -e "$OUT" ]]; then
    echo "$OUT already exists; choose a new output directory" >&2
    exit 2
fi
mkdir -p "$OUT"

for ((n = 1; n <= SESSIONS; n++)); do
    label=$(printf 'boot-%02d' "$n")
    echo "[$label] restarting $LIMA_INSTANCE" >&2
    limactl stop "$LIMA_INSTANCE"
    limactl start "$LIMA_INSTANCE"
    echo "[$label] running $RUNS measured rounds" >&2
    limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
        sudo python3 -I bench/v2.py latency \
        --config bench/v2-config.json \
        --out "$OUT/$label-latency" \
        --session "$label" \
        --runs "$RUNS" \
        --warmups "$WARMUPS" \
        --gap-ms "$GAP_MS" \
        --seed "$((SEED + n))"
done

python3 -I bench/v2.py summarize "$OUT"/boot-*-latency \
    --out "$OUT/latency-summary" \
    --baseline kiln-none \
    --bootstrap-seed "$SEED"

echo "replicated latency campaign complete: $OUT" >&2
