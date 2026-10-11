#!/usr/bin/env bash
# Re-run the kiln/Podman network comparison after creating Podman's dedicated
# kiln-bench bridge. The original all-runtime campaign used Podman's default
# 10.88.0.0/16 network, which overlaps kiln0 and is not publishable as a
# functional network comparison.
#
# Usage: bench/run-v2-podman-net.sh [output-directory]
# Environment: SESSIONS (5), RUNS (100), WARMUPS (10), GAP_MS (100),
#              SEED (20261031), BOOT_SETTLE_S (20), LIMA_INSTANCE (kiln).
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

OUT=${1:-bench/results/v2/macbook-air-2026-10-11/podman-net-corrected}
SESSIONS=${SESSIONS:-5}
RUNS=${RUNS:-100}
WARMUPS=${WARMUPS:-10}
GAP_MS=${GAP_MS:-100}
SEED=${SEED:-20261031}
BOOT_SETTLE_S=${BOOT_SETTLE_S:-20}
LIMA_INSTANCE=${LIMA_INSTANCE:-kiln}
CASES='^(kiln-net|podman-crun-net)$'

if [[ -e "$OUT" ]]; then
    echo "$OUT already exists; choose a new output directory" >&2
    exit 2
fi
mkdir -p "$OUT"

restart_vm() {
    local label=$1
    echo "[$label] restarting $LIMA_INSTANCE" >&2
    limactl stop "$LIMA_INSTANCE"
    limactl start "$LIMA_INSTANCE"
    sleep "$BOOT_SETTLE_S"
}

for ((n = 1; n <= SESSIONS; n++)); do
    label=$(printf 'podman-net-boot-%02d' "$n")
    restart_vm "$label"
    limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
        sudo python3 -I bench/v2.py latency \
        --config bench/v2-config.json \
        --out "$OUT/$label-latency" \
        --session "$label" \
        --runs "$RUNS" \
        --warmups "$WARMUPS" \
        --gap-ms "$GAP_MS" \
        --case "$CASES" \
        --seed "$((SEED + n))"
done

python3 -I bench/v2.py summarize "$OUT"/podman-net-boot-*-latency \
    --out "$OUT/latency-summary" \
    --baseline kiln-net \
    --bootstrap-seed "$SEED"

restart_vm podman-net-gap
limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
    sudo python3 -I bench/v2.py latency \
    --config bench/v2-config.json \
    --out "$OUT/gap-sweep" \
    --session podman-net-gap \
    --runs 10 \
    --warmups 2 \
    --gap-ms 0,10,100,1000,5000 \
    --case "$CASES" \
    --seed "$((SEED + 100))"
python3 -I bench/v2.py summarize "$OUT/gap-sweep" \
    --out "$OUT/gap-summary" \
    --baseline kiln-net \
    --bootstrap-seed "$SEED"

restart_vm podman-net-concurrency
limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
    sudo python3 -I bench/v2.py latency \
    --config bench/v2-config.json \
    --out "$OUT/concurrency-warmup" \
    --session podman-net-concurrency-warmup \
    --runs 2 \
    --warmups 0 \
    --gap-ms 0 \
    --case "$CASES" \
    --seed "$((SEED + 200))"
limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
    sudo python3 -I bench/v2.py concurrency \
    --config bench/v2-config.json \
    --out "$OUT/concurrency" \
    --session podman-net-concurrency \
    --levels 1,4,16,32,64 \
    --batches 3 \
    --gap-ms 500 \
    --case "$CASES" \
    --seed "$((SEED + 201))"
python3 -I bench/v2.py summarize "$OUT/concurrency" \
    --out "$OUT/concurrency-summary" \
    --baseline kiln-net \
    --bootstrap-seed "$SEED"

restart_vm podman-net-memory
limactl shell --workdir "$ROOT" "$LIMA_INSTANCE" -- \
    sudo python3 -I bench/v2.py memory \
    --config bench/v2-config.json \
    --out "$OUT/memory" \
    --session podman-net-memory \
    --counts 0,10,25,50,100 \
    --repeats 3 \
    --settle-s 2 \
    --case "$CASES" \
    --seed "$((SEED + 300))"
python3 -I bench/v2.py summarize "$OUT/memory" \
    --out "$OUT/memory-summary" \
    --baseline kiln-net \
    --bootstrap-seed "$SEED"

echo "corrected Podman network campaign complete: $OUT" >&2
