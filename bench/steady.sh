#!/bin/sh
# Steady state: once a sandbox runs, its code runs on the same kernel as any
# other runtime's, so it should take the same time. One CPU-bound and one
# I/O-bound workload, timed inside the sandbox with busybox `time -p` (so
# startup isn't counted), REPS times per runtime, interleaved. Needs
# bench/setup.sh first.
#
#   sudo bench/steady.sh [label]     # results go to bench/results/<label>/
set -eu
cd "$(dirname "$0")"
. ./lib.sh
REPS=${REPS:-7}
out="results/${1:-steady}"
mkdir -p "$out"

# CPU: hash 512 MiB of zeros. I/O: write 1 GiB to the sandbox's writable
# layer and fsync it. Both single-threaded, under the same 1-CPU limit.
cpu='dd if=/dev/zero bs=1M count=512 2>/dev/null | sha256sum >/dev/null'
io='dd if=/dev/zero of=/root/io.bin bs=1M count=1024 conv=fsync 2>/dev/null; rm /root/io.bin'

python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/cpu" \
    --root "$BENCH/bundle/rootfs" -- time -p sh -c "$cpu"
python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/io" \
    --root "$BENCH/bundle/rootfs" --rw -- time -p sh -c "$io"

# run RUNTIME WORKLOAD prints the workload's wall time in seconds.
run() {
    script=$(eval echo "\$$2")
    case $1 in
    kiln) "$KILN" run -- time -p sh -c "$script" ;;
    docker) docker run --rm --network none $LIMITS kiln-alpine time -p sh -c "$script" ;;
    runc | crun) "$1" run --bundle "$BENCH/$2" "kiln-steady-$1" ;;
    esac 2>&1 | awk '$1 == "real" {print $2}'
}

: >"$out/times.txt"
for workload in cpu io; do
    rep=0
    while [ "$rep" -lt "$REPS" ]; do
        for runtime in kiln docker runc crun; do
            echo "$workload $runtime $(run "$runtime" "$workload")" >>"$out/times.txt"
        done
        rep=$((rep + 1))
    done
done

python3 -I - "$out/times.txt" <<'PY' | tee "$out/summary.md"
import collections, statistics, sys
times = collections.defaultdict(list)
for line in open(sys.argv[1]):
    workload, runtime, seconds = line.split()
    times[workload, runtime].append(float(seconds))
print("| workload | runtime | median s | min | max |")
print("|---|---|---:|---:|---:|")
for (workload, runtime), t in times.items():
    print(f"| {workload} | {runtime} | {statistics.median(t):.2f} | {min(t):.2f} | {max(t):.2f} |")
PY
