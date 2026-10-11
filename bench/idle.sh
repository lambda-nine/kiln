#!/bin/sh
# Idle overhead: host memory for one idle sandbox per runtime, the same for
# many sandboxes at once, and the fixed cost of daemons. Needs bench/setup.sh.
#
#   sudo bench/idle.sh [label]     # results go to bench/results/<label>/
#
# For one idle sandbox it reports, per host process it adds (kiln's shim and
# PID 1; Docker's containerd-shim and the container's process; runc and crun
# leave only the container's process), RSS, PSS and USS from smaps_rollup
# (PSS splits shared pages between the processes that map them; USS counts
# only pages no other process maps, so it's what stopping them would free),
# and the
# sandbox cgroup's memory.current (what the kernel charges to it: its
# processes' memory plus kernel objects like page tables and dentries).
# Then it starts N (default 50) idle sandboxes and reports how much
# MemTotal - MemAvailable grew, per sandbox: everything, kernel included.
set -eu
cd "$(dirname "$0")"
. ./lib.sh
N=${N:-50}
out="results/${1:-idle}"
mkdir -p "$out"

kib() { awk -v k="$2" '$1 == k":" {print $2}' "/proc/$1/smaps_rollup"; }
# Drops the page cache first, so file pages read in the meantime don't count.
used_kib() {
    sync
    echo 3 >/proc/sys/vm/drop_caches
    sleep 2
    awk '/^MemTotal/ {t=$2} /^MemAvailable/ {a=$2} END {print t-a}' /proc/meminfo
}
cgroup_kib() { echo $(( $(cat "/sys/fs/cgroup$(cut -d: -f3 "/proc/$1/cgroup")/memory.current") / 1024 )); }

# host_pids RUNTIME ID prints "role=pid" for each host process of the sandbox.
host_pids() {
    case $1 in
    kiln*)
        dir=/var/lib/kiln/runs/$2
        echo "shim=$(cat "$dir/shim.pid") pid1=$(cat "$dir/init.pid")"
        ;;
    docker*)
        echo "shim=$(pgrep -f "containerd-shim-runc-v2 .*-id $2") pid1=$(docker inspect -f '{{.State.Pid}}' "$2")"
        ;;
    runc | crun)
        echo "pid1=$("$1" state "$2" | python3 -Ic 'import json, sys; print(json.load(sys.stdin)["pid"])')"
        ;;
    esac
}

{
    echo "### One idle sandbox (KiB)"
    echo
    echo "| runtime | processes | RSS | PSS | USS | cgroup memory.current |"
    echo "|---|---|---:|---:|---:|---:|"
    for runtime in kiln kiln-net docker docker-net runc crun; do
        id=$(start_idle "$runtime" "kiln-idle-$runtime")
        sleep 2
        rss=0 pss=0 uss=0 names="" cg=0
        for pair in $(host_pids "$runtime" "$id"); do
            pid=${pair#*=}
            rss=$((rss + $(kib "$pid" Rss)))
            pss=$((pss + $(kib "$pid" Pss)))
            uss=$((uss + $(kib "$pid" Private_Clean) + $(kib "$pid" Private_Dirty)))
            names="$names ${pair%%=*}"
            [ "${pair%%=*}" = pid1 ] && cg=$(cgroup_kib "$pid")
        done
        echo "| $runtime |$names | $rss | $pss | $uss | $cg |"
        stop_idle "$runtime" "$id"
    done

    echo
    echo "### $N idle sandboxes: growth of MemTotal - MemAvailable (KiB)"
    echo
    echo "| runtime | total | per sandbox |"
    echo "|---|---:|---:|"
    for runtime in kiln docker runc crun; do
        before=$(used_kib)
        ids=""
        i=0
        while [ "$i" -lt "$N" ]; do
            ids="$ids $(start_idle "$runtime" "kiln-many-$runtime-$i")"
            i=$((i + 1))
        done
        after=$(used_kib)
        for id in $ids; do stop_idle "$runtime" "$id"; done
        echo "| $runtime | $((after - before)) | $(((after - before) / N)) |"
    done

    echo
    echo "### Daemons (KiB)"
    echo
    echo "| process | needed for | RSS | PSS |"
    echo "|---|---|---:|---:|"
    for name in dockerd containerd; do
        pid=$(pidof "$name")
        echo "| $name | every Docker container | $(kib "$pid" Rss) | $(kib "$pid" Pss) |"
    done
    for unit in kiln-dns kiln-metrics; do
        pid=$(systemctl show -p MainPID --value "$unit")
        need="DNS for networked sandboxes"
        [ "$unit" = kiln-metrics ] && need="Prometheus metrics (optional)"
        echo "| $unit | $need | $(kib "$pid" Rss) | $(kib "$pid" Pss) |"
    done
} | tee "$out/summary.md"
