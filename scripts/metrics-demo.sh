#!/bin/sh
# Gives the Grafana dashboard something to show for about three minutes:
# a CPU-throttled sandbox, one using two cores, one hitting its egress and DNS
# allowlist, and three that get OOM-killed. Run inside the VM:
#   sudo scripts/metrics-demo.sh
set -u
K=${KILN:-/usr/local/bin/kiln}
spin='timeout 170 sh -c "while :; do :; done"'

# Throttled: 0.5 cores for a busy loop, after writing 60 MB to disk.
$K run --cpus 0.5 --memory 128M -- sh -c "dd if=/dev/zero of=/root/f bs=1M count=60 2>/dev/null; $spin" >/dev/null 2>&1 &
# Two busy loops on two cores.
$K run --cpus 2 --memory 256M -- sh -c "$spin & $spin" >/dev/null 2>&1 &
# Allowed example.com only: 1.1.1.1 is rejected, evil-N.com is refused.
$K run --allow example.com:80 -- sh -c 'for i in $(seq 80); do
    wget -qT1 -O- http://1.1.1.1; nslookup evil-$i.com; wget -qO- http://example.com; sleep 1
done' >/dev/null 2>&1 &
# OOM: a 100 MB shell variable under a 32 MB limit. Each run ends before
# Prometheus scrapes it; the kiln_all_oom_kills_total counter still sees it.
for _ in 1 2 3; do
    sleep 30
    $K run --memory 32M -- sh -c 'x=$(head -c 100000000 /dev/zero | tr "\0" a)' >/dev/null 2>&1
done
wait
