#!/bin/sh
# Regression checks from the second independent review: host ports closed to
# sandboxes, DNS forwarder concurrency bounded, inode quota enforced, and no
# leftovers. Run inside the VM after installing: scripts/review-regressions.sh
set -eu
KILN=${KILN:-/usr/local/bin/kiln}

echo "1. Firewall boundary"
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sh -c '
    for p in 22 3000 9090 9840 9841; do
        if nc -z -w 1 10.88.0.1 "$p" >/dev/null 2>&1; then
            echo "FAIL: host port $p reachable"
            exit 1
        fi
    done
    nc -z -w 1 10.88.0.1 53
'
echo "PASS"

echo "2. DNS worker bound"
before=$(systemctl show kiln-dns -p TasksCurrent --value)
(
    sudo "$KILN" run --net full --memory 64M --pids 64 --disk 16M -- sh -c '
        i=0
        while [ "$i" -lt 20 ]; do
            (sleep 3 | nc 10.88.0.1 53 >/dev/null 2>&1) &
            i=$((i + 1))
        done
        wait
    '
) &
runpid=$!
peak=$before
while kill -0 "$runpid" 2>/dev/null; do
    current=$(systemctl show kiln-dns -p TasksCurrent --value)
    [ "$current" -gt "$peak" ] && peak=$current
    sleep 0.1
done
wait "$runpid"
echo "DNS tasks: before=$before peak=$peak"
[ "$peak" -le 24 ] || { echo "FAIL: DNS task count is still query-proportional"; exit 1; }

echo "3. Inode quota"
created=$(
    sudo "$KILN" run --disk 1M --memory 64M --pids 16 -- sh -c '
        mkdir /tmp/inodes
        i=0
        while [ "$i" -lt 5000 ]; do
            touch "/tmp/inodes/$i" 2>/dev/null || break
            i=$((i + 1))
        done
        echo "$i"
    '
)
echo "Created under 1 MiB quota: $created"
[ "$created" -lt 5000 ] || { echo "FAIL: no effective inode limit"; exit 1; }

echo "4. Cleanup"
[ -z "$(find /var/lib/kiln/runs -mindepth 1 -maxdepth 1 -print -quit)" ]
[ -z "$(find /run/kiln/net/leases -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]
[ -z "$(find /sys/fs/cgroup/kiln -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)" ]
systemctl is-active --quiet kiln-dns
systemctl is-active --quiet kiln-metrics
echo "PASS"
