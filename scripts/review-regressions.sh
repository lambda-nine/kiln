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

echo "4. Stale lease reconciliation"
stale=10.88.0.2
sudo install -d /run/kiln/net/leases /run/kiln/net/dns
printf '%s' '0-4294967295' | sudo tee "/run/kiln/net/leases/$stale" >/dev/null
printf '%s\n' '*' | sudo tee "/run/kiln/net/dns/$stale" >/dev/null
assigned=$(sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sh -c \
    'ip -4 -o addr show dev eth0 | sed "s/.* inet //; s/ .*//"')
echo "Address after stale lease: $assigned"
[ "$assigned" = "$stale/16" ] || { echo "FAIL: stale lease was not reclaimed"; exit 1; }
[ ! -e "/run/kiln/net/dns/$stale" ] || { echo "FAIL: stale DNS policy remains"; exit 1; }
echo "PASS"

echo "5. Base nftables reconciliation"
sudo nft add rule inet kiln forward counter accept comment '"review stale rule"'
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- true
if sudo nft -s list chain inet kiln forward | grep -q 'review stale rule'; then
    echo "FAIL: stale base rule survived reconciliation"
    exit 1
fi
echo "PASS"

echo "6. Alpine release signature"
scripts/fetch-alpine.sh --verify-only
echo "PASS"

echo "7. Per-sandbox conntrack limit"
before=$(sudo nft list counter inet kiln conntrack_rejected | awk '/packets/ {print $2}')
sudo "$KILN" run --net full --memory 64M --pids 256 --disk 16M -- sh -c '
    i=0
    while [ "$i" -lt 320 ]; do
        (printf x | nc -u -w 1 1.1.1 "$((10000 + i))" >/dev/null 2>&1) &
        i=$((i + 1))
        [ $((i % 70)) -eq 0 ] && wait
    done
    wait
'
after=$(sudo nft list counter inet kiln conntrack_rejected | awk '/packets/ {print $2}')
echo "Conntrack-limit rejects: before=$before after=$after"
[ "$after" -gt "$before" ] || { echo "FAIL: conntrack limit did not reject excess flows"; exit 1; }
# The next sandbox usually reuses the same IP while the previous flows are
# still in conntrack. It must start with a fresh count, not inherit the limit.
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sh -c '
    printf x | nc -u -w 1 1.1.1.1 53 >/dev/null 2>&1 || true
'
fresh=$(sudo nft list counter inet kiln conntrack_rejected | awk '/packets/ {print $2}')
[ "$fresh" -eq "$after" ] || { echo "FAIL: next sandbox inherited the previous sandbox's conntrack count"; exit 1; }
echo "PASS"

echo "8. Persistent sandbox lifecycle"
persistent=$(sudo "$KILN" create --read-only --net full --memory 64M --pids 16 --disk 16M)
sudo "$KILN" ls | grep -q "^$persistent[[:space:]]\+running"
[ "$(cat "/sys/fs/cgroup/kiln/$persistent/pids.max")" = 16 ]
sudo "$KILN" exec "$persistent" -- sh -c 'echo persistent >/workspace/review-state'
[ "$(sudo "$KILN" exec "$persistent" -- cat /workspace/review-state)" = persistent ]
if sudo "$KILN" exec "$persistent" -- touch /etc/review-write 2>/dev/null; then
    echo "FAIL: persistent exec did not inherit Landlock"
    exit 1
fi
set +e
sudo "$KILN" exec "$persistent" -- sh -c 'exit 37'
code=$?
set -e
[ "$code" -eq 37 ] || { echo "FAIL: exec returned $code, expected 37"; exit 1; }
sudo "$KILN" rm "$persistent"
[ ! -e "/var/lib/kiln/runs/$persistent" ]

stale=$(sudo "$KILN" create --net full --memory 64M --pids 16 --disk 16M)
shim=$(cat "/var/lib/kiln/runs/$stale/shim.pid")
ip=$(awk -v id="$stale" '$0 == id { sub(".*/", "", FILENAME); print FILENAME }' /run/kiln/net/leases/*)
sudo kill -9 "$shim"
i=0
while kill -0 "$shim" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
sudo "$KILN" gc
[ ! -e "/var/lib/kiln/runs/$stale" ]
[ ! -e "/sys/fs/cgroup/kiln/$stale" ]
[ ! -e "/run/kiln/net/leases/$ip" ]
echo "PASS"

echo "9. Cleanup"
[ -z "$(find /var/lib/kiln/runs -mindepth 1 -maxdepth 1 -print -quit)" ]
[ -z "$(find /run/kiln/net/leases -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]
[ -z "$(find /sys/fs/cgroup/kiln -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)" ]
systemctl is-active --quiet kiln-dns
systemctl is-active --quiet kiln-metrics
echo "PASS"
