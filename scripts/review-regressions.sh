#!/bin/sh
# Security and lifecycle regression checks: host ports closed to sandboxes,
# bounded shared services, quota enforcement, concurrent network reuse, and no
# leftovers. Run inside the VM after installing: scripts/review-regressions.sh
set -eu
KILN=${KILN:-/usr/local/bin/kiln}

sh scripts/install-regressions.sh

sh scripts/service-upgrade-regressions.sh

sudo python3 -I scripts/service-regressions.py "$KILN"

sh scripts/toolchain-regressions.sh

sh scripts/writable-regressions.sh

sh scripts/private-egress-regressions.sh

sh scripts/create-certainty-regressions.sh

sh scripts/gc-regressions.sh

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

sudo python3 -I scripts/dns-regressions.py "$KILN"
sudo python3 -I scripts/dns-fairness-regressions.py "$KILN"
sudo python3 -I scripts/dns-reserve-regressions.py "$KILN"

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

echo "5. Persistent shim protects an in-progress lease"
persistent=$(sudo "$KILN" create --memory 64M --pids 16 --disk 16M)
create_pid=${persistent##*-}
fake="review-shim-$create_pid"
sudo install -d "/var/lib/kiln/runs/$fake"
sudo cp "/var/lib/kiln/runs/$persistent/shim.pid" "/var/lib/kiln/runs/$fake/shim.pid"
sudo cp "/var/lib/kiln/runs/$persistent/shim.start" "/var/lib/kiln/runs/$fake/shim.start"
printf '%s' "$fake" | sudo tee "/run/kiln/net/leases/$stale" >/dev/null
assigned=$(sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sh -c \
    'ip -4 -o addr show dev eth0 | sed "s/.* inet //; s/ .*//"')
[ "$assigned" = "10.88.0.3/16" ] || { echo "FAIL: live persistent shim did not protect lease"; exit 1; }
[ "$(cat "/run/kiln/net/leases/$stale")" = "$fake" ]
sudo rm -rf "/var/lib/kiln/runs/$fake"
sudo rm -f "/run/kiln/net/leases/$stale"
sudo "$KILN" rm "$persistent"
echo "PASS"

echo "6. Base nftables reconciliation"
sudo nft add rule inet kiln forward counter accept comment '"review stale rule"'
sudo nft flush set inet kiln private
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- true
if sudo nft -s list chain inet kiln forward | grep -q 'review stale rule'; then
    echo "FAIL: stale base rule survived reconciliation"
    exit 1
fi
sudo nft list set inet kiln private | grep -q '192.168.0.0/16' || { echo "FAIL: private set was not restored"; exit 1; }
echo "PASS"

echo "7. Alpine release signature"
scripts/fetch-alpine.sh --verify-only
echo "PASS"

echo "8. Per-sandbox conntrack limit"
before=$(sudo nft list counter inet kiln conntrack_rejected | awk '/packets/ {print $2}')
sudo "$KILN" run --net full --memory 64M --pids 256 --disk 16M -- sh -c '
    i=0
    while [ "$i" -lt 320 ]; do
        (printf x | nc -u -w 1 1.1.1.1 "$((10000 + i))" >/dev/null 2>&1) &
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

echo "9. Persistent sandbox lifecycle"
persistent=$(sudo "$KILN" create --read-only --net full --memory 64M --pids 16 --disk 16M)
sudo "$KILN" ls | grep -q "^$persistent[[:space:]]\+running"
[ "$(sudo stat -c %a "/var/lib/kiln/runs/$persistent")" = 700 ]
[ "$(sudo stat -c %a "/var/lib/kiln/runs/$persistent/control.sock")" = 600 ]
[ "$(cat "/sys/fs/cgroup/kiln/$persistent/pids.max")" = 16 ]
# kiln exec refuses terminal stdio, so every call redirects all three fds.
sudo "$KILN" exec "$persistent" -- sh -c 'echo persistent >/workspace/review-state' </dev/null >/dev/null 2>&1
[ "$(sudo "$KILN" exec "$persistent" -- cat /workspace/review-state </dev/null 2>&1)" = persistent ]
if sudo "$KILN" exec "$persistent" -- touch /etc/review-write </dev/null >/dev/null 2>&1; then
    echo "FAIL: persistent exec did not inherit Landlock"
    exit 1
fi
set +e
sudo "$KILN" exec "$persistent" -- sh -c 'exit 37' </dev/null >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 37 ] || { echo "FAIL: exec returned $code, expected 37"; exit 1; }
# A client killed mid-exec must stop its command's process group and leave
# the sandbox serving; callers such as kilnd time out execs this way.
set +e
sudo timeout -s KILL 1 "$KILN" exec "$persistent" -- sh -c 'sleep 30 & sleep 30' </dev/null >/dev/null 2>&1
set -e
left=$(sudo timeout 10 "$KILN" exec "$persistent" -- sh -c 'pgrep sleep || echo none' </dev/null 2>&1)
[ "$left" = none ] || { echo "FAIL: exec after a killed client returned: $left"; exit 1; }
sudo "$KILN" ls | grep -q "^$persistent[[:space:]]\+running"
# kiln's own exec failures exit 125, distinct from the command's codes.
set +e
sudo "$KILN" exec 0000000000000000-0 -- true </dev/null >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 125 ] || { echo "FAIL: exec into a missing sandbox returned $code, expected 125"; exit 1; }
# With a terminal on stdio, exec must fail before reaching the sandbox.
set +e
tty_out=$(timeout 20 script -qec "sudo -n '$KILN' exec $persistent -- touch /workspace/tty-ran" /dev/null </dev/null 2>&1)
code=$?
set -e
[ "$code" -eq 125 ] || { echo "FAIL: exec from a terminal returned $code, expected 125"; exit 1; }
echo "$tty_out" | grep -q 'interactive (PTY) exec is not implemented' || {
    echo "FAIL: exec from a terminal did not explain the refusal: $tty_out"
    exit 1
}
if sudo "$KILN" exec "$persistent" -- test -e /workspace/tty-ran </dev/null >/dev/null 2>&1; then
    echo "FAIL: exec from a terminal ran the command"
    exit 1
fi
sudo "$KILN" rm "$persistent"
[ ! -e "/var/lib/kiln/runs/$persistent" ]

# Process groups are only a signaling convenience, not a containment boundary.
# Verify that persistent exec cleanup also reaches descendants that create a
# session/process group, daemonize, or keep the client's output pipes open.
sh scripts/exec-tree-regressions.sh

stale=$(sudo "$KILN" create --net full --memory 64M --pids 16 --disk 16M)
unrequested_stale=$(sudo "$KILN" create --memory 64M --pids 16 --disk 16M)
shim=$(sudo cat "/var/lib/kiln/runs/$stale/shim.pid")
unrequested_shim=$(sudo cat "/var/lib/kiln/runs/$unrequested_stale/shim.pid")
ip=$(awk -v id="$stale" '$0 == id { sub(".*/", "", FILENAME); print FILENAME }' /run/kiln/net/leases/*)
sudo kill -9 "$shim"
sudo kill -9 "$unrequested_shim"
i=0
while kill -0 "$shim" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
sudo "$KILN" gc "$stale"
[ ! -e "/var/lib/kiln/runs/$stale" ]
[ ! -e "/sys/fs/cgroup/kiln/$stale" ]
[ ! -e "/run/kiln/net/leases/$ip" ]
[ -e "/var/lib/kiln/runs/$unrequested_stale" ] || {
    echo "FAIL: scoped GC removed an unrequested stale sandbox"
    exit 1
}
sudo "$KILN" ls | grep -q "^$unrequested_stale[[:space:]]\+stale"
sudo "$KILN" gc "$unrequested_stale"
[ ! -e "/var/lib/kiln/runs/$unrequested_stale" ]
echo "PASS"

echo "10. pids.max refuses exec without destroying a persistent sandbox"
limited=$(sudo "$KILN" create --memory 64M --pids 1 --disk 16M)
cleanup_limited() {
    if [ -n "${limited:-}" ] && sudo test -e "/var/lib/kiln/runs/$limited"; then
        sudo timeout 10 "$KILN" rm "$limited" >/dev/null 2>&1 || true
    fi
}
trap cleanup_limited EXIT HUP INT TERM
# PID 1 consumes the only slot, so the exec fork must fail with EAGAIN. This
# is compatible with Chapter 2's rule that background work cannot survive a
# completed exec to fill the limit for a later request.
[ "$(sudo cat "/sys/fs/cgroup/kiln/$limited/pids.current")" = 1 ]
init_pid=$(sudo cat "/var/lib/kiln/runs/$limited/init.pid")
max_before=$(sudo awk '$1 == "max" { print $2 }' "/sys/fs/cgroup/kiln/$limited/pids.events")
set +e
sudo "$KILN" exec "$limited" -- true </dev/null >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 125 ] || { echo "FAIL: refused exec returned $code, expected 125"; exit 1; }
max_after=$(sudo awk '$1 == "max" { print $2 }' "/sys/fs/cgroup/kiln/$limited/pids.events")
[ "$max_after" -gt "$max_before" ] || { echo "FAIL: pids.events max did not increase"; exit 1; }
sudo kill -0 "$init_pid"
sudo "$KILN" ls | grep -q "^$limited[[:space:]]\+running"
sudo timeout 10 "$KILN" rm "$limited"
[ ! -e "/var/lib/kiln/runs/$limited" ]
limited=
trap - EXIT HUP INT TERM
echo "PASS"

echo "11. Persistent PID 1 idle lifecycle"
sh scripts/pid1-lifecycle-regressions.sh

echo "12. Persistent control protocol"
sh scripts/control-protocol-regressions.sh
sudo python3 -I scripts/busy-exec-regressions.py "$KILN"

echo "13. Persistent registry identity"
sh scripts/shim-identity-regressions.sh

echo "13b. Persistent typed exec outcomes"
sudo python3 -I scripts/typed-exec-regressions.py "$KILN"

echo "14. Bridge ports isolated"
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sleep 5 &
first=$!
i=0
while [ -z "$(ls /run/kiln/net/leases 2>/dev/null)" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
peer=$(ls /run/kiln/net/leases)
port=$(bridge -d link show master kiln0)
echo "$port" | grep -q 'isolated on' || { echo "FAIL: sandbox bridge port is not isolated"; exit 1; }
sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- sh -c "
    if ping -c 1 -W 1 $peer >/dev/null 2>&1; then echo 'FAIL: reached sandbox $peer'; exit 1; fi
"
wait "$first"
echo "PASS"

echo "15. Concurrent network reuse stress"
wave=0
failed=0
while [ "$wave" -lt 10 ]; do
    pids=
    i=0
    while [ "$i" -lt 16 ]; do
        sudo "$KILN" run --net full --memory 64M --pids 16 --disk 16M -- true &
        pids="$pids $!"
        i=$((i + 1))
    done
    for pid in $pids; do
        wait "$pid" || failed=1
    done
    wave=$((wave + 1))
done
[ "$failed" -eq 0 ] || { echo "FAIL: concurrent network start failed"; exit 1; }
echo "PASS"

echo "16. Cleanup"
[ -z "$(find /var/lib/kiln/runs -mindepth 1 -maxdepth 1 -print -quit)" ]
[ -z "$(find /run/kiln/net/leases -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]
[ -z "$(find /sys/fs/cgroup/kiln -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)" ]
i=0
while [ -n "$(find /sys/class/net -mindepth 1 -maxdepth 1 -name 'kv*' -print -quit)" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
[ -z "$(find /sys/class/net -mindepth 1 -maxdepth 1 -name 'kv*' -print -quit)" ] || {
    echo "FAIL: kiln veth remains after cleanup"
    exit 1
}
systemctl is-active --quiet kiln-dns
systemctl is-active --quiet kiln-metrics
echo "PASS"
