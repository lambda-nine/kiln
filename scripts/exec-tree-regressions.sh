#!/bin/sh
# Focused persistent-exec containment checks. Run as an ordinary VM user after
# scripts/install.sh; the individual kiln commands use sudo.
set -eu

KILN=${KILN:-/usr/local/bin/kiln}
sandbox=
client=
tmpdir=

cleanup() {
    if [ -n "$client" ]; then
        sudo kill "$client" 2>/dev/null || true
        wait "$client" 2>/dev/null || true
        client=
    fi
    if [ -n "$sandbox" ]; then
        sudo "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1 || true
        sandbox=
    fi
    sudo "$KILN" gc >/dev/null 2>&1 || true
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
        tmpdir=
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "FAIL: $*"
    exit 1
}

tmpdir=$(mktemp -d)
setpgid_helper=$tmpdir/setpgid-helper
cc -static -O2 -Wall -Wextra -Werror scripts/exec-tree-setpgid.c -o "$setpgid_helper"

# Installs /workspace/tree in the sandbox:
#   tree detach MARKER [LINE]  run under setsid: checks that this shell leads
#                              its own session, prints LINE if given, writes
#                              MARKER, then stays alive as a would-be survivor.
#   tree await MARKER          waits up to 5 s for MARKER.
install_tree_helper() {
    sudo "$KILN" exec "$sandbox" -- sh -c \
        'cat >/workspace/tree && chmod 755 /workspace/tree' >/dev/null 2>&1 <<'EOF'
#!/bin/sh
case $1 in
detach)
    [ "$(awk '{print $6}' /proc/self/stat)" = "$$" ] || exit 1
    [ -z "${3:-}" ] || echo "$3"
    echo ready >"$2"
    exec sleep 30
    ;;
await)
    i=0
    while [ ! -e "$2" ]; do
        [ "$i" -lt 100 ] || exit 1
        sleep 0.05
        i=$((i + 1))
    done
    ;;
esac
EOF
}

create_sandbox() {
    sandbox=$(sudo "$KILN" create --memory 64M --pids "${1:-32}" --disk 16M)
    install_tree_helper
}

remove_sandbox() {
    removed=$sandbox
    sudo "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1
    sandbox=
    [ ! -e "/sys/fs/cgroup/kiln/$removed" ] || fail "kiln rm left the cgroup of $removed"
}

marker() {
    sudo test -e "/var/lib/kiln/runs/$sandbox/upper/workspace/$1"
}

assert_no_sleep() {
    found=$(sudo timeout 10 "$KILN" exec "$sandbox" -- \
        sh -c 'pgrep -x sleep >/dev/null && echo found || echo none' \
        </dev/null 2>/dev/null)
    [ "$found" = none ] || fail "$1 left a sleep descendant after exec cleanup"
}

disconnect_case() {
    name=$1
    command=$2
    create_sandbox
    if [ "$name" = setpgid ]; then
        sudo "$KILN" exec "$sandbox" -- sh -c \
            'cat >/workspace/setpgid-helper && chmod 755 /workspace/setpgid-helper' \
            <"$setpgid_helper" >/dev/null 2>&1
    fi
    set +e
    sudo timeout -s KILL 1 "$KILN" exec "$sandbox" -- sh -c "$command" \
        </dev/null >/dev/null 2>&1
    set -e
    marker "$name-escaped" || fail "$name did not establish the intended escape condition"
    assert_no_sleep "$name"
    remove_sandbox
    echo "PASS: $name descendants"
}

disconnect_case setsid \
    'setsid sh -c '\''sid=$(awk "{print \$6}" /proc/self/stat); [ "$sid" = "$$" ] && touch /workspace/setsid-escaped; exec sleep 30'\'' & sleep 30'
disconnect_case setpgid \
    '/workspace/setpgid-helper /workspace/setpgid-escaped & sleep 30'
disconnect_case double-fork \
    'setsid sh -c "sh -c '\''touch /workspace/double-fork-escaped; exec sleep 30'\'' &" & sleep 30'

# The leader exits only once its detached descendant is running, so the
# status can't be reported until the cgroup has been drained.
create_sandbox
set +e
sudo "$KILN" exec "$sandbox" -- sh -c '
    setsid /workspace/tree detach /workspace/leader-child-ready &
    /workspace/tree await /workspace/leader-child-ready || exit 99
    exit 37' </dev/null >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 37 ] || fail "leader exit returned $code, expected 37"
marker leader-child-ready || fail "the detached descendant never started"
assert_no_sleep "normal leader exit"
remove_sandbox
echo "PASS: normal exit drains descendants"

# A nohup'd, detached descendant keeps the client's stdout and stderr open.
# Only the reader is under a timeout: a leaked writer shows up as 124.
create_sandbox
fifo=$tmpdir/eof.fifo
mkfifo "$fifo"
sudo "$KILN" exec "$sandbox" -- sh -c '
    nohup setsid /workspace/tree detach /workspace/eof-ready "descendant ready" &
    /workspace/tree await /workspace/eof-ready || exit 99
    echo "leader done"
    exit 23' </dev/null >"$fifo" 2>&1 &
client=$!
set +e
timeout 5 cat "$fifo" >"$tmpdir/eof.out"
code=$?
set -e
[ "$code" -ne 124 ] || fail "inherited stdout/stderr did not reach EOF after leader exit"
[ "$code" -eq 0 ] || fail "reading the exec's output failed (exit $code)"
set +e
wait "$client"
code=$?
set -e
client=
[ "$code" -eq 23 ] || fail "exec returned $code, expected 23"
grep -qx "descendant ready" "$tmpdir/eof.out" || fail "missing the descendant's output"
grep -qx "leader done" "$tmpdir/eof.out" || fail "missing the leader's output"
marker eof-ready || fail "the nohup descendant never started"
assert_no_sleep "nohup inherited stdio"
remove_sandbox
echo "PASS: inherited stdout/stderr EOF"

create_sandbox
sudo "$KILN" exec "$sandbox" -- sh -c \
    'setsid /workspace/tree detach /workspace/exec-active & sleep 30' \
    </dev/null >/dev/null 2>&1 &
client=$!
i=0
while ! marker exec-active && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
marker exec-active || fail "active exec's detached descendant did not start"
set +e
sudo timeout 5 "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 0 ] || fail "kiln rm did not interrupt an active exec (exit $code)"
[ ! -e "/sys/fs/cgroup/kiln/$sandbox" ] || fail "kiln rm left the cgroup of $sandbox"
sandbox=
wait "$client" 2>/dev/null || true
client=
echo "PASS: rm interrupts active exec"

# Under pids.max 4, PID 1 and an exec holding three tasks fill the sandbox.
# Killed tasks hold their slots until reaped, so an exec that starts right
# after a disconnect would fail to fork, and take PID 1 down, unless the
# previous exec was fully reaped first.
create_sandbox 4
sudo sh -eu -c '
    kiln=$1 sandbox=$2 fifo=$3 rounds=$4
    i=0
    while [ "$i" -lt "$rounds" ]; do
        rm -f "$fifo"
        mkfifo "$fifo"
        "$kiln" exec "$sandbox" -- sh -c "sleep 30 & sleep 30 &
            read n </sys/fs/cgroup/pids.current; echo full \$n; exec sleep 30" \
            </dev/null >"$fifo" 2>/dev/null &
        pid=$!
        line=$(timeout 5 head -n 1 "$fifo") || true
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        [ "$line" = "full 4" ] || {
            echo "FAIL: round $i: exec did not fill the task slots ($line)"
            exit 1
        }
        out=$("$kiln" exec "$sandbox" -- echo reused </dev/null 2>&1) || {
            echo "FAIL: round $i: immediate reuse failed: $out"
            exit 1
        }
        [ "$out" = reused ] || {
            echo "FAIL: round $i: immediate reuse printed $out"
            exit 1
        }
        i=$((i + 1))
    done
' sh "$KILN" "$sandbox" "$tmpdir/stress.fifo" 100
sudo "$KILN" ls | grep -q "^$sandbox	running" || fail "sandbox died during reuse stress"
remove_sandbox
echo "PASS: immediate reuse after disconnect under pids.max 4 (100 rounds)"

# PID 1 keeps the exec cgroup's descriptors; the workload must not reach
# them. Opening its own /proc entries shows the probes themselves work.
create_sandbox
probe=$(sudo "$KILN" exec "$sandbox" -- sh -c '
    ls /proc/self/fd >/dev/null 2>&1 && echo self-fd
    (exec 3</proc/self/mem) 2>/dev/null && echo self-mem
    ls /proc/1/fd >/dev/null 2>&1 && echo pid1-fd
    (exec 3</proc/1/mem) 2>/dev/null && echo pid1-mem
    echo end' </dev/null 2>/dev/null)
[ "$probe" = "$(printf 'self-fd\nself-mem\nend')" ] ||
    fail "workload reached PID 1's descriptors or memory: $(echo $probe)"
remove_sandbox
echo "PASS: workload cannot open /proc/1/fd or /proc/1/mem"

echo "PASS: persistent exec tree containment"
