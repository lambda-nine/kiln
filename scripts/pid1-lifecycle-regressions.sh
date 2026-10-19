#!/bin/sh
# Focused persistent PID 1 lifecycle checks. Run as an ordinary VM user after
# scripts/install.sh; the individual kiln and namespace commands use sudo.
set -eu

KILN=${KILN:-/usr/local/bin/kiln}
sandbox=
client=
tmpdir=

cleanup() {
    if [ -n "$client" ]; then
        kill "$client" 2>/dev/null || true
        wait "$client" 2>/dev/null || true
        client=
    fi
    if [ -n "$sandbox" ]; then
        sudo timeout 10 "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1 || true
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

create_sandbox() {
    sandbox=$(sudo "$KILN" create --memory 64M --pids 32 --disk 16M)
}

remove_sandbox() {
    removed=$sandbox
    sudo timeout 10 "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1
    sandbox=
    [ ! -e "/var/lib/kiln/runs/$removed" ] || fail "kiln rm left $removed"
}

marker() {
    sudo test -e "/var/lib/kiln/runs/$sandbox/upper/workspace/$1"
}

tmpdir=$(mktemp -d)

# Inject one host-controlled process into the sandbox PID namespace. Its shell
# exits immediately, so the gated child is adopted by PID 1. Releasing it only
# after adoption makes the test independent of scheduler speed.
create_sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
orphan_gate=$tmpdir/orphan-release
sudo nsenter -t "$init_pid" -p sh -c '
    gate=$1
    (while [ ! -e "$gate" ]; do sleep 0.02; done) &
' sh "$orphan_gate" >/dev/null 2>&1
i=0
children=
while [ -z "$children" ] && [ "$i" -lt 50 ]; do
    children=$(sudo cat "/proc/$init_pid/task/$init_pid/children")
    sleep 0.02
    i=$((i + 1))
done
[ -n "$children" ] || fail "test orphan was never adopted by PID 1"
: >"$orphan_gate"
i=0
while [ -n "$children" ] && [ "$i" -lt 150 ]; do
    children=$(sudo cat "/proc/$init_pid/task/$init_pid/children")
    sleep 0.02
    i=$((i + 1))
done
[ -z "$children" ] || fail "PID 1 left an idle adopted child unreaped: $children"
[ "$(sudo timeout 10 "$KILN" exec "$sandbox" -- echo usable </dev/null 2>/dev/null)" = usable ] ||
    fail "sandbox was not serviceable after idle reaping"
remove_sandbox
echo "PASS: idle PID 1 reaps adopted children"

# With no exec to receive them, the same signals the shim forwards during an
# exec terminate the idle sandbox. They must never remain pending for a future
# unrelated command.
for sig in TERM HUP USR1 USR2; do
    create_sandbox
    stopped=$sandbox
    init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
    sudo kill "-$sig" "$init_pid"
    i=0
    while sudo test -e "/var/lib/kiln/runs/$stopped" && [ "$i" -lt 250 ]; do
        sleep 0.02
        i=$((i + 1))
    done
    if sudo test -e "/var/lib/kiln/runs/$stopped"; then
        fail "idle $sig did not stop and clean the sandbox"
    fi
    sandbox=
done
echo "PASS: idle forwarded signals stop the sandbox"

# Acceptance alone does not make a command active. Hold an exec request after
# connect(), signal idle PID 1, and then finish the request. The sandbox must
# stop without launching the command or forwarding the stale TERM into it.
create_sandbox
delayed=$sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
socket=/var/lib/kiln/runs/$sandbox/control.sock
ready=$tmpdir/delayed-ready
release=$tmpdir/delayed-release
# create returns just before serve creates its signalfd. Include that stable
# lifetime descriptor in the baseline so only accept() can raise the count.
i=0
signalfd_ready=no
while [ "$i" -lt 100 ]; do
    if sudo sh -c '
        for info in "$1"/fdinfo/*; do
            grep -q "^sigmask:" "$info" 2>/dev/null && exit 0
        done
        exit 1
    ' sh "/proc/$init_pid"; then
        signalfd_ready=yes
        break
    fi
    sleep 0.02
    i=$((i + 1))
done
[ "$signalfd_ready" = yes ] || fail "PID 1 did not create its lifetime signalfd"
fds_before=$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
sudo python3 - "$socket" "$ready" "$release" <<'PY' &
import array
import os
import socket
import struct
import sys
import time

path, ready, release = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
open(ready, "w").close()
while not os.path.exists(release):
    time.sleep(0.01)
argv = [b"sh", b"-c", b"echo ran >/workspace/delayed-ran"]
payload = struct.pack("=I", len(argv))
payload += b"".join(struct.pack("=I", len(arg)) + arg for arg in argv)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(3)])
try:
    sock.sendmsg([bytes([1, 0, 0, 0]) + struct.pack("=I", len(payload))],
                 [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
    sock.sendall(payload)
    data = sock.recv(4)
except (BrokenPipeError, ConnectionResetError):
    data = b""
sys.exit(0 if data == b"" else 1)
PY
client=$!
i=0
while [ ! -e "$ready" ] && [ "$i" -lt 100 ]; do
    sleep 0.02
    i=$((i + 1))
done
[ -e "$ready" ] || fail "delayed request did not connect"
i=0
fds_now=$fds_before
while [ "$fds_now" -le "$fds_before" ] && [ "$i" -lt 100 ]; do
    fds_now=$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
    sleep 0.02
    i=$((i + 1))
done
[ "$fds_now" -gt "$fds_before" ] || fail "PID 1 did not accept the delayed request"
sudo kill -TERM "$init_pid"
: >"$release"
i=0
while sudo test -e "/var/lib/kiln/runs/$delayed" && [ "$i" -lt 250 ]; do
    sleep 0.02
    i=$((i + 1))
done
sudo test ! -e "/var/lib/kiln/runs/$delayed" ||
    fail "idle TERM crossed request admission instead of stopping the sandbox"
set +e
wait "$client"
code=$?
set -e
client=
[ "$code" -eq 0 ] || fail "delayed request received a command status"
sandbox=
echo "PASS: idle shutdown cannot cross delayed request admission"

# The leader and its child share the execution process group. The leader's
# TERM trap deliberately waits for the child, so forwarding only to the leader
# wedges; forwarding to the group lets the child record the signal and exit.
create_sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
sudo "$KILN" exec "$sandbox" -- sh -c '
    (trap "echo child-term >/workspace/group-forwarded; exit 0" TERM
     echo child-ready >/workspace/group-child-ready
     while :; do sleep 1; done) &
    child=$!
    trap '\''wait "$child"; exit 0'\'' TERM
    while [ ! -e /workspace/group-child-ready ]; do sleep 0.02; done
    echo ready >/workspace/group-ready
    wait "$child"
' </dev/null >"$tmpdir/group.out" 2>"$tmpdir/group.err" &
client=$!
i=0
while ! marker group-ready && [ "$i" -lt 100 ]; do
    sleep 0.02
    i=$((i + 1))
done
marker group-ready || fail "signal-forwarding command did not become ready"
sudo kill -TERM "$init_pid"
i=0
while kill -0 "$client" 2>/dev/null && [ "$i" -lt 150 ]; do
    sleep 0.02
    i=$((i + 1))
done
kill -0 "$client" 2>/dev/null && fail "TERM forwarded only to the exec leader"
set +e
wait "$client"
code=$?
set -e
client=
[ "$code" -eq 0 ] || fail "group-forwarding exec returned $code, expected 0"
marker group-forwarded || fail "TERM did not reach the execution process group"
[ "$(sudo timeout 10 "$KILN" exec "$sandbox" -- echo reusable </dev/null 2>/dev/null)" = reusable ] ||
    fail "sandbox was not reusable after group signal forwarding"
remove_sandbox
echo "PASS: signals reach the execution process group"

# Rust starts kiln with SIGPIPE ignored. Workloads must instead inherit the
# conventional default so a pipeline producer dies with 128 + SIGPIPE (141),
# rather than observing EPIPE and returning an application error such as 1.
create_sandbox
set +e
sudo "$KILN" exec "$sandbox" -- sh -c \
    'set -o pipefail; yes | head -n 1 >/dev/null' \
    </dev/null >"$tmpdir/sigpipe.out" 2>"$tmpdir/sigpipe.err"
code=$?
set -e
[ "$code" -eq 141 ] || fail "pipeline returned $code, expected SIGPIPE status 141"
[ "$(sudo timeout 10 "$KILN" exec "$sandbox" -- echo reusable </dev/null 2>/dev/null)" = reusable ] ||
    fail "sandbox was not reusable after SIGPIPE"
remove_sandbox
set +e
sudo "$KILN" run --memory 64M --pids 16 --disk 16M -- sh -c \
    'set -o pipefail; yes | head -n 1 >/dev/null' \
    </dev/null >"$tmpdir/oneshot-sigpipe.out" 2>"$tmpdir/oneshot-sigpipe.err"
code=$?
set -e
[ "$code" -eq 141 ] || fail "one-shot pipeline returned $code, expected SIGPIPE status 141"
echo "PASS: persistent and one-shot commands restore default SIGPIPE"

echo "PASS: persistent PID 1 lifecycle"
