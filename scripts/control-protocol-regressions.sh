#!/bin/sh
# Focused persistent control-protocol checks. Run as an ordinary VM user after
# scripts/install.sh; the individual kiln and namespace commands use sudo.
set -eu

KILN=${KILN:-/usr/local/bin/kiln}
sandbox=
client=
client_pidfile=
stopped_pid=
tmpdir=

cleanup() {
    if [ -n "$stopped_pid" ]; then
        sudo kill -CONT "$stopped_pid" 2>/dev/null || true
        stopped_pid=
    fi
    if [ -n "$client" ]; then
        if [ -n "$client_pidfile" ] && [ -s "$client_pidfile" ]; then
            sudo kill "$(cat "$client_pidfile")" 2>/dev/null || true
        fi
        kill "$client" 2>/dev/null || true
        wait "$client" 2>/dev/null || true
        client=
        client_pidfile=
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

wait_ready() {
    ready=$1
    i=0
    while [ ! -e "$ready" ] && [ "$i" -lt 100 ]; do
        sleep 0.02
        i=$((i + 1))
    done
    [ -e "$ready" ] || fail "raw control client did not become ready"
}

stop_client() {
    if [ -n "$client_pidfile" ] && [ -s "$client_pidfile" ]; then
        sudo kill "$(cat "$client_pidfile")" 2>/dev/null || true
    fi
    kill "$client" 2>/dev/null || true
    wait "$client" 2>/dev/null || true
    client=
    client_pidfile=
}

tmpdir=$(mktemp -d)

# A peer that sends only part of the fixed header gets one bounded framing
# window. Once it expires, the serial server must accept a legitimate exec.
create_sandbox
socket=/var/lib/kiln/runs/$sandbox/control.sock
ready=$tmpdir/header-ready
sudo python3 - "$socket" "$ready" <<'PY' &
import os
import socket
import sys
import time

path, ready = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.sendall(b"\x01\x00\x00\x00")
with open(ready, "w") as ready_file:
    ready_file.write(str(os.getpid()))
time.sleep(30)
PY
client=$!
client_pidfile=$ready
wait_ready "$ready"
out=$(sudo timeout 6 "$KILN" exec "$sandbox" -- echo recovered </dev/null 2>/dev/null) ||
    fail "a partial header wedged the next exec"
[ "$out" = recovered ] || fail "post-timeout exec printed $out"
stop_client
remove_sandbox
echo "PASS: partial header deadline"

# The same absolute deadline covers the payload; it does not restart for each
# byte. A removal queued behind a slow or crashed sender must still complete.
create_sandbox
socket=/var/lib/kiln/runs/$sandbox/control.sock
ready=$tmpdir/payload-ready
sudo python3 - "$socket" "$ready" <<'PY' &
import array
import os
import socket
import struct
import sys
import time

path, ready = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(3)])
sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", 4096)],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
sock.sendall(b"x")
with open(ready, "w") as ready_file:
    ready_file.write(str(os.getpid()))
time.sleep(30)
PY
client=$!
client_pidfile=$ready
wait_ready "$ready"
removed=$sandbox
sudo timeout 6 "$KILN" rm "$sandbox" </dev/null >/dev/null 2>&1 ||
    fail "a partial payload wedged kiln rm"
sandbox=
[ ! -e "/var/lib/kiln/runs/$removed" ] || fail "kiln rm left $removed after a stalled payload"
stop_client
echo "PASS: partial payload deadline"

# Once PID 1 has accepted a frame, stopping it past the absolute deadline and
# queuing a valid body must not let that expired request run after resumption.
# The injected-clock Rust test covers expiration during a successful read.
create_sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
fds_before=$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
socket=/var/lib/kiln/runs/$sandbox/control.sock
ready=$tmpdir/queued-ready
go=$tmpdir/queued-go
sudo python3 - "$socket" "$ready" "$go" <<'PY' &
import array
import os
import socket
import struct
import sys
import time

path, ready, go = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(8)
sock.connect(path)
argv = [b"sh", b"-c", b"touch /workspace/deadline-overrun-ran"]
argv += [b"x" * 60000 for _ in range(14)]
payload = struct.pack("=I", len(argv))
payload += b"".join(struct.pack("=I", len(arg)) + arg for arg in argv)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(3)])
sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", len(payload))],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
with open(ready, "w") as ready_file:
    ready_file.write(str(os.getpid()))
for _ in range(500):
    if os.path.exists(go):
        break
    time.sleep(0.01)
else:
    raise SystemExit("timed out waiting to send queued request body")
try:
    sock.sendall(payload)
    response = sock.recv(4)
except (BrokenPipeError, ConnectionResetError):
    pass
except socket.timeout:
    raise SystemExit("timed out waiting for queued request rejection")
else:
    if response:
        raise SystemExit("expired queued request received a command status")
PY
client=$!
client_pidfile=$ready
wait_ready "$ready"
minimum_fds=$((fds_before + 4))
i=0
while [ "$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)" -lt "$minimum_fds" ] &&
    [ "$i" -lt 100 ]; do
    sleep 0.02
    i=$((i + 1))
done
[ "$i" -lt 100 ] || fail "PID 1 did not accept the queued request header"
stopped_pid=$init_pid
sudo kill -STOP "$stopped_pid"
touch "$go"
sleep 3
sudo kill -CONT "$stopped_pid"
stopped_pid=
wait "$client" || fail "queued request client failed"
client=
client_pidfile=
out=$(sudo timeout 6 "$KILN" exec "$sandbox" -- sh -c \
    'test ! -e /workspace/deadline-overrun-ran && echo bounded' </dev/null 2>/dev/null) ||
    fail "a request completed after its absolute deadline"
[ "$out" = bounded ] || fail "post-deadline exec printed $out"
remove_sandbox
echo "PASS: accepted frame deadline survives PID 1 pause"

# Framing remains part of the idle state. A shutdown signal must interrupt a
# stalled body immediately instead of waiting for the framing deadline.
create_sandbox
stopped=$sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
socket=/var/lib/kiln/runs/$sandbox/control.sock
ready=$tmpdir/signal-ready
sudo python3 - "$socket" "$ready" <<'PY' &
import array
import os
import socket
import struct
import sys
import time

path, ready = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(3)])
sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", 4096)],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
sock.sendall(b"x")
with open(ready, "w") as ready_file:
    ready_file.write(str(os.getpid()))
time.sleep(30)
PY
client=$!
client_pidfile=$ready
wait_ready "$ready"
sudo kill -TERM "$init_pid"
i=0
while sudo test -e "/var/lib/kiln/runs/$stopped" && [ "$i" -lt 50 ]; do
    sleep 0.02
    i=$((i + 1))
done
sudo test ! -e "/var/lib/kiln/runs/$stopped" ||
    fail "a stalled payload delayed idle signal handling"
sandbox=
stop_client
echo "PASS: signal-aware framing"

# A complete length-framed request may half-close its write side while keeping
# the read side open for the response. That is not cancellation.
create_sandbox
socket=/var/lib/kiln/runs/$sandbox/control.sock
sudo python3 - "$socket" <<'PY'
import array
import os
import socket
import struct
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(4)
sock.connect(sys.argv[1])
argv = [b"sh", b"-c", b"echo ran >/workspace/half-close-ran"]
payload = struct.pack("=I", len(argv))
payload += b"".join(struct.pack("=I", len(arg)) + arg for arg in argv)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(3)])
sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", len(payload))],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
sock.sendall(payload)
sock.shutdown(socket.SHUT_WR)
status = b""
while len(status) < 4:
    try:
        part = sock.recv(4 - len(status))
    except socket.timeout:
        raise SystemExit("timed out waiting for exec status")
    if not part:
        raise SystemExit("EOF before exec status")
    status += part
if struct.unpack("=i", status)[0] != 0:
    raise SystemExit(f"unexpected exec status {struct.unpack('=i', status)[0]}")
PY
marker half-close-ran || fail "half-close canceled a complete exec request"
remove_sandbox
echo "PASS: explicit half-close semantics"

# The ancillary buffer intentionally holds only the three allowed stdio fds.
# MSG_CTRUNC must reject an overfull rights message, not silently run it with
# only the descriptors that fit in the receiver's bounded ancillary buffer.
create_sandbox
socket=/var/lib/kiln/runs/$sandbox/control.sock
sudo python3 - "$socket" <<'PY'
import array
import os
import socket
import struct
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(3)
sock.connect(sys.argv[1])
argv = [b"sh", b"-c", b"touch /workspace/truncated-rights-ran"]
payload = struct.pack("=I", len(argv))
payload += b"".join(struct.pack("=I", len(arg)) + arg for arg in argv)
fds = array.array("i", [os.open(os.devnull, os.O_RDWR) for _ in range(5)])
sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", len(payload))],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
try:
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    response = sock.recv(4)
except (BrokenPipeError, ConnectionResetError):
    pass
except socket.timeout:
    raise SystemExit("timed out waiting for overfull SCM_RIGHTS rejection")
else:
    if response:
        raise SystemExit("overfull SCM_RIGHTS request received a status")
PY
out=$(sudo timeout 6 "$KILN" exec "$sandbox" -- sh -c \
    'test ! -e /workspace/truncated-rights-ran && echo safe' </dev/null 2>/dev/null) ||
    fail "overfull SCM_RIGHTS request damaged the sandbox"
[ "$out" = safe ] || fail "truncated SCM_RIGHTS request ran its command"
remove_sandbox
echo "PASS: truncated SCM_RIGHTS rejected"

# Removal has one canonical frame: op 2, a zero body and no descriptors.
# Data or rights on that operation are malformed and must not stop PID 1.
create_sandbox
socket=/var/lib/kiln/runs/$sandbox/control.sock
sudo python3 - "$socket" <<'PY'
import array
import os
import socket
import struct
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(3)
sock.connect(sys.argv[1])
fd = os.open(os.devnull, os.O_RDWR)
sock.sendmsg([b"\x02\x00\x00\x00" + struct.pack("=I", 1)],
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
try:
    sock.sendall(b"x")
    sock.shutdown(socket.SHUT_WR)
    response = sock.recv(4)
except (BrokenPipeError, ConnectionResetError):
    pass
except socket.timeout:
    raise SystemExit("timed out waiting for malformed removal rejection")
else:
    if response:
        raise SystemExit("malformed removal request received a status")
PY
out=$(sudo timeout 6 "$KILN" exec "$sandbox" -- echo alive </dev/null 2>/dev/null) ||
    fail "malformed removal stopped the sandbox"
[ "$out" = alive ] || fail "sandbox was not reusable after malformed removal"
remove_sandbox
echo "PASS: malformed removal rejected"

# Deterministic protocol fuzzing varies operations, lengths, bodies and fd
# counts. Every malformed connection must close its received fds and leave PID
# 1 ready for the next valid request.
create_sandbox
init_pid=$(sudo cat "/var/lib/kiln/runs/$sandbox/init.pid")
fds_before=$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
socket=/var/lib/kiln/runs/$sandbox/control.sock
sudo python3 - "$socket" <<'PY'
import array
import os
import random
import socket
import struct
import sys
import time

path = sys.argv[1]
rng = random.Random(0x4B494C4E)
nulls = [os.open(os.devnull, os.O_RDWR) for _ in range(4)]
for i in range(256):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(path)
    try:
        case = i % 5
        if case == 0:
            sock.sendall(bytes([rng.randrange(3, 256), 0, 0, 0]) + struct.pack("=I", 0))
        elif case == 1:
            payload = struct.pack("=I", 0)
            sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", len(payload))],
                         [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", nulls[:3]))])
            sock.sendall(payload)
        elif case == 2:
            sock.sendall(b"\x01\x00\x00\x00" + struct.pack("=I", 64) + os.urandom(rng.randrange(0, 16)))
        elif case == 3:
            sock.sendall(b"\x01\x00\x00\x00" + struct.pack("=I", 1024 * 1024 + 1))
        else:
            payload = struct.pack("=II", 1, 4096) + b"short"
            sock.sendmsg([b"\x01\x00\x00\x00" + struct.pack("=I", len(payload))],
                         [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", nulls[:rng.randrange(3)]))])
            sock.sendall(payload)
    except (BrokenPipeError, ConnectionResetError):
        pass
    sock.close()
    if i % 32 == 31:
        time.sleep(0.01)
PY
out=$(sudo timeout 10 "$KILN" exec "$sandbox" -- echo fuzz-survivor </dev/null 2>/dev/null) ||
    fail "malformed-frame fuzzing wedged or stopped the sandbox"
[ "$out" = fuzz-survivor ] || fail "post-fuzz exec printed $out"
fds_after=$(sudo find "/proc/$init_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
[ "$fds_after" -eq "$fds_before" ] ||
    fail "malformed frames leaked PID 1 fds ($fds_before before, $fds_after after)"
remove_sandbox
echo "PASS: 256 malformed frames"

echo "PASS: persistent control protocol"
