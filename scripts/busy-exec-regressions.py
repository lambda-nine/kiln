#!/usr/bin/env python3
"""Refused or incomplete busy headers must not hold up removal or disconnects."""
import array
from contextlib import ExitStack, contextmanager
from pathlib import Path
import os
import signal
import socket
import select
import struct
import subprocess
import sys
import time

KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
# One stalled header used to cost PID 1 its full two-second request deadline.
PROMPT = 1.9
PARTIAL_HEADERS = 6
FRAME_CAPABILITIES = 2


def connect(identifier):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.8)
    s.connect(f"/var/lib/kiln/runs/{identifier}/control.sock")
    return s


def exact(s, size):
    data = b""
    while len(data) < size:
        part = s.recv(size - len(data))
        assert part, "EOF before status"
        data += part
    return data


def typed_busy(s):
    magic, version, kind, size = struct.unpack("<8sHHI", exact(s, 16))
    assert (magic, version, kind) == (b"KILNEXO\0", 1, 1) and size <= 2072
    payload = exact(s, size)
    assert payload[0] == 2 and payload[2] == 1
    assert struct.unpack("<H", payload[8:10])[0] == 5, payload


def run_dir(identifier):
    return Path(f"/var/lib/kiln/runs/{identifier}")


def wait_gone(identifier):
    deadline = time.monotonic() + 3
    while run_dir(identifier).exists():
        assert time.monotonic() < deadline, "removal did not finish cleanup"
        time.sleep(0.01)


@contextmanager
def sandbox():
    identifier = subprocess.check_output([KILN, "create"], text=True).strip()
    clients = []
    try:
        with open("/dev/null", "r+b") as null:
            rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [null.fileno()] * 3))]
            yield identifier, clients, rights
    finally:
        for client in clients:
            client.close()
        run = run_dir(identifier)
        if run.exists():
            subprocess.run([KILN, "rm", identifier], timeout=5, check=False,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + 3
            while run.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if run.exists():
                subprocess.run([KILN, "gc", identifier], check=True, timeout=5)
                assert not run.exists(), "fixture cleanup left its sandbox"


def start_active(identifier, clients, rights):
    """Starts a sleeping typed exec and returns once its command has run."""
    active = connect(identifier)
    clients.append(active)
    args = [b"sh", b"-c", b"echo ready >/workspace/busy-ready; exec sleep 30"]
    body = struct.pack("<I", len(args)) + b"".join(struct.pack("<I", len(arg)) + arg for arg in args)
    active.sendmsg([b"\x04\0\0\0" + struct.pack("<I", len(body))], rights)
    active.sendall(body)
    marker = run_dir(identifier) / "upper/workspace/busy-ready"
    deadline = time.monotonic() + 5
    while not marker.exists():
        assert time.monotonic() < deadline, "active command never started"
        time.sleep(0.01)
    return active


def partial_headers(identifier, clients, rights):
    """Leaves one-byte exec headers open, half of them holding descriptors."""
    streams = []
    for index in range(PARTIAL_HEADERS):
        stream = connect(identifier)
        clients.append(stream)
        stream.sendmsg([b"\x04"], rights if index % 2 else [])
        streams.append(stream)
    return streams


def probe(identifier):
    """A complete request answered while busy. The listener is first-in
    first-out, so the answer proves earlier connections were accepted."""
    with connect(identifier) as s:
        s.sendall(b"\x03\0\0\0" + struct.pack("<I", 0))
        magic, version, kind, size = struct.unpack("<8sHHI", exact(s, 16))
        assert (magic, version, kind) == (b"KILNEXO\0", 1, FRAME_CAPABILITIES) and size <= 2072
        exact(s, size)


def assert_closed(stream, what):
    """PID 1 closed this stream. A byte it never read turns EOF into a reset."""
    stream.settimeout(PROMPT)
    try:
        assert stream.recv(1) == b"", what
    except ConnectionResetError:
        pass


def init_fds(identifier):
    pid = (run_dir(identifier) / "init.pid").read_text().strip()
    return len(list(Path(f"/proc/{pid}/fd").iterdir()))


def header_refusal(op):
    with sandbox() as (identifier, clients, rights):
        start_active(identifier, clients, rights)
        if op == 4:
            # A real machine client must still observe Busy if refusal
            # interrupts a body larger than the Unix socket send buffer.
            with ExitStack() as stack:
                files = [stack.enter_context(open("/dev/null", "r+b")) for _ in range(3)]
                rx, tx = socket.socketpair()
                stack.callback(rx.close)
                stack.callback(tx.close)
                rx.settimeout(0.8)
                fds = [tx.fileno(), *(f.fileno() for f in files)]
                args = [KILN, "exec", "--protocol=1", f"--status-fd={fds[0]}",
                        f"--stdin-fd={fds[1]}", f"--stdout-fd={fds[2]}", f"--stderr-fd={fds[3]}",
                        identifier, "--", "sh", "-c", "true", *(["x" * 60000] * 12)]
                child = subprocess.run(args, pass_fds=fds, capture_output=True, timeout=5)
                assert child.returncode == 125 and not child.stdout and not child.stderr, child
                tx.close()
                typed_busy(rx)
        refused = connect(identifier)
        clients.append(refused)
        order = "<I" if op == 4 else "=I"
        start = time.monotonic()
        refused.sendmsg([bytes([op, 0, 0, 0]) + struct.pack(order, 1024 * 1024)], rights)
        refused.sendall(b"x")
        remover = connect(identifier)
        clients.append(remover)
        remover.sendall(b"\x02\0\0\0" + struct.pack("=I", 0))
        if op == 1:
            assert struct.unpack("=i", exact(refused, 4))[0] == 125
        else:
            typed_busy(refused)
        assert struct.unpack("=i", exact(remover, 4))[0] == 0
        assert time.monotonic() - start < 0.8, "partial busy body delayed removal"
        wait_gone(identifier)
    print(f"PASS: opcode {op} header-only busy refusal and queued removal")


def partial_then_remove():
    with sandbox() as (identifier, clients, rights):
        start_active(identifier, clients, rights)
        partials = partial_headers(identifier, clients, rights)
        start = time.monotonic()
        remover = connect(identifier)
        clients.append(remover)
        remover.settimeout(PROMPT)
        remover.sendall(b"\x02\0\0\0" + struct.pack("=I", 0))
        assert struct.unpack("=i", exact(remover, 4))[0] == 0
        elapsed = time.monotonic() - start
        assert elapsed < PROMPT, f"partial headers delayed removal for {elapsed:.2f}s"
        wait_gone(identifier)
        for partial in partials:
            assert_closed(partial, "partial header outlived removal")
    print(f"PASS: partial headers did not delay removal ({elapsed:.3f}s)")


def active_disconnect():
    with sandbox() as (identifier, clients, rights):
        idle_fds = init_fds(identifier)
        active = start_active(identifier, clients, rights)
        partials = partial_headers(identifier, clients, rights)
        probe(identifier)
        pid = (run_dir(identifier) / "init.pid").read_text().strip()
        procs = Path(f"/sys/fs/cgroup/kiln/{identifier}/exec/cgroup.procs")
        children = Path(f"/proc/{pid}/task/{pid}/children")
        assert procs.read_text().strip(), "active command is not in the exec cgroup"
        start = time.monotonic()
        active.close()
        while procs.read_text().strip() or children.read_text().strip():
            elapsed = time.monotonic() - start
            assert elapsed < PROMPT, f"partial headers delayed disconnect for {elapsed:.2f}s"
            time.sleep(0.01)
        elapsed = time.monotonic() - start
        for partial in partials:
            assert_closed(partial, "partial header carried past its exec")
        code = subprocess.run([KILN, "exec", identifier, "--", "sh", "-c", "exit 7"], timeout=5,
                              stdin=subprocess.DEVNULL, capture_output=True).returncode
        assert code == 7, f"exec after disconnect returned {code}"
        deadline = time.monotonic() + 1
        while init_fds(identifier) != idle_fds:
            assert time.monotonic() < deadline, "PID 1 kept descriptors after its exec"
            time.sleep(0.01)
    print(f"PASS: active disconnect drained despite partial headers ({elapsed:.3f}s)")


def partial_rights_expire():
    with sandbox() as (identifier, clients, rights):
        start_active(identifier, clients, rights)
        busy_fds = init_fds(identifier)
        start = time.monotonic()
        partial = connect(identifier)
        clients.append(partial)
        partial.sendmsg([b"\x04"], rights)
        probe(identifier)
        # The accepted stream and its three descriptors, read with the byte.
        deadline = start + 1
        while init_fds(identifier) != busy_fds + 4:
            assert time.monotonic() < deadline, "partial header's descriptors were not held"
            time.sleep(0.01)
        deadline = start + 2 + PROMPT
        while init_fds(identifier) != busy_fds:
            assert time.monotonic() < deadline, "expired header kept its descriptors"
            time.sleep(0.01)
        elapsed = time.monotonic() - start
        assert elapsed >= 1.5, f"header expired after only {elapsed:.2f}s"
        assert_closed(partial, "expired header kept its stream")
        probe(identifier)
    print(f"PASS: partial header's descriptors closed at its deadline ({elapsed:.2f}s)")


def disconnect_with_queued_removal(count):
    # Round-three PoC: stop PID 1 so disconnect and listener readability arrive
    # in the same poll pass, with a partial frame before the complete removal.
    with sandbox() as (identifier, clients, rights):
        active = start_active(identifier, clients, rights)
        pid = int((run_dir(identifier) / "init.pid").read_text())
        stopped = False
        try:
            os.kill(pid, signal.SIGSTOP)
            stopped = True
            partials = []
            for _ in range(count):
                partial = connect(identifier)
                clients.append(partial)
                partials.append(partial)
                partial.sendmsg([b"\x04"], rights)
            remover = connect(identifier)
            clients.append(remover)
            remover.settimeout(PROMPT)
            remover.sendall(b"\x02\0\0\0\0\0\0\0")
            active.close()
            start = time.monotonic()
            os.kill(pid, signal.SIGCONT)
            stopped = False
            assert struct.unpack("=i", exact(remover, 4))[0] == 0
            elapsed = time.monotonic() - start
            assert elapsed < PROMPT, f"busy-to-idle backlog delayed removal {elapsed:.2f}s"
            wait_gone(identifier)
            for partial in partials:
                assert_closed(partial, "busy-to-idle partial stream survived removal")
        finally:
            if stopped:
                os.kill(pid, signal.SIGCONT)
    print(f"PASS: simultaneous disconnect and {count} queued partials/remove ({elapsed:.3f}s)")


def continuous_connectors_cannot_postpone_descendant_cleanup():
    flood_code = r'''
import socket, sys, time
end = time.monotonic() + 6
ready = False
attempts = 0
while time.monotonic() < end:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.05)
        try:
            stream.connect(sys.argv[1])
            stream.sendall(b"\x04")
            attempts += 1
            if not ready:
                print("ready", flush=True)
                sys.stdin.buffer.read(1)  # Every worker gets one slot before flooding.
                ready = True
        except OSError:
            pass
print(attempts, flush=True)
'''
    with sandbox() as (identifier, clients, rights):
        active = connect(identifier)
        clients.append(active)
        args = [b"sh", b"-c", b"setsid sh -c 'echo ready >/workspace/flood-descendant; exec sleep 30' & exec sleep 30"]
        body = struct.pack("<I", len(args)) + b"".join(struct.pack("<I", len(arg)) + arg for arg in args)
        active.sendmsg([b"\x04\0\0\0" + struct.pack("<I", len(body))], rights)
        active.sendall(body)
        deadline = time.monotonic() + 5
        while not (run_dir(identifier) / "upper/workspace/flood-descendant").exists():
            assert time.monotonic() < deadline, "setsid descendant did not start"
            time.sleep(0.01)
        pid = int((run_dir(identifier) / "init.pid").read_text())
        procs = Path(f"/sys/fs/cgroup/kiln/{identifier}/exec/cgroup.procs")
        assert len(procs.read_text().split()) >= 2, "no descendant held for cleanup"
        workers = []
        stopped = False
        try:
            os.kill(pid, signal.SIGSTOP)
            stopped = True
            for _ in range(64):
                partial = connect(identifier)
                clients.append(partial)
                partial.sendall(b"\x04")
            for _ in range(4):
                workers.append(subprocess.Popen([sys.executable, "-I", "-c", flood_code,
                    str(run_dir(identifier) / "control.sock")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for worker in workers:
                readable, _, _ = select.select([worker.stdout], [], [], 3)
                assert readable and worker.stdout.readline().strip() == b"ready", "flood did not start"
            for worker in workers:
                worker.stdin.write(b"g")
                worker.stdin.close()
                worker.stdin = None
            # The stopped listener fills while four independent connectors keep
            # replacing accepted sockets. Cancellation must not await quiescence.
            time.sleep(0.1)
            active.close()
            start = time.monotonic()
            os.kill(pid, signal.SIGCONT)
            stopped = False
            children = Path(f"/proc/{pid}/task/{pid}/children")
            while procs.read_text().strip() or children.read_text().strip():
                assert time.monotonic() - start < PROMPT, "continuous connections postponed descendant cleanup"
                time.sleep(0.005)
            elapsed = time.monotonic() - start
            assert all(worker.poll() is None for worker in workers), "flood ended before cleanup"
            print(f"PASS: descendants drained during four continuous connector floods ({elapsed:.3f}s)")
        finally:
            if stopped:
                os.kill(pid, signal.SIGCONT)
            for worker in workers:
                worker.terminate()
            for worker in workers:
                worker.communicate(timeout=3)


for op in (1, 4):
    header_refusal(op)
partial_then_remove()
active_disconnect()
for count in (1, 9, 25, 128):
    disconnect_with_queued_removal(count)
partial_rights_expire()
continuous_connectors_cannot_postpone_descendant_cleanup()
