#!/usr/bin/env python3
"""Valid exec header + one body byte must not hold up a queued removal."""
import array
from contextlib import ExitStack
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"


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


for op in (1, 4):
    identifier = subprocess.check_output([KILN, "create"], text=True).strip()
    clients = []
    try:
        with open("/dev/null", "r+b") as null:
            rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [null.fileno()] * 3))]
            active = connect(identifier)
            clients.append(active)
            args = [b"sh", b"-c", b"echo ready >/workspace/busy-ready; exec sleep 30"]
            body = struct.pack("<I", len(args)) + b"".join(struct.pack("<I", len(arg)) + arg for arg in args)
            active.sendmsg([b"\x04\0\0\0" + struct.pack("<I", len(body))], rights)
            active.sendall(body)
            marker = Path(f"/var/lib/kiln/runs/{identifier}/upper/workspace/busy-ready")
            deadline = time.monotonic() + 5
            while not marker.exists():
                assert time.monotonic() < deadline, "active command never started"
                time.sleep(0.01)
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
        deadline = time.monotonic() + 3
        run = Path(f"/var/lib/kiln/runs/{identifier}")
        while run.exists():
            assert time.monotonic() < deadline, "removal did not finish cleanup"
            time.sleep(0.01)
        print(f"PASS: opcode {op} header-only busy refusal and queued removal")
    finally:
        for client in clients:
            client.close()
        run = Path(f"/var/lib/kiln/runs/{identifier}")
        if run.exists():
            subprocess.run([KILN, "rm", identifier], timeout=5, check=False,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + 3
            while run.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if run.exists():
                subprocess.run([KILN, "gc", identifier], check=True, timeout=5)
                assert not run.exists(), "fixture cleanup left its sandbox"
