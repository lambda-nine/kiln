#!/usr/bin/env python3
"""Invert round-three's 128-source starvation PoC; run as root in the VM.

The first 128 sources try two partial TCP frames each. Source 129 must receive
an immediate policy REFUSED over TCP and UDP, before any frame expires.
"""

from pathlib import Path
import os
import socket
import struct
import subprocess
import time
import sys


KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
ATTACKERS = 128
ids = []
slow = []
root_net = os.open("/proc/self/ns/net", os.O_RDONLY)


def enter(pid):
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        os.setns(fd, os.CLONE_NEWNET)
    finally:
        os.close(fd)


def root():
    os.setns(root_net, os.CLONE_NEWNET)


def query(ident):
    return (struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0)
            + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1))


try:
    for _ in range(ATTACKERS + 1):
        identifier = subprocess.check_output(
            [KILN, "create", "--allow=1.1.1.1:443", "--memory=32M", "--pids=8", "--disk=16M"],
            text=True,
        ).strip()
        ids.append(identifier)
    pids = [Path(f"/var/lib/kiln/runs/{identifier}/init.pid").read_text().strip()
            for identifier in ids]

    dns_pid = subprocess.check_output(["systemctl", "show", "kiln-dns", "-p", "MainPID", "--value"], text=True).strip()
    fd_dir = Path(f"/proc/{dns_pid}/fd")
    baseline_fds = len(list(fd_dir.iterdir()))
    started = time.monotonic()
    for source_index, pid in enumerate(pids[:ATTACKERS]):
        enter(pid)
        for _ in range(2):
            try:
                stream = socket.create_connection(("10.88.0.1", 53), timeout=1)
            except OSError as error:
                raise AssertionError(
                    f"connection {len(slow) + 1} from source {source_index + 1} failed"
                ) from error
            try:
                stream.sendall(b"\x10\x00x")
            except (BrokenPipeError, ConnectionResetError):
                pass  # Existing holders may be refused to protect the reserve.
            slow.append(stream)
    root()
    assert time.monotonic() - started < 2.5, "slow frames began expiring before saturation"

    enter(pids[-1])
    victim = socket.create_connection(("10.88.0.1", 53), timeout=1)
    victim.settimeout(1)
    frame = query(0x4B49)
    victim.sendall(struct.pack("!H", len(frame)) + frame)
    def exact(stream, size):
        data = b""
        while len(data) < size:
            chunk = stream.recv(size - len(data))
            assert chunk, "new source was denied a TCP admission"
            data += chunk
        return data
    with victim:
        answer = exact(victim, struct.unpack("!H", exact(victim, 2))[0])
    assert answer[:2] == frame[:2] and answer[3] & 15 == 5, answer
    assert time.monotonic() - started < 3, "attack frames expired before victim reply"
    held = len(list(fd_dir.iterdir())) - baseline_fds
    assert 240 <= held <= 256, f"attack held {held} streams; reserve/global bound not exercised"

    # UDP has its own pool, so the scope of this denial is TCP DNS.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(2)
    q = query(0x4B50)
    udp.sendto(q, ("10.88.0.1", 53))
    reply, _ = udp.recvfrom(4096)
    assert reply[:2] == q[:2] and reply[3] & 15 == 5, reply
    udp.close()
    print("PASS: 128 sources x2 partial frames leave source 129 TCP and UDP capacity before expiry")
finally:
    root()
    for stream in slow:
        stream.close()
    os.close(root_net)
    failures = []
    for identifier in reversed(ids):
        try:
            subprocess.run([KILN, "rm", identifier], check=True, timeout=15,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except (subprocess.SubprocessError, OSError):
            failures.append(identifier)
    assert not failures, f"could not remove test sandboxes: {failures}"
