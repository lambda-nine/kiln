#!/usr/bin/env python3
"""Run as root: one sandbox's slow TCP frames must not delay another's UDP DNS."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
ids = []
slow = None
try:
    for _ in range(2):
        ids.append(subprocess.check_output([KILN, "create", "--net", "full"], text=True).strip())
    pids = [Path(f"/var/lib/kiln/runs/{identifier}/init.pid").read_text().strip() for identifier in ids]
    # Only enter the network namespace: Python remains the host interpreter,
    # while packets get the first sandbox's real source address.
    source = r'''
import socket, time
clients = []
for _ in range(16):
    s = socket.create_connection(("10.88.0.1", 53), timeout=2)
    s.sendall(b"\x10\x00x")
    clients.append(s)
print("ready", flush=True)
end = time.monotonic() + 6
while time.monotonic() < end:
    for s in clients[:]:
        try: s.sendall(b"x")
        except OSError:
            clients.remove(s)
            s.close()
    time.sleep(0.1)
'''
    slow = subprocess.Popen(["nsenter", "-t", pids[0], "-n", sys.executable, "-I", "-c", source],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ready, _, _ = select.select([slow.stdout], [], [], 5)
    assert ready and slow.stdout.readline().strip() == b"ready", "slow clients failed to start"
    time.sleep(0.2)
    query = r'''
import socket, struct, time
q = struct.pack("!HHHHHH", 0x4b49, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
start = time.monotonic()
s.sendto(q, ("10.88.0.1", 53))
reply, _ = s.recvfrom(4096)
assert reply[:2] == q[:2] and reply[3] & 15 == 0 and struct.unpack("!H", reply[6:8])[0] > 0, reply
assert time.monotonic() - start < 1.5
print("PASS: second sandbox resolves example.com over UDP with 16 slow TCP clients")
'''
    subprocess.run(["nsenter", "-t", pids[1], "-n", sys.executable, "-I", "-c", query], check=True, timeout=4)
finally:
    if slow is not None:
        slow.terminate()
        try:
            slow.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            slow.kill()
            slow.communicate(timeout=3)
    for identifier in reversed(ids):
        subprocess.run([KILN, "rm", identifier], check=True, timeout=10,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
