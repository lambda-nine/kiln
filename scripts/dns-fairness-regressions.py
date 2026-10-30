#!/usr/bin/env python3
"""Run as root: DNS service is shared fairly between sandbox source IPs.

Inverts both PoCs from the 2026-10-30 re-attack. 18 sandboxes holding two slow
TCP frames each, and reconnecting as they expire, must leave a nineteenth able
to query over TCP and UDP. One sandbox flooding UDP must leave another's 40
queries answered.

The victims' only allowlist entry is an IP, so their DNS policy is empty and
every name gets an immediate REFUSED. That proves scheduling without depending
on the upstream resolver; dns-regressions.py covers forwarding.
"""
import contextlib
import http.client
from pathlib import Path
import re
import select
import subprocess
import sys
import time

KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
REFUSE_ALL = ["--allow", "1.1.1.1:443"]
BLOCKERS = 18
HOLD_SECONDS = 7
VICTIM_ROUNDS = 8
FLOOD_SECONDS = 5
VICTIM_QUERIES = 40

# Only the network namespace is entered: Python stays the host interpreter, and
# packets get the sandbox's real source address.
BLOCKER = r'''
import select, socket, sys, time
def slow():
    s = socket.create_connection(("10.88.0.1", 53), timeout=2)
    s.sendall(b"\x10\x00x")
    return s
end = time.monotonic() + float(sys.argv[1])
clients = [slow(), slow()]
print("ready", flush=True)
reconnects = 0
while time.monotonic() < end:
    closed, _, _ = select.select(clients, [], [], 0.05)
    for s in closed:
        clients.remove(s)
        s.close()
    while len(clients) < 2:
        try:
            clients.append(slow())
            reconnects += 1
        except OSError:
            time.sleep(0.05)
            break
print(reconnects, flush=True)
'''

TCP_AND_UDP_VICTIM = r'''
import socket, struct, sys, time
def query(ident):
    return struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0) + b"\x06denied\x07invalid\0" + struct.pack("!HH", 1, 1)
def check(reply, q):
    assert reply[:2] == q[:2] and reply[3] & 15 == 5, reply
def read_exact(s, size):
    data = b""
    while len(data) < size:
        chunk = s.recv(size - len(data))
        assert chunk, "server closed the victim's stream"
        data += chunk
    return data
worst = 0
for n in range(int(sys.argv[1])):
    q = query(0x4b00 + n)
    start = time.monotonic()
    t = socket.create_connection(("10.88.0.1", 53), timeout=1.5)
    t.settimeout(1.5)
    t.sendall(struct.pack("!H", len(q)) + q)
    check(read_exact(t, struct.unpack("!H", read_exact(t, 2))[0]), q)
    t.close()
    worst = max(worst, time.monotonic() - start)
    start = time.monotonic()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1.5)
    u.sendto(q, ("10.88.0.1", 53))
    check(u.recvfrom(4096)[0], q)
    u.close()
    worst = max(worst, time.monotonic() - start)
    time.sleep(0.45)
print(f"{worst:.3f}")
'''

FLOOD = r'''
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tail = struct.pack("!HHHH", 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
end = time.monotonic() + float(sys.argv[1])
n = 0
while time.monotonic() < end:
    try:
        s.sendto(struct.pack("!HH", n & 0xffff, 0x100) + tail, ("10.88.0.1", 53))
    except OSError:
        continue
    n += 1
    if n == 2000:
        print("ready", flush=True)
print(n, flush=True)
'''

UDP_VICTIM = r'''
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
resends = 0
worst = 0
for n in range(int(sys.argv[1])):
    q = struct.pack("!HHHHHH", 0x8000 + n, 0x100, 1, 0, 0, 0) + b"\x06denied\x07invalid\0" + struct.pack("!HH", 1, 1)
    start = time.monotonic()
    for attempt in range(2):
        s.sendto(q, ("10.88.0.1", 53))
        try:
            reply, _ = s.recvfrom(4096)
        except TimeoutError:
            resends += 1
            continue
        assert reply[:2] == q[:2] and reply[3] & 15 == 5, reply
        break
    else:
        raise AssertionError(f"query {n} lost twice")
    worst = max(worst, time.monotonic() - start)
    time.sleep(0.02)
print(resends, f"{worst:.3f}")
'''


@contextlib.contextmanager
def harness():
    """Sandboxes and clients that are torn down however the scenario ends."""
    ids = []
    clients = []
    failures = []
    try:
        yield ids, clients
    finally:
        for client in clients:
            if client.poll() is None:
                client.terminate()
        for client in clients:
            try:
                client.wait(timeout=3)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        for identifier in reversed(ids):
            try:
                subprocess.run([KILN, "rm", identifier], check=True, timeout=10,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError):
                failures.append(identifier)
        if failures:
            raise SystemExit(f"FAIL: could not remove sandboxes: {failures}")


def create(ids, *args):
    identifier = subprocess.check_output([KILN, "create", *args], text=True, timeout=30).strip()
    ids.append(identifier)
    return Path(f"/var/lib/kiln/runs/{identifier}/init.pid").read_text().strip()


def ns_command(pid, source, *args):
    return ["nsenter", "-t", pid, "-n", sys.executable, "-I", "-c", source, *map(str, args)]


def start_client(clients, pid, source, *args):
    client = subprocess.Popen(ns_command(pid, source, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    clients.append(client)
    return client


def wait_ready(clients, seconds):
    deadline = time.monotonic() + seconds
    waiting = {client.stdout: client for client in clients}
    while waiting:
        ready, _, _ = select.select(list(waiting), [], [], max(0, deadline - time.monotonic()))
        assert ready, f"{len(waiting)} clients not ready after {seconds}s"
        for stream in ready:
            line = stream.readline().strip()
            assert line == b"ready", waiting[stream].stderr.read().decode()
            del waiting[stream]


def finish(client, seconds):
    """Waits for a client whose output is too small to fill its pipes."""
    client.wait(timeout=seconds)
    assert client.returncode == 0, client.stderr.read().decode()
    return client.stdout.read().split()


def run_victim(pid, source, *args):
    result = subprocess.run(ns_command(pid, source, *args), text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.split()


def query_metrics():
    """kiln_dns_queries_total by outcome, summed over query types."""
    connection = http.client.HTTPConnection("127.0.0.1", 9841, timeout=3)
    connection.request("GET", "/metrics")
    body = connection.getresponse().read().decode()
    connection.close()
    totals = {}
    for outcome, value in re.findall(r'^kiln_dns_queries_total\{[^}]*outcome="(\w+)"[^}]*\} (\d+)', body, re.M):
        totals[outcome] = totals.get(outcome, 0) + int(value)
    return totals


def slow_tcp_sources():
    with harness() as (ids, clients):
        pids = [create(ids, *REFUSE_ALL) for _ in range(BLOCKERS + 1)]
        blockers = [start_client(clients, pid, BLOCKER, HOLD_SECONDS) for pid in pids[:-1]]
        wait_ready(blockers, 10)
        time.sleep(0.15)
        worst, = run_victim(pids[-1], TCP_AND_UDP_VICTIM, VICTIM_ROUNDS)
        assert all(blocker.poll() is None for blocker in blockers), "a blocker stopped before the victim finished"
        for blocker in blockers:
            reconnects = int(finish(blocker, HOLD_SECONDS + 5)[0])
            # Two streams, each held to its 3s frame deadline. Far more would
            # mean the forwarder closed them early, and the attack never held.
            assert 2 <= reconnects <= 10, f"blocker reconnected {reconnects} times in {HOLD_SECONDS}s"
        print(f"PASS: {BLOCKERS} sources x2 slow frames: 19th source's TCP and UDP answered, "
              f"{VICTIM_ROUNDS} rounds, worst {worst}s")


def udp_flood():
    with harness() as (ids, clients):
        flood_pid = create(ids, "--net", "full")
        victim_pid = create(ids, *REFUSE_ALL)
        before = query_metrics()
        flood = start_client(clients, flood_pid, FLOOD, FLOOD_SECONDS)
        wait_ready([flood], 5)
        resends, worst = run_victim(victim_pid, UDP_VICTIM, VICTIM_QUERIES)
        assert flood.poll() is None, "the flood stopped before the victim finished"
        assert int(resends) <= VICTIM_QUERIES // 10, f"{resends}/{VICTIM_QUERIES} victim queries needed a resend"
        sent = int(finish(flood, FLOOD_SECONDS + 5)[0])
        after = query_metrics()
        served = sum(after.get(outcome, 0) - before.get(outcome, 0) for outcome in ("forwarded", "servfail"))
        assert served > 0, "the flood's queries never reached a worker"
        assert after.get("refused", 0) - before.get("refused", 0) >= VICTIM_QUERIES
        print(f"PASS: {sent} flooded datagrams, {served} served: victim's {VICTIM_QUERIES} queries "
              f"answered, {resends} resends, worst {worst}s")


slow_tcp_sources()
udp_flood()
