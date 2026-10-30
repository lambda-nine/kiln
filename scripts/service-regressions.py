#!/usr/bin/env python3
"""Run as root after install: listener identities and real kernel metrics/DNS."""
from pathlib import Path
import http.client
import os
import pwd
import re
import subprocess
import sys
import time

KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"


def run(*args, **kw):
    return subprocess.check_output(args, text=True, timeout=30, **kw).strip()


for service, expected_caps in (("kiln-dns", 1 << 10), ("kiln-metrics", 0)):
    pid = run("systemctl", "show", service, "-p", "MainPID", "--value")
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    uid = pwd.getpwnam(service).pw_uid
    assert uid != 0 and set(map(int, status["Uid"].split())) == {uid}, status["Uid"]
    for field in ("CapEff", "CapPrm", "CapBnd", "CapAmb"):
        assert int(status[field], 16) == expected_caps, (service, field, status[field])
    assert status["NoNewPrivs"].strip() == "1"
    assert status["Seccomp"].strip() == "2"
    print(f"PASS: {service} uid={uid} CapEff={int(status['CapEff'], 16):016x}, NNP and seccomp")

# The root-created policy must remain readable even with a restrictive caller
# umask, while control sockets/run directories stay private.
old_mask = os.umask(0o077)
try:
    identifier = run(KILN, "create", "--net=full", "--memory=64M", "--pids=16", "--disk=16M")
finally:
    os.umask(old_mask)
try:
    directory = Path(f"/var/lib/kiln/runs/{identifier}")
    assert directory.stat().st_mode & 0o777 == 0o700
    pid = (directory / "init.pid").read_text().strip()
    # Enter only the sandbox network; keep the host Python and its libraries.
    dns_test = r'''
import socket, struct
q = struct.pack("!HHHHHH", 0x4b49, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(4)
    s.sendto(q, ("10.88.0.1", 53))
    reply = s.recv(4096)
    assert reply[:2] == q[:2] and reply[3] & 15 == 0 and reply[6:8] != b"\0\0", reply
with socket.create_connection(("10.88.0.1", 53), timeout=4) as s:
    s.sendall(struct.pack("!H", len(q)) + q)
    def exact(n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            assert c
            b += c
        return b
    reply = exact(struct.unpack("!H", exact(2))[0])
    assert reply[:2] == q[:2] and reply[3] & 15 == 0 and reply[6:8] != b"\0\0", reply
'''
    run("nsenter", "-t", pid, "-n", sys.executable, "-I", "-c", dns_test)
    run(KILN, "exec", identifier, "--", "sh", "-c",
        "dd if=/dev/zero of=/workspace/service-metrics bs=1M count=2 2>/dev/null; "
        "nc -z -w 1 10.88.0.1 9840 >/dev/null 2>&1 || true", stdin=subprocess.DEVNULL)
    run("systemctl", "restart", "kiln-metrics-collect.service")
    conn = http.client.HTTPConnection("127.0.0.1", 9840, timeout=5)
    conn.request("GET", "/metrics")
    response = conn.getresponse()
    body = response.read().decode()
    conn.close()
    assert response.status == 200
    assert "kiln_metrics_snapshot_fresh 1\n" in body
    for metric, minimum in (("memory_bytes", 1), ("pids", 1), ("disk_used_bytes", 2 * 1024 * 1024),
                            ("disk_limit_bytes", 16 * 1024 * 1024)):
        sample = re.search(rf'^kiln_sandbox_{metric}\{{run="{identifier}"\}} (\S+)$', body, re.M)
        assert sample and float(sample[1]) >= minimum, (metric, body)
    sample = re.search(r'^kiln_all_host_rejected_packets_total (\S+)$', body, re.M)
    assert sample and float(sample[1]) >= 1, body
    # Neither service account can replace the policy, snapshot, or reach the
    # private run directory. The collector remains their only data publisher.
    for service in ("kiln-dns", "kiln-metrics"):
        for path in ("/run/kiln/net/dns", "/run/kiln-metrics/metrics.prom"):
            result = subprocess.run(["runuser", "-u", service, "--", "test", "-w", path], check=False)
            assert result.returncode != 0, (service, path)
        assert subprocess.run(["runuser", "-u", service, "--", "test", "-r", str(directory)], check=False).returncode != 0
    print("PASS: non-root DNS forwards UDP/TCP; capability-free HTTP serves live cgroup, quota and nft samples")
finally:
    subprocess.run([KILN, "rm", identifier], check=True, timeout=15, stdin=subprocess.DEVNULL)

# One-second successful jobs must not hit systemd's default 5/10s start limit.
stamps = []
for _ in range(21):
    stamps.append(Path("/run/kiln-metrics/metrics.prom").stat().st_mtime_ns)
    time.sleep(1)
assert sum(a != b for a, b in zip(stamps, stamps[1:])) >= 15, stamps
assert max((b - a) / 1e9 for a, b in zip(stamps, stamps[1:])) < 3, stamps
print("PASS: collector advances for twenty seconds without start-limit gaps")

# A collector that fails at initial dependency startup must leave HTTP alive,
# reporting stale state, and recover through the timer without restarting HTTP.
dropin = Path("/run/systemd/system/kiln-metrics-collect.service.d/phase0-test.conf")
try:
    run("systemctl", "stop", "kiln-metrics-collect.timer", "kiln-metrics-collect.service")
    Path("/run/kiln-metrics/metrics.prom").unlink(missing_ok=True)
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("[Service]\nExecStart=\nExecStart=/bin/false\n")
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", "kiln-metrics")
    http_pid = run("systemctl", "show", "kiln-metrics", "-p", "MainPID", "--value")
    def freshness():
        deadline = time.monotonic() + 3
        while True:
            connection = http.client.HTTPConnection("127.0.0.1", 9840, timeout=3)
            try:
                connection.request("GET", "/metrics")
                return connection.getresponse().read().decode()
            except ConnectionRefusedError:
                assert time.monotonic() < deadline, "HTTP did not start"
                time.sleep(0.05)
            finally:
                connection.close()
    assert "kiln_metrics_snapshot_fresh 0\n" in freshness()
    dropin.unlink()
    run("systemctl", "daemon-reload")
    run("systemctl", "reset-failed", "kiln-metrics-collect.service")
    run("systemctl", "restart", "kiln-metrics-collect.timer")
    deadline = time.monotonic() + 5
    while "kiln_metrics_snapshot_fresh 1\n" not in freshness():
        assert time.monotonic() < deadline, "timer did not recover collection"
        time.sleep(0.1)
    assert run("systemctl", "show", "kiln-metrics", "-p", "MainPID", "--value") == http_pid
    print("PASS: failed initial collector leaves HTTP alive and timer recovery restores samples")
finally:
    dropin.unlink(missing_ok=True)
    if dropin.parent.exists():
        dropin.parent.rmdir()
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", "kiln-metrics-collect.timer", "kiln-metrics-collect.service", "kiln-metrics")
