#!/usr/bin/env python3
"""Checkpoint lease, source metadata, protected paths and image identity in
real sandboxes; run as root on the prepared Linux VM.

    sudo python3 -I scripts/checkpoint-regressions.py [KILN [OLD_KILN]]

OLD_KILN (optional) is a kiln without checkpoint leases (bit 0x40); its
sandbox's PID 1 must be refused before any lease byte. The test registers a
private copy of the alpine image and removes it, its registry entry and (if
this run created it) the registry directory before exiting.
"""
import importlib.util
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

# Root runs this; never leave a root-owned __pycache__ in the checkout.
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("typed", os.path.join(HERE, "typed-exec-regressions.py"))
typed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(typed)

KILN, OLD_KILN = typed.KILN, typed.OLD_KILN
LEASE = 0x40
RUNS = "/var/lib/kiln/runs"
IMAGES = "/var/lib/kiln/images"
REGISTRY = "/var/lib/kiln/image-registry"
IMAGE = f"c1-regression-{os.getpid()}"
LEASE_BUSY = b"a checkpoint lease is held"
PINNED_EFFECTIVE = "effective index=off metacopy=off nfs_export=off redirect_dir=nofollow"


def kiln(*args, check=True, timeout=30):
    p = subprocess.run([KILN, *args], capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise AssertionError((args, p.returncode, p.stdout, p.stderr))
    return p


def create(image, *extra):
    out = kiln("create", "--require-exec-protocol=1", "--image", image, "--memory", "64M", "--pids", "32",
               "--disk", "64M", *extra, timeout=15).stdout.decode().strip()
    assert out, "create printed no ID"
    return out


def read_frame(sock, timeout=10):
    """One KILNEXO frame from a stream carrying several: (type, payload)."""
    sock.settimeout(timeout)
    data = b""
    while len(data) < 16:
        part = sock.recv(16 - len(data))
        if not part:
            return None if not data else ("truncated", data)
        data += part
    magic, version, kind, size = struct.unpack("<8sHHI", data)
    assert (magic, version) == (b"KILNEXO\0", 1) and kind in (1, 2, 3) and size <= 2072, data
    payload = b""
    while len(payload) < size:
        part = sock.recv(size - len(payload))
        assert part, "truncated frame"
        payload += part
    return kind, data + payload


def lease_state(frame_bytes):
    payload = typed.frame(frame_bytes, 3)
    state, reserved, generation = struct.unpack("<B7sQ", payload)
    assert reserved == b"\0" * 7 and generation > 0
    return state, generation


def outcome_full(frame_bytes):
    o = typed.outcome(frame_bytes)
    size = struct.unpack("<I", frame_bytes[32:36])[0]
    return o, frame_bytes[40:40 + size]


class LeaseCli:
    """`kiln checkpoint-lease` driven over its private status socket."""

    def __init__(self, identifier, kiln_path=KILN):
        self.status, theirs = socket.socketpair()
        self.child = subprocess.Popen([kiln_path, "checkpoint-lease", "--protocol=1",
                                       f"--status-fd={theirs.fileno()}", identifier],
                                      pass_fds=(theirs.fileno(),), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        theirs.close()
        self.first = read_frame(self.status)

    def granted(self):
        assert self.first and self.first[0] == 3, ("no grant", self.first, self.finish())
        state, generation = lease_state(self.first[1])
        assert state == 1
        return generation

    def ack(self, generation):
        self.status.sendall(b"KILNACK\0" + struct.pack("<Q", generation))

    def last(self):
        frame = read_frame(self.status)
        assert read_frame(self.status, timeout=5) is None, "status carried more than the final frame"
        return frame

    def finish(self):
        try:
            out, err = self.child.communicate(timeout=15)
        finally:
            if self.child.poll() is None:
                self.child.kill()
                self.child.communicate()
            self.status.close()
        assert out == b"", ("CLI polluted stdout", out)
        return self.child.returncode, err


def human_exec(identifier, *args):
    with open("/dev/null", "rb") as null_in, open("/dev/null", "wb") as null_out:
        return subprocess.run([KILN, "exec", identifier, "--", *args], stdin=null_in, stdout=subprocess.PIPE,
                              stderr=null_out, timeout=15)


def exec_until_runs(identifier, args):
    """The first exec after a lease ends; one racing its end may be refused."""
    for _ in range(100):
        rc, status, out, err, diag = typed.machine(identifier, args)
        o = typed.outcome(status)
        if o[5] != 5:
            return rc, o, out
        time.sleep(0.05)
    raise AssertionError("lease never ended")


def upper_entries(identifier):
    upper = f"{RUNS}/{identifier}/upper"
    found = []
    for root, dirs, files in os.walk(upper):
        for name in dirs + files:
            found.append(os.path.relpath(os.path.join(root, name), upper))
    return sorted(found)


def layout(identifier):
    with open(f"{RUNS}/{identifier}/layout") as f:
        return f.read()


def reference(identifier):
    with open(f"{RUNS}/{identifier}/image") as f:
        return f.read()


def check_contract_and_layout(identifier, dns):
    contract = kiln("checkpoint-contract", *(["--dns"] if dns else [])).stdout.decode().splitlines()
    assert contract[0] == "kiln-protected-paths 1"
    mounts = [line.split(" ", 1)[1] for line in contract if line.startswith("mount ")]
    out = human_exec(identifier, "cat", "/proc/self/mountinfo")
    assert out.returncode == 0
    actual = [line.split()[4] for line in out.stdout.decode().splitlines()]
    assert actual == mounts, ("runtime mounts differ from the contract", actual, mounts)
    text = layout(identifier)
    assert "verified yes\n" in text and PINNED_EFFECTIVE in text, text
    generated = [line.split(" ", 1)[1] for line in text.splitlines() if line.startswith("generated ")]
    assert generated == [line.split(" ", 1)[1] for line in contract if line.startswith("generated ")], text
    # A fresh upper holds only what the contract says the runtime generates.
    expected = sorted({g.lstrip("/") for g in generated} | {os.path.dirname(g).lstrip("/") for g in generated})
    assert upper_entries(identifier) == expected, upper_entries(identifier)
    for g in generated:
        st = os.lstat(f"{RUNS}/{identifier}/upper{g}")
        assert (st.st_uid, st.st_gid) == (0, 0), "generated entry not host-root owned"


def run_lease(identifier):
    marker = "/tmp/c1-ran-during-lease"
    touch = ["sh", "-c", f"touch {marker}"]
    cli = LeaseCli(identifier)
    generation = cli.granted()
    assert typed.features(typed.caps(identifier)) & LEASE, "probe during lease"
    rc, status, out, err, diag = typed.machine(identifier, touch)
    o, text = outcome_full(status)
    assert (rc, o[:3], o[5:7], text) == (125, (2, 0, 1), (5, 1), LEASE_BUSY), (rc, o, text)
    rc, status, *_ = typed.machine(identifier, touch, options=typed.options_frame("/tmp", [("A", "1")]))
    assert (rc, typed.outcome(status)[5:7]) == (125, (5, 1))
    assert human_exec(identifier, *touch).returncode == 125
    second = LeaseCli(identifier)
    o, text = outcome_full(second.first[1])
    assert second.first[0] == 1 and o[5:7] == (5, 15) and text == LEASE_BUSY, (o, text)
    assert second.last() is None and second.finish()[0] == 125
    time.sleep(5)  # longer than two framing windows: no lease timer
    rc, status, *_ = typed.machine(identifier, touch)
    assert typed.outcome(status)[5] == 5
    assert not os.path.lexists(f"{RUNS}/{identifier}/upper{marker}")
    cli.ack(generation)
    kind, released = cli.last()
    assert kind == 3 and lease_state(released) == (2, generation)
    assert cli.finish()[0] == 0
    rc, o, _ = exec_until_runs(identifier, ["test", "!", "-e", marker])
    assert (rc, o[4]) == (0, 0), "a refused command ran"

    # The CLI dying ends the lease without success.
    cli = LeaseCli(identifier)
    cli.granted()
    cli.child.send_signal(signal.SIGKILL)
    assert cli.finish()[0] == -signal.SIGKILL
    assert exec_until_runs(identifier, ["true"])[0] == 0
    # The driver closing its status socket abandons the lease.
    cli = LeaseCli(identifier)
    cli.granted()
    cli.status.shutdown(socket.SHUT_WR)
    kind, frame = cli.last()
    o, text = outcome_full(frame)
    assert kind == 1 and o[5:7] == (11, 15) and b"ended without release" in text, (o, text)
    assert cli.finish()[0] == 125
    assert exec_until_runs(identifier, ["true"])[0] == 0
    # A wrong-generation acknowledgment is not forwarded.
    cli = LeaseCli(identifier)
    generation = cli.granted()
    cli.ack(generation + 1)
    o, text = outcome_full(cli.last()[1])
    assert o[5:7] == (1, 15) and b"names lease" in text, (o, text)
    assert cli.finish()[0] == 125
    assert exec_until_runs(identifier, ["true"])[0] == 0
    # A lease during an exec is refused; the exec is unaffected.
    active = typed.raw_exec(identifier, ["sh", "-c", "sleep 1"])
    time.sleep(0.2)
    busy = LeaseCli(identifier)
    o, text = outcome_full(busy.first[1])
    assert o[5:7] == (5, 15) and text == b"another exec is active", (o, text)
    busy.finish()
    assert typed.outcome(typed.receive(active))[0] == 1
    active.close()


def run_stalled_probes(identifier):
    """Adversarial-review LOW: probes wait behind stalled connections as op 4 does."""
    def stalled():
        conns = []
        for _ in range(2):
            c = socket.socket(socket.AF_UNIX)
            c.connect(f"{RUNS}/{identifier}/control.sock")
            c.send(b"\x04")
            conns.append(c)
        return conns
    held = stalled()
    started = time.monotonic()
    rc, status, out, err, diag = typed.machine(identifier, ["echo", "ok"], options=typed.options_frame())
    assert rc == 0 and out == b"ok\n" and time.monotonic() - started > 2, (rc, typed.outcome(status))
    for c in held:
        c.close()
    held = stalled()
    started = time.monotonic()
    cli = LeaseCli(identifier)
    generation = cli.granted()
    assert time.monotonic() - started > 2
    cli.ack(generation)
    assert lease_state(cli.last()[1]) == (2, generation) and cli.finish()[0] == 0
    for c in held:
        c.close()


def run_old_pid1(capable):
    if OLD_KILN is None:
        print("SKIP: old PID 1 refusal (no older kiln given)")
        return
    old = subprocess.check_output([OLD_KILN, "create", "--require-exec-protocol=1", "--memory", "64M",
                                   "--pids", "32", "--disk", "16M"], timeout=10).decode().strip()
    try:
        assert not typed.features(typed.caps(old)) & LEASE
        assert not os.path.exists(f"{RUNS}/{old}/image") and not os.path.exists(f"{RUNS}/{old}/layout")
        cli = LeaseCli(old)
        o, text = outcome_full(cli.first[1])
        assert o[5:7] == (4, 13) and text.startswith(b"sandbox_unsupported:workspace_checkpoint: the run has no image"), text
        assert cli.last() is None and cli.finish()[0] == 125
        # Even with copied metadata, PID 1 without bit 6 gets only operation 3.
        for name in ("image", "layout"):
            shutil.copyfile(f"{RUNS}/{capable}/{name}", f"{RUNS}/{old}/{name}")
        cli = LeaseCli(old)
        o, text = outcome_full(cli.first[1])
        assert o[5:7] == (4, 13) and b"does not grant checkpoint leases" in text, text
        assert cli.last() is None and cli.finish()[0] == 125
        rc, status, *_ = typed.machine(old, ["true"])
        assert rc == 0, "old PID 1 stopped serving after the refused lease"
    finally:
        subprocess.run([OLD_KILN, "rm", old], check=True, timeout=15)


def run_registry_and_sandboxes():
    # cp -a keeps the sandbox-range ownership the image check requires.
    subprocess.run(["cp", "-a", f"{IMAGES}/alpine", f"{IMAGES}/{IMAGE}"], check=True, timeout=60)
    plain = create(IMAGE)
    try:
        ref = reference(plain)
        assert ref == f"kiln-image-ref 1\nname {IMAGE}\nidentity none image is not registered\n", ref
        cli = LeaseCli(plain)
        o, text = outcome_full(cli.first[1])
        assert o[5:7] == (4, 13) and b"sandbox_unsupported:workspace_checkpoint" in text and b"not registered" in text
        cli.finish()
        entry = kiln("image", "register", IMAGE, timeout=120).stdout.decode()
        assert f"name {IMAGE}\ngeneration 1\nstate registered\n" in entry, entry
        assert kiln("image", "verify", IMAGE, timeout=120).stdout.decode() == entry
        assert kiln("image", "register", IMAGE, timeout=120).stdout.decode() == entry, "no-op re-registration"
        # A run referencing the name by name alone still blocks removal.
        for action in (("unregister", IMAGE), ("rm", IMAGE)):
            p = kiln("image", *action, check=False)
            assert p.returncode != 0 and plain.encode() in p.stderr, p.stderr
    finally:
        kiln("rm", plain)

    capable = create(IMAGE)
    try:
        ref = reference(capable)
        assert f"name {IMAGE}\ngeneration 1\nsha256 " in ref, ref
        check_contract_and_layout(capable, dns=False)
        run_lease(capable)
        run_stalled_probes(capable)
        run_old_pid1(capable)
        p = kiln("image", "rm", IMAGE, check=False)
        assert p.returncode != 0 and capable.encode() in p.stderr and b"new image name" in p.stderr
    finally:
        kiln("rm", capable)

    try:
        dns = create(IMAGE, "--net", "full")
    except AssertionError as e:
        print(f"SKIP: DNS-generated entry check (create --net full failed: {e})")
    else:
        try:
            check_contract_and_layout(dns, dns=True)
        finally:
            kiln("rm", dns)

    # One-shot runs use the same pins and references.
    p = subprocess.run([KILN, "run", "--image", IMAGE, "--disk", "64M", "--", "true"], capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr

    # Unreferenced: replacement gets a new generation; removal works.
    with open(f"{IMAGES}/{IMAGE}/etc/c1-replaced", "w") as f:
        f.write("changed\n")
    assert kiln("image", "verify", IMAGE, check=False).returncode != 0
    entry = kiln("image", "register", IMAGE, timeout=120).stdout.decode()
    assert "generation 2\nstate registered\n" in entry, entry
    kiln("image", "rm", IMAGE)
    assert not os.path.exists(f"{IMAGES}/{IMAGE}")
    assert "state retired" in kiln("image", "inspect", IMAGE).stdout.decode()


def main():
    assert os.listdir(RUNS) == [], "run with no other sandboxes: unknown runs block image removal"
    registry_existed = os.path.isdir(REGISTRY)
    try:
        run_registry_and_sandboxes()
    finally:
        if os.path.isdir(f"{IMAGES}/{IMAGE}"):
            shutil.rmtree(f"{IMAGES}/{IMAGE}")
        for leftover in (f"{REGISTRY}/{IMAGE}", f"{REGISTRY}/.{IMAGE}.tmp"):
            if os.path.lexists(leftover):
                os.remove(leftover)
        if not registry_existed and os.path.isdir(REGISTRY):
            os.rmdir(REGISTRY)
    print("PASS: checkpoint lease, unsupported and old-PID-1 refusals, stalled probes, pinned layout, "
          "protected paths, image identity and references")


if __name__ == "__main__":
    main()
