#!/usr/bin/env python3
"""Checkpoint capture, fork and refusals in real sandboxes; run as root on the
prepared Linux VM (XFS runs filesystem with project quotas).

    sudo python3 -I scripts/checkpoint-format-regressions.py [KILN [OLD_KILN]]

Registers a private copy of the alpine image, captures real sandboxes under
their operation 6 lease, forks them with `kiln create --from-checkpoint`,
mutates source and forks, and checks every refusal it can produce on a real
upper. OLD_KILN (optional) is a kiln whose sandboxes are not checkpoint
sources. Removes every sandbox, artifact, the image copy and its registry
entry (and the registry and checkpoint directories if this run created them).
"""
import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
OLD_KILN = sys.argv[2] if len(sys.argv) > 2 else None
RUNS = "/var/lib/kiln/runs"
CPS = f"{RUNS}/.checkpoints"
IMAGES = "/var/lib/kiln/images"
REGISTRY = "/var/lib/kiln/image-registry"
IMAGE = f"c2-format-{os.getpid()}"
INSTANCE = hashlib.sha256(f"c2-{os.getpid()}-{time.time()}".encode()).hexdigest()[:32]
BOOKKEEPING = {b"trusted.overlay.origin", b"trusted.overlay.impure", b"trusted.overlay.uuid"}
SANDBOXES = []


def cp(n):
    return f"cp-{n:032x}"


def kiln(*args, check=True, timeout=120, binary=None):
    p = subprocess.run([binary or KILN, *args], capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise AssertionError((args, p.returncode, p.stdout, p.stderr))
    return p


def create(*extra, image=None, check=True, binary=None):
    p = kiln("create", "--require-exec-protocol=1", "--image", image or IMAGE, "--memory", "128M", "--pids", "64",
             *(extra if any(a.startswith("--disk") for a in extra) else ("--disk", "256M", *extra)),
             check=check, timeout=60, binary=binary)
    if p.returncode == 0:
        sandbox = p.stdout.decode().strip()
        SANDBOXES.append(sandbox)
        return sandbox
    return p


def remove(sandbox):
    kiln("rm", sandbox)
    SANDBOXES.remove(sandbox)


def sh(sandbox, script, rc=0):
    p = subprocess.run([KILN, "exec", sandbox, "sh", "-c", script], capture_output=True, timeout=60)
    assert rc is None or p.returncode == rc, (script, p.returncode, p.stdout, p.stderr)
    return p.stdout.decode(errors="replace")


def record(text):
    lines = text.decode().splitlines()
    assert lines[0] == "kiln-checkpoint-record 1", text
    return dict(line.split(" ", 1) for line in lines[1:])


def capture(sandbox, n, max_bytes=64 << 20, generation=1):
    return kiln("checkpoint", "capture", "--instance", INSTANCE, "--checkpoint", cp(n), "--generation",
                str(generation), "--max-bytes", str(max_bytes), sandbox, check=False, timeout=300)


def captured(sandbox, n, **kw):
    p = capture(sandbox, n, **kw)
    assert p.returncode == 0, (p.stdout, p.stderr)
    return record(p.stdout)


def refused(p, reason, *words):
    assert p.returncode == 125, (p.returncode, p.stdout, p.stderr)
    lines = p.stdout.decode().splitlines()
    assert lines[0] == "kiln-checkpoint-failure 1" and lines[1] == f"reason {reason}", p.stdout
    for w in words:
        assert w in lines[2], (w, lines[2])
    return lines[2]


def fork_refused(p, reason):
    assert p.returncode != 0 and reason.encode() in p.stderr, (p.returncode, p.stderr)


def inventory():
    lines = kiln("checkpoint", "ls").stdout.decode().splitlines()
    assert lines[0] == "kiln-checkpoint-inventory 1", lines
    return [tuple(line.split(" ", 2)) for line in lines[1:]]


def rm_checkpoint(n):
    out = kiln("checkpoint", "rm", "--instance", INSTANCE, "--checkpoint", cp(n)).stdout.decode()
    assert out.startswith("kiln-checkpoint-removed 1\n"), out


def upper(sandbox):
    return f"{RUNS}/{sandbox}/upper"


def logical(sandbox):
    """The upper as the format sees it: every entry's type, mode, IDs, mtime,
    content or target, hardlink group and user xattrs, without bookkeeping."""
    root = upper(sandbox)
    out, groups = {}, {}
    for directory, dirs, files in os.walk(root):
        for name in files:
            st = os.lstat(os.path.join(directory, name))
            if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                groups.setdefault(st.st_ino, []).append(os.fsencode(os.path.relpath(os.path.join(directory, name), root)))
    for directory, dirs, files in os.walk(root):
        for name in sorted(dirs + files) + ([""] if directory == root else []):
            path = os.path.join(directory, name) if name else directory
            st = os.lstat(path)
            rel = os.fsencode(os.path.relpath(path, root))
            kind = stat.S_IFMT(st.st_mode)
            entry = [kind]
            if stat.S_ISCHR(st.st_mode):
                entry.append(st.st_rdev)
            else:
                entry += [stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns]
            if stat.S_ISREG(st.st_mode):
                with open(path, "rb") as f:
                    entry.append(hashlib.sha256(f.read()).hexdigest())
                if st.st_nlink > 1:
                    entry.append(("group", min(groups[st.st_ino]), len(groups[st.st_ino]), st.st_nlink))
            elif stat.S_ISLNK(st.st_mode):
                entry.append(os.readlink(path))
            if not stat.S_ISCHR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                xattrs = {}
                for x in os.listxattr(path, follow_symlinks=False):
                    if x.encode() not in BOOKKEEPING:
                        xattrs[x] = os.getxattr(path, x, follow_symlinks=False)
                entry.append(sorted(xattrs.items()))
            out[rel] = entry
    return out


def inodes(sandbox):
    found = set()
    for directory, dirs, files in os.walk(upper(sandbox)):
        for name in files:
            st = os.lstat(os.path.join(directory, name))
            if stat.S_ISREG(st.st_mode):
                found.add((st.st_dev, st.st_ino))
    return found


POPULATE = r"""
set -e
mkdir -p /workspace/d/e /workspace/empty-dir
echo alpha > /workspace/a
ln /workspace/a /workspace/d/a2
ln -s ../a /workspace/d/l
ln -s /etc/shadow /workspace/abs
ln -s /proc/self/root /workspace/escape
printf raw > "/workspace/$(printf 'n\377')"
printf 'line\n' > "/workspace/new
line"
: > /workspace/zero
chown 1234:2345 /workspace/d/a2
chown 65535:65535 /workspace/zero
chmod 4755 /workspace/a
chmod 1777 /workspace/d
chmod 555 /workspace/d/e
rm /etc/motd
rm -rf /etc/apk && mkdir /etc/apk && echo x > /etc/apk/only
echo changed >> /etc/os-release
dd if=/dev/zero of=/workspace/sparse bs=1 count=0 seek=8388608 2>/dev/null
echo middle | dd of=/workspace/sparse bs=1 seek=4194304 conv=notrunc 2>/dev/null
touch -d '2020-01-02 03:04:05' /workspace/d/e /workspace/abs 2>/dev/null || touch /workspace/d/e
"""


def bookkeeping_counts(n):
    with open(f"{CPS}/{INSTANCE}/{cp(n)}/complete") as f:
        line = [l for l in f.read().splitlines() if l.startswith("excluded-bookkeeping ")][0]
    return {kv.split("=")[0]: int(kv.split("=")[1]) for kv in line.split(" ")[1:]}


def run_round_trip():
    src = create()
    sh(src, POPULATE)
    os.setxattr(f"{upper(src)}/workspace/a", "user.note", b"\x00\xffv")
    os.setxattr(f"{upper(src)}/workspace/d", "user.dir", b"d")
    before = logical(src)
    rec = captured(src, 1)
    assert rec["image"] == IMAGE and int(rec["entries"]) == len(before), (rec, len(before))
    assert int(rec["logical-bytes"]) >= 8 << 20 and int(rec["allocated-bytes"]) < 4 << 20, rec
    assert int(rec["charge-bytes"]) >= int(rec["logical-bytes"]) + 16384 * int(rec["entries"]), rec
    counts = bookkeeping_counts(1)
    assert counts["trusted.overlay.origin"] > 0 and counts["trusted.overlay.uuid"] == 1, counts
    assert record(kiln("checkpoint", "inspect", "--instance", INSTANCE, "--checkpoint", cp(1),
                       "--verify").stdout) == rec
    assert logical(src) == before, "capture changed the source"
    assert sh(src, "cat /workspace/a") == "alpha\n", "the source runs commands after capture"

    # Forks are exact, independent copies (no bookkeeping, no shared inode).
    forks = [create("--from-checkpoint", f"{INSTANCE}/{cp(1)}") for _ in range(2)]
    for f in forks:
        assert logical(f) == before, f"fork {f} differs from its source"
        assert not inodes(f) & inodes(src), "a fork shares an inode with its source"
        for path in ("workspace/a", "workspace/d"):
            names = [x.encode() for x in os.listxattr(f"{upper(f)}/{path}")]
            assert not set(names) & BOOKKEEPING, names
    assert not inodes(forks[0]) & inodes(forks[1])
    f = forks[0]
    assert sh(f, "cat /workspace/a /workspace/d/a2; readlink /workspace/d/l; stat -c '%h %a %u:%g' /workspace/a") \
        == "alpha\nalpha\n../a\n2 4755 1234:2345\n"
    assert sh(f, "stat -c '%u:%g' /workspace/zero") == "65535:65535\n"
    sh(f, "test ! -e /etc/motd && test \"$(ls /etc/apk)\" = only && grep -q changed /etc/os-release")
    sh(f, "test \"$(dd if=/workspace/sparse bs=1 skip=4194304 count=6 2>/dev/null)\" = middle")
    # A fork checkpointed again has the same content digest.
    assert captured(f, 2)["content-sha256"] == rec["content-sha256"]
    # Mutations stay where they happen.
    # (Through /workspace/a: /workspace/d is sticky, and protected_regular
    # refuses O_CREAT on another owner's file there.)
    sh(forks[0], "echo fork > /workspace/a && rm /workspace/zero")
    sh(src, "echo source > /workspace/a && mkdir /workspace/later")
    assert sh(forks[1], "cat /workspace/a; test -e /workspace/zero; test ! -e /workspace/later") == "alpha\n"
    assert sh(src, "cat /workspace/d/a2") == "source\n"
    seen = sh(forks[0], "cat /workspace/a /workspace/d/a2; stat -c '%h %i' /workspace/a /workspace/d/a2")
    assert seen.startswith("fork\nfork\n"), (seen, sh(forks[0], "ls -lai /workspace /workspace/d"),
        os.stat(f"{upper(forks[0])}/workspace/a"), os.stat(f"{upper(forks[0])}/workspace/d/a2"))
    assert logical(forks[1]) == before
    kiln("checkpoint", "inspect", "--instance", INSTANCE, "--checkpoint", cp(1), "--verify")
    # Deleting the source keeps the checkpoint usable; deleting the checkpoint
    # keeps the forks.
    remove(src)
    late = create("--from-checkpoint", f"{INSTANCE}/{cp(1)}")
    assert logical(late) == before
    rm_checkpoint(1)
    rm_checkpoint(2)
    assert sh(forks[1], "cat /workspace/a") == "alpha\n"
    for s in [*forks, late]:
        remove(s)
    print("ok: round trip, forks, independence, re-capture digest, source and checkpoint deletion")


def host_fixture(sandbox, apply, undo, reason, *words):
    apply()
    try:
        refused(capture(sandbox, 90), reason, *words)
    finally:
        undo()
    assert not [i for i in inventory() if i[0] != "published"], inventory()


def run_refusals():
    src = create()
    sh(src, "mkdir -p /workspace/d && echo x > /workspace/f && echo y > /workspace/g")
    u = upper(src)
    # Busy: a running command.
    busy = subprocess.Popen([KILN, "exec", src, "sleep", "3"])
    time.sleep(0.5)
    refused(capture(src, 90), "checkpoint_busy")
    busy.wait()
    # Special files made inside the sandbox.
    sh(src, "mkfifo /workspace/fifo")
    refused(capture(src, 90), "checkpoint_metadata_unsupported", "is a FIFO")
    sh(src, "rm /workspace/fifo")
    # Metadata the format refuses, put on the raw upper from the host.
    f, d = f"{u}/workspace/f", f"{u}/workspace/d"
    host_fixture(src, lambda: subprocess.run(["setfacl", "-m", "u:2000000001:r", f], check=True),
                 lambda: subprocess.run(["setfacl", "-b", f], check=True), "checkpoint_metadata_unsupported", "POSIX ACL")
    cap = bytes.fromhex("01000002" "00200000" "00000000" "00000000" "00000000")
    host_fixture(src, lambda: os.setxattr(f, "security.capability", cap), lambda: os.removexattr(f, "security.capability"),
                 "checkpoint_metadata_unsupported", "file capability")
    host_fixture(src, lambda: os.setxattr(d, "trusted.overlay.redirect", b"/x"),
                 lambda: os.removexattr(d, "trusted.overlay.redirect"), "checkpoint_metadata_unsupported", "redirect")
    host_fixture(src, lambda: os.setxattr(f, "trusted.overlay.metacopy", b""),
                 lambda: os.removexattr(f, "trusted.overlay.metacopy"), "checkpoint_metadata_unsupported", "metacopy")
    host_fixture(src, lambda: os.setxattr(f, "user.overlay.x", b"1"), lambda: os.removexattr(f, "user.overlay.x"),
                 "checkpoint_metadata_unsupported", "user.overlay")
    host_fixture(src, lambda: os.setxattr(f, "user.big", b"v" * 4096), lambda: os.removexattr(f, "user.big"),
                 "checkpoint_metadata_unsupported", "4096 bytes")
    host_fixture(src, lambda: os.chown(f, 0, 0), lambda: os.chown(f, 2_000_000_000, 2_000_000_000),
                 "checkpoint_metadata_unsupported", "outside the sandbox range")
    host_fixture(src, lambda: os.link(f, f"{RUNS}/{src}/outside-link"), lambda: os.unlink(f"{RUNS}/{src}/outside-link"),
                 "checkpoint_metadata_unsupported", "outside the upper")
    def shadowed():
        os.makedirs(f"{u}/proc/1")
        for p in (f"{u}/proc", f"{u}/proc/1"):
            os.chown(p, 2_000_000_000, 2_000_000_000)
    host_fixture(src, shadowed, lambda: shutil.rmtree(f"{u}/proc"), "checkpoint_layout_unsupported", "/proc/1")
    # Names, targets and values never appear in a refusal.
    os.setxattr(f, "user.overlay.secret-name", b"secret-value")
    detail = refused(capture(src, 90), "checkpoint_metadata_unsupported")
    assert "secret" not in detail and "/workspace" not in detail, detail
    os.removexattr(f, "user.overlay.secret-name")
    # Size: logical bytes (a sparse file is charged its length) within R.
    sh(src, "dd if=/dev/zero of=/workspace/sparse bs=1 count=0 seek=8388608 2>/dev/null")
    refused(capture(src, 90, max_bytes=4 << 20), "checkpoint_size_limit")
    refused(capture(src, 90, max_bytes=1), "invalid_request")
    sh(src, "rm /workspace/sparse")
    # The image must still be the registration the run was created from.
    marker = f"{IMAGES}/{IMAGE}/etc/c2-image-changed"
    etc = os.stat(f"{IMAGES}/{IMAGE}/etc")
    with open(marker, "w") as fh:
        fh.write("x\n")
    try:
        refused(capture(src, 90), "checkpoint_image_unavailable")
    finally:
        os.remove(marker)
        os.utime(f"{IMAGES}/{IMAGE}/etc", ns=(etc.st_atime_ns, etc.st_mtime_ns))
    kiln("image", "verify", IMAGE, timeout=300)
    assert not [i for i in inventory() if i[0] != "published"], inventory()
    # A worker killed mid-copy leaves only staging; the lease ends with it.
    sh(src, "dd if=/dev/urandom of=/workspace/big bs=1M count=48 2>/dev/null")
    worker = subprocess.Popen([KILN, "checkpoint", "capture", "--instance", INSTANCE, "--checkpoint", cp(91),
                               "--generation", "1", "--max-bytes", str(256 << 20), src], stdout=subprocess.PIPE)
    deadline = time.time() + 30
    while time.time() < deadline and not [i for i in inventory() if i[0] == "staging"] and worker.poll() is None:
        time.sleep(0.02)
    staged = [i for i in inventory() if i[0] == "staging"]
    assert worker.poll() is None, ("the worker exited before it was killed", worker.returncode, worker.stdout.read())
    worker.send_signal(signal.SIGKILL)
    worker.wait()
    left = inventory()
    assert staged and left == staged, ("the killed worker should leave exactly its staging", staged, left)
    assert not os.path.exists(f"{CPS}/{INSTANCE}/{cp(91)}"), "a killed worker published"
    assert sh(src, "echo after-kill") == "after-kill\n", "the lease outlived its worker"
    rm_checkpoint(91)
    assert not [i for i in inventory() if cp(91) in i[2]], inventory()
    sh(src, "rm /workspace/big")
    # Old runs and old PID 1 are not sources.
    if OLD_KILN:
        old = create(binary=OLD_KILN)
        refused(capture(old, 90), "sandbox_unsupported:workspace_checkpoint")
        remove(old)
    remove(src)
    print("ok: busy, FIFO, ACL, capability, redirect, metacopy, user.overlay, xattr cap, unmapped owner, "
          "outside link, protected path, redaction, size, image change, killed worker, old run")


def run_fork_refusals():
    src = create()
    sh(src, "echo nameserver 192.0.2.1 > /etc/resolv.conf; echo w > /workspace/w")
    captured(src, 3)
    source = f"{INSTANCE}/{cp(3)}"
    fork_refused(create("--from-checkpoint", source, image="alpine", check=False), "checkpoint_spec_mismatch")
    fork_refused(create("--from-checkpoint", source, "--read-only", check=False), "checkpoint_spec_mismatch")
    fork_refused(create("--from-checkpoint", source, "--disk", "64K", check=False), "checkpoint_disk_too_small")
    fork_refused(create("--from-checkpoint", f"{INSTANCE}/{cp(77)}", check=False), "invalid_request")
    # A sandbox whose runtime writes /etc/resolv.conf can't take one that holds it.
    fork_refused(create("--from-checkpoint", source, "--net", "full", check=False), "checkpoint_layout_unsupported")
    # A corrupt object is found while it is copied: the create fails and its
    # run is removed.
    runs_before = sorted(os.listdir(RUNS))
    obj = f"{CPS}/{INSTANCE}/{cp(3)}/objects/00000000"
    with open(obj, "r+b") as fh:
        data = fh.read()
        fh.seek(0)
        fh.write(bytes([data[0] ^ 1]) + data[1:])
    fork_refused(create("--from-checkpoint", source, check=False), "checkpoint_corrupt")
    assert sorted(os.listdir(RUNS)) == runs_before, "a failed restore left a run behind"
    refused(kiln("checkpoint", "inspect", "--instance", INSTANCE, "--checkpoint", cp(3), "--verify", check=False),
            "checkpoint_corrupt")
    # Artifact headers are image references.
    remove(src)
    p = kiln("image", "rm", IMAGE, check=False)
    assert p.returncode != 0 and b"checkpoint" in p.stderr, p.stderr
    rm_checkpoint(3)
    print("ok: spec, read-only, disk, missing, DNS conflict, corrupt object, image reference")


def run_dns_round_trip():
    try:
        src = create("--net", "full")
    except AssertionError as e:
        print(f"SKIP: DNS round trip (create --net full failed: {e})")
        return
    sh(src, "echo 10.0.0.1 extra >> /etc/hosts; echo w > /workspace/w")
    rec = captured(src, 4)
    with open(f"{CPS}/{INSTANCE}/{cp(4)}/manifest.json") as fh:
        assert '"/etc/resolv.conf"' in fh.read()
    fork = create("--net", "full", "--from-checkpoint", f"{INSTANCE}/{cp(4)}")
    assert sh(fork, "grep -c extra /etc/hosts; grep -c nameserver /etc/resolv.conf") == "1\n1\n"
    assert captured(fork, 5)["content-sha256"] == rec["content-sha256"], "DNS bootstrap changed restored metadata"
    plain = create("--from-checkpoint", f"{INSTANCE}/{cp(4)}")
    sh(plain, "grep -q extra /etc/hosts")
    for s in (src, fork, plain):
        remove(s)
    rm_checkpoint(4)
    rm_checkpoint(5)
    print("ok: DNS sandbox round trip with generated entries")


def project_used_kib(sandbox):
    """The XFS project usage of a run directory (its project is its inode)."""
    projid = os.stat(f"{RUNS}/{sandbox}").st_ino
    out = subprocess.run(["xfs_quota", "-x", "-c", f"quota -p -N -b {projid}", RUNS], capture_output=True,
                         text=True).stdout.split()
    return int(out[1]) if len(out) > 1 else None


def run_allowance():
    """The worst case C1 measured (1-byte files, 250-byte names, 32 xattrs of
    4 KiB) restores within the charge S: a fork whose disk is exactly S."""
    src = create("--disk", "512M")
    count = 1000
    sh(src, f"mkdir /workspace/m && cd /workspace/m && i=0; while [ $i -lt {count} ]; do "
            f"printf x > \"$(printf '%0250d' $i)\"; i=$((i+1)); done")
    base = f"{upper(src)}/workspace/m"
    for name in os.listdir(base):
        for k in range(32):
            os.setxattr(f"{base}/{name}", f"user.x{k:02d}", b"v" * 120)
    started = time.time()
    rec = captured(src, 6, max_bytes=256 << 20)
    elapsed = time.time() - started
    charge = int(rec["charge-bytes"])
    fork = create("--disk", str(charge), "--from-checkpoint", f"{INSTANCE}/{cp(6)}")
    used = project_used_kib(fork)
    assert sh(fork, f"ls /workspace/m | wc -l") == f"{count}\n"
    print(f"measured: entries={rec['entries']} logical={rec['logical-bytes']} allocated={rec['allocated-bytes']} "
          f"charge S={charge} fork-project-used={used} KiB capture={elapsed:.1f}s")
    if used is not None:
        assert used * 1024 <= charge, (used, charge)
    for s in (src, fork):
        remove(s)
    rm_checkpoint(6)
    print("ok: worst-case metadata restores within S")


def run_namespace():
    for d in (CPS, f"{CPS}/{INSTANCE}"):
        if not os.path.isdir(d):
            os.mkdir(d, 0o700)
    out = kiln("ls").stdout.decode()
    assert ".checkpoints" not in out, out
    kiln("gc")
    p = kiln("gc", ".checkpoints", check=False)
    assert p.returncode != 0 and b"invalid sandbox ID" in p.stderr, p.stderr
    p = kiln("rm", ".checkpoints", check=False)
    assert p.returncode != 0
    assert os.path.isdir(CPS)
    print("ok: inventory and GC skip the checkpoint namespace")


def main():
    assert os.listdir(RUNS) == [], "run with no other sandboxes"
    registry_existed = os.path.isdir(REGISTRY)
    try:
        subprocess.run(["cp", "-a", f"{IMAGES}/alpine", f"{IMAGES}/{IMAGE}"], check=True, timeout=120)
        kiln("image", "register", IMAGE, timeout=300)
        run_namespace()
        run_round_trip()
        run_refusals()
        run_fork_refusals()
        run_dns_round_trip()
        run_allowance()
        assert inventory() == [], inventory()
    finally:
        for s in list(SANDBOXES):
            subprocess.run([KILN, "rm", s], capture_output=True, timeout=60)
        for kind, instance, name in (inventory() if os.path.isdir(CPS) else []):
            if instance == INSTANCE and name.startswith(("cp-", ".staging-cp-", ".removing-cp-")):
                checkpoint = name if name.startswith("cp-") else "cp-" + name.split("cp-", 1)[1][:32]
                subprocess.run([KILN, "checkpoint", "rm", "--instance", INSTANCE, "--checkpoint", checkpoint],
                               capture_output=True)
        if os.path.isdir(f"{CPS}/{INSTANCE}"):
            os.rmdir(f"{CPS}/{INSTANCE}")
        if os.path.isdir(CPS) and not os.listdir(CPS):
            os.rmdir(CPS)
        if os.path.isdir(f"{IMAGES}/{IMAGE}"):
            p = subprocess.run([KILN, "image", "rm", IMAGE], capture_output=True)
            if os.path.isdir(f"{IMAGES}/{IMAGE}"):
                shutil.rmtree(f"{IMAGES}/{IMAGE}")
        for leftover in (f"{REGISTRY}/{IMAGE}", f"{REGISTRY}/.{IMAGE}.tmp"):
            if os.path.lexists(leftover):
                os.remove(leftover)
        if not registry_existed and os.path.isdir(REGISTRY):
            os.rmdir(REGISTRY)
    assert os.listdir(RUNS) == [], os.listdir(RUNS)
    print("PASS: checkpoint format round trips, forks, independence, refusals, fork preflight, DNS, namespace")


if __name__ == "__main__":
    main()
