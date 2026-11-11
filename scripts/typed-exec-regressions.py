#!/usr/bin/env python3
"""Installed-path typed exec acceptance; run as root on the prepared Linux VM."""
import array
import errno
import fcntl
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"
# Optional: an older kiln without exec options (feature 0x20) to create a
# sandbox whose PID 1 the new CLI must refuse before sending anything.
OLD_KILN = sys.argv[2] if len(sys.argv) > 2 else None
EXEC_OPTIONS = 0x20
BASE_ENV = [("HOME", "/root"), ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            ("TERM", "xterm")]
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
F_SEAL_FUTURE_WRITE = 0x10  # Linux 5.1; not exported by Python's fcntl


def frame(data, expected):
    assert len(data) >= 16, ("missing/truncated reply", data)
    magic, version, kind, size = struct.unpack("<8sHHI", data[:16])
    assert (magic, version, kind) == (b"KILNEXO\0", 1, expected)
    assert size <= 2072 and len(data) == 16 + size
    return data[16:]


def outcome(data):
    p = frame(data, 1)
    result, termination, cleanup, flags, value, kind, stage, errno, size, reserved = struct.unpack("<BBBBiHHiII", p[:24])
    assert reserved == 0 and flags & ~3 == 0 and size <= 2048 and len(p) == 24 + size
    p[24:].decode("utf-8")
    return result, termination, cleanup, flags, value, kind, stage, errno


def caps(identifier=None, kiln=KILN):
    args = [kiln, "capabilities", "--protocol=1"]
    if identifier:
        args.append(identifier)
    p = frame(subprocess.check_output(args, timeout=5), 2)
    features, control, status, package, provenance, reserved = struct.unpack("<IHHHHI", p[:16])
    assert features & 15 == 15 and (control, status, reserved) == (1, 1, 0)
    assert package <= 64 and provenance <= 128 and len(p) == 16 + package + provenance
    p[16:].decode("utf-8")
    return p


def features(p):
    return struct.unpack("<I", p[:4])[0]


def options_frame(cwd=None, env=()):
    """docs/exec-protocol-v1.md "Exec options": entries sorted by name bytes."""
    cwd = (cwd or "").encode()
    body = cwd
    for name, value in sorted(((n.encode(), v.encode()) for n, v in env)):
        body += struct.pack("<I", len(name)) + name + struct.pack("<I", len(value)) + value
    return struct.pack("<8sHHIII", b"KILNOPT\0", 1, 0, 24 + len(body), len(cwd), len(env)) + body


def sealed(data, seals=SEALS, allow_sealing=True):
    fd = os.memfd_create("typed-exec-options", os.MFD_CLOEXEC | (os.MFD_ALLOW_SEALING if allow_sealing else 0))
    os.write(fd, data)
    if seals:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    return fd


def machine(identifier, args, version=1, broken_status=None, options=None, kiln=KILN):
    """options: frame bytes (sent in a correctly sealed memfd) or a ready fd."""
    if isinstance(options, bytes):
        options = sealed(options)
    status_rx, status_tx = socket.socketpair()
    # Regular temporary output files permit inspecting evidence even when the
    # status receiver deliberately disconnects or refuses to read.
    with open("/dev/null", "rb") as source, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        if broken_status == "disconnect":
            status_rx.close()
        elif broken_status == "nonreader":
            status_tx.setblocking(False)
            try:
                while True:
                    status_tx.send(b"x" * 4096)
            except BlockingIOError:
                pass
            status_tx.setblocking(True)
        descriptors = (status_tx.fileno(), source.fileno(), out.fileno(), err.fileno())
        extra = () if options is None else (f"--exec-options-fd={options}",)
        command = [kiln, "exec", f"--protocol={version}", f"--status-fd={descriptors[0]}",
                   f"--stdin-fd={descriptors[1]}", f"--stdout-fd={descriptors[2]}",
                   f"--stderr-fd={descriptors[3]}", *extra, identifier, "--", *args]
        if options is not None:
            descriptors += (options,)
        child = subprocess.Popen(command, pass_fds=descriptors, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status_tx.close()
        if options is not None:
            os.close(options)
        # Read status concurrently in the ordinary case. CLI diagnostics have
        # their own bounded-by-test stream, never the workload stderr file.
        result = bytearray()
        def read_status():
            while True:
                chunk = status_rx.recv(2090)
                if not chunk:
                    return
                result.extend(chunk)
                assert len(result) <= 2088
        reader = None
        if broken_status is None:
            reader = threading.Thread(target=read_status)
            reader.start()
        try:
            cli_out, cli_err = child.communicate(timeout=10)
            if reader:
                reader.join(timeout=5)
                assert not reader.is_alive(), "status did not close after one frame"
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
            status_rx.close()
            if reader:
                reader.join(timeout=5)
        out.seek(0)
        err.seek(0)
        assert cli_out == b"", ("CLI polluted stdout", cli_out)
        return child.returncode, bytes(result), out.read(), err.read(), cli_err


def raw_exec(identifier, args, allow_early_close=False, options=None):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    client.connect(f"/var/lib/kiln/runs/{identifier}/control.sock")
    payload = struct.pack("<I", len(args))
    for arg in args:
        arg = arg.encode()
        payload += struct.pack("<I", len(arg)) + arg
    op = 4 if options is None else 5
    payload += options or b""
    with open("/dev/null", "r+b") as null:
        rights = array.array("i", [null.fileno()] * 3)
        try:
            client.sendmsg([struct.pack("<B3xI", op, len(payload))], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        except (BrokenPipeError, ConnectionResetError):
            # Cancellation-only peers may race the closing of an incomplete
            # busy header. Response-bearing calls still require valid framing.
            if not allow_early_close:
                client.close()
                raise
            return client
    try:
        client.sendall(payload)
    except (BrokenPipeError, ConnectionResetError):
        # An early busy refusal can interrupt a body send. The caller still
        # must validate the explicit Busy frame, never infer one from errno.
        pass
    return client


def receive(client):
    data = bytearray()
    while True:
        try:
            part = client.recv(2089)
        except ConnectionResetError:
            # Header-only refusal leaves body bytes unread in PID 1. Match
            # the production decoder: only a complete Busy frame permits RST.
            result = outcome(bytes(data))
            assert result[:3] == (2, 0, 1) and result[5:7] == (5, 1)
            return bytes(data)
        if not part:
            return bytes(data)
        data.extend(part)
        assert len(data) <= 2088


def pid1_host_pid(identifier):
    with open(f"/var/lib/kiln/runs/{identifier}/shim.pid") as f:
        shim = f.read().strip()
    children = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat") as f:
                    stat = f.read()
            except FileNotFoundError:
                continue
            if stat[stat.rindex(")") + 2:].split()[1] == shim:
                children.append(int(entry))
    assert len(children) == 1, children
    return children[0]


def chdir_failed(result, code):
    rc, status, out, err, diag = result
    assert outcome(status) == (2, 0, 2, 0, 0, 6, 14, code), (outcome(status), code)
    assert rc == 126 and out == err == b"", (rc, out, err)


def run_options(identifier):
    """Operation 5: cwd, environment, seals, bounds and descriptor closure."""
    assert features(caps()) & EXEC_OPTIONS and features(caps(identifier)) & EXEC_OPTIONS
    environ = ["/bin/cat", "/proc/self/environ"]
    rc, status, out, err, diag = machine(identifier, environ, options=options_frame())
    assert rc == 0 and outcome(status)[4] == 0
    assert out == b"".join(f"{n}={v}\0".encode() for n, v in BASE_ENV), out
    overrides = [("TERM", "dumb"), ("A0", "x"), ("A", ""), ("_", "雪 =$(x)"), ("a", "l")]
    rc, status, out, err, diag = machine(identifier, environ, options=options_frame(env=overrides))
    merged = dict(BASE_ENV)
    merged.update(overrides)
    assert out == b"".join(f"{n}={merged[n]}\0".encode() for n in sorted(merged, key=str.encode)), out
    # PATH is an override for lookup too; relative names resolve in the cwd.
    assert machine(identifier, ["sh", "-c", "mkdir -p /tmp/m3a-bin && printf '#!/bin/sh\\necho \"$PWD|$PATH\"\\n'"
                                " > /tmp/m3a-bin/m3a-tool && chmod 755 /tmp/m3a-bin/m3a-tool && ln -sfn m3a-loop /tmp/m3a-loop"])[0] == 0
    rc, status, out, err, diag = machine(identifier, ["m3a-tool"], options=options_frame("/tmp", [("PATH", "/tmp/m3a-bin")]))
    assert (rc, out) == (0, b"/tmp|/tmp/m3a-bin\n"), (rc, out, err)
    rc, status, out, err, diag = machine(identifier, ["./m3a-tool"], options=options_frame("/tmp/m3a-bin"))
    assert (rc, out) == (0, f"/tmp/m3a-bin|{BASE_ENV[1][1]}\n".encode()), (rc, out, err)
    rc, status, out, err, diag = machine(identifier, ["pwd", "-P"], options=options_frame("/tmp/m3a-bin/../../etc"))
    assert (rc, out) == (0, b"/etc\n")
    # PID 1 kept its own cwd and environment.
    rc, status, out, err, diag = machine(identifier, ["sh", "-c", "pwd; env | grep -c '^A0=' || true"])
    assert out == b"/\n0\n", out

    # chdir failures: LaunchFailed/Chdir with errno, drained, PID 1 reusable.
    for cwd, code in [("/no/such/dir", errno.ENOENT), ("/var/lib/kiln/runs", errno.ENOENT),
                      ("/etc/passwd", errno.ENOTDIR), ("/proc/1/cwd", errno.EACCES),
                      ("/tmp/m3a-loop", errno.ELOOP), ("/" + "a" * 4095, errno.ENAMETOOLONG)]:
        chdir_failed(machine(identifier, ["sh", "-c", "echo ran; echo ran >&2"], options=options_frame(cwd)), code)
        assert outcome(machine(identifier, ["true"])[1])[4] == 0

    # No descriptor PID 1 held before closure can become the cwd.
    pid1 = pid1_host_pid(identifier)
    held = {int(n): os.readlink(f"/proc/{pid1}/fd/{n}") for n in os.listdir(f"/proc/{pid1}/fd")}
    print("PID 1 descriptors:", held)
    for n in range(0, max(held) + 5):
        rc, status, out, err, diag = machine(identifier, ["pwd"], options=options_frame(f"/proc/self/fd/{n}"))
        result = outcome(status)
        assert result[:7] == (2, 0, 2, 0, 0, 6, 14) and result[7] in (errno.ENOENT, errno.ENOTDIR), (n, result)
        assert out == b"", (n, out)

    # The CLI refuses anything but an exactly sealed memfd, before connecting.
    refused = (2, 0, 1, 0, 0, 1, 1, 0)
    frame = options_frame("/tmp")
    regular = tempfile.TemporaryFile()
    regular.write(frame)
    regular.flush()
    pipe_r, pipe_w = os.pipe()
    os.write(pipe_w, frame)
    os.close(pipe_w)
    for name, fd in [("missing seal", sealed(frame, SEALS & ~fcntl.F_SEAL_WRITE)),
                     ("unsealed", sealed(frame, 0)), ("no sealing", sealed(frame, 0, allow_sealing=False)),
                     ("extra seal", sealed(frame, SEALS | F_SEAL_FUTURE_WRITE)),
                     ("regular file", os.dup(regular.fileno())), ("pipe", pipe_r),
                     ("oversize", sealed(frame + b"\0" * (40 * 1024 + 1 - len(frame))))]:
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "echo ran"], options=fd)
        assert (rc, outcome(status), out, err) == (125, refused, b"", b""), (name, rc, outcome(status), out)
    regular.close()

    # Frame bounds: each at its limit runs; one past it is refused.
    max_total = [(f"V{i}", "x" * 4092) for i in range(8)]
    for env in ([(f"V{i:02}", "") for i in range(64)], [("N" + "_" * 127, "v")], [("V", "x" * 4096)], max_total):
        rc, status, out, err, diag = machine(identifier, ["true"], options=options_frame(None, env))
        assert rc == 0 and outcome(status)[4] == 0
    duplicate = options_frame(None, [("A", "1"), ("B", "2")]).replace(b"B", b"A")
    for frame in [options_frame("/" + "a" * 4096), options_frame("relative"), options_frame("/a\0b"),
                  options_frame(None, [(f"V{i:02}", "") for i in range(65)]), options_frame(None, [("N" + "_" * 128, "v")]),
                  options_frame(None, [("V", "x" * 4097)]), options_frame(None, max_total[:7] + [("V7", "x" * 4093)]),
                  options_frame(None, [("1A", "v")]), options_frame(None, [("A", "a\0b")]), duplicate,
                  options_frame("/tmp") + b"\0", options_frame("/tmp")[:-1]]:
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "echo ran"], options=frame)
        assert (rc, outcome(status), out) == (125, refused, b""), (rc, outcome(status), frame[:40])
        assert b"\0b" not in diag and b"xxxxxxxx" not in diag

    # PID 1 revalidates: a raw operation 5 with a bad frame is closed unanswered.
    for frame in [options_frame("relative"), options_frame(None, [("A", "1"), ("B", "2")]).replace(b"B", b"A")]:
        bad = raw_exec(identifier, ["sh", "-c", "echo ran > /tmp/m3a-raw"], allow_early_close=True, options=frame)
        assert receive(bad) == b""
        bad.close()
    assert machine(identifier, ["test", "!", "-e", "/tmp/m3a-raw"])[0] == 0
    good = raw_exec(identifier, ["pwd"], options=options_frame("/tmp"))
    assert outcome(receive(good))[:5] == (1, 1, 2, 0, 0)
    good.close()
    # Operation 5 is classified busy from its header like operation 4.
    active = raw_exec(identifier, ["sh", "-c", "sleep 1"])
    busy = raw_exec(identifier, ["true"], options=options_frame("/tmp"))
    assert outcome(receive(busy))[5:7] == (5, 1)
    busy.close()
    assert outcome(receive(active))[0] == 1
    active.close()


def run_old_pid1():
    """A PID 1 without 0x20 is refused before the new CLI sends any exec."""
    if OLD_KILN is None:
        print("SKIP: old PID 1 refusal (no older kiln given)")
        return
    old = subprocess.check_output([OLD_KILN, "create", "--require-exec-protocol=1", "--memory", "64M",
                                   "--pids", "32", "--disk", "16M"], timeout=10).decode().strip()
    try:
        assert not features(caps(old)) & EXEC_OPTIONS
        rc, status, out, err, diag = machine(old, ["sh", "-c", "echo ran; touch /tmp/m3a-ran"],
                                             options=options_frame("/tmp", [("A", "1")]))
        assert (rc, outcome(status), out, err) == (125, (2, 0, 1, 0, 0, 4, 13, 0), b"", b""), (rc, outcome(status))
        # Plain operation 4 from the new CLI still works on the old PID 1, and
        # proves the refused command never ran.
        rc, status, out, err, diag = machine(old, ["test", "!", "-e", "/tmp/m3a-ran"])
        assert rc == 0 and outcome(status)[4] == 0
    finally:
        subprocess.run([OLD_KILN, "rm", old], check=True, timeout=15)


def run():
    caps()
    rejected = subprocess.run([KILN, "create", "--require-exec-protocol=2"], capture_output=True, timeout=5)
    assert rejected.returncode != 0 and rejected.stdout == b""
    identifier = subprocess.check_output([KILN, "create", "--require-exec-protocol=1", "--memory", "64M",
                                          "--pids", "32", "--disk", "16M"], timeout=10).decode().strip()
    try:
        caps(identifier)
        for code in (125, 126, 127, 143):
            rc, status, out, err, diag = machine(identifier, ["sh", "-c", f"printf 'o\\000\\377'; printf 'e\\000\\376' >&2; exit {code}"])
            assert outcome(status) == (1, 1, 2, 0, code, 0, 0, 0)
            assert (rc, out, err, diag) == (code, b"o\0\xff", b"e\0\xfe", b"")
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "kill -TERM $$"])
        assert outcome(status) == (1, 2, 2, 0, 15, 0, 0, 0) and rc == 143
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "kill -PIPE $$"])
        assert outcome(status) == (1, 2, 2, 0, 13, 0, 0, 0) and rc == 141
        for signal in (34, 64):
            rc, status, out, err, diag = machine(identifier, ["sh", "-c", f"kill -{signal} $$"])
            assert outcome(status) == (1, 2, 2, 0, signal, 0, 0, 0) and rc == 128 + signal
        rc, status, out, err, diag = machine(identifier, ["/no/such/executable"])
        assert outcome(status) == (2, 0, 2, 0, 0, 6, 8, 2) and rc == 127
        assert out == err == b"", "bootstrap diagnostic leaked into command streams"
        fake = b"KILNEXO\0\x01\0\x01\0\x18\0\0\0" + struct.pack("<BBBBiHHiII", 1, 1, 2, 0, 0, 0, 0, 0, 0, 0)
        octal = "".join(f"\\{byte:03o}" for byte in fake)
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", f"printf '{octal}'; printf '{octal}' >&2; exit 125"])
        assert outcome(status)[4] == 125 and out == err == fake
        rc, status, out, err, diag = machine(identifier, ["printf", "%s", "--protocol=99", "--status-fd=1"])
        assert out == b"--protocol=99--status-fd=1" and outcome(status)[4] == 0
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "for f in /proc/self/fd/*; do [ -e \"$f\" ] || continue; [ \"${f##*/}\" -lt 3 ] || exit 91; done; test ! -r /proc/1/fd/3"])
        assert rc == 0 and outcome(status)[4] == 0
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "test ! -r /proc/1/fd/3"])
        assert outcome(status)[4] == 0
        rc, status, out, err, diag = machine(identifier, ["sh", "-c", "printf unexpected"], version=2)
        assert rc == 125 and outcome(status)[5:7] == (4, 1) and out == err == b""
        active = raw_exec(identifier, ["sh", "-c", "sleep 1"])
        caps(identifier)
        busy = raw_exec(identifier, ["true"])
        assert outcome(receive(busy))[5:7] == (5, 1)
        busy.close()
        assert outcome(receive(active))[0] == 1
        active.close()
        for broken in ("disconnect", "nonreader"):
            rc, _, out, err, diag = machine(identifier, ["sh", "-c", "printf kept; printf evidence >&2"], broken_status=broken)
            assert rc == 125 and (out, err) == (b"kept", b"evidence") and diag
            assert outcome(machine(identifier, ["true"])[1])[4] == 0
        # PID 1 peer-close/EPIPE and unread-small-response recovery. Leaving a
        # 40-byte reply unread does not force backpressure; the isolated Rust
        # protocol fixture fills the send buffer to EAGAIN deterministically.
        for _ in range(10):
            raw_exec(identifier, ["true"], allow_early_close=True).close()
        peer = raw_exec(identifier, ["true"], allow_early_close=True)
        time.sleep(0.1)
        assert outcome(machine(identifier, ["true"])[1])[4] == 0
        peer.close()
        run_options(identifier)
    finally:
        subprocess.run([KILN, "rm", identifier], check=True, timeout=15)
    limited = subprocess.check_output([KILN, "create", "--require-exec-protocol=1", "--memory", "64M",
                                       "--pids", "1", "--disk", "16M"], timeout=10).decode().strip()
    try:
        rc, status, out, err, diag = machine(limited, ["true"])
        assert outcome(status) == (2, 0, 1, 0, 0, 6, 5, errno.EAGAIN) and rc == 125
        assert out == err == b""
        caps(limited)
    finally:
        subprocess.run([KILN, "rm", limited], check=True, timeout=15)
    run_old_pid1()
    print("PASS: typed exec v1, real-time signals, bootstrap, spoofing, compatibility, status backpressure, control peer-close/unread, recovery, exec options")


if __name__ == "__main__":
    run()
