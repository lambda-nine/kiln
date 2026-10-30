#!/usr/bin/env python3
"""Installed-path typed exec acceptance; run as root on the prepared Linux VM."""
import array
import errno
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


KILN = sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/kiln"


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


def caps(identifier=None):
    args = [KILN, "capabilities", "--protocol=1"]
    if identifier:
        args.append(identifier)
    p = frame(subprocess.check_output(args, timeout=5), 2)
    features, control, status, package, provenance, reserved = struct.unpack("<IHHHHI", p[:16])
    assert features & 15 == 15 and (control, status, reserved) == (1, 1, 0)
    assert package <= 64 and provenance <= 128 and len(p) == 16 + package + provenance
    p[16:].decode("utf-8")
    return p


def machine(identifier, args, version=1, broken_status=None):
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
        command = [KILN, "exec", f"--protocol={version}", f"--status-fd={descriptors[0]}",
                   f"--stdin-fd={descriptors[1]}", f"--stdout-fd={descriptors[2]}",
                   f"--stderr-fd={descriptors[3]}", identifier, "--", *args]
        child = subprocess.Popen(command, pass_fds=descriptors, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status_tx.close()
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


def raw_exec(identifier, args):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    client.connect(f"/var/lib/kiln/runs/{identifier}/control.sock")
    payload = struct.pack("<I", len(args))
    for arg in args:
        arg = arg.encode()
        payload += struct.pack("<I", len(arg)) + arg
    with open("/dev/null", "r+b") as null:
        rights = array.array("i", [null.fileno()] * 3)
        client.sendmsg([struct.pack("<B3xI", 4, len(payload))], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
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
            raw_exec(identifier, ["true"]).close()
        peer = raw_exec(identifier, ["true"])
        time.sleep(0.1)
        assert outcome(machine(identifier, ["true"])[1])[4] == 0
        peer.close()
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
    print("PASS: typed exec v1, real-time signals, bootstrap, spoofing, compatibility, status backpressure, control peer-close/unread, recovery")


if __name__ == "__main__":
    run()
