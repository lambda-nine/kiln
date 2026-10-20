# Persistent-exec protocol v1

Protocol v1 is first supplied by the kiln commit introducing this document,
based on baseline `3b425525ba48cdfa1830fce3f7616a945136624b` (`3b42552`).
The commit is identified externally after committing; embedding its own hash
would change it. Capability negotiation, rather than a package version or
sortable commit string, is the compatibility gate.

## Requests

Each root-only Unix control connection carries one request and one reply.
The request header is eight bytes: operation u8, three zero reserved bytes,
body length u32. Operations 1 (legacy exec) and 2 (remove) retain their
native-endian lengths, argv and i32 replies. Operations 3 (capabilities) and
4 (typed exec) use little endian throughout. No machine client falls back to
operation 1 or interprets an i32 legacy reply.

Operation 3 has zero body length and no descriptors. Operation 4 requires
exactly three descriptors (stdin, stdout, stderr) in one SCM_RIGHTS message
attached to the header. Its body is argc u32 followed by each argument's byte
length u32 and those bytes, without a terminator. Require 1–4096 arguments,
no NUL bytes, no trailing body bytes, and a total body at most 1 MiB.
Descriptors attached to a body, unexpected ancillary messages, ancillary
truncation and invalid reserved/header fields are rejected and closed.
One absolute two-second signal-aware receive deadline covers header and body.
A complete request may half-close its write side while retaining its reader;
a full close cancels an active exec. A busy exec returns a failure for that
request; capability probes remain available while an exec runs.

## Reply framing

All operation 3/4 replies and CLI machine status use this 16-byte header:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | `4b 49 4c 4e 45 58 4f 00` (`KILNEXO\0`) |
| 8 | 2 | LE u16 version, exactly 1 |
| 10 | 2 | LE u16 type: 1 outcome, 2 capabilities |
| 12 | 4 | LE u32 payload length, at most 2072 |

The largest frame is 2088 bytes. A connection ends after exactly one frame.
Require EOF; reject missing, truncated, malformed, unsupported-version,
duplicate or trailing responses. Reject oversized lengths before allocation.
An exec may run arbitrarily long before the first reply byte. Once framing
begins, the entire frame and EOF have one two-second deadline. Capability
probes instead have an absolute two-second exchange deadline. Response writes
handle partial writes, EINTR and EAGAIN, use nonblocking send with SIGPIPE
suppressed, and stop within two seconds or when signals need servicing.
A disconnected or non-reading peer is a request-local failure. A lost reply
does not prove a command result: receivers report missing/truncated control
response and perform their cleanup barrier when needed.

## Outcome payload (type 1)

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 1 | Outcome: 1 command, 2 runtime failure |
| 1 | 1 | Termination: 0 unobserved, 1 exited, 2 signaled |
| 2 | 1 | Cleanup: 0 unconfirmed, 1 no child started, 2 drained |
| 3 | 1 | Flags: bit 0 core dumped, bit 1 diagnostic truncated |
| 4 | 4 | LE i32 exit code or signal; zero if unobserved |
| 8 | 2 | LE u16 failure kind |
| 10 | 2 | LE u16 stage |
| 12 | 4 | LE i32 errno: zero absent, otherwise positive |
| 16 | 4 | LE u32 diagnostic byte length, at most 2048 |
| 20 | 4 | Reserved, zero |
| 24 | variable | Diagnostic UTF-8, without terminator |

Failure kinds: 0 None, 1 InvalidRequest, 2 Unavailable, 3 NotFound,
4 Incompatible, 5 Busy, 6 LaunchFailed, 7 Io, 8 Protocol, 9 CleanupFailed,
10 Internal, 11 Stopped.

Stages: 0 None, 1 Validate, 2 Connect, 3 Request, 4 Prepare, 5 Fork,
6 Admission, 7 Stdio, 8 Exec, 9 Wait, 10 Cleanup, 11 Report, 12 Capture,
13 Handshake. Release failures use Admission; signal preparation uses Stdio.

A command requires observed termination, drained cleanup and all diagnostic
fields zero/empty. Exit codes are 0–255 and Linux signals 1–64. Core dumped
is valid only with signal termination. A runtime failure requires a nonzero
failure kind and may retain observed termination after a later failure.
Observed termination contradicts no-child-started. Reject unknown enum/flag
values, nonzero reserved bytes, negative errno, invalid UTF-8, inconsistent
lengths and contradictory fields. Diagnostic truncation preserves UTF-8
boundaries and sets its flag. A busy reply's no-child-started applies only to
the rejected request and says nothing about another active exec's cgroup.

PID 1's CLOEXEC bootstrap channel carries trusted Joined/error records until
exec closes it. Pipe/fork failures use Prepare/Fork with no child started;
admission/release, stdio/signal preparation, and exec failures are LaunchFailed
with their stage and errno. Bootstrap messages never enter workload stderr.
Every path after fork kills the direct child if necessary, drains the exec
cgroup and reaps before publication. Failed cleanup retains observed command
termination, reports CleanupFailed/unconfirmed, and stops PID 1 rather than
admitting another command beside possible leftovers.

Golden exit-125 frame (40 bytes, hex):

```text
4b494c4e45584f00 0100 0100 18000000
01010200 7d000000 0000 0000 00000000 00000000 00000000
```

## Capability payload (type 2)

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 4 | LE u32 feature bits |
| 4 | 2 | LE u16 typed control version |
| 6 | 2 | LE u16 private status/stdio version |
| 8 | 2 | LE u16 package-version byte length (at most 64) |
| 10 | 2 | LE u16 provenance byte length (at most 128) |
| 12 | 4 | Reserved, zero |
| 16 | variable | Package string then provenance string, UTF-8 |

Required feature bits are bit 0 typed control, bit 1 private machine stdio
and status, bit 2 descendant drainage, bit 3 signal-aware request framing
(mask `0x0000000f`). Unknown additional bits can be ignored. Require all four
bits and both versions equal to 1. Package and provenance are diagnostic
evidence only. PID 1 returns its own build information, which can differ from
the installed CLI after an upgrade.

Golden capabilities for package `0.1.0` and provenance `git test`:

```text
4b494c4e45584f00 0100 0200 1d000000
0f000000 0100 0100 0500 0800 00000000 302e312e30 6769742074657374
```

## CLI transport and compatibility

```text
kiln capabilities --protocol=1 [ID]
kiln create --require-exec-protocol=1 [other create options]
kiln exec --protocol=1 --status-fd=N --stdin-fd=I --stdout-fd=O --stderr-fd=E ID -- ARGV...
```

Capabilities writes one binary frame to stdout: installed CLI provenance
without ID, that sandbox PID 1's capabilities with ID. An unsupported create
requirement fails before resource creation. Existing incompatible PID 1
instances require explicit recreation; upgrading the CLI cannot upgrade them.
Old binaries reject the new required flags/operations before workload launch.

Machine exec requires all four private FDs, distinct numbers at least 3, a
Unix stream status socket, readable stdin and writable stdout/stderr. Status
must not alias a workload stream, including duplicated handles to the same
socket. Terminal workload FDs remain forbidden. Inherited FDs regain CLOEXEC;
only I/O/E cross SCM_RIGHTS, and CLI copies close after transfer. Status closes
after exactly one typed frame, including structured host validation/connect/
request/protocol failures. An invalid status FD itself cannot carry a frame.
CLI stderr remains a separate diagnostic stream, also for argument-parser,
loader or panic failures. Callers should bound that diagnostic capture.

Workloads cannot forge outcomes by printing frames or passing flag-like argv
after `--`: status never reaches PID 1 or the workload. Bootstrap closes the
control listener, client, signalfd and cgroup handles before workload exec;
PID 1 remains nondumpable, protecting `/proc/1/fd` access. No status files or
output trailers exist. PID 1 captures neither output nor counts; the caller's
stream readers are the count authority.

Human exec remains operation 1 with its shell exit projection: command exit
code, 128 + signal, 125 infrastructure, 126 admission/release/stdio bootstrap,
127 execvp. Real command exits 125/126/127 are command outcomes in protocol v1.
The CLI process exit is a projection/consistency check, never machine status
authority. If the private receiver disconnects or refuses to read, the CLI
reports a diagnostic and exits 125; PID 1 remains usable.

Tests: Rust golden vectors, every split, invalid frames, bounded writes,
test-only bootstrap fault injection and a separate protocol server fixture;
`scripts/typed-exec-regressions.py` for real installed-path cgroup acceptance,
invoked by `scripts/review-regressions.sh`. No bootstrap injection hooks are
compiled into shipped binaries.
