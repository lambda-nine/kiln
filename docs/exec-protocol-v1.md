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
native-endian lengths, argv and i32 replies. Operations 3 (capabilities),
4 (typed exec) and 5 (typed exec with options) use little endian throughout.
No machine client falls back to operation 1 or interprets an i32 legacy reply.

Operation 3 has zero body length and no descriptors. Operation 4 requires
exactly three descriptors (stdin, stdout, stderr) in one SCM_RIGHTS message
attached to the header. Its body is argc u32 followed by each argument's byte
length u32 and those bytes, without a terminator. Require 1–4096 arguments,
nonempty `argv[0]`, no NUL bytes, no trailing body bytes, and a total body at
most 1 MiB. The body size is `4 + sum(4 + UTF-8 byte length)`. Unicode,
newlines, other non-NUL controls, later empty arguments and flag-like values
are literal argv data.
Operation 5 is operation 4's argv block, with the same bounds, followed by
one exec options frame (below) that ends the body; its total body is at most
1 MiB + 40 KiB. It has operation 4's descriptors, replies and busy handling.
Operation 4's bytes are unchanged; a caller with no cwd and no environment
overrides keeps using it.
Descriptors attached to a body, unexpected ancillary messages, ancillary
truncation and invalid reserved/header fields are rejected and closed.
One absolute two-second signal-aware receive deadline covers header and body.
A complete request may half-close its write side while retaining its reader;
a full close cancels an active exec. While busy, both legacy and typed execs
are classified from the fixed header: their descriptors close before a busy
reply is sent, and no refused body is read. A partial body cannot delay a
queued removal. Linux may close this socket with `ECONNRESET` because the
refused request body is unread: only a complete, validated Busy frame with
no child started is accepted before that reset. All other resets, truncated
frames and trailing bytes remain protocol failures. Clients also read this
acknowledgement if the early refusal interrupts their body write.
Capability probes remain available while an exec runs.

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
13 Handshake, 14 Chdir. Release failures use Admission; signal preparation
uses Stdio. Chdir occurs only for operation 5, so decoders that predate it
never receive it from requests they send.

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
admission/release, stdio/signal preparation, cwd and exec failures are
LaunchFailed with their stage and errno. Bootstrap messages never enter workload stderr.
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

Bit 4 (`0x00000010`) advertises **persistent-create preflight certainty** in
this build. It is additive to the four required exec bits and does not change
exec protocol v1 or older PID 1 compatibility. Machine managers that rely on
create certainty must require this bit from the installed CLI before create.
`kiln create` returns **124**, with empty stdout, only when validation, missing
image or another preflight failure occurred before `container::new_id` and
before any sandbox allocation. CLI syntax/configuration failures are included;
help/version keep exit 0. Success still prints exactly the new sandbox ID.
Every other nonzero exit, signal, timeout, missing result or malformed output
is allocation-ambiguous. Human stderr text is never an absence signal. This
contract applies only to persistent `create`, not `run` or `exec`.

Bit 5 (`0x00000020`) advertises **exec options**: PID 1 accepts operation 5
and the CLI accepts `--exec-options-fd`. It is additive like bit 4: PID 1
instances without it still serve operation 4, and the CLI refuses options
against them before sending any exec byte (below). This build advertises
`0x3f`.

Golden capabilities for package `0.1.0` and provenance `git test`:

```text
4b494c4e45584f00 0100 0200 1d000000
0f000000 0100 0100 0500 0800 00000000 302e312e30 6769742074657374
```

## Exec options (operation 5)

The options frame carries a working directory and environment overrides for
one command. All integers are little endian; lengths count bytes.

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | `4b 49 4c 4e 4f 50 54 00` (`KILNOPT\0`) |
| 8 | 2 | LE u16 version, exactly 1 |
| 10 | 2 | Reserved, zero |
| 12 | 4 | LE u32 frame length, header included; equals the bytes present |
| 16 | 4 | LE u32 cwd length, 0–4096; 0 means no cwd |
| 20 | 4 | LE u32 environment entry count, 0–64 |
| 24 | variable | cwd bytes, then each entry: u32 name length, name, u32 value length, value |

Rules, enforced by the CLI and again by PID 1 (a frame is valid only if all
hold; there are no defaults or repairs):

- At least 24 and at most 40,960 bytes; no trailing bytes after the last
  entry, and the length field must match.
- cwd, when present: starts with `/`, at most 4,096 bytes, no NUL, UTF-8. It
  is not normalized: `..` and symlinks resolve inside the sandbox's own root.
- Names: 1–128 bytes matching `[A-Za-z_][A-Za-z0-9_]*`. Values: at most 4,096
  bytes of UTF-8 without NUL; empty is allowed. The sum of
  `len(name) + len(value) + 2` over all entries is at most 32,768.
- Entries are strictly ascending by name bytes. Duplicates are therefore
  rejected rather than resolved, and every option set has exactly one
  encoding. There is no "unset".

Every frame within these bounds is at most 37,272 bytes, so the 40 KiB cap
only bounds reads. Golden frames (hex):

```text
no cwd, no entries (24 bytes):
4b494c4e4f505400 0100 0000 18000000 00000000 00000000

cwd "/w", entries A="" and B="2" (45 bytes):
4b494c4e4f505400 0100 0000 2d000000 02000000 02000000 2f77
01000000 41 00000000  01000000 42 01000000 32
```

Operation 4 and 5 requests for `argv = ["true"]`, the second with the 45-byte
frame above (header, then body):

```text
op 4: 04000000 0c000000  01000000 04000000 74727565
op 5: 05000000 39000000  01000000 04000000 74727565 <45-byte frame>
```

**Environment.** The command's environment is a fixed base overlaid by the
entries, an entry winning by name, `PATH` included, sorted by name bytes and
passed to `execve` as `NAME=VALUE`:

```text
HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TERM=xterm
```

The base is what PID 1 gives every command started under a cleared host
environment; operation 5 uses these constants, not PID 1's own environment.
Program lookup uses the C library's `execvp` rules with the effective `PATH`,
and relative names resolve in the new cwd. Sorting is by name, so `A` precedes
`A0` although `A=` sorts after `A0=`.

**Launch order.** The forked child runs exactly: cgroup admission; close the
cgroup handles; `dup2` stdio; `setpgid`; close every descriptor except stdio
and the bootstrap channel; reset the signal mask and `SIGPIPE`; then
`chdir(cwd)`; then `execvp`. When `chdir` runs no inherited directory
descriptor is left, so `/proc/self/fd/N` cannot name one, and PID 1 is
nondumpable, so `/proc/1/cwd` is refused. A failed `chdir` is reported over
the bootstrap channel as LaunchFailed, stage 14 Chdir, with its errno (for
example ENOENT, ENOTDIR, EACCES, ELOOP, ENAMETOOLONG; a 4,096-byte cwd is
valid in the frame and fails here with ENAMETOOLONG), after the usual cgroup
drain, with cleanup Drained and PID 1 reusable. There is no fallback to `/`.
The human projection is 126. A LaunchFailed/Chdir/ENOENT payload begins
`02000200 00000000 0600 0e00 02000000`. PID 1 never applies the cwd or the
environment to itself, and a frame that fails PID 1's validation closes the
connection without a reply and without a child.

## CLI transport and compatibility

```text
kiln capabilities --protocol=1 [ID]
kiln create --require-exec-protocol=1 [other create options]
kiln exec --protocol=1 --status-fd=N --stdin-fd=I --stdout-fd=O --stderr-fd=E ID -- ARGV...
kiln exec --protocol=1 --status-fd=N --stdin-fd=I --stdout-fd=O --stderr-fd=E --exec-options-fd=P ID -- ARGV...
```

`--exec-options-fd=P` names a memfd holding one options frame, sealed with
exactly `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE` (not
`F_SEAL_FUTURE_WRITE` or `F_SEAL_EXEC`), readable, at least 3, distinct from
the other four descriptors and not the same file as a workload stream. The CLI
restores its CLOEXEC, reads it with `pread` under the 40 KiB bound, validates
the frame and closes it; the frame's bytes go into operation 5 unchanged. The
CLI never opens, stats or `chdir`s the path, and options never appear on a
command line. A bad descriptor or frame is InvalidRequest/Validate with no
child started. Before sending any exec byte the CLI probes the sandbox's PID 1
(operation 3, on its own connection): without bit 5 it reports
Incompatible/Handshake with no child started and sends nothing else; a probe
that fails after connecting is Protocol/Handshake.

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

Tests: Rust golden vectors (operation 4 pinned unchanged, operation 5 and
options frames), every split, invalid frames, every options bound and one
past it, seal and descriptor checks, chdir failures with errno and drainage,
`/proc/self/fd/N` for every descriptor PID 1 held and `/proc/1/cwd`, bounded writes,
test-only bootstrap fault injection and a separate protocol server fixture
that saturates PID 1's response socket to EAGAIN after cleanup and verifies
signal-aware recovery. `scripts/typed-exec-regressions.py` covers installed-path
cgroup acceptance, including real-time leader signals 34 and 64, exec options
in a real sandbox (and, given an older kiln as its second argument, refusal of
a PID 1 without bit 5 before sending), and is invoked by
`scripts/review-regressions.sh`. Its control peer-close/unread-small-response
checks do not force response backpressure. No fixture injection hooks are
compiled into shipped binaries.
