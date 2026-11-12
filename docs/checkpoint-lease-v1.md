# Checkpoint lease and source contract v1

This is the runtime half of workspace checkpoints: what kiln guarantees about
a source sandbox while a checkpoint is captured. Capture itself (walking and
copying the upper layer) is not part of it. The pieces are:

- **Operation 6, `CheckpointLease`,** advertised by capability bit 6
  (`0x40`). While a lease is held, PID 1 runs no command.
- **`kiln checkpoint-lease`,** the CLI a manager drives to hold one.
- **Pinned overlay options,** read back from the kernel into run metadata.
- **Image content identity** in run metadata ([image-identity-v1.md](image-identity-v1.md)).
- **The protected-path contract** a capture must respect.

It extends [exec-protocol-v1.md](exec-protocol-v1.md). Operations 1 to 5,
their bytes, their replies and their goldens are unchanged. Every integer
below is little endian.

## Operation 6 request

The eight-byte request header with operation 6, zero reserved bytes and
body length 0, with no descriptors:

```text
06000000 00000000
```

A nonzero length, a descriptor, a nonzero reserved byte or a body closes the
connection with no reply. Header framing has the same two-second absolute
deadline as every idle request.

## Lease frames (reply type 3)

Lease state uses the protocol's 16-byte `KILNEXO\0` reply header with type 3
and a 16-byte payload:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 1 | State: 1 Granted, 2 Released |
| 1 | 7 | Reserved, zero |
| 8 | 8 | LE u64 lease generation, nonzero |

Unknown states, nonzero reserved bytes, generation 0 and any other payload
length are rejected. Generations start at 1 for each PID 1 and increase with
every lease it grants. A generation names a lease; it isn't a secret or a
boot identity.

```text
Granted, generation 1 (32 bytes):
4b494c4e45584f00 0100 0300 10000000  01 00000000000000 0100000000000000

Released, generation 0x0102030405060708, payload:
02 00000000000000 0807060504030201
```

A refusal is an ordinary type 1 outcome frame (below). Decoders that predate
type 3 reject it as an unknown type; they never send operation 6, so they
never receive one.

## Acknowledgment record

The holder sends exactly one 16-byte record, and only after its last read of
the source: `KILNACK\0`, then the LE u64 generation it was granted.

```text
generation 1: 4b494c4e41434b00 0100000000000000
```

## PID 1 state machine

```text
          op 6, idle, quiescent            ack(g) valid, framed in 2 s
  IDLE ─────────────────────────► LEASED ───────────────────────────► IDLE
   │  send Granted(g)               │  recheck quiescent, send Released(g)
   │                                │
   │  op 6, busy ─► Busy outcome    ├─ holder EOF, reset or half-close ──► IDLE
   │  op 6, not quiescent ─►        ├─ malformed, trailing or wrong-g ack ► IDLE
   │    CleanupFailed outcome,      ├─ partial ack older than 2 s ───────► IDLE
   │    PID 1 stops                 ├─ op 2 (kiln rm) ─► ack remover, stop
   │                                └─ forwarded signal ─► stop
```

- **Grant.** PID 1 grants only from idle, after draining queued signals as
  exec admission does. It proves the sandbox quiescent by reading the exec
  cgroup's `cgroup.events` (`populated 0`) and by `waitpid(-1, WNOHANG)`
  returning `ECHILD`. Every process in the sandbox's PID namespace descends
  from PID 1, and orphans are reparented to it, so having no child means PID 1
  is alone. Exited children are reaped on the way. If the idle sandbox is not
  quiescent, PID 1 replies `CleanupFailed`, stage 15 (Lease), and stops: under
  the existing cleanup rule it never admits work beside possible leftovers.
- **While leased.** PID 1 serves no command. New connections are classified
  from their fixed header, as during an exec. Operation 3 gets capabilities.
  Operations 4 and 5 get `Busy`, stage Validate, `NoChildStarted`, with the
  diagnostic `a checkpoint lease is held`. Operation 1 gets its i32 125.
  Operation 6 gets `Busy`, stage 15. Their descriptors close before the reply,
  and no body is read. Operation 6 during an exec gets `Busy`, stage 15, with
  `another exec is active`.
- **No timer.** The lease lives as long as the holder's connection. PID 1 has
  no lease deadline, so a holder still reading the source is never released
  underneath. The only deadline is framing: an acknowledgment must complete
  within two seconds of its first byte. A holder sends it only after it has
  finished reading, so that window can't cut a read short.
- **Release.** A complete, valid record naming this lease's generation makes
  PID 1 recheck quiescence, then send Released with the same generation and
  close. Released certifies that no command ran between Granted and Released.
- **Every other end is without success.** These end the lease with no Released:
  - the holder dies, closes, resets or half-closes before acknowledging;
  - a malformed, trailing, generation-0 or wrong-generation acknowledgment;
  - a removal or a forwarded stop signal.
  The holder sees EOF or a reset where Released should be.
- **Queued requests.** As after an exec, requests queued during the lease
  are refused as busy when it ends. A queued removal still wins.

The holder must not half-close before acknowledging: for a lease, a
half-close means abandonment. This differs from exec requests, which may
half-close after a complete request.

## `kiln checkpoint-lease`

```text
kiln checkpoint-lease --protocol=1 --status-fd=N ID
```

`N` is a private, connected, anonymous Unix stream socketpair end (the same
checks as machine exec's status descriptor). The command runs no sandbox
command and never reads or copies sandbox files. The status socket is two-way:

1. Before contacting PID 1, the CLI reads the run's metadata. A run without an
   image identity or a verified layout record is refused (below).
2. It probes PID 1 with operation 3 on its own connection. Without bit 6, or
   without protocol 1, it refuses and sends nothing else.
3. It sends operation 6. A *failure* outcome from PID 1 is forwarded as the
   final frame. A command outcome (`FailureKind` None) where a lease frame
   belongs, before Granted or after the acknowledgment, is a protocol
   violation, Protocol / 15 Lease. It is never forwarded as success.

   While the probe reply and the grant are pending, the CLI watches the status
   socket too. The driver closing it, or writing anything before Granted,
   abandons the wait at once. Otherwise the wait has no timer, so a request
   queued behind PID 1's valid work still waits for it.
4. On a grant it writes the Granted frame to the status socket. That frame is
   readiness: the source is quiescent and stays so.
5. It waits, with no timer, for the driver's 16-byte acknowledgment on the
   status socket. A valid record naming the granted generation is forwarded
   byte for byte to PID 1. The CLI then requires Released for the same
   generation, plus EOF, within two seconds, and writes Released as the final
   frame.
6. If the driver closes the status socket, or PID 1's connection shows
   anything before the acknowledgment (EOF, a reset or data), the lease is
   lost. A malformed, wrong-generation or incomplete acknowledgment
   (incomplete for more than two seconds after its first byte) closes the
   lease connection. Each of these writes one final outcome frame.

The status stream is therefore one frame (a refusal or failure) or two frames
(Granted, then Released or a failure). Exit status is 0 only when the final
frame is Released for the granted generation; every other final frame,
including any outcome, is 125. The frames are the authority; the exit status is
a consistency check.

| Failure | Kind / stage | Cleanup |
|---|---|---|
| Unsupported run or PID 1 | Incompatible / 13 Handshake, diagnostic `sandbox_unsupported:workspace_checkpoint: …` | NoChildStarted |
| Bad arguments / protocol version | InvalidRequest or Incompatible / 1 Validate | NoChildStarted |
| Run missing / connect failed | NotFound or Unavailable / 2 Connect | NoChildStarted |
| Probe failed after connecting | Protocol / 13 Handshake | NoChildStarted |
| Sending operation 6 failed | Io / 3 Request | NoChildStarted |
| Lease busy | Busy / 15 Lease (from PID 1) | NoChildStarted |
| Lease lost (driver or PID 1 gone) | Stopped / 15 Lease | NoChildStarted |
| Bad acknowledgment from the driver | InvalidRequest / 15 Lease | NoChildStarted |
| Malformed grant or release, or a command outcome in place of one | Protocol / 15 Lease | NoChildStarted |
| Driver gone while the probe or grant was pending | Protocol / 13 Handshake or 15 Lease | NoChildStarted |

The driver owns cancellation: it closes the status socket or kills the CLI.
When the CLI dies, its lease connection closes and PID 1 ends the lease. A
driver that reads no Released has no successful lease, whatever the exit
status says. A capture built on this command publishes success only after
Released, and only if every source read happened between Granted and the
acknowledgment.

## Run metadata

Two files in `/var/lib/kiln/runs/<id>/`, both root-only (0600 in a 0700
directory), written before the sandbox is reported created:

- `image`: the run's image reference ([image-identity-v1.md](image-identity-v1.md)).
- `layout`: the overlay options read back from the kernel, and the entries
  the runtime generates in the upper.

```text
kiln-layout 1
pinned index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off
defaults index=N metacopy=N nfs_export=N redirect_dir=N redirect_always_follow=Y
super rw,lowerdir=<lower>,upperdir=<upper>,workdir=<work>,redirect_dir=nofollow,uuid=on,nouserxattr
effective index=off metacopy=off nfs_export=off redirect_dir=nofollow uuid=on nouserxattr
verified yes
generated /etc/resolv.conf
```

`verified no REASON` replaces the last line (and possibly `defaults`, `super`
and `effective`) when the options couldn't be proven. Keys are strict and
unique, except `generated`, which repeats.

Both files are published by rename without an fsync on the create path. A
crash can lose them, but losing one only fails closed: a run with no image
reference blocks image removal as unknown, and a run with no layout record is
not a checkpoint source. A run is a **checkpoint source** only when `image`
holds an identity and `layout` says `verified yes`. Runs created before this
version have neither file. They keep working for everything else and are
refused with `sandbox_unsupported:workspace_checkpoint`.

## Pinned overlay options

Every new run, persistent or one-shot, mounts its overlay with
`index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off` appended to its
layer options. kiln pins them for all creates rather than an opt-in subset:

- **They change nothing for ordinary use.** On the supported kernel (Ubuntu
  24.04, 6.8) the module defaults are `index=N metacopy=N nfs_export=N
  redirect_dir=N redirect_always_follow=Y`. So index, metacopy and NFS export
  were already off, and redirects were already never created.
- **The one difference is following.** The default redirect mode is
  `follow`. Pinning `nofollow` also stops the kernel following a redirect it
  finds in a layer. kiln's layers contain none: the upper starts empty, and
  images are unpacked without overlay xattrs.
- **On other hosts** whose defaults create redirects or metacopy files,
  pinning keeps directory renames of lower directories returning `EXDEV`.
  That is permitted by POSIX, and `mv` and similar tools already handle it.

The options are validated as **effective**, not as requested:

1. After mounting, PID 1's setup (still real root, before `pivot_root`) finds
   its mount by `statx(STATX_MNT_ID)` in `/proc/self/mountinfo`.
2. OverlayFS shows a feature only when it differs from the module default, so
   the effective value is the shown option or, if absent, the
   `/sys/module/overlay/parameters` value. The parameters are read before and
   after mountinfo and must agree.
3. The three layer paths must be the run's own.
4. Only `rw`, the layers, `index`, `metacopy`, `nfs_export`, `redirect_dir`,
   `xino`, `uuid` and `nouserxattr` are recognized. Ubuntu's 6.8 kernel shows
   `nouserxattr` on every overlay; it confirms the metadata lives in
   `trusted.overlay.*`. Any other option, such as `userxattr`,
   `volatile` or `default_permissions`, or a duplicate, makes the mount
   unverifiable.

The result is recorded in `layout`. A run whose options don't verify still
runs normally; it just isn't a checkpoint source.

### What the upper holds under the pins (measured)

These forms were measured on Ubuntu 24.04, kernel 6.8.0-147, with an ext4
image lower and an XFS upper. Pinned and default mounts wrote identical
uppers.

- **Whiteouts** are character devices 0:0. No xattr-form whiteouts appeared.
- **Opaque directories** carry `trusted.overlay.opaque=y`. Some newly created
  upper directories carry it too. The `x` form never appeared.
- **Copied-up entries** always carry `trusted.overlay.origin`, a file handle
  for the lower inode. This happens even with `index=off` and
  `nfs_export=off`: `uuid=off` only zeroes the UUID inside the handle, and no
  option removes it.
- **Copied-up directories** carry `trusted.overlay.impure=y`. The upper root
  carries `trusted.overlay.uuid` when `uuid=on`, the effective default here.
- **No redirects or metacopy.** No `redirect` or `metacopy` xattr appeared.
  Renaming a lower directory fails with `EXDEV`; `mv` then copies, which
  leaves a whiteout and a plain new directory.

A capture format must therefore account for `origin`, `impure` and `uuid`.
They are kernel bookkeeping for inode-number stability and readdir, not
sandbox data.

## Protected paths

`runtime/src/protected.rs` is the contract a capture enforces, as data and
functions. kiln's setup code takes its mount targets from the same constants.
`kiln checkpoint-contract [--dns]` (hidden) prints it:

```text
kiln-protected-paths 1
mount /            mount /dev        mount /dev/null   mount /dev/zero
mount /dev/full    mount /dev/random mount /dev/urandom mount /dev/tty
mount /dev/shm     mount /proc       mount /sys/fs/cgroup
target /dev        target /proc      target /sys/fs/cgroup
ancestor /         ancestor /sys     ancestor /sys/fs
generated /etc/resolv.conf                      (with --dns only)
excluded /dev  excluded /dev/shm  [excluded /etc/resolv.conf]  excluded /proc  excluded /sys/fs/cgroup
```

(The real output has one item per line.) `protected::check(path, kind,
generated)` classifies one raw-upper entry:

| Path | Rule | Allowed in the upper |
|---|---|---|
| A mount target or ancestor (`/`, `/sys`, `/sys/fs`, `/dev`, `/proc`, `/sys/fs/cgroup`) | Scaffold | A plain, non-opaque directory: directory metadata only. A symlink, whiteout, other type or opaque flag is `checkpoint_layout_unsupported`. |
| Beneath a mount target | Shadowed | Nothing. Those trees are covered by runtime mounts; anything there is refused. |
| A generated entry (`/etc/resolv.conf` when the run's network has DNS) | Generated | Excluded whatever it is; the new sandbox regenerates it. It is the one entry expected to be owned by host root. |
| The parent of a generated entry (`/etc`) | GeneratedParent | A directory, opaque allowed. A symlink or other type is refused. |
| Everything else | Ordinary | Sandbox data, subject to the capture format's own rules. |

`generated` comes from the run's `layout` record, since a run without DNS
leaves `/etc/resolv.conf` to the sandbox. `protected::writable_overlaps_reserved`
says whether a requested writable path equals, contains or lies beneath a
mount target or generated entry; checkpoint-capable fork specs must refuse
those. `/dev/shm` is tmpfs default scratch and is always excluded.

## Tests

- **Rust goldens:**
  - `exec_protocol.rs`: lease frames, acknowledgment, stage 15, single-frame
    reads at every split.
  - `persistent.rs`: operation 6 request bytes, with operation 4 unchanged.
  - `overlay.rs`: effective-option interpretation, mountinfo escapes, the
    layout record.
  - `protected.rs`: every rule.
- **PID 1 fixture tests** (`init.rs`):
  - Grant, busy refusal of operations 1, 4, 5 and 6, probes, and no release
    after more than two framing windows.
  - Release, increasing generations, holder death and half-close.
  - Malformed, trailing, wrong-generation and stalled acknowledgments.
  - Lease refused during an exec; removal and SIGTERM during a lease;
    refusal and stop when not quiescent; malformed operation 6 requests.
  - The feature probe waiting behind stalled connections the way operation 4
    does.
- **CLI tests** (`persistent.rs`): host failures on the private status
  socket, the metadata gate, and the hold loop against a scripted PID 1 and
  driver.
- **`scripts/checkpoint-regressions.py`** covers the same behavior in real
  sandboxes:
  - the lease against direct `kiln exec`;
  - the old-PID-1 refusal before any lease byte;
  - recorded effective options;
  - real mounts and a fresh upper against the contract;
  - image registration, references and refused replacement.
