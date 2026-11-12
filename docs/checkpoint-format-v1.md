# Workspace checkpoint format v1

A checkpoint is a normalized copy of a persistent sandbox's **raw upper
layer**, taken while the source holds no running command (operation 6,
[checkpoint-lease-v1.md](checkpoint-lease-v1.md)). It is stored as a private
artifact of ordinary files: a canonical JSON manifest and one flat object per
regular-file inode. A new sandbox can be created from it: kiln rebuilds a
fresh, independent upper from the artifact before the new sandbox mounts
anything. Nothing is linked, cloned, mounted or shared between the source,
the artifact and any fork.

This document is the contract for the bytes on disk, the digests a client
can reproduce, the walker's refusals, and the capture and restore order.
It is consumed by the per-node daemon's helper; kiln itself has no policy
about who may capture or fork, or for how long an artifact lives.

> Status: experimental. kiln shares the host kernel and was reviewed
> adversarially by AI models, not audited. The format treats every byte of an
> upper and of an artifact as hostile input.

## Commands

All need root.

```text
kiln checkpoint capture --instance I --checkpoint C --generation G --max-bytes R ID
kiln checkpoint inspect --instance I --checkpoint C [--verify]
kiln checkpoint rm --instance I --checkpoint C
kiln checkpoint ls
kiln create --from-checkpoint I/C [the usual create options]
```

- `I` is the owning daemon's instance identity, 32 lowercase hex digits.
  `C` is `cp-` and 32 lowercase hex digits. `G` is the nonzero capture
  generation the artifact is bound to. `R` is the reservation in bytes
  (64 KiB to 1 TiB): the artifact's project quota and the largest charge
  capture accepts.
- `capture`, `inspect` and `rm` print one record on stdout and exit 0, or
  print a failure record and exit 125:

```text
kiln-checkpoint-failure 1
reason <token>
detail <one line, at most 512 characters>
```

- `capture` and `inspect` print:

```text
kiln-checkpoint-record 1
instance <I>
checkpoint <C>
generation <G>
content-sha256 <hex>
binding-sha256 <hex>
image <name>
image-sha256 <hex>
entries <N, root included>
logical-bytes <L>
allocated-bytes <A>
charge-bytes <S>
limit-bytes <R>
```

- `inspect` validates everything except object bytes; `--verify` also
  rehashes every object. `rm` prints `kiln-checkpoint-removed 1` and
  `existed yes|no`. `ls` prints `kiln-checkpoint-inventory 1` and one
  `published|staging|removing|unknown <instance or -> <name>` line per entry,
  and removes nothing.
- `kiln create --from-checkpoint` runs every check below before allocating
  anything (exit 124, the reason token at the start of the cause). A failure
  after allocation (a corrupt object found while copying, a full disk)
  removes the new run and reports `sandbox shim failed during setup: <token>: …`.

## Storage

```text
/var/lib/kiln/runs/.checkpoints/            0700 root
  <instance>/                               0700 root
    <checkpoint>/                           0700 root, its own XFS project quota (R)
      header                                0600
      objects/                              0700
        00000000, 00000001, …               0600, one per regular-file inode
      manifest.json                         0600
      complete                              0600
    .staging-<checkpoint>-<generation>-<nonce>/  a capture in progress or interrupted
    .removing-<checkpoint>-…/               a removal in progress or interrupted
```

- The namespace is inside the runs filesystem, so artifacts share its XFS
  project quotas. `kiln ls` and `kiln gc` skip `.checkpoints` explicitly,
  and it is never a valid sandbox ID.
- Every directory is root-owned with no group or other access; every file is
  0600 with one link. Readers check this and refuse anything else.
- Only validated IDs form paths. Every file inside an artifact is opened
  relative to a held directory descriptor with `O_NOFOLLOW`.
- An artifact directory holds exactly `complete`, `header`, `manifest.json`
  and `objects`, and `objects/` exactly the names `%08x` for `0` to `K-1`.
  Anything else, missing or extra, is `checkpoint_corrupt`.
- Object numbers are the order of `file` entries in the manifest. An object
  is the file's logical bytes with holes preserved (`SEEK_DATA`/`SEEK_HOLE`),
  so its length is the file's length.
- Artifacts are never deduplicated, linked or cloned. Reflinks are not used
  in v1.

### Locks

Each capture creates its own staging directory exclusively (`mkdirat`, with
a random 64-bit nonce in the name; an existing directory is never adopted)
and holds an exclusive `flock` on it from creation through its reply: the
flock follows the directory through its rename into place, so nobody can
open, remove or replace the artifact before the capture has answered.
`inspect` and a fork's restore hold a shared lock on the artifact for as
long as they read it; `rm` takes an exclusive one on each directory it
removes. All are non-blocking: a held lock is `checkpoint_busy`. Two
captures of one checkpoint may both stage; exactly one rename succeeds, and
the other is `checkpoint_busy` and removes only its own staging directory.

### The header

Written and synced first, right after the quota. Identity and lifetime
fields are outside the content digest and inside the binding digest.

```text
kiln-checkpoint 1
format 1
instance <I>
checkpoint <C>
generation <G>
source <the source run ID>
source-lease <the operation 6 lease generation the copy ran under>
image <name>
image-generation <the registration generation the source was created with>
image-sha256 <its tree digest>
image-directory <fsid as 16 hex>:<inode>:<birth seconds>.<9-digit nanoseconds>
layout <the source overlay's verified effective features>
limit-bytes <R>
```

### The completion marker

Written and synced last, before the rename:

```text
kiln-checkpoint-complete 1
content-sha256 <hex>
binding-sha256 <hex>
entries <N, root included>
objects <K>
logical-bytes <L>
manifest-bytes <length of manifest.json>
excluded-bookkeeping trusted.overlay.impure=<n> trusted.overlay.origin=<n> trusted.overlay.uuid=<n>
```

Both records are strict: these keys in this order, canonical decimal numbers
(no leading zeros), no extra lines, a final newline.

## Digests

```text
content_sha256 = SHA-256("kilnd.workspace-checkpoint.1" || 0x00 || manifest.json)
binding_sha256 = SHA-256("kiln.checkpoint-binding.1" || 0x00 || header || content_sha256 as 32 raw bytes)
```

`content_sha256` covers the normalized workspace only: two captures of the
same files, metadata and topology have the same digest, whichever sandbox,
node or time they came from. In particular a fork, captured again unchanged,
has its checkpoint's content digest (when it also generates the same runtime
entries, since the exclusion list is part of the manifest). `binding_sha256` ties that content to
one instance, checkpoint ID, generation, source and image registration.
Both are integrity fingerprints, not encryption or proof of authorship.

## The manifest

`manifest.json` is canonical JSON with no trailing newline, at most 16 MiB:

- no whitespace; object keys sorted by their bytes; integers only (no
  fraction, exponent, leading zero or `-0`);
- strings: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`; printable ASCII
  (0x20 to 0x7e) as itself; every other character, DEL included, as
  lowercase `\uXXXX` UTF-16 units;
- byte strings (paths, symlink targets, xattr names and values) are base64,
  RFC 4648 section 4: standard alphabet, `=` padding, canonical.

Readers parse and re-encode and refuse any manifest whose bytes differ, so
every manifest has exactly one encoding.

```json
{
  "entries": [ENTRY, …],
  "excluded_paths": ["/dev", "/dev/shm", "/etc/resolv.conf", "/proc", "/sys/fs/cgroup"],
  "excluded_xattrs": ["trusted.overlay.impure", "trusted.overlay.origin", "trusted.overlay.uuid"],
  "format": 1,
  "image_sha256": "<64 lowercase hex>",
  "read_only_root": false,
  "root": {"gid": 0, "mode": 493, "mtime": [1700000000, 5], "uid": 0, "xattrs": []},
  "scope": "persistent_overlay",
  "writable_paths": []
}
```

(Shown with whitespace for reading; the stored form has none.)

- `excluded_paths` is the protected-path contract's exclusion list for the
  source's generated entries ([protected.rs](../runtime/src/protected.rs)):
  `/etc/resolv.conf` appears only when the source's network wrote one.
- `excluded_xattrs` is fixed: the kernel's overlay bookkeeping that capture
  leaves out (below).
- `read_only_root` and `writable_paths` are the source run's policy record
  (`<run>/policy`): sorted, unique, absolute. A fork must match them exactly.
- `root` is the upper root's own record. It has no path and no opaque flag
  (the contract forbids an opaque root).

### Entries

Every entry has `path` (base64 of the path relative to the upper root, no
leading slash) and `type`. Metadata fields:

- `mode` is `st_mode & 07777`, setuid, setgid and sticky included;
- `uid` and `gid` are sandbox-namespace IDs, 0 to 65535 (host ID minus the
  sandbox range base 2,000,000,000);
- `mtime` is `[seconds, nanoseconds]`, nanoseconds below 10^9. Access,
  change and birth times and inode numbers are not part of the format;
- `xattrs` is `[[name, value], …]`, sorted by name bytes, `user.*` only
  (never `user.overlay.*`), at most 32 per entry and 4 KiB of names plus
  values.

| `type` | Fields besides `path` and `type` |
|---|---|
| `dir` | `gid`, `mode`, `mtime`, `opaque` (bool), `uid`, `xattrs` |
| `file` | `gid`, `mode`, `mtime`, `object`, `sha256` (hex), `size`, `uid`, `xattrs` |
| `symlink` | `gid`, `mtime`, `target` (base64, 1 to 1,023 bytes, no NUL), `uid` |
| `hardlink` | `link`: the index in `entries` of an earlier `file` entry |
| `whiteout` | none |

### Order and structure

- **Order.** Entries are in walk order: a pre-order traversal with siblings
  sorted by name bytes. Equivalently, entries are sorted by their path's
  list of components compared bytewise (Python:
  `sorted(paths, key=lambda p: p.split(b"/"))`). Paths are unique.
- **Parents.** The parent of every entry is the root or an earlier `dir`
  entry. Nothing is ever beneath a symlink, file, hardlink or whiteout.
- **Paths.** At most 4,096 bytes and 128 components; each component is
  1 to 255 bytes, not `.` or `..`, with no `/` or NUL. Names need not be
  UTF-8.
- **Hardlinks.** One `file` entry per inode carries the data (the first name
  in walk order); every other name is a `hardlink` to it. Link counts must
  be fully explained inside the upper.
- **Objects.** `object` numbers are `0, 1, 2, …` in the order of `file`
  entries.
- **Contract.** Every entry must be one the protected-path contract
  captures; a runtime-generated entry may never appear (it is excluded at
  capture and regenerated by every new sandbox).
- **Bounds.** At most 65,536 entries including the root.

### Golden

The manifest built by `golden()` in
[manifest.rs](../runtime/src/checkpoint/manifest.rs) (every entry type, a
non-UTF-8 name, a setuid file, a hardlink, a user xattr with a NUL byte, an
opaque directory, a whiteout and a negative mtime) encodes to 1,396 bytes:

```text
SHA-256 of the bytes  40f75cb126dc570bdddaf7f3c581fafa1e5df0373512a94a80f0e1de24736272
content_sha256        a4a64bb84cfc3abc7a7604ebcafccea446513ab0f2265036c677eda37c8ed3ba
```

The binding digest of that content with the test header in
[capture.rs](../runtime/src/checkpoint/capture.rs) (`cp-…09`, limit 1 GiB)
is `bc29aba1f548315a45d64dc0734e38365b6310f3b6b994135b9db85533537138`. Both
were reproduced by an independent encoder written from this document.

## What capture keeps, excludes and refuses

| Upper entry | Rule |
|---|---|
| Directory | `dir`. `trusted.overlay.opaque=y` becomes `opaque: true`. |
| Regular file | `file` (first name of an inode) or `hardlink`. Bytes copied and hashed; holes stay holes but count as zeros in the digest and the logical size. |
| Symlink | `symlink`, target bytes as read, never followed. A hardlinked symlink is refused. |
| Character device 0:0 | `whiteout` (the kernel's whiteout). Owner, mode, times and link count carry no meaning and are not recorded: overlayfs shares one whiteout inode by hardlink, with names in the run's work directory (measured on 6.8). |
| Runtime-generated entry (`/etc/resolv.conf` with DNS) | Excluded; must be a single-link file, symlink or whiteout. |
| `trusted.overlay.origin` (directory, file, symlink), `trusted.overlay.impure=y` (root, directory), `trusted.overlay.uuid` (16 bytes, root) | Excluded kernel bookkeeping, counted in `complete`; restore never writes them. |
| Everything else | Refused, with a typed reason. Nothing else is ever left out. |

Refusals, by reason token. Details name an entry by its manifest ordinal
(`entry 17`), never by its path, link target, user xattr name or any value;
runtime paths and kernel xattr names appear as they are.

| Reason | When |
|---|---|
| `sandbox_unsupported:workspace_checkpoint` | The run has no image identity, no verified layout or no policy record (an older kiln created it), or its PID 1 doesn't grant leases. |
| `checkpoint_busy` | The source runs or queues a command, holds another lease, or the checkpoint already exists or has an operation. |
| `checkpoint_layout_unsupported` | A protected-path violation (anything beneath `/dev`, `/proc` or `/sys/fs/cgroup`; a mount target or ancestor that is not a plain, non-opaque directory; `/etc` not a directory when DNS is generated); a generated file replaced by a directory or hardlinked; a mount crossing; a path over 4,096 bytes or deeper than 128; a writable path overlapping a reserved one, or absent or not a plain directory in the merged view (read-only root). |
| `checkpoint_metadata_unsupported` | A FIFO, socket, block device or non-whiteout character device; a POSIX ACL; a file capability; any other `security.*`, `trusted.*` or `system.*` xattr; an overlay redirect, metacopy, index handle (`upper`, `nlink`), xattr whiteout or its `opaque=x` marker, escaped (`trusted.overlay.overlay.*`), misplaced or unknown overlay xattr; a `user.overlay.*` xattr; a user xattr on a symlink or whiteout; more than 32 user xattrs or 4 KiB of them; an owner outside the sandbox range; a hardlink with names outside the upper; a hardlinked symlink; a symlink target over 1,023 bytes. |
| `checkpoint_image_unavailable` | The image is no longer registered with the generation, digest and directory the source recorded, or its rehash differs. |
| `checkpoint_size_limit` | Over 65,536 entries or a 16 MiB manifest; retained metadata over the 32 MiB worker heap budget; file bytes (each file rounded up to 4 KiB) plus 16 KiB per entry over R; the artifact's quota filled; or the final charge S over R. |
| `checkpoint_io` | A source entry changed or was replaced during the copy, PID 1 ended the lease, the run's identity or metadata changed, or the release failed. |
| `checkpoint_corrupt` | Any artifact check failed (below). |
| `invalid_request` | A malformed ID or limit, or a missing sandbox or checkpoint. |

Fork refusals add `checkpoint_spec_mismatch` (image name, root-write policy
or writable paths differ) and `checkpoint_disk_too_small` (`--disk` below
S, or the new sandbox's quota filled during restore).

The xattr-whiteout form (a zero-size file with `trusted.overlay.whiteout`
under an `opaque=x` directory) is refused rather than decoded: the pinned
upper never contains it (measured), and an upper that does was not written
by this kernel configuration.

## Capture order

1. Refuse before allocating anything: IDs and R, then the source run's
   metadata (image identity, verified layout, policy record), generated
   entries and writable paths.
2. Take operation 6 in this process (the copy happens under the lease, held
   by the copying process itself). PID 1 refuses while anything runs.
3. Rehash the image under the shared image lock (`kiln image verify`) and
   require the registration the run recorded: generation, digest and
   directory identity.
4. Create `.staging-C-G-<nonce>` exclusively (0700), take its lock, install
   the project quota of R while it is empty, create `objects/`, write and
   sync `header`.
5. Walk the raw upper (below) and copy each regular file into its object,
   syncing each object. The lease connection is checked every 256 entries.
6. Still under the lease: every writable path must be a plain directory in
   the merged view (below); the run directory, upper, image reference,
   layout, policy and shim identity must be unchanged. Then acknowledge the
   lease and require PID 1's Released for the same generation. No source
   byte is read after this point.
7. Validate the manifest with the reader's own rules and encode it; write
   and sync `manifest.json`; sync `objects/`; write and sync `complete`; sync
   the staging directory.
8. Through the same locked descriptor, validate the staged directory exactly
   as a reader would (contents, modes, header against the original, both
   digests, manifest, objects), then measure A and compute S. If S > R,
   fail: nothing was published.
9. Last: rename the staging directory to C (never replacing) and sync the
   instance directory. The record is built from the still-locked artifact
   and the original header; the name is never reopened.

Any failure before step 9 removes the staging directory and leaves no
artifact under C. A killed worker leaves only staging, which `ls` lists and
`rm` removes; the lease ends with the worker's connection.

### Writable paths

A sandbox restored from a checkpoint never creates directories: its tree is
the checkpoint's exactly. So for a read-only root, every configured
writable path and the default scratch directories Landlock opens (`/tmp`,
`/root`, `/workspace`; `/dev/shm` is a tmpfs) must already be a plain
directory in the merged view, the captured upper over the verified image:
an upper directory merges with the image's unless it is opaque, an upper
whiteout or non-directory hides it, and image components are opened
without following. Capture checks this under the lease and refuses an
absent or non-directory writable path with `checkpoint_layout_unsupported`;
the fork preflight checks it again against the artifact and the fork's
image; and the fork's init opens every writable path without following and
without creating (an absent one fails the create). Ordinary creates still
create missing writable directories.

### Worker memory

Capture and restore stay inside the design's 64 MiB worker limit at the
largest workspace the caps admit:

- Xattrs are read through one reusable 64 KiB buffer and refused at the
  first name over the caps (32 user xattrs, 4 KiB); a kept value costs its
  own bytes, packed per entry.
- Retained entries, inode and link tables and directory listings in
  progress share a 32 MiB heap budget (`checkpoint_size_limit` beyond it).
  A directory listing is bounded as it is read.
- The manifest is encoded and decoded without a JSON tree: entries are
  written directly and read one at a time (each re-encoded and compared, so
  the document stays canonical). The encoded manifest is at most 16 MiB.
- Restore verifies the rebuilt upper by comparing each walked entry with the
  manifest as it is produced, never holding a second copy.
- Restore flushes the new upper (`syncfs`) every 512 entries or 16 MiB, so the
  dirty page cache and filesystem metadata charged to the worker's memory
  cgroup stay bounded for many small, xattr-heavy files.
- Measured on the VM in a 64 MiB cgroup without swap, one operation per
  process as in production: 16,000 files with 32 xattrs each, and 28,000
  files with 250-byte names (each near the 16 MiB manifest cap), peak at about
  33 MB for capture and for restore.

### The walker

- Every entry is looked up by name relative to its held parent with
  `AT_SYMLINK_NOFOLLOW`. Directories and regular files are then opened with
  `O_NOFOLLOW|O_NOATIME` and must be the inode looked up (device, inode and
  type). Every name and every opened descriptor must be on the upper's mount
  (`STATX_MNT_ID`) and device.
- Special files are classified from their metadata and never opened.
  Symlinks are read with `readlinkat`.
- A file must be unchanged (size, mtime, ctime) after it is read and must
  read exactly its size; a directory must be unchanged after its entries are
  walked.
- Each entry is admitted against the cap before it is copied: entries,
  manifest bytes, and file bytes plus 16 KiB per entry within R. A sparse
  file is charged its logical length before any of it is read.

## Storage charge

Measured on the staged directory, before publication:

```text
L = sum of regular-file lengths, once per inode, each rounded up to 4 KiB
N = manifest entries, root included
M = manifest.json, header and complete, each rounded up to 4 KiB
A = the artifact project's allocated bytes (XFS quota usage)
S = max(A, L + 16 KiB * N + M)
```

S is the charge a daemon reserves for the artifact and the smallest `--disk`
a fork accepts. C1 measured the worst case on the supported XFS at about
16.7 KiB per entry including a 4 KiB data block (a 1-byte file, a 250-byte
name, 32 xattrs totaling 4 KiB), under the formula's 20 KiB; the margin
holds only with the 32-xattr and 4 KiB caps above.

## Restore (`kiln create --from-checkpoint`)

Before allocation:

1. Open the artifact under its shared lock and validate it: names, owners
   and modes; header binding to the path; `complete`; the content and
   binding digests; the full manifest rules above; every object's presence,
   type, mode, link count and length.
2. The new sandbox's image name must be the header's, its root-write policy
   and writable paths the manifest's (`checkpoint_spec_mismatch`).
3. The checkpoint must not hold an entry the new sandbox's runtime
   generates, and the parent of each must be a plain directory or absent.
4. Rehash the image (`verify`): its digest must be the manifest's
   `image_sha256` (`checkpoint_image_unavailable`).
5. `--disk` must be at least S.
6. For a read-only root, every writable path must be a plain directory in
   the merged view of the checkpoint over the image (see Writable paths).

Then the usual create installs the run's quota, creates `upper`, `work` and
`merged`, takes the image reference (whose recorded digest must again be the
checkpoint's) and writes the policy record. Before anything mounts:

- Entries are created in manifest order, each exclusively and relative to
  its held parent: `mkdirat`, `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`,
  `symlinkat`, `mknodat(S_IFCHR, 0)` for a whiteout, and `linkat` (no
  following) to a regular file this restore created earlier, rechecked by
  inode.
- File bytes are copied from the object, holes preserved, and must match the
  entry's SHA-256 as they are copied.
- Metadata: owner through the destination ID map, then user xattrs, then
  `trusted.overlay.opaque=y` for an opaque directory (the only overlay xattr
  ever written), then the mode, then mtime. Directory times are set when
  their subtree is complete, the root last.
- The restored upper is walked with the capture walker and must produce the
  manifest's root and entries exactly, with no bookkeeping, all link counts
  explained, and no inode shared with an artifact object.
- Writable paths are checked as above: preflight refuses an absent one, and
  init opens them without creating anything.

The artifact lock is released, then the sandbox's init mounts the overlay.
Before any privileged mount or DNS write it checks, component by component
without following, that every mount target and the DNS file's parent are
directories in the merged view and that the DNS file is absent or a
single-link regular file. The DNS file is then written without following
any component, and the captured times of `/etc` and `/` are put back
(writing it may create or copy up entries). Any failure fails the create
and removes the run; a sandbox never starts on a partial or empty upper.

## Independence

- An artifact never shares an inode with its source: objects are new files
  in their own project.
- A fork never shares an inode with the artifact or the source: bytes are
  copied, and hardlinks are only made between files of the same new upper.
- A fork can be checkpointed again, indefinitely, with no layer chain.
- Deleting a source leaves its checkpoints usable. Deleting a checkpoint
  leaves its forks running.
- Artifact headers are image references: `kiln image rm`, `unregister` and
  replacement are refused while an artifact or staging directory names the
  image or can't be read.

## Not in v1

Reflinks, deduplication, compression, tar, mounting an artifact, sharing
hardlinks, ACLs, file capabilities, special files, any API or expiry
(the daemon owns those), cross-node transfer and in-place restore.
