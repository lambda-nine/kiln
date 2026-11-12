# Image content identity v1

Images are still installed and selected by name:
`/var/lib/kiln/images/NAME`, owned by the sandbox ID range. A name says
nothing about content, so checkpoints bind a source to an image's **content
digest** instead. This document defines the registry, the canonical tree
manifest behind the digest, and the run references that keep an image
alive.

## Commands

```text
kiln image register NAME     hash the installed tree and record its identity
kiln image inspect NAME      print the registry entry
kiln image verify NAME       rehash and compare with the registration
kiln image unregister NAME   retire the registration (the image stays usable by name)
kiln image rm NAME           delete the image directory and retire its registration
```

Each command needs root and validates NAME as `kiln create --image` does.
`register`, `inspect`, `verify` and `unregister` print the entry they read
or wrote.

## Registry

`/var/lib/kiln/image-registry/` is root-owned, mode 0700, and holds one file
per name. A file is published with a synced temporary file, a rename and a
directory sync:

```text
kiln-image 1
name alpine
generation 1
state registered
sha256 <64 lowercase hex: the tree digest>
directory <fsid as 16 hex>:<inode>:<birth seconds>.<9-digit nanoseconds>
entries <manifest records>
bytes <regular-file bytes, one per hardlink group>
```

Records are strict: keys in this order, canonical numbers, no extra lines.

**Trusting the registry.** Every read and write first checks the registry
root itself. It must be a real directory, not a symlink, owned by the
running user (root on a real host), and not group or world writable. Entry
files are opened with `O_NOFOLLOW`. A registry that fails these checks is
refused by `register`, `verify`, `inspect` and `unregister`. When a create
meets such a registry, the run still works, but its reference records no
identity (`identity none image registry unusable: …`).

- **Directory identity.** The `directory` line identifies the directory the
  name resolved to at registration: the filesystem ID from `fstatfs`, the
  inode, and the `statx` birth time. The birth time tells a reused inode
  number apart. The identity is the cheap check a create makes. Capture and
  fork rehash the tree and compare the digest itself (`verify`).
- **Generations.** A name's generation starts at 1 and increases with every
  replacement or re-registration. Unregistering or removing a name leaves its
  file with `state retired`, so a generation is never reused for one name.
- **Registering again.** Unchanged content in the same directory is a no-op.
  Anything else replaces the registration, and that is refused while the name
  is referenced (below).
- **Registration needs a quiescent image.** Registration walks the tree
  twice, and the two walks must produce the same digest, entry count and byte
  count. Each directory's own metadata must also be unchanged after its
  entries are walked. These checks catch an unsynchronized change made while
  the image is being registered. They are not an atomic snapshot: a writer
  that coordinates with the walk, for example by watching it with inotify, can
  show both walks the same mixed state, and no finite number of walks rules
  that out. So registration requires an image nobody is changing:
  - cooperating installers, such as `fetch-alpine.sh`, hold the exclusive
    images flock while they change an image;
  - host root is trusted not to change an image while it is being registered.
- **The digest counts only when re-verified.** Capture and fork rehash the
  tree and compare it with the registration (`verify`). A mismatch, including
  one from a digest of a state the tree never had, fails closed with no
  checkpoint. A future version may close the gap by hashing a staged or
  immutable copy of the image instead of the live directory.

## Serialization

Every registry operation, and every reference acquisition, holds an `flock`
on `/var/lib/kiln/images` itself, so taking the lock creates no files.
Reference acquisition holds it shared; registration, replacement, retirement
and removal hold it exclusively. `scripts/fetch-alpine.sh` takes the same
exclusive lock around its directory exchange. It refuses to replace `alpine`
while that name is registered: install changed content under a new name, or
unregister it first.

## Run references

Every new run, persistent or one-shot, writes `/var/lib/kiln/runs/<id>/image`
before its overlay is mounted. This happens after the run's quota is set,
under the shared lock:

```text
kiln-image-ref 1
name alpine
generation 1
sha256 <64 hex>
directory <same form as the registry>
```

When the name isn't registered, its registration is retired, or the current
directory isn't the registered one (for example, it was swapped outside
kiln), the reference has no identity. The run works by name as before, but
it is not a checkpoint source:

```text
kiln-image-ref 1
name alpine
identity none image is not registered
```

**A run directory is a durable reference.** Replacing, unregistering or
removing a name is refused while any run directory under
`/var/lib/kiln/runs` references it. It is also refused while any run's
reference is missing or unreadable, because that run's image is unknown. Runs
created by older kiln versions have no reference at all, so they block every
image removal until they are gone. A crashed shim's run directory blocks until
`kiln gc` removes it. The reference is published by rename without an fsync;
after a crash a lost reference is an unknown reference, which still blocks
(the check fails closed).

## Canonical tree manifest

The digest is SHA-256 over the domain bytes `kiln.image-tree.1\0`, then one
record per entry, then a trailer. Entries are in pre-order, with siblings
sorted by name bytes, and the root first with the empty path. Integers are
little endian. Each record is:

| Field | Encoding |
|---|---|
| marker | u8 1 |
| path | u32 length, then bytes relative to the root (`etc/passwd`); empty for the root |
| type | u8: 1 directory, 2 regular, 3 hardlink, 4 symlink, 5 character device, 6 block device, 7 FIFO, 8 socket |
| mode | u32 `st_mode & 07777` (permissions with setuid, setgid and sticky) |
| uid, gid | u32 each, host IDs as stored |
| mtime | i64 seconds, u32 nanoseconds |
| xattrs | u32 count, then each u32 name length, name, u32 value length, value, sorted by name bytes |
| regular | u64 size, then the 32-byte SHA-256 of the file's bytes |
| hardlink | u64 ordinal of the record that first named this inode |
| symlink | u32 length, then the raw target bytes |
| devices | u32 major, u32 minor; never the device's contents |
| directory, FIFO, socket | nothing more |

The trailer is u8 0 and then the u64 record count. Because of the markers and
length prefixes, two different trees never produce the same stream.

- **Hardlinks.** Any non-directory entry with more than one link is recorded
  in full at its first name: a regular file, a symlink, a device, a FIFO or a
  socket. Each later name of that inode in the tree is a hardlink record that
  points to that ordinal, with the shared inode's metadata. The target's type
  is the first record's type. Two hardlinked symlinks and two independent
  identical symlinks therefore have different digests.
- **Mount boundary.** The walk records the image root's mount ID
  (`statx(STATX_MNT_ID)`). It requires that ID, and the root's device, for
  every entry looked up by name and for every directory or file it opens. A
  bind mount from the same filesystem keeps the device number but changes the
  mount ID, so it is refused. That includes a bind mount over a single file.
- **Walking.** The walk is fd-relative and never follows a link. Directories
  open with `O_DIRECTORY|O_NOFOLLOW`. Regular files open with
  `O_NOFOLLOW|O_NOATIME`, and are compared with their `lstat` result before
  and after reading. Symlinks are read with `readlinkat`. Special files are
  never opened; their xattrs are read with `l*xattr` through the held
  directory.
- **Refusals.** These are errors:
  - a mount crossing, including a same-filesystem bind mount;
  - a directory whose metadata changed while its entries were walked;
  - a file whose size, mtime or ctime changed while it was read;
  - an entry replaced mid-walk;
  - more than 256 directory levels, 4,096-byte paths, 4,096-byte link
    targets, 4,194,304 entries, 1,024 xattrs on one entry, or 64 KiB of xattr
    names or of one value.
- **Excluded from the digest.** Inode numbers, link counts, atime, ctime and
  birth time.

Two golden streams are pinned in `image.rs`. The second one is a hardlinked
symlink:

```text
records: root dir 0755 0:0 mtime 0.0; "x" symlink "t" 0777 0:0 mtime 5.6;
         "y" hardlink to ordinal 1; "z" FIFO 0600 0:0 mtime 5.6
digest:  6dfe3feda0e00a245470b8372fd800a2d557a7d10ef3d4a4449b65ea372166be
```

The first one:

```text
records: root dir 0755 2000000000:2000000000 mtime 1.2;
         "a" regular 04755 0:0 mtime -1.999999999, xattr user.a=v, bytes "abc";
         "b" hardlink to ordinal 1; "c" symlink "/x" 0777; "d" char 1:3 0666
digest:  fca85a1249061f75d12ea03317e274ab7d0e1a2b17c675c34b207aa083b2b6a3
```

An independent Python encoding of the same records gives the same digest.

## Installers

- **`fetch-alpine.sh`** keeps working unchanged for unregistered images. To
  make an image a checkpoint source, run `kiln image register NAME` after
  installing it.
- **kiln-guest's Firecracker root filesystem** is built read-only, has no
  checkpoint support, and needs no registry. A guest image that later wants
  checkpoints would run `kiln image register alpine` at build time. That
  writes `/var/lib/kiln/image-registry/alpine` into the image, so the
  directory identity must be taken on the filesystem the guest actually
  mounts, not at build time on the build host's filesystem.
