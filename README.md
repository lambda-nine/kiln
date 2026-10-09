# kiln

A small Linux sandbox runtime, written in Rust, for running AI agent tool calls.
Built layer by layer to learn how containers actually work.

## Dev setup (macOS)

macOS has no namespaces or cgroups, so kiln builds and runs inside a Linux VM.
This folder is mounted read-write into the VM at the same path.

```sh
brew install lima
limactl create --name=kiln lima.yaml && limactl start kiln
limactl shell --workdir "$PWD" kiln      # now in Ubuntu 24.04
sudo scripts/fetch-alpine.sh             # once: unpack Alpine as the "alpine" image
sudo scripts/setup-storage.sh            # once: XFS with project quotas for --disk
cargo build
sudo target/debug/kiln run -- sh
sudo target/debug/kiln run --keep -- sh  # keep the run dir to see what changed
sudo target/debug/kiln run --memory 64M --cpus 0.5 --pids 32 --disk 100M --stats -- sh
```

## Layers

1. **Namespaces** (done): `clone()` with new UTS, PID and mount namespaces.
   The command runs as PID 1 with its own hostname and its own `/proc`.
2. **Root filesystem** (done): an overlayfs root, with the Alpine image as the
   read-only lower layer and a per-run upper layer. `pivot_root` swaps it in and
   the host's root is detached. `/dev` is a tmpfs with only a few safe devices.
   The run directory is deleted afterwards unless you pass `--keep`.
3. **cgroups v2** (done): each run gets `/sys/fs/cgroup/kiln/<run-id>` with
   `memory.max` (default 512M, no swap, whole sandbox killed on OOM), `cpu.max`
   (default 1 core) and `pids.max` (default 128). The sandbox has its own cgroup
   namespace and a read-only view of its own limits at `/sys/fs/cgroup`.
   `--stats` prints peak memory, CPU time, throttling and OOM kills on exit.
4. Rootless: user namespaces with UID/GID maps.
5. seccomp-bpf and Landlock.
6. Networking: veth, bridge, nftables egress rules.
7. Cold-start time: measure it, then make it fast.
8. **kiln-init** (done): PID 1 inside the sandbox is kiln itself. It forks the
   command as PID 2, forwards SIGTERM/HUP/USR1/USR2 to it, reaps orphans, and
   exits with the command's code. The host-side `kiln` survives Ctrl-C and
   `kill`, passes them on, and still cleans up.

9. **Disk limits** (done): `/var/lib/kiln/runs` is an XFS filesystem (in a
   sparse file on a loop device) mounted with `prjquota`. Each run directory
   gets its own project ID with PROJINHERIT and a hard block limit (`--disk`,
   default 1G). Done with raw `FS_IOC_FSSETXATTR` ioctls and `quotactl_fd`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for where this is going.

## Notes

- **PID 1 ignores signals from inside its own namespace.** `kill -9 $$` inside
  `kiln run -- sh` does nothing: the kernel drops signals sent to a namespace's
  init from within it unless init installed a handler. A `kill -9` from the host
  works (exit code 137). This is why containers often run a tiny init like `tini`.
- **Mount propagation.** On systemd hosts `/` is a shared mount, so a new mount
  namespace still sends new mounts back to the host. kiln marks `/` private
  (`MS_REC | MS_PRIVATE`) before mounting anything.
- **Overlay deletes are "whiteouts".** Deleting `/etc/motd` in the sandbox
  can't touch the read-only image, so overlayfs records it in `upper/` as a
  character device with number 0/0. `rm -rf /bin` inside a sandbox leaves the
  image intact, and `upper/` is an exact record of what a run changed. For an
  agent, that record is a free audit log.
- **pivot_root, not chroot.** `chroot` only changes how paths resolve and can be
  escaped. `pivot_root(".", ".")` stacks the old root on top of the new one;
  `umount2(".", MNT_DETACH)` then removes it, so nothing reaches the host
  filesystem. It fails with `EINVAL` if the mounts are still shared, another
  reason for the `MS_PRIVATE` step.
- **No mount cleanup needed.** The overlay is mounted inside the sandbox's
  mount namespace, so the kernel tears it down when the last process exits. The
  host never sees it (`findmnt -t overlay` stays empty during a run).
- **Getting into a cgroup before the command runs.** The parent creates the
  cgroup, clones the child, writes the child's PID to `cgroup.procs`, and only
  then writes a byte to a pipe the child is blocked on. Without that handshake
  the command could start before its limits apply. (`clone3` with
  `CLONE_INTO_CGROUP` is the newer way to do this in one syscall.)
- **Controllers are enabled top-down.** A cgroup can only use `memory`, `cpu`
  or `pids` if its parent lists them in `cgroup.subtree_control`, and a cgroup
  that hands controllers to children can't hold processes itself ("no internal
  processes"). That's why runs live under `/sys/fs/cgroup/kiln/` and not in it.
- **CPU limits are quotas per 100 ms period.** `--cpus 0.25` writes
  `25000 100000` to `cpu.max`. A busy loop for 2 s then gets 500 ms of CPU and
  is throttled once in each of 20 periods (see `nr_throttled` in `cpu.stat`).
- **The cgroup namespace must come after the move.** It makes the process's
  *current* cgroup look like `/`. Unshare it before joining the sandbox's cgroup
  and the host's cgroup becomes the root instead.
- **PID 1 bites again.** Before kiln-init, `kiln run -- timeout 2 sh -c
  'while :; do :; done'` never ended: busybox `timeout` sends SIGTERM from
  inside the namespace, and PID 1 ignored it. Now the command is PID 2 and it
  exits after 2 s with code 143.
- **Waiting for signals instead of handling them.** Both kiln-init and the
  host-side `kiln` block signals with `sigprocmask` and pick them up one at a
  time with `sigwait`, in the same loop that reaps children. No async signal
  handlers, so no async-signal-safety rules to get wrong.
- **Don't forward Ctrl-C.** The terminal sends SIGINT to its whole foreground
  process group, and the sandboxed command is in that group, so it already got
  the signal. Forwarding it too would deliver it twice. Ctrl-C ends a run with
  130 and everything is cleaned up.
- **Project quotas cap a directory tree, not a user.** Classic quotas limit
  what a UID owns. XFS project quotas limit whatever is tagged with a project
  ID, and PROJINHERIT makes new files inherit the tag from their directory.
  kiln uses the run directory's inode number as the ID. Inspect live usage
  with `sudo xfs_quota -x -c 'report -p -h' /var/lib/kiln/runs`.
- **A full quota looks like a full disk.** XFS returns `ENOSPC` ("No space
  left on device"), not `EDQUOT`, when a project hits its limit.
- **Writing files costs memory too.** Writing 100 MB to disk showed a memory
  peak of about 100 MiB: page cache is charged to the writer's cgroup. It's
  reclaimable, so it causes writeback rather than OOM kills, but it counts
  toward `memory.max`.
