# Changelog

Notable changes to kiln. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout.

## Unreleased

- Narrow the documented checkpoint lock invariant and pin the stale-removal
  detail (kilnd checkpoint C3 adversarial recheck, L2 and L3): the invariant
  now covers published and `.removing-*` directories, naming a capture's
  unlocked cleanup of its own fresh staging directory as the one safe
  exception, and the stale-removal regression asserts the binding check's
  "changed while this removal checked it" detail, not just `checkpoint_busy`.
  No behaviour change.

- Bind checkpoint removal to the directories it checked (kilnd checkpoint C3
  adversarial recheck, H1-R1): `kiln checkpoint rm` now locks each directory
  before reading its header, and checks that the name still denotes the
  locked directory (same device and inode) before trusting it and again after
  renaming it. A remover that lost a race to another removal and a capture of
  a new generation under the same name is `checkpoint_busy` and removes
  nothing, instead of deleting the new generation. Unchecked `rm` sweeps
  malformed `.staging-C-*` and `.removing-C-*` names again, as before
  generation-checked removal; `rm --generation` still leaves them alone.

- Make checkpoint removal generation-checked (kilnd checkpoint C3 adversarial
  review, H1): `kiln checkpoint rm --generation G` reads the published header
  under the exclusive lock and refuses another generation with the new
  `checkpoint_generation_mismatch`, touching nothing; staging and interrupted
  removals of other generations are left alone, and removal directories now
  carry their generation (`.removing-C-G-PID-N`). Without `--generation`, `rm`
  behaves as before.

- Prepare the repository for public visibility: open the README with status,
  the four Lambda IX repositories, a quickstart and the license; drop a
  reference to an unrelated project from ARCHITECTURE.md and the agent notes;
  ignore `dist/`.

- Document the installed host-service users/capabilities, privileged jobs and
  metrics freshness contract; record finite DNS reserve and busy-to-idle
  admission guarantees with their end-to-end regressions.

- Build installation with the locked dependency set and install from the active Cargo target directory, including inherited `CARGO_TARGET_DIR` paths.

### Runtime

- Add the checkpoint source contract (docs/checkpoint-lease-v1.md,
  docs/image-identity-v1.md):
  - **Leases.** Typed operation 6 `CheckpointLease`, capability bit `0x40`,
    reply type 3 and stage 15 Lease. PID 1 grants a lease only when idle and
    provably quiescent (empty exec cgroup, no child processes). While a lease is
    held, PID 1 refuses every exec and lease as busy and still answers probes. A
    lease lasts as long as its connection, with no timer, and ends successfully
    only with a valid acknowledgment. `kiln checkpoint-lease` holds one for a
    driver on a private status socket. It refuses old runs and PID 1 instances
    without `0x40` before sending any lease byte.
  - **Overlay options.** Every run pins `index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off`,
    reads the effective options back from mountinfo and the module defaults,
    and records them in `<run>/layout`.
  - **Image identity.** `kiln image register|inspect|verify|unregister|rm`
    keeps a root-owned registry of canonical full-tree SHA-256 digests. Every
    run writes `<run>/image`, a reference that blocks replacing or removing its
    image. `fetch-alpine.sh` refuses to replace a registered name.
  - **Protected paths.** `runtime/src/protected.rs` is the contract for
    runtime mount targets and generated entries; kiln's setup uses its
    constants.
  - Operations 1 to 5 are byte-for-byte unchanged.

- Close the checkpoint contract gaps found by adversarial review:
  - **Exit status.** `kiln checkpoint-lease` exits 0 only for Released. A command outcome in place of a lease
    frame is a protocol failure.
  - **Cancellation.** Driver closure cancels a pending probe or grant.
  - **Mount boundary.** The image walk refuses same-filesystem bind mounts by mount ID.
  - **Hardlinks.** The tree manifest records hardlink topology for every non-directory type.
  - **Quiescent registration.** Registration walks the tree twice and requires the walks to agree and the
    directories to stay stable. This catches unsynchronized changes during registration, but it is not an
    atomic snapshot. Registration requires a quiescent image, and capture and fork re-verify the digest,
    which fails closed on a mismatch.
  - **Trusted registry.** A symlinked, foreign-owned or group- or world-writable registry root is refused
    everywhere.

- Let the capability probe before operation 5 (and 6) wait for its reply like
  an exec reply, keeping only the connect bounded, so a probe queued behind
  stalled root-only connections no longer fails where operation 4 waits and
  runs (adversarial-review LOW).

- Add workspace checkpoints, format v1 (docs/checkpoint-format-v1.md):
  - **Capture.** `kiln checkpoint capture` takes operation 6 itself, rehashes the image against the run's
    recorded identity, and walks the raw upper with descriptor-relative, no-follow, `O_NOATIME` reads inside one
    mount. Regular-file bytes go into flat numbered objects with SHA-256 (holes preserved); everything else goes
    into a canonical JSON manifest with a reproducible `content_sha256`. Artifacts live under
    `/var/lib/kiln/runs/.checkpoints/<instance>/<checkpoint>/`, built in a staging directory with its own XFS
    project quota and published through the fsync order of the design. Source reads end before the lease is
    released.
  - **Refusals, never drops.** FIFOs, sockets, devices, ACLs, file capabilities, other security, trusted and
    system xattrs, every overlay form except the opaque flag, `user.overlay.*`, unmapped owners, links leaving
    the upper, protected-path violations, and over-limit sizes, xattrs, depths and link targets are typed
    refusals. Only the kernel's `trusted.overlay.origin`, `impure` and `uuid` bookkeeping is excluded, and
    its counts are recorded in the artifact.
  - **Fork.** `kiln create --from-checkpoint INSTANCE/CHECKPOINT` validates the artifact, image (by
    rehashed content), root-write policy, writable paths, generated entries and disk before allocating
    anything, rebuilds a fresh upper by exclusive descriptor-relative creation with every object verified,
    then walks it again and requires the manifest exactly. It shares no inode with the source or the artifact.
    A fork's init checks the merged scaffolding without following before mounting or writing DNS, writes DNS
    without following, and restores `/etc` and `/` times.
  - **Inventory and removal.** `kiln checkpoint inspect [--verify]`, `rm` and `ls`. `kiln ls` and `kiln gc`
    skip the namespace; artifact headers are image references, so `kiln image rm` is refused while one names
    the image or can't be read.
  - Every run records `<run>/policy` (root-write policy and writable paths); runs without it are not sources.

- Close the checkpoint format gaps found by adversarial review:
  - **Worker memory.** Xattrs are read through one reusable buffer, capped while they are read and packed per
    entry (each value had kept a 64 KiB allocation). Retained metadata and directory listings share a 32 MiB
    heap budget, the manifest codec streams instead of building a JSON tree, and restore verifies without a
    second copy, so capture and restore stay inside 64 MiB at the caps' worst case.
  - **Writable paths.** A sandbox restored from a checkpoint no longer creates missing writable directories.
    Capture (under the lease) and the fork preflight refuse a read-only checkpoint whose writable path is absent
    or not a plain directory, and the fork's init opens writable paths without creating them.
  - **Publication.** Each capture stages in its own exclusively created directory (nonce-named) and keeps its
    lock through the reply. The staged artifact is validated and its charge checked before the rename, which is
    the last step, and the record comes from the locked artifact, never from reopening the name. A losing
    concurrent capture is `checkpoint_busy` and removes only its own staging.

- Fix image registration publishing a digest of a state that was never installed. Two matching walks of the live
  directory are not a snapshot: a writer coordinating with the walk could show both the same mixed state.
  `kiln image register` now copies the tree into a root-only stage under the exclusive image lock, hashes the copy,
  and installs exactly that copy with `renameat2(RENAME_EXCHANGE)`, so the registered digest is the installed
  tree's. The registered directory is always the new copy; registration needs space for one extra copy, and the next
  registration of a name deletes a crashed one's `.register-NAME-*` stage. Registration other than a no-op, including
  a first registration, is now refused while any run references the name (adversarial-review HIGH).

- Fix driver closure waiting for the two-second framing deadline once part of a probe reply or lease grant had
  arrived. `kiln checkpoint-lease` now reads both frames incrementally and watches the driver's status socket until
  the last byte, so closure cancels at once (adversarial-review LOW).

- Add exec options: typed operation 5 (operation 4's argv block plus a
  strict, versioned cwd/environment frame), `kiln exec --exec-options-fd=N`
  for a memfd sealed with exactly write/shrink/grow/seal, capability bit
  `0x20`, and launch stage 14 Chdir. The command's environment is
  `HOME`/`PATH`/`TERM` overlaid by the overrides, sorted by name; `chdir`
  runs after descriptor closure with no fallback to `/`. The CLI refuses a
  PID 1 without `0x20` before sending; operation 4 is byte-for-byte unchanged.

- Drain the busy listener before disconnect and through the transition to idle;
  bound total finalization work, kill descendants before it, and retain observed
  command outcomes when shutdown arrives after execution. Queued partial
  headers cannot delay removal or become later execs.

- Reserve the final sixteen TCP DNS admissions for sources with no outstanding
  permit, preserving the 256-stream bound under the 128-source partial-frame attack.

- Run the DNS and metrics listeners as separate system users, with only DNS
  retaining bind-service capability. Split bridge setup and privileged quota/
  nft collection into hardened jobs with no listeners; expose snapshot freshness.

- Advertise persistent-create preflight certainty (capability `0x10`): exit
  124 with empty stdout proves failure before `new_id` or any allocation;
  every other create failure remains ambiguous for machine callers.

- Read busy headers incrementally beside active-client, signal and listener
  events; bound pending headers and prioritize complete removal over partial
  clients without delaying disconnect cleanup.

- Schedule DNS work by source IP: bound each UDP source's backlog and worker
  share, and frame TCP incrementally before source-fair worker admission.
  Keep the separate pools, absolute TCP deadline and 4096-byte frame cap.

- Share one complete non-public IPv4 deny set across literals/prefixes,
  hostname answers and the allowlist/full-mode nft guard, including special-use,
  documentation, multicast, reserved and limited broadcast destinations.

- Restore fixed-header busy refusal for legacy and typed execs: close received descriptors and reply without reading the refused body or delaying queued removal.

- Bound DNS TCP frames by one absolute deadline and a 4096-byte cap; limit each source to two TCP admissions and reserve separate UDP workers.

- Fail GC on partial cgroup or network teardown, verify resource absence, and retain registry identity and unconfirmed leases for retry.

- Reject private, link-local and metadata egress before every networked accept; refuse private literals/prefixes and filter hostname resolutions.

- Resolve writable directories through root-relative handles without following symlinks or procfs magic links; reject grants for the sandbox root.

- Keep strict Clippy checks passing on Rust 1.88 and 1.99 using stable let chains and integer divisibility checks.

- Align CLI and persistent-protocol validation with kilnd's request contract:
  bounded ASCII image/allowlist fields, canonical non-root writable paths,
  strict persistent IDs, 1–4096 literal argv entries, nonempty `argv[0]`, no
  NUL, and a 1 MiB encoded request body. Unicode, newlines, later empty
  arguments and flag-like values remain literal rather than shell syntax.

- `kiln gc ID...` now limits crash cleanup to explicitly named stale
  sandboxes while retaining global `kiln gc` for operators. Scoped cleanup
  deduplicates and validates IDs, ignores unrelated registry entries, and
  rechecks shim identity/liveness before removing resources.

- Decode raw Linux wait statuses so real-time signals 34–64 remain typed
  command outcomes and adopted-child cleanup reaps them successfully. Add
  deterministic test-only PID 1 response-backpressure and signal recovery.

- Add persistent-exec protocol v1: versioned bounded outcome/capability frames,
  raw exit/signal/core status, typed bootstrap/runtime failures, and private
  machine status plus explicit workload stdio FDs. Preserve legacy requests
  and human exit projections, including ordinary command exits 125/126/127.
  PID 1 drains/reaps before status, serves capabilities while busy and survives
  disconnected/non-reading reply peers. Add capability probes and a create
  requirement flag that rejects unsupported versions before creation. Protocol
  v1 is first supplied by the resulting kiln commit based on `3b42552`; see
  [the protocol specification](docs/exec-protocol-v1.md).

- `kiln ls` and `kiln gc` now require the recorded shim PID and Linux process
  start time to match, so same-boot PID reuse cannot make stale sandbox state
  appear live. Identity files are published atomically with the PID marker
  last; incomplete, malformed or unreadable metadata fails closed instead of
  being misrepresented as an empty registry or a dead shim.
- Persistent control requests now use nonblocking, signal-aware framing with
  one absolute two-second header-and-payload deadline. Malformed frames and
  truncated or misplaced SCM_RIGHTS data close safely without wedging later
  exec/removal requests; a completed write half-close is explicitly allowed,
  while a full client close still cancels its active exec.
- Persistent PID 1 now polls one lifetime-scoped signal fd alongside its
  control listener, reaps adopted children while idle, and treats forwarded
  signals received with no active exec as requests to stop the sandbox rather
  than retaining them for a later command, including across request admission.
  During a persistent exec, signals reach the command's process group; both
  one-shot and persistent commands restore the normal default `SIGPIPE`
  disposition before `exec`.
- A persistent sandbox now survives a per-request setup failure, including
  `fork()` being refused at `pids.max`; only that `kiln exec` fails with 125.
- Persistent `kiln exec` now contains every descendant in a reusable child
  cgroup, with gated admission before workload execution. PID 1 kills and
  drains it on leader exit, client disconnect, startup failure or active
  `kiln rm` before reporting status, reuse or removal. Detached background
  work cannot survive its exec; cleanup and GC remove child cgroups first.
- `kiln exec`: if the client disconnects before its command finishes, PID 1
  stops the command and its descendants and keeps serving. Before, the command
  ran on, blocked later execs, and PID 1 then exited on the failed status
  write, removing the whole sandbox.
- `kiln exec` exits 125 when kiln itself fails (invalid ID, missing sandbox,
  terminal stdio), as `docker exec` does, instead of 1, which a command can
  return too.

### Project

- Moved the project home to the Lambda IX GitHub organization and changed the
  default macOS checkout path to `~/Projects/lambda-nine/kiln`.
- `lima.yaml` also mounts the sibling `~/Projects/lambda-nine/kilnd` checkout
  so the control daemon builds and tests in the same VM.

## 0.1.0 - 2026-10-11

Initial public release. kiln is an experimental, shared-kernel sandbox runtime
for AI agent tool calls. It is not production software and not a security
boundary for hostile multi-tenant workloads; see [SECURITY.md](SECURITY.md).

### Runtime

- `kiln run`: one-shot sandboxes with UTS, PID, mount, IPC, network, cgroup and
  user namespaces; an overlayfs root over a verified Alpine image with
  `pivot_root`; and kiln-init as PID 1 for signal forwarding and reaping.
- Resource limits with cgroups v2 (`--memory`, `--cpus`, `--pids`, with
  `--stats`), started directly in the cgroup with `clone3(CLONE_INTO_CGROUP)`,
  and per-run XFS project quotas for blocks and inodes (`--disk`).
- Sandbox root mapped to an unprivileged host UID range, `no_new_privs`, a
  seccomp-bpf denylist that also blocks namespace creation, and an optional
  Landlock read-only mode (`--read-only`, `--writable`).
- Terminal-injection ioctls are denied. Persistent `kiln exec` refuses raw
  terminal descriptors until kiln has a controlled PTY mode.
- Per-run directories and persistent control sockets have explicit root-only
  permissions, independent of the invoking shell's umask.
- Networking: no network by default; `--net full` or `--allow` allowlists over
  a bridge, veth pair and nftables egress policy that blocks the host, private
  ranges and other sandboxes, with per-IP conntrack limits and a filtering DNS
  forwarder (`kiln dns`).
- Persistent sandboxes: `kiln create`, `exec`, `ls`, `rm` and `gc`.
- Observability: `kiln metrics` (Prometheus exporter), `kiln stats`,
  `KILN_TRACE=1` startup phase timing, and an optional Prometheus and Grafana
  setup.
- Setup scripts for a Lima Ubuntu 24.04 VM, the Alpine image (pinned release
  key, checksum and signature), XFS storage, services and monitoring.
- `kiln --version` reports the package version and source commit provenance.

### Reviews and tests

- Fixes from two adversarial reviews by AI models (not a professional audit),
  with a manual privileged regression script, `scripts/review-regressions.sh`.

### Benchmarks and papers

- A randomized benchmark harness (`bench/v2.py`) with tests, a published raw
  corpus for one ARM Lima VM, and its analysis in
  [docs/benchmarks.md](docs/benchmarks.md). Results are from a single machine
  and are bounded as described there.
- A design paper and a performance white paper (LaTeX sources and PDFs under
  `docs/`).

### Project

- Apache License 2.0, security policy, contributing guide, release checklist
  and CI on Ubuntu 24.04 x86_64, plus generated third-party dependency notices.
- `lima.yaml` mounts `{{.Home}}/Projects/kiln` instead of one user's absolute
  path. The VM it creates is unchanged for a clone at that location, but the
  file's SHA-256 no longer matches the `lima_config` hash recorded in the
  committed benchmark manifests.
