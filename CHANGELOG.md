# Changelog

Notable changes to kiln. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout.

## Unreleased

### Runtime

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
