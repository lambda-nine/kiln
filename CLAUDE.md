# kiln: notes for agents

kiln is a small Linux sandbox runtime in Rust for running AI agent tool calls.
It's Stephen's project, built layer by layer to learn how containers work
(namespaces, cgroups v2, overlayfs, seccomp, Landlock, nftables) and to show
that a purpose-built runtime can start sandboxes faster than general-purpose
ones. Read these before changing anything:

- [README.md](README.md): what each layer does, dev setup, and the notes and
  review findings behind the design.
- [ARCHITECTURE.md](ARCHITECTURE.md): today's flow, the target design, the
  decisions, the failure-mode table and the build order.
- [CONTRIBUTING.md](CONTRIBUTING.md): the checks and documentation rules.
- [docs/benchmarks.md](docs/benchmarks.md) and [bench/README.md](bench/README.md):
  benchmark method, results and the v2 harness.
- [RELEASING.md](RELEASING.md): the release checklist.

## Working here

- **Build and run in the Lima VM, not on macOS.** The Mac has no namespaces or
  cgroups. The VM is named `kiln` (Ubuntu 24.04, aarch64, 4 CPUs, 4 GiB) and
  mounts this checkout at the same path. Enter it with
  `limactl shell --workdir "$PWD" kiln`. `kiln` needs root: `sudo target/debug/kiln ...`.
- **The VM only mounts `~/Projects/lambda-nine/kiln` and
  `~/Projects/lambda-nine/kilnd`.** A worktree elsewhere isn't visible inside
  it. Do VM work in these checkouts, or add a mount to `lima.yaml`.
- **Checks before every commit** (all unprivileged, the same as CI):
  `python3 -I -m unittest discover -s bench/tests -v`, `cargo test --locked`,
  `cargo clippy --locked --all-targets -- -D warnings`, `git diff --check`.
  Don't run `cargo fmt`; the source isn't rustfmt-normalized.
- **Privileged regression checks** for anything touching sandbox setup,
  networking, storage or cleanup: `scripts/install.sh`, then
  `scripts/review-regressions.sh` in the VM. Don't run them while a benchmark
  is running in the VM; they disturb each other.
- **Keep the docs in step:** update the README, ARCHITECTURE.md or
  docs/benchmarks.md when behavior, limits or numbers change, and add a line
  under "Unreleased" in CHANGELOG.md.
- **Commits are attributed to Stephen only** (GitHub `stcrestrada`). No
  `Co-Authored-By` trailers of any kind.

## Rules for claims and benchmarks

- **Never edit raw results** under `bench/results/`. New measurements go in a
  new directory, using `bench/v2.py`.
- **Every claim names its condition.** There is no single "cold start" number;
  always give the idle gap, the case and the session count, as
  docs/benchmarks.md does.
- **Say plainly that steady state is a tie.** Once a program runs, every
  runtime uses the same kernel features. Claim only what's measured: startup
  latency, `exec` latency, idle memory per sandbox, no daemon, security on by
  default.
- **Numbers in the papers are generated, not typed.** The white paper's figures
  come from `docs/whitepaper/gen-data.py`. Rebuild the PDFs with `tectonic` as
  in RELEASING.md step 3, and commit the `.tex` and `.pdf` together.
- **Security wording:** kiln is experimental and shares the host kernel. It was
  reviewed adversarially by AI models, not audited. Don't describe it as a
  security boundary for hostile multi-tenant workloads.

## Status (October 12, 2026)

- **v0.1.0 is tagged and staged as a private draft release** in the original
  private archive on GitHub. The active repository is also private. Publishing
  a release or making the repository public needs Stephen's explicit approval
  for that release (RELEASING.md).
  Rootfs tarballs in the draft include GPL/LGPL Alpine packages and need a
  redistribution review before they're published.
- **Done:** layers 1-11 in the README (namespaces through persistent
  sandboxes with `create`/`exec`/`ls`/`rm`/`gc`), metrics, two adversarial
  review rounds, cold-start work (`clone3(CLONE_INTO_CGROUP)`, netlink instead
  of `ip`/`nsenter`, batched nft), the v2 benchmark campaign, the design paper
  (`docs/paper/`) and the performance white paper (`docs/whitepaper/`).
- **The reusable harness/control daemon will live beside this repository** as
  `~/Projects/lambda-nine/kilnd`. ARCHITECTURE.md's target diagram shows the
  long-term shape; the daemon is not part of this repository.

## Next, roughly in order

1. **`kilnd`**, the per-node daemon in ARCHITECTURE.md: sandbox manager with
   reconcile on startup, run records, and a gRPC API over a Unix socket.
2. **A pool of pre-created sandboxes** in `kilnd`, the next startup win named
   in both papers.
3. **Rerun the benchmarks on bare Linux** (the Mac Mini, once it's set up)
   instead of one Lima VM on a laptop.
4. **The Go operator on k3s** with a Sandbox CRD, `kilnd` as a DaemonSet.

Open items from the failure-mode table: allowlist drift (the DNS forwarder
should add resolved IPs to the sandbox's nft set), per-sandbox ID ranges
through idmapped mounts, a seccomp allowlist, and iocost model tuning.

## Housekeeping

- The `~/Projects/kiln-*` folders are old worktrees on `agent/*` branches.
  Their work landed on `main` as rebased commits; check before reusing one,
  and remove them with `git worktree remove` when Stephen agrees.
- Docker, Podman and the other compared runtimes are installed in the VM for
  benchmarks. Docker's daemons cost about 160 MiB of the VM's 4 GiB.
