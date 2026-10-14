# Security policy

## Supported versions

Security fixes go to the `main` branch and the latest release. Older releases
are not patched.

| Version        | Supported |
|----------------|-----------|
| latest release | yes       |
| `main`         | yes       |
| anything older | no        |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
<https://github.com/lambda-nine/kiln/security/advisories/new>

Please don't open a public issue, pull request or discussion for a
vulnerability. Include what you can of:

- the kiln commit or release, host distribution and kernel version (`uname -r`)
- the command line and flags used
- what a sandbox could do that it shouldn't, and the steps to reproduce it

kiln is maintained by one person. Responses are best effort, with no
guaranteed response or fix time. When a fix is ready, it is released and
disclosed through the same advisory, with credit if you want it.

## Security boundary today

kiln is an experimental, shared-kernel sandbox runtime. Read this before
relying on it:

- **Shared kernel.** Sandboxes are Linux namespaces, cgroups, seccomp and
  Landlock on the host's kernel. A kernel bug reachable from inside a sandbox
  can compromise the host. There is no VM isolation tier yet.
- **Reviewed, not audited.** The design and code have had adversarial reviews
  by AI models, summarized in the README. No professional security audit has
  been done.
- **Not a boundary for hostile multi-tenant workloads.** Don't use kiln to
  separate mutually untrusted tenants.
- **One shared host UID range.** Every sandbox maps its IDs 0-65535 to the same
  host range, 2000000000-2000065535. The user ID does not separate one sandbox
  from another.
- **seccomp denylist.** The filter blocks a list of risky syscalls and
  namespace creation. Everything else is allowed; an allowlist would be
  stricter.
- **One-shot terminal passthrough.** `kiln run` preserves the caller's
  standard streams and controlling terminal for interactive use. It blocks
  the terminal-injection ioctls `TIOCSTI` and `TIOCLINUX`, but code in the
  sandbox can still read terminal input while it runs, change terminal
  settings and print escape sequences. Redirecting the three standard streams
  alone does not remove `/dev/tty`; invoke kiln from a noninteractive service
  that allocates no controlling terminal for fully untrusted one-shot
  workloads. Persistent `kiln exec` refuses terminal descriptors until kiln
  has a controlled PTY mode.
- **Rootful host services.** `kiln` runs as root, and so do the `kiln dns` and
  `kiln metrics` services. The optional Prometheus and Grafana stack also runs
  on the host. Bugs in any of them are host bugs.
- **One supported environment.** kiln is developed and dogfooded on Ubuntu
  24.04 with Linux 6.8 or newer, in the Lima VM described in the README. CI
  builds and runs unprivileged tests on Ubuntu 24.04 x86_64. Other
  distributions, kernels and architectures are untested.

[ARCHITECTURE.md](ARCHITECTURE.md) lists known failure modes and which of them
are open.
