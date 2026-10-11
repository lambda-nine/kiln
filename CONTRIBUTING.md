# Contributing to kiln

kiln is a small, experimental project. Issues and pull requests are welcome.
For anything larger than a fix, open an issue first so we can agree on the
approach. Report security issues privately as described in
[SECURITY.md](SECURITY.md), never in a public issue.

## Requirements

- Rust 1.88 or newer, with clippy
- Python 3.12 or newer (standard library only) for the benchmark harness
- Linux for runtime tests. On macOS, use the Lima VM described in the
  [README](README.md#dev-setup-macos). Ubuntu 24.04 with Linux 6.8 or newer is
  the only tested environment.

## Workflow

1. Fork the repository and create a branch from `main`.
2. Make one focused change. Match the style of the code around it, and keep
   comments for what the code can't say itself.
3. Update the README, [ARCHITECTURE.md](ARCHITECTURE.md) or
   [docs/benchmarks.md](docs/benchmarks.md) when behavior, limits or numbers
   change, and add a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).
4. Run the checks below and open a pull request against `main` that says what
   changed, why, and how you tested it.

## Checks

CI runs these on Ubuntu 24.04 x86_64 for every push and pull request. Run
them yourself first:

```sh
python3 -I -m unittest discover -s bench/tests -v
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

CI also checks the syntax of every tracked shell script and validates every
tracked JSON file. It does not run `cargo fmt`; the source isn't
rustfmt-normalized, so don't reformat unrelated code.

The privileged namespace, network, quota and lifecycle regression checks
need root and a prepared host, so they are not in CI. If your change touches
sandbox setup, networking, storage or cleanup, run them manually in the Lima
VM after `scripts/install.sh` and say so in the pull request:

```sh
scripts/review-regressions.sh
```

## Benchmarks

Don't edit raw results under `bench/results/`. New measurements go in a new
directory, using the method in [bench/README.md](bench/README.md), and claims
in the docs must stay within what the data shows.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License, Version 2.0](LICENSE), as described in its section 5.
