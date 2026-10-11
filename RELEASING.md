# Releasing kiln

This is the checklist for staging a release while the repository is private.
It ends with a draft GitHub release. Changing the repository's visibility and
publishing the draft each need explicit approval from the maintainer, given
for that release.

The examples use `v0.1.0`; replace the version throughout.

## 1. Clean, current tree

```sh
git switch main
git pull --ff-only
git status --porcelain        # must print nothing
git log -1 --format='%H %s'   # the commit to release
```

- `version` in [`runtime/Cargo.toml`](runtime/Cargo.toml) matches the release.
- [CHANGELOG.md](CHANGELOG.md) has a dated section for it, and "Unreleased"
  is empty.
- CI is green on this exact commit.

## 2. Tests

On any Linux host with Rust 1.88+ and Python 3.12+ (the CI checks):

```sh
python3 -I -m unittest discover -s bench/tests -v
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

In the Lima VM, on the same commit, after installing the release binary in
step 4:

```sh
scripts/review-regressions.sh
```

## 3. Deterministic PDFs

Rebuild both papers with a fixed timestamp and confirm they match what is
committed. Requires `tectonic` and the fonts named in the `.tex` files.

```sh
(cd docs/paper && SOURCE_DATE_EPOCH=0 tectonic kiln.tex)
(cd docs/whitepaper &&
  python3 -I gen-data.py ../../bench/results data \
    ../../bench/results/v2/macbook-air-2026-10-11 &&
  SOURCE_DATE_EPOCH=0 tectonic kiln-whitepaper.tex)
git status --porcelain docs/   # must print nothing
```

If anything changed, commit the regenerated files and start again from step 1.

## 4. ARM64 Linux release build

Build in the Lima VM (Ubuntu 24.04, aarch64):

```sh
cargo build --release --locked
file target/release/kiln      # ELF 64-bit LSB ... ARM aarch64
sudo install -m 0755 target/release/kiln /usr/local/bin/kiln
```

Package the binary with the license and README, outside the repository:

```sh
out=$(mktemp -d)
name=kiln-v0.1.0-aarch64-unknown-linux-gnu
mkdir "$out/$name"
cp target/release/kiln LICENSE README.md SECURITY.md CHANGELOG.md "$out/$name/"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -C "$out" -cf - "$name" | gzip -n >"$out/$name.tar.gz"
```

Only aarch64 Linux is built and tested for a release. CI checks x86_64
builds, but no x86_64 binary is published.

## 5. Benchmark rootfs artifacts

The committed benchmark manifests identify the exact rootfs tarballs by path,
size and SHA-256. An exact rerun needs those files, so attach them to the
release. **Never commit rootfs tarballs to Git.**

| Manifest key          | File in the VM                            | Bytes     | SHA-256 |
|-----------------------|-------------------------------------------|-----------|---------|
| `rootfs_tar`          | `/var/lib/kiln-bench/alpine-rootfs.tar`   | 9482240   | `5f647b1718ebe07ea94c8a8fece9a0a56e0c45b4662282259cd7dd3bfa3cb2c6` |
| `workload_rootfs_tar` | `/var/lib/kiln-bench/workload-rootfs.tar` | 117867520 | `89e1b9c5ed208195b2779515491468ac0da36fa3158f7a5f7bdd7f3192193359` |

```sh
cp /var/lib/kiln-bench/alpine-rootfs.tar /var/lib/kiln-bench/workload-rootfs.tar "$out/"
(cd "$out" && sha256sum alpine-rootfs.tar workload-rootfs.tar)
```

Both hashes must match the table exactly. Attach only files that match; a
regenerated tarball is a different artifact unless its hash matches too. If
an original is missing or differs, leave it out and say so in the release
notes.

## 6. Checksums

```sh
(cd "$out" && sha256sum "$name.tar.gz" alpine-rootfs.tar workload-rootfs.tar >SHA256SUMS)
cat "$out/SHA256SUMS"
```

## 7. Annotated tag

```sh
git tag -a v0.1.0 -m "kiln v0.1.0"
git show v0.1.0 --stat        # annotated, on the commit from step 1
git push origin v0.1.0
```

## 8. Draft release

Write the notes from the CHANGELOG section, including the security status and
any rootfs artifact left out. Then create a **draft**:

```sh
gh release create v0.1.0 --draft --verify-tag --title "kiln v0.1.0" \
  --notes-file notes.md \
  "$out/$name.tar.gz" "$out/alpine-rootfs.tar" "$out/workload-rootfs.tar" \
  "$out/SHA256SUMS"
```

Download the draft's assets and check them against `SHA256SUMS`.

## 9. Stop for approval

Staging ends here. Do not run either of these without explicit approval from
the maintainer for this release:

- making the repository public (`gh repo edit --visibility public ...`)
- publishing the draft (`gh release edit v0.1.0 --draft=false`)

After the repository is public, turn on private vulnerability reporting so the
link in [SECURITY.md](SECURITY.md) works, and confirm GitHub detects the
Apache-2.0 license.
