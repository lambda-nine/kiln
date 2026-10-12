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
cargo install cargo-about --version 0.9.2 --locked --features cli
cargo about generate --locked --fail third-party-licenses.hbs \
  --output-file THIRD-PARTY-LICENSES.md
git diff --exit-code -- THIRD-PARTY-LICENSES.md
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

Build in the Lima VM (Ubuntu 24.04, aarch64) with the same Rust 1.88.0
toolchain used by CI. Leave `KILN_BUILD_COMMIT` unset so the binary derives
provenance from the clean tagged checkout:

```sh
kiln_source_root=$(pwd)
kiln_cargo_root=${CARGO_HOME:-$HOME/.cargo}
kiln_rustflags="--remap-path-prefix=$kiln_source_root=/usr/src/kiln --remap-path-prefix=$kiln_cargo_root=/usr/local/cargo"
env -u KILN_BUILD_COMMIT RUSTFLAGS="$kiln_rustflags" \
  cargo +1.88.0 build --release --locked
file target/release/kiln      # ELF 64-bit LSB ... ARM aarch64
target/release/kiln --version # release commit, clean
sudo install -m 0755 target/release/kiln /usr/local/bin/kiln
sudo systemctl restart kiln-dns kiln-metrics
```

Package the binary with the license and README, outside the repository:

```sh
out=$(mktemp -d)
name=kiln-v0.1.0-aarch64-unknown-linux-gnu
mkdir "$out/$name"
cp target/release/kiln LICENSE THIRD-PARTY-LICENSES.md README.md \
  SECURITY.md CHANGELOG.md "$out/$name/"
{
  target/release/kiln --version
  rustc +1.88.0 -Vv
  cargo +1.88.0 -V
  ld --version | head -n 1
  uname -srmo
  printf '%s\n' \
    'RUSTFLAGS=--remap-path-prefix=<checkout>=/usr/src/kiln --remap-path-prefix=<cargo-home>=/usr/local/cargo'
} >"$out/$name/BUILDINFO.txt"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --mode='u=rwX,go=rX' \
    -C "$out" -cf - "$name" | gzip -n >"$out/$name.tar.gz"
```

Only aarch64 Linux is built and privileged-tested for this release. CI builds
and runs unprivileged tests natively on x86_64, but no x86_64 binary is
published. Archive metadata is normalized; bit-for-bit binary reproducibility
has not been established. `BUILDINFO.txt` records the build environment.

## 5. Benchmark rootfs artifacts

The committed benchmark manifests identify the exact rootfs tarballs by path,
size and SHA-256. A close rerun needs those inputs, but the campaign's original
resolved Lima instance configuration was not archived, so the tarballs are not
sufficient for a byte-for-byte environment replay. **Never commit rootfs
tarballs to Git.**

| Manifest key          | File in the VM                            | Bytes     | SHA-256 |
|-----------------------|-------------------------------------------|-----------|---------|
| `rootfs_tar`          | `/var/lib/kiln-bench/alpine-rootfs.tar`   | 9482240   | `5f647b1718ebe07ea94c8a8fece9a0a56e0c45b4662282259cd7dd3bfa3cb2c6` |
| `workload_rootfs_tar` | `/var/lib/kiln-bench/workload-rootfs.tar` | 117867520 | `89e1b9c5ed208195b2779515491468ac0da36fa3158f7a5f7bdd7f3192193359` |

```sh
sudo install -m 0644 /var/lib/kiln-bench/alpine-rootfs.tar \
  /var/lib/kiln-bench/workload-rootfs.tar "$out/"
sudo chown "$(id -u):$(id -g)" "$out/alpine-rootfs.tar" "$out/workload-rootfs.tar"
(cd "$out" && sha256sum alpine-rootfs.tar workload-rootfs.tar)
{
  echo '# Benchmark rootfs package inventory'
  for artifact in alpine-rootfs.tar workload-rootfs.tar; do
    case "$artifact" in
      alpine-rootfs.tar) db=./lib/apk/db/installed ;;
      *) db=lib/apk/db/installed ;;
    esac
    printf '\n## %s\n\n| Package | Version | License | Origin | Aports commit |\n' "$artifact"
    echo '|---|---|---|---|---|'
    tar -xOf "$out/$artifact" "$db" | awk -F: '
      $1 == "P" { p=$2 }
      $1 == "V" { v=$2 }
      $1 == "L" { l=substr($0,3) }
      $1 == "o" { o=$2 }
      $1 == "c" { print "| " p " | " v " | " l " | " o " | " $2 " |" }
    '
  done
} >"$out/ROOTFS-PACKAGES.md"
```

Both hashes must match the table exactly. Attach only files that match; a
regenerated tarball is a different artifact unless its hash matches too. If
an original is missing or differs, leave it out and say so in the release
notes.

These tarballs contain Alpine packages under several third-party licenses,
including GPL and LGPL packages. They may be preserved in an unpublished
private draft. Before publishing them, provide the required license notices
and corresponding source alongside them, or remove the tarballs from the
release and publish only their hashes and package inventory. Treat that as a
separate redistribution review, not as covered by kiln's Apache-2.0 license.

## 6. Checksums and Mac handoff

```sh
(cd "$out" && sha256sum "$name.tar.gz" alpine-rootfs.tar \
  workload-rootfs.tar ROOTFS-PACKAGES.md >SHA256SUMS)
cat "$out/SHA256SUMS"
```

The commands above run in the VM. Copy the completed staging directory to a
private directory on the Mac before using `gh`, then verify the checksums again
there:

```sh
# On the Mac; replace GUEST_OUT with the path printed by: echo "$out"
mac_out=$(mktemp -d /tmp/kiln-v0.1.0.XXXXXX)
name=kiln-v0.1.0-aarch64-unknown-linux-gnu
limactl copy --backend=rsync -r "kiln:GUEST_OUT/." "$mac_out/"
(cd "$mac_out" && shasum -a 256 -c SHA256SUMS)
```

## 7. Annotated tag

```sh
git tag -a v0.1.0 -m "kiln v0.1.0"
git show v0.1.0 --stat        # annotated, on the commit from step 1
env -u GITHUB_TOKEN git push git@github.com:stcrestrada/kiln.git v0.1.0
```

## 8. Draft release

Write the notes from the CHANGELOG section, including the security status and
any rootfs artifact left out. Then create a **draft**:

```sh
env -u GITHUB_TOKEN gh release create v0.1.0 --draft --verify-tag \
  --title "kiln v0.1.0" \
  --notes-file notes.md \
  "$mac_out/$name.tar.gz" "$mac_out/alpine-rootfs.tar" \
  "$mac_out/workload-rootfs.tar" "$mac_out/ROOTFS-PACKAGES.md" \
  "$mac_out/SHA256SUMS"
```

Download the draft's assets and check them against `SHA256SUMS`.

## 9. Stop for approval

Staging ends here. Do not publish the draft or expose the source publicly
without explicit approval from the maintainer for this release.

At approval time, choose one public-source path:

- **Current repository:** change its visibility to public. This is the simple
  switch, but GitHub may retain pre-rewrite objects that are not reachable
  from current `main` or its tags; anyone with an old object ID or activity
  link may still be able to view them.
- **Fresh repository:** create a new public repository from the reviewed
  branches and tags only. This does not require a GitHub organization and
  avoids publishing the current remote's unreachable objects, but historical
  commit IDs cited by the benchmark corpus and papers must remain available or
  be explained.

After that choice, publishing the draft is a separate action
(`gh release edit v0.1.0 --draft=false`) and still requires explicit approval.

Before publishing, also resolve the rootfs redistribution gate in step 5 and
state that the aarch64 binary was privileged-tested while x86_64 had only the
unprivileged CI checks. The release archive depends on glibc from Ubuntu 24.04;
it is not a portable static binary.

After the repository is public, turn on private vulnerability reporting so the
link in [SECURITY.md](SECURITY.md) works, and confirm GitHub detects the
Apache-2.0 license.
