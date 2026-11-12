#!/bin/sh
# Downloads the latest Alpine minirootfs, verifies its detached signature and
# unpacks it as kiln's "alpine" image. Run inside the VM:
#   sudo scripts/fetch-alpine.sh
#   scripts/fetch-alpine.sh --verify-only
set -eu

# Sandboxes run in a user namespace that maps their IDs 0..65535 to host IDs
# starting here, so image files get shifted into that range. Must match
# ID_BASE in runtime/src/userns.rs.
id_base=2000000000

arch=$(uname -m)
base="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/$arch"
dest=/var/lib/kiln/images/alpine
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
key="$script_dir/keys/alpine-ncopa.asc"
pinned_fingerprint=0482D84022F52DF1C4E7CD43293ACD0907D9495A

[ $# -le 1 ] && { [ $# -eq 0 ] || [ "$1" = --verify-only ]; } || {
    echo "usage: $0 [--verify-only]" >&2
    exit 2
}
verify_only=${1:-}

meta=$(curl -fsSL "$base/latest-releases.yaml" | grep -A8 'flavor: alpine-minirootfs')
file=$(echo "$meta" | awk '/^  file:/ {print $2}')
sha=$(echo "$meta" | awk '/^  sha256:/ {print $2}')
case "$file" in
  ""|.*|*[!A-Za-z0-9._-]*) echo "invalid Alpine release filename: $file" >&2; exit 1 ;;
esac
case "$file" in
  alpine-minirootfs-*-$arch.tar.gz) ;;
  *) echo "unexpected Alpine minirootfs filename: $file" >&2; exit 1 ;;
esac
if [ "${#sha}" -ne 64 ] || printf '%s' "$sha" | grep -q '[^0-9a-fA-F]'; then
    echo "invalid sha256 in Alpine release metadata" >&2
    exit 1
fi

tmp=$(mktemp -d)
stage=
trap 'rm -rf "$tmp" ${stage:+"$stage"}' EXIT
GNUPGHOME="$tmp/gnupg"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
curl -fsSL -o "$tmp/$file" "$base/$file"
curl -fsSL -o "$tmp/$file.asc" "$base/$file.asc"
echo "$sha  $tmp/$file" | sha256sum -c -
gpg --batch --dearmor --output "$tmp/alpine-keyring.gpg" "$key"
fingerprint=$(gpg --batch --show-keys --with-colons "$key" | awk -F: '$1 == "fpr" { print $10; exit }')
[ "$fingerprint" = "$pinned_fingerprint" ] || {
    echo "pinned Alpine key has unexpected fingerprint: $fingerprint" >&2
    exit 1
}
gpgv --keyring "$tmp/alpine-keyring.gpg" "$tmp/$file.asc" "$tmp/$file"
[ "$verify_only" = --verify-only ] && { echo "verified $file with Alpine key $fingerprint"; exit 0; }

parent=$(dirname "$dest")
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.alpine.XXXXXX")
tar -xzf "$tmp/$file" -C "$stage"
# Mount points kiln needs, made once here so runs don't record them in upper/.
mkdir -p "$stage/sys/fs/cgroup" "$stage/workspace"

# Shift every file's owner and group by id_base (root:root becomes
# 2000000000:2000000000). chown clears setuid/setgid bits, so put the mode back.
python3 -I - "$stage" "$id_base" <<'PY'
import os, stat, sys

root, base = sys.argv[1], int(sys.argv[2])

def shift(path):
    st = os.lstat(path)
    os.lchown(path, st.st_uid + base, st.st_gid + base)
    if not stat.S_ISLNK(st.st_mode):
        os.chmod(path, stat.S_IMODE(st.st_mode))

for dirpath, dirnames, filenames in os.walk(root):
    shift(dirpath)
    for name in filenames:
        shift(os.path.join(dirpath, name))
    for name in dirnames:  # symlinks to directories aren't walked into
        path = os.path.join(dirpath, name)
        if os.path.islink(path):
            shift(path)
PY
# Replace under kiln's image registry lock (an flock on the images directory).
# A name registered with `kiln image register` keeps its content: install
# changed content under a new name, or `kiln image unregister alpine` first.
python3 -I - "$stage" "$dest" /var/lib/kiln/image-registry/alpine <<'PY'
import ctypes, fcntl, os, sys

stage, dest, entry = sys.argv[1:]
lock = os.open(os.path.dirname(dest), os.O_RDONLY | os.O_DIRECTORY)
fcntl.flock(lock, fcntl.LOCK_EX)
try:
    with open(entry, encoding="utf-8") as f:
        registered = "state registered" in f.read().splitlines()
except FileNotFoundError:
    registered = False
if registered:
    sys.exit(f"{dest} is registered in the kiln image registry; refusing to replace it "
             "(install under a new image name, or run: kiln image unregister alpine)")
if not os.path.lexists(dest):
    os.rename(stage, dest)
else:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(stage), -100, os.fsencode(dest), 2) != 0:
        raise OSError(ctypes.get_errno(), "renameat2(RENAME_EXCHANGE)")
PY
echo "unpacked $file into $dest (owned by uid/gid $id_base and up)"
