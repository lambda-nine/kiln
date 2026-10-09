#!/bin/sh
# Downloads the latest Alpine minirootfs and unpacks it as kiln's "alpine" image.
# Run inside the VM: sudo scripts/fetch-alpine.sh
set -eu

# Sandboxes run in a user namespace that maps their IDs 0..65535 to host IDs
# starting here, so image files get shifted into that range. Must match
# ID_BASE in runtime/src/userns.rs.
id_base=2000000000

arch=$(uname -m)
base="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/$arch"
dest=/var/lib/kiln/images/alpine

meta=$(curl -fsSL "$base/latest-releases.yaml" | grep -A8 'flavor: alpine-minirootfs')
file=$(echo "$meta" | awk '/^  file:/ {print $2}')
sha=$(echo "$meta" | awk '/^  sha256:/ {print $2}')

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$file" "$base/$file"
echo "$sha  $tmp/$file" | sha256sum -c -

rm -rf "$dest"
mkdir -p "$dest"
tar -xzf "$tmp/$file" -C "$dest"

# Shift every file's owner and group by id_base (root:root becomes
# 2000000000:2000000000). chown clears setuid/setgid bits, so put the mode back.
python3 -I - "$dest" "$id_base" <<'PY'
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
echo "unpacked $file into $dest (owned by uid/gid $id_base and up)"
