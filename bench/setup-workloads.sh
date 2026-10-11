#!/bin/sh
# Build one expanded Alpine tree for representative short tool workloads and
# install that exact tree into kiln, Docker, Podman and containerd/nerdctl.
# Run after bench/setup.sh, inside the VM: sudo bench/setup-workloads.sh
set -eu

BENCH=/var/lib/kiln-bench
KILN_IMAGES=/var/lib/kiln/images
DEST=$KILN_IMAGES/workloads
ID_BASE=2000000000 # userns::ID_BASE in runtime/src/userns.rs
BUILDER=kiln-workload-image-builder

[ "$(id -u)" -eq 0 ] || {
    echo "run as root: sudo bench/setup-workloads.sh" >&2
    exit 1
}
[ -f "$BENCH/alpine-rootfs.tar" ] || {
    echo "run sudo bench/setup.sh first" >&2
    exit 1
}

tmp=$(mktemp -d "$BENCH/.workload-build.XXXXXX")
stage=$(mktemp -d "$KILN_IMAGES/.workloads.XXXXXX")
cleanup() {
    docker rm -f "$BUILDER" >/dev/null 2>&1 || true
    rm -rf "$tmp"
    [ -n "$stage" ] && rm -rf "$stage"
}
trap cleanup EXIT HUP INT TERM

docker rm -f "$BUILDER" >/dev/null 2>&1 || true
docker run --name "$BUILDER" kiln-alpine \
    sh -ec 'apk add --no-cache ca-certificates nodejs python3'
docker export "$BUILDER" -o "$tmp/workload-rootfs.tar"
docker rm "$BUILDER" >/dev/null

# Docker export is the merged filesystem with normal 0-based ownership. Make
# the same bytes available to each image frontend before shifting kiln's copy.
docker image rm -f kiln-workloads >/dev/null 2>&1 || true
docker import "$tmp/workload-rootfs.tar" kiln-workloads >/dev/null
if command -v podman >/dev/null 2>&1; then
    podman image rm -f localhost/kiln-workloads:latest >/dev/null 2>&1 || true
    podman import "$tmp/workload-rootfs.tar" localhost/kiln-workloads:latest >/dev/null
fi
if command -v nerdctl >/dev/null 2>&1; then
    nerdctl image rm -f kiln-workloads:latest >/dev/null 2>&1 || true
    nerdctl image import "$tmp/workload-rootfs.tar" kiln-workloads:latest >/dev/null
fi

python3 -I - "$tmp/workload-rootfs.tar" "$stage" "$ID_BASE" <<'PY'
import os
import stat
import sys
import tarfile

archive, root, base_text = sys.argv[1:]
base = int(base_text)
with tarfile.open(archive) as tar:
    # "tar" rejects absolute member names and `..` traversal while allowing
    # the absolute symlink targets that are normal inside an Alpine rootfs
    # (for example /bin/arch -> /bin/busybox).
    tar.extractall(root, filter="tar")

# Docker adds this marker to its containers; it is not part of the workload.
try:
    os.unlink(os.path.join(root, ".dockerenv"))
except FileNotFoundError:
    pass
os.makedirs(os.path.join(root, "sys/fs/cgroup"), exist_ok=True)
os.makedirs(os.path.join(root, "workspace"), exist_ok=True)

def shift(path: str) -> None:
    st = os.lstat(path)
    os.lchown(path, st.st_uid + base, st.st_gid + base)
    if not stat.S_ISLNK(st.st_mode):
        os.chmod(path, stat.S_IMODE(st.st_mode))

for dirpath, dirnames, filenames in os.walk(root):
    shift(dirpath)
    for name in filenames:
        shift(os.path.join(dirpath, name))
    for name in dirnames:
        path = os.path.join(dirpath, name)
        if os.path.islink(path):
            shift(path)
PY

# Swap the prepared tree into place only after extraction and ownership
# shifting succeeded. If an older image existed, stage then names that old tree
# and the trap removes it.
python3 -I - "$stage" "$DEST" <<'PY'
import ctypes
import errno
import os
import sys

stage, dest = sys.argv[1:]
if not os.path.lexists(dest):
    os.rename(stage, dest)
else:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(stage), -100, os.fsencode(dest), 2) != 0:
        value = ctypes.get_errno()
        if value == errno.ENOSYS:
            raise OSError(value, "renameat2 is required for an atomic image swap")
        raise OSError(value, "renameat2(RENAME_EXCHANGE)")
PY

cp "$tmp/workload-rootfs.tar" "$BENCH/.workload-rootfs.tar.new"
mv "$BENCH/.workload-rootfs.tar.new" "$BENCH/workload-rootfs.tar"

echo "workload image is ready in kiln, Docker, Podman and nerdctl"
echo "artifact: $BENCH/workload-rootfs.tar"
