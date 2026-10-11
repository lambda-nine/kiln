#!/bin/sh
# Prepares the other runtimes to start the exact Alpine tree kiln uses:
#   - a Docker image "kiln-alpine" (docker import)
#   - an OCI bundle for runc and crun in /var/lib/kiln-bench/bundle
# Run inside the VM once kiln's image exists: sudo bench/setup.sh
set -eu
cd "$(dirname "$0")"
IMAGE=/var/lib/kiln/images/alpine
BENCH=/var/lib/kiln-bench
ID_BASE=2000000000 # userns::ID_BASE in runtime/src/userns.rs

rm -rf "$BENCH"
mkdir -p "$BENCH/bundle/rootfs"
python3 -I rootfs-tar.py "$IMAGE" "$BENCH/alpine.tar" "$ID_BASE"

docker image rm -f kiln-alpine >/dev/null 2>&1 || true
docker import "$BENCH/alpine.tar" kiln-alpine >/dev/null

tar -xf "$BENCH/alpine.tar" -C "$BENCH/bundle/rootfs" --numeric-owner
rm "$BENCH/alpine.tar"
(cd "$BENCH/bundle" && runc spec && python3 -I "$OLDPWD/oci-config.py" config.json)

echo "docker image kiln-alpine and OCI bundle $BENCH/bundle are ready"
