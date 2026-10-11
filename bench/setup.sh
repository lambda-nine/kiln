#!/bin/sh
# Prepares the other runtimes to start the exact Alpine tree kiln uses:
#   - a Docker image "kiln-alpine" (docker import)
#   - OCI bundles for runc and crun in /var/lib/kiln-bench: "bundle" runs
#     `true`, "idle" runs `sleep infinity` on the same root filesystem
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
(cd "$BENCH" && runc spec && mv config.json spec-template.json)
python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/bundle" -- true
python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/idle" \
    --root "$BENCH/bundle/rootfs" -- sleep infinity

echo "docker image kiln-alpine and OCI bundles in $BENCH are ready"
