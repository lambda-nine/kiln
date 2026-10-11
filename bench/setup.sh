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
python3 -I rootfs-tar.py "$IMAGE" "$BENCH/alpine-rootfs.tar" "$ID_BASE"

docker image rm -f kiln-alpine >/dev/null 2>&1 || true
docker import "$BENCH/alpine-rootfs.tar" kiln-alpine >/dev/null

if command -v podman >/dev/null 2>&1; then
    podman image rm -f localhost/kiln-alpine:latest >/dev/null 2>&1 || true
    podman import "$BENCH/alpine-rootfs.tar" localhost/kiln-alpine:latest >/dev/null
    # Podman's default 10.88.0.0/16 overlaps kiln0. A container can start on
    # that bridge while its traffic follows kiln0's route and DNS fails, so
    # networked benchmark cases use an explicit non-overlapping bridge.
    podman network rm -f kiln-bench >/dev/null 2>&1 || true
    podman network create --subnet 10.89.0.0/24 --gateway 10.89.0.1 kiln-bench >/dev/null
fi
if command -v nerdctl >/dev/null 2>&1; then
    nerdctl image rm -f kiln-alpine:latest >/dev/null 2>&1 || true
    nerdctl image import "$BENCH/alpine-rootfs.tar" kiln-alpine:latest >/dev/null
fi

tar -xf "$BENCH/alpine-rootfs.tar" -C "$BENCH/bundle/rootfs" --numeric-owner
(cd "$BENCH" && runc spec && mv config.json spec-template.json)
python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/bundle" -- true
python3 -I oci-config.py "$BENCH/spec-template.json" "$BENCH/idle" \
    --root "$BENCH/bundle/rootfs" -- sleep infinity

echo "runtime images, OCI bundles and $BENCH/alpine-rootfs.tar are ready"
