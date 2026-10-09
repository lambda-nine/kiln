#!/bin/sh
# Puts /var/lib/kiln/runs on an XFS filesystem with project quotas, so kiln can
# cap each sandbox's disk use. The filesystem lives in a sparse file mounted
# through a loop device, so no spare disk partition is needed.
# Run inside the VM: sudo scripts/setup-storage.sh [size, default 20G]
set -eu

size=${1:-20G}
img=/var/lib/kiln/storage.xfs
mnt=/var/lib/kiln/runs

if mountpoint -q "$mnt"; then
  echo "$mnt is already mounted"
  exit 0
fi
mkdir -p "$mnt"
if [ -n "$(ls -A "$mnt")" ]; then
  echo "$mnt is not empty; remove leftover runs first" >&2
  exit 1
fi

if [ ! -f "$img" ]; then
  truncate -s "$size" "$img"
  mkfs.xfs -q "$img"
fi
grep -q "^$img " /etc/fstab || echo "$img $mnt xfs loop,prjquota 0 0" >> /etc/fstab
mount "$mnt"
echo "mounted $img on $mnt with project quotas"
