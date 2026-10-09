#!/bin/sh
# Downloads the latest Alpine minirootfs and unpacks it as kiln's "alpine" image.
# Run inside the VM: sudo scripts/fetch-alpine.sh
set -eu

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
echo "unpacked $file into $dest"
