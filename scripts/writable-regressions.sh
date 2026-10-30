#!/bin/sh
# --writable exceptions must name real directories beneath the pivoted root.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
image=review-writable-$$
image_dir=/var/lib/kiln/images/$image
cleanup() { sudo rm -rf "$image_dir"; }
trap cleanup EXIT HUP INT TERM
sudo cp -a /var/lib/kiln/images/alpine "$image_dir"
sudo ln -s / "$image_dir/root-link"
sudo ln -s /etc "$image_dir/etc-link"
for path in /proc/self/root /root-link /etc-link; do
    if sudo "$KILN" run --image "$image" --read-only --writable "$path" -- sh -c \
        'echo bypass >/etc/review-writable-bypass'; then
        echo "FAIL: writable $path followed a link"
        exit 1
    fi
done
sudo "$KILN" run --image "$image" --read-only --writable /new/nested -- sh -c \
    'echo allowed >/new/nested/file && echo allowed >/tmp/review-default'
echo "PASS: writable paths refuse image symlinks and procfs magic links"
