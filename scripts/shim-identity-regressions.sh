#!/bin/sh
# Focused persistent-registry checks. Run as an ordinary VM user after
# scripts/install.sh; the individual host-state operations use sudo.
set -eu

KILN=${KILN:-/usr/local/bin/kiln}
bad_id="badbad-$$"
missing_id="missing-$$"
malformed_id="malformed-$$"
stale_id="deadbeef-$$"
bad_dir="/var/lib/kiln/runs/$bad_id"
missing_dir="/var/lib/kiln/runs/$missing_id"
malformed_dir="/var/lib/kiln/runs/$malformed_id"
stale_dir="/var/lib/kiln/runs/$stale_id"
victim=

cleanup() {
    sudo rm -rf "$bad_dir" "$missing_dir" "$malformed_dir" "$stale_dir"
    if [ -n "$victim" ]; then
        kill "$victim" 2>/dev/null || true
        wait "$victim" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

expect_failure() {
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: command unexpectedly succeeded: $*"
        exit 1
    fi
}

sleep 60 &
victim=$!

echo "1. Registry access failures are errors"
sudo install -d -m 0700 "$bad_dir"
printf '%s\n' "$victim" | sudo tee "$bad_dir/shim.pid" >/dev/null
sudo mkdir "$bad_dir/shim.start"
sudo chmod 0600 "$bad_dir/shim.pid"

# A caller that cannot traverse a registry entry must not receive a successful
# empty listing, and malformed/unreadable identity metadata must stop both
# listing and collection even when the control socket is absent.
expect_failure sudo -u nobody "$KILN" ls
expect_failure sudo "$KILN" ls
expect_failure sudo "$KILN" gc
sudo test -d "$bad_dir"
sudo rm -rf "$bad_dir"
echo "PASS: registry access failures propagate"

echo "2. Incomplete identity blocks collection"
sudo install -d -m 0700 "$missing_dir"
printf '%s\n' "$victim" | sudo tee "$missing_dir/shim.pid" >/dev/null
sudo chmod 0600 "$missing_dir/shim.pid"
expect_failure sudo "$KILN" ls
expect_failure sudo "$KILN" gc
sudo test -d "$missing_dir"
sudo rm -rf "$missing_dir"
echo "PASS: missing start time is indeterminate"

echo "3. Malformed identity blocks collection"
sudo install -d -m 0700 "$malformed_dir"
printf '%s\n' "$victim" | sudo tee "$malformed_dir/shim.pid" >/dev/null
printf '%s\n' not-a-start-time | sudo tee "$malformed_dir/shim.start" >/dev/null
sudo chmod 0600 "$malformed_dir/shim.pid" "$malformed_dir/shim.start"
expect_failure sudo "$KILN" ls
expect_failure sudo "$KILN" gc
sudo test -d "$malformed_dir"
sudo rm -rf "$malformed_dir"
echo "PASS: malformed start time is indeterminate"

echo "4. Reused PIDs do not prove shim liveness"
sudo install -d -m 0700 "$stale_dir"
sudo touch "$stale_dir/control.sock"
printf '%s\n' "$victim" | sudo tee "$stale_dir/shim.pid" >/dev/null
printf '0\n' | sudo tee "$stale_dir/shim.start" >/dev/null
sudo chmod 0600 "$stale_dir/control.sock" "$stale_dir/shim.pid" "$stale_dir/shim.start"

record=$(sudo "$KILN" ls | awk -v id="$stale_id" '$1 == id { print $2 " " $3 }')
[ "$record" = "stale $victim" ] || {
    echo "FAIL: mismatched shim identity was reported as: ${record:-missing}"
    exit 1
}

sudo "$KILN" gc >/dev/null
sudo test ! -e "$stale_dir"
kill -0 "$victim"
echo "PASS: PID start-time mismatch is stale and safe to collect"

echo "PASS: persistent registry identity"
