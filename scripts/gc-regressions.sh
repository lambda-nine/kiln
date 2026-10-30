#!/bin/sh
# A failed teardown must retain both registry identity and network lease.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
id=
cgroup=
cleanup() {
    if [ -n "$cgroup" ]; then sudo rmdir "$cgroup/extra" 2>/dev/null || true; fi
    if [ -n "$id" ]; then sudo "$KILN" gc "$id" >/dev/null 2>&1 || true; fi
    if [ -n "$cgroup" ]; then sudo rmdir "$cgroup" 2>/dev/null || true; fi
}
trap cleanup EXIT HUP INT TERM
id=$(sudo "$KILN" create --net full)
cgroup=/sys/fs/cgroup/kiln/$id
run=/var/lib/kiln/runs/$id
sudo mkdir "$cgroup/extra"
shim=$(sudo cat "$run/shim.pid")
sudo kill -KILL "$shim"
sleep 0.2
if sudo "$KILN" gc "$id"; then
    echo 'FAIL: gc succeeded with a child cgroup still present'; exit 1
fi
sudo test -f "$run/shim.pid"
sudo test -f "$run/shim.start"
sudo test -d "$cgroup/extra"
sudo rmdir "$cgroup/extra"
sudo "$KILN" gc "$id"
sudo test ! -e "$run"
sudo test ! -e "$cgroup"
id=
echo 'PASS: failed cgroup teardown retains registry and a retry finishes'

tmp=$(mktemp -d)
cleanup_network() {
    rm -rf "$tmp"
    cleanup
}
trap cleanup_network EXIT HUP INT TERM
cat >"$tmp/nft" <<'NFT'
#!/bin/sh
echo 'injected nft failure' >&2
exit 1
NFT
chmod +x "$tmp/nft"
id=$(sudo "$KILN" create --net full)
cgroup=/sys/fs/cgroup/kiln/$id
run=/var/lib/kiln/runs/$id
lease=$(sudo grep -lxF "$id" /run/kiln/net/leases/*)
shim=$(sudo cat "$run/shim.pid")
sudo kill -KILL "$shim"
sleep 0.2
if sudo env PATH="$tmp:$PATH" "$KILN" gc "$id"; then
    echo 'FAIL: gc succeeded after nft teardown failure'; exit 1
fi
sudo test -f "$run/shim.pid"
sudo test -f "$lease"
sudo "$KILN" gc "$id"
sudo test ! -e "$run"
sudo test ! -e "$lease"
sudo test ! -e "$cgroup"
id=
echo 'PASS: network teardown failure retains lease and registry for retry'
