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

# A sandbox can build a directory tree deeper than the shim's soft descriptor
# limit (1024 under systemd, which kilnd's helper and the shims it starts
# inherit). Its teardown must still remove everything.
command -v chattr >/dev/null || { echo 'FAIL: needs chattr (e2fsprogs)'; exit 1; }
pinned=
cleanup_deep() {
    if [ -n "$pinned" ]; then sudo chattr -i "$pinned" 2>/dev/null || true; fi
    cleanup_network
}
trap cleanup_deep EXIT HUP INT TERM
chain='cd /tmp && i=0; while [ "$i" -lt 1500 ]; do mkdir d && cd d || exit 1; i=$((i + 1)); done; touch bottom'
id=$(sudo sh -c "ulimit -S -n 1024; exec \"$KILN\" create --net=none")
run=/var/lib/kiln/runs/$id
sudo "$KILN" exec "$id" -- sh -c "$chain"
sudo "$KILN" rm "$id"
sudo test ! -e "$run"
sudo test ! -e "/sys/fs/cgroup/kiln/$id"
id=
echo 'PASS: a 1500-level tree under a soft descriptor limit of 1024 is torn down completely'

# A teardown that fails keeps the identity: the run stays listed (stale), and
# kiln gc removes it once the cause is gone. An immutable file in the upper,
# which only host root can set, makes the shim's removal fail. It is the
# chain's bottom file, the only entry of the deepest directory, so the removal
# fails before it has removed any of the 1500 levels: kiln gc, under the same
# soft descriptor limit, then has the whole deep tree to remove.
id=$(sudo sh -c "ulimit -S -n 1024; exec \"$KILN\" create --net=none")
run=/var/lib/kiln/runs/$id
sudo "$KILN" exec "$id" -- sh -c "$chain"
deep=$run/upper/tmp/$(i=0; while [ "$i" -lt 1500 ]; do printf 'd/'; i=$((i + 1)); done)
pinned=${deep}bottom
sudo chattr +i "$pinned"
if out=$(sudo "$KILN" rm "$id" 2>&1); then
    echo 'FAIL: rm succeeded with an immutable file in the upper'; exit 1
fi
echo "$out" | grep -qF 'is still present' && echo "$out" | grep -qF "kiln gc $id" ||
    { echo "FAIL: rm did not say the run directory is left for gc: $out"; exit 1; }
sudo test -f "$run/shim.pid"
sudo test -f "$run/shim.start"
sudo test -f "$run/image"
sudo test -f "$pinned" || { echo 'FAIL: the deep branch did not survive the failed teardown'; exit 1; }
sudo "$KILN" ls | awk -F '\t' -v id="$id" '$1 == id && $2 == "stale" { found = 1 } END { exit !found }' ||
    { echo 'FAIL: the failed teardown is not listed as stale'; exit 1; }
logged=0
for _ in 1 2 3 4 5; do
    if sudo journalctl -q -t kiln -n 50 --no-pager | grep -qF "sandbox $id: teardown left"; then logged=1; break; fi
    sleep 0.2
done
[ "$logged" = 1 ] || { echo 'FAIL: the shim did not log its teardown failure'; exit 1; }
if sudo sh -c "ulimit -S -n 1024; exec \"$KILN\" gc \"$id\""; then
    echo 'FAIL: gc succeeded with the immutable file still there'; exit 1
fi
sudo test -f "$run/shim.pid"
sudo test -f "$pinned" || { echo 'FAIL: the deep branch is gone before gc could remove it'; exit 1; }
sudo chattr -i "$pinned"
pinned=
sudo sh -c "ulimit -S -n 1024; exec \"$KILN\" gc \"$id\""
sudo test ! -e "$run"
sudo test ! -e "/sys/fs/cgroup/kiln/$id"
id=
echo 'PASS: a failed teardown keeps all 1500 levels and its identity, stays listed, logs why, and kiln gc under a soft descriptor limit of 1024 removes the deep tree'
