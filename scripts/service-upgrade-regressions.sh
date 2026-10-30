#!/bin/sh
# Preserve DNS for an already-live sandbox with an old root-only policy.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
id=$(sudo "$KILN" create --net full --memory 64M --pids 16 --disk 16M)
trap 'sudo "$KILN" rm "$id" >/dev/null' EXIT HUP INT TERM
policy=$(sudo find /run/kiln/net/leases -maxdepth 1 -type f -exec awk -v id="$id" '$0 == id {sub(".*/", "", FILENAME); print FILENAME}' {} +)
sudo chmod 0600 "/run/kiln/net/dns/$policy"
scripts/install.sh
sudo runuser -u kiln-dns -- test -r "/run/kiln/net/dns/$policy"
sudo "$KILN" exec "$id" -- nslookup example.com </dev/null >/dev/null 2>&1
echo 'PASS: installation migrates a live root-only DNS policy without recreating its sandbox'
