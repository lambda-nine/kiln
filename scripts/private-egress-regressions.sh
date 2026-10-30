#!/bin/sh
# No packets leave the VM: validate forbidden inputs and inspect nft ordering.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
sandbox=
cleanup() { if [ -n "$sandbox" ]; then sudo "$KILN" rm "$sandbox" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT HUP INT TERM
for entry in 169.254.169.254:80 10.0.0.0/8 localhost:80; do
    if output=$(sudo "$KILN" create --allow "$entry" 2>&1); then
        sandbox=$output
        echo "FAIL: private destination $entry was accepted"
        exit 1
    fi
    printf '%s\n' "$output" | grep -Eq 'private|link-local' || {
        echo "FAIL: missing private-destination diagnostic: $output"; exit 1;
    }
done
for mode in allow full; do
    if [ "$mode" = allow ]; then
        sandbox=$(sudo "$KILN" create --allow 1.1.1.1:443)
    else
        sandbox=$(sudo "$KILN" create --net full)
    fi
    lease=$(sudo grep -lxF "$sandbox" /run/kiln/net/leases/*)
    ip=${lease##*/}
    chain=sb_$(printf '%s' "$ip" | tr . _)
    sudo nft list chain inet kiln "$chain" | python3 -c '
import sys
rules = sys.stdin.read()
lines = rules.splitlines()
guard = next(i for i, line in enumerate(lines) if "ip daddr @private" in line)
accept = next(i for i, line in enumerate(lines) if "accept" in line.split())
assert guard < accept, rules
'
    sudo "$KILN" rm "$sandbox"
    sandbox=
done
echo "PASS: private literals, prefixes, resolved hostnames and packet-time guard"
