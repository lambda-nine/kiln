#!/bin/sh
# No packets leave the VM: validate forbidden inputs and inspect nft ordering.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
sandbox=
cleanup() { if [ -n "$sandbox" ]; then sudo "$KILN" rm "$sandbox" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT HUP INT TERM
for entry in 169.254.169.254:80 10.0.0.0/8 localhost:80 0.0.0.0/8 192.0.0.0/24 192.0.2.1 192.88.99.1 198.18.0.0/15 198.51.100.1 203.0.113.1 224.0.0.0/4 240.0.0.0/4 255.255.255.255; do
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

# A hostname changes after a full-mode sandbox starts. Test both RFC 1918
# and special-use rebinding; each lookup first returns public unicast, then
# a forbidden answer. No packet can leave the VM on success.
for rebound in 10.0.0.1 198.18.0.1; do
    sandbox=$(sudo "$KILN" create --net full)
    first=$(sudo "$KILN" exec "$sandbox" -- sh -c '
        printf "1.1.1.1 rebind.invalid\n" >/etc/hosts
        getent hosts rebind.invalid
    ' </dev/null 2>&1)
    printf '%s\n' "$first" | grep -q '^1.1.1.1[[:space:]]'
    before=$(sudo nft list counter inet kiln egress_rejected | awk '/packets/ {print $2}')
    second=$(sudo "$KILN" exec "$sandbox" -- sh -c '
        printf "%s rebind.invalid\n" "$1" >/etc/hosts
        getent hosts rebind.invalid
        printf x | nc -u -w 1 rebind.invalid 80 || true
    ' sh "$rebound" </dev/null 2>&1)
    printf '%s\n' "$second" | grep -q "^$rebound[[:space:]]"
    after=$(sudo nft list counter inet kiln egress_rejected | awk '/packets/ {print $2}')
    [ "$after" -gt "$before" ] || { echo 'FAIL: full-mode hostname rebinding bypassed packet guard'; exit 1; }
    sudo "$KILN" rm "$sandbox"
    sandbox=
    echo "PASS: full-mode public-first/$rebound-second hostname is rejected at packet time"
done
