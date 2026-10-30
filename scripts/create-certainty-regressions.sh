#!/bin/sh
# Machine-readable persistent-create preflight failures, against installed kiln.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
sudo python3 -I - "$KILN" <<'PY'
from pathlib import Path
import struct
import subprocess
import sys

kiln = sys.argv[1]

def inventory():
    roots = ['/var/lib/kiln/runs', '/sys/fs/cgroup/kiln', '/run/kiln/net/leases', '/run/kiln/net/dns']
    return {root: sorted(p.name for p in Path(root).iterdir()) if Path(root).exists() else [] for root in roots}

caps = subprocess.check_output([kiln, 'capabilities', '--protocol=1'])
assert caps[:8] == b'KILNEXO\0' and struct.unpack_from('<I', caps, 16)[0] & 0x10
before = inventory()
for args in [
    ['--image=round2-definitely-missing-image'],
    ['--allow=10.0.0.1:443'],
    ['--allow=198.18.0.0/15'],
    ['--memory=invalid'],
    ['--image=../escape'],
    ['--require-exec-protocol=2'],
    ['--read-only', '--writable=/'],
    ['--unrecognized-create-option'],
]:
    result = subprocess.run([kiln, 'create', *args], capture_output=True, timeout=10)
    assert result.returncode == 124 and result.stdout == b'' and result.stderr, result
    assert inventory() == before, args
    print('PASS: exit 124, empty stdout, unchanged allocation inventory:', ' '.join(args))

# This passes image/config preflight and reaches runtime setup after new_id.
# Even when its cleanup succeeds, it must not claim preflight certainty.
result = subprocess.run([kiln, 'create', '--pids=0'], capture_output=True, timeout=15)
if result.returncode == 0:
    subprocess.run([kiln, 'rm', result.stdout.decode().strip()], check=True, timeout=10)
assert result.returncode not in (0, 124), result
assert result.stdout == b'', result
assert inventory() == before, 'runtime failure left resources behind'
print('PASS: post-preflight failure stays ambiguous (exit', result.returncode, ')')
PY
