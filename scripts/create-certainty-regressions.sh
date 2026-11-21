#!/bin/sh
# Machine-readable persistent-create preflight failures, against installed kiln.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
sudo python3 -I - "$KILN" <<'PY'
import os
from pathlib import Path
import struct
import subprocess
import sys

kiln = sys.argv[1]
IMAGES = Path('/var/lib/kiln/images')
SANDBOX_ROOT = 2000000000  # userns::ID_BASE, the owner of every image

def inventory():
    roots = ['/var/lib/kiln/runs', '/sys/fs/cgroup/kiln', '/run/kiln/net/leases', '/run/kiln/net/dns']
    return {root: sorted(p.name for p in Path(root).iterdir()) if Path(root).exists() else [] for root in roots}

caps = subprocess.check_output([kiln, 'capabilities', '--protocol=1'])
assert caps[:8] == b'KILNEXO\0' and struct.unpack_from('<I', caps, 16)[0] & 0x10
before = inventory()
# A symlinked alias of the default image, and an image with nothing in it.
alias = IMAGES / f'ccr-alias-{os.getpid()}'
empty = IMAGES / f'ccr-empty-{os.getpid()}'
try:
    alias.symlink_to('alpine')
    empty.mkdir(mode=0o755)
    os.chown(empty, SANDBOX_ROOT, SANDBOX_ROOT)

    refusals = [
        ['--image=round2-definitely-missing-image'],
        ['--allow=10.0.0.1:443'],
        ['--allow=198.18.0.0/15'],
        ['--memory=invalid'],
        ['--image=../escape'],
        ['--require-exec-protocol=2'],
        ['--read-only', '--writable=/'],
        ['--unrecognized-create-option'],
        # Writable paths decided against the image: symlinked and regular-file
        # parents of the default Alpine image, and kiln's own mounts.
        *[['--read-only', f'--writable={path}'] for path in [
            '/var/run/x', '/var/lock/x', '/etc/passwd/x', '/etc/os-release/x', '/bin/sh/x', '/etc/mtab/x',
            '/proc/x', '/sys/x', '/dev/x', '/tmp/' + 'a' * 256]],
        ['--read-only', '--net=full', '--writable=/etc/resolv.conf/x'],
        # One step past each limit floor or maximum.
        ['--cpus=0.009'], ['--cpus=inf'], ['--cpus=175921861'], ['--memory=33554431'], ['--pids=15'],
        ['--pids=4194305'], ['--disk=67108863'], ['--disk=0'], ['--hostname=' + 'h' * 65],
        # An image name that is a symlink.
        [f'--image={alias.name}'],
    ]
    for args in refusals:
        result = subprocess.run([kiln, 'create', *args], capture_output=True, timeout=10)
        assert result.returncode == 124 and result.stdout == b'' and result.stderr, (args, result)
        assert inventory() == before, args
        print('PASS: exit 124, empty stdout, unchanged allocation inventory:', ' '.join(args)[:120])

    # At each floor, and writable paths the shim makes or kiln provides.
    for args in [
        ['--cpus=0.01', '--memory=32M', '--pids=16', '--disk=64M'],
        ['--read-only', '--writable=/dev/shm/x', '--writable=/etc', '--writable=/workspace/new/deep',
         '--writable=/tmp/' + 'a' * 255],
    ]:
        result = subprocess.run([kiln, 'create', *args], capture_output=True, timeout=15)
        assert result.returncode == 0, (args, result)
        identifier = result.stdout.decode().strip()
        script = 'for d in /dev/shm/x /etc /workspace/new/deep; do [ ! -d "$d" ] || touch "$d/ok"; done'
        ran = subprocess.run([kiln, 'exec', identifier, '--', 'sh', '-c', script], stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=15)
        assert ran.returncode == 0, (args, ran)
        subprocess.run([kiln, 'rm', identifier], check=True, timeout=15)
        assert inventory() == before, args
        print('PASS: created, ran and removed:', ' '.join(args)[:120])

    # This passes the whole preflight and fails after new_id: the image has no
    # /dev for kiln's /dev tmpfs (container.rs setup_dev), which only the
    # sandbox's own setup finds. Image content is the operator's, not the
    # caller's, so the preflight doesn't look for it. Even when its cleanup
    # succeeds, it must not claim preflight certainty.
    result = subprocess.run([kiln, 'create', f'--image={empty.name}'], capture_output=True, timeout=15)
    if result.returncode == 0:
        subprocess.run([kiln, 'rm', result.stdout.decode().strip()], check=True, timeout=10)
    assert result.returncode not in (0, 124), result
    assert result.stdout == b'', result
    assert inventory() == before, 'runtime failure left resources behind'
    print('PASS: post-preflight failure stays ambiguous (exit', result.returncode, ') and leaves no run directory')
finally:
    alias.unlink(missing_ok=True)
    if empty.exists():
        empty.rmdir()
PY
