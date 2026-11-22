#!/bin/sh
# Machine-readable persistent-create preflight failures, against installed kiln.
set -eu
KILN=${KILN:-/usr/local/bin/kiln}
sudo python3 -I - "$KILN" <<'PY'
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

kiln = sys.argv[1]
IMAGES = Path('/var/lib/kiln/images')
SANDBOX_ROOT = 2000000000  # userns::ID_BASE, the owner of every image

RUNS = Path('/var/lib/kiln/runs')

def inventory():
    roots = [str(RUNS), '/sys/fs/cgroup/kiln', '/run/kiln/net/leases', '/run/kiln/net/dns']
    return {root: sorted(p.name for p in Path(root).iterdir()) if Path(root).exists() else [] for root in roots}

def deep(top, components):
    """A writable path of one-byte components under a top-level name Alpine lacks."""
    return '/' + top + '/a' * (components - 1)

def deep_set(made):
    """Writable paths whose walk makes exactly `made` directories (512 components per path at most)."""
    paths, left = [], made
    for top in 'bcdefghijklmnopq':
        if left == 0:
            break
        paths.append(deep(top, min(512, left)))
        left -= min(512, left)
    assert left == 0, made
    return paths

def writable(paths):
    return ['--read-only', *[f'--writable={path}' for path in paths]]

def quota(run_id):
    """The run's XFS project inode use and hard limit (its project ID is the run directory's inode)."""
    project = os.stat(RUNS / run_id).st_ino
    report = subprocess.run(['xfs_quota', '-x', '-c', 'report -p -N -i', str(RUNS)], capture_output=True, text=True,
                            check=True).stdout
    fields = next(line.split() for line in report.splitlines() if line.split()[:1] == [f'#{project}'])
    return int(fields[1]), int(fields[3])

# The writable directories a create makes count against its inode quota, less
# exactly what the run's own files use. These boundaries are literal numbers,
# measured, not derived from kiln's constants: at the 64M floor (4096 inodes)
# a persistent run's own files take 10 and a one-shot run's 8. Alpine has
# every default writable directory, so the deep sets are all the walk makes.
assert all((IMAGES / 'alpine' / d).is_dir() for d in ('tmp', 'root', 'workspace'))
REVIEW_SET = deep_set(16 * 512)

caps = subprocess.check_output([kiln, 'capabilities', '--protocol=1'])
assert caps[:8] == b'KILNEXO\0' and struct.unpack_from('<I', caps, 16)[0] & 0x10
before = inventory()
# A symlinked alias of the default image, and an image with nothing in it.
alias = IMAGES / f'ccr-alias-{os.getpid()}'
empty = IMAGES / f'ccr-empty-{os.getpid()}'
dns_image = IMAGES / f'ccr-dns-{os.getpid()}'
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
        # Writable directories past the run's inode quota at the 64M floor: the
        # 2026-11-22 review's 16 paths of 512 components and 8 of them. The
        # boundary cases are below.
        *[['--disk=64M', *writable(paths)] for paths in [REVIEW_SET, REVIEW_SET[:8]]],
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

    # The physical boundary of a persistent create at the 64M floor: 4085
    # directories create and the deepest takes a file; 4086 create with all
    # 4096 inodes in use and still run a command; 4087 are refused before
    # allocation. At 67108865 bytes the quota rounds up to 4097 inodes, and
    # 4087 directories fill it. The review's set creates once --disk has room.
    def persistent_fits(disk, made, command, used=None, limit=None):
        paths = deep_set(made)
        result = subprocess.run([kiln, 'create', '--net=none', f'--disk={disk}', *writable(paths)],
                                capture_output=True, timeout=60)
        assert result.returncode == 0, (disk, made, result.returncode, result.stderr)
        identifier = result.stdout.decode().strip()
        try:
            got = quota(identifier)
            assert used is None or got[0] == used, (disk, made, got)
            assert limit is None or got[1] == limit, (disk, made, got)
            ran = subprocess.run([kiln, 'exec', identifier, '--', *command(paths)], stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=15)
            assert ran.returncode == 0, (disk, made, ran)
        finally:
            subprocess.run([kiln, 'rm', identifier], check=True, timeout=60)
        assert inventory() == before, (disk, made)
        print(f'PASS: persistent create of {made} writable directories at --disk={disk} created (inodes used, limit: '
              f'{got[0]}, {got[1]}), ran {" ".join(command(paths))[:40]}... and was removed')

    def refused(command, disk, made, room, limit):
        args = [kiln, command, '--keep'] if command == 'run' else [kiln, command]
        args += ['--net=none', f'--disk={disk}', *writable(deep_set(made))]
        result = subprocess.run(args + (['--', 'true'] if command == 'run' else []), capture_output=True, timeout=60)
        assert result.returncode == (124 if command == 'create' else 1) and result.stdout == b'', (command, made, result)
        for text in [f'needs {made} new entries', f'more than the {room} that --disk leaves',
                     f'its inode limit of {limit}']:
            assert text.encode() in result.stderr, (command, made, text, result.stderr)
        assert inventory() == before, (command, made)
        print(f'PASS: {command} of {made} writable directories at --disk={disk} refused before allocation '
              f'(exit {result.returncode}), inventory unchanged')

    touch = lambda paths: ['touch', paths[-1] + '/ok']
    true = lambda paths: ['true']
    persistent_fits('64M', 4085, touch)
    persistent_fits('64M', 4086, true, used=4096, limit=4096)
    refused('create', '64M', 4087, 4086, 4096)
    persistent_fits('67108865', 4087, true, used=4097, limit=4097)
    refused('create', '67108865', 4088, 4087, 4097)
    persistent_fits('256M', 16 * 512, touch)

    # The same boundary for a one-shot kiln run, which keeps 8 for its own
    # files: 4088 directories run (kept, so the quota can be read: all 4096
    # inodes), 4089 are refused before its run directory. --keep makes a run
    # directory made before the refusal stay and fail the inventory check.
    result = subprocess.run([kiln, 'run', '--keep', '--net=none', '--disk=64M', *writable(deep_set(4088)), '--',
                             'true'], capture_output=True, timeout=60)
    kept = sorted(set(inventory()[str(RUNS)]) - set(before[str(RUNS)]))
    try:
        assert result.returncode == 0, (result.returncode, result.stderr)
        assert len(kept) == 1, kept
        used = quota(kept[0])
        assert used == (4096, 4096), used
    finally:
        for name in kept:
            shutil.rmtree(RUNS / name)
    assert inventory() == before, 'kiln run --keep left more than its run directory'
    print(f'PASS: kiln run of 4088 writable directories at --disk=64M ran (kept run directory: inodes used, limit '
          f'{used[0]}, {used[1]}) and its kept directory was removed')
    refused('run', '64M', 4089, 4088, 4096)

    # kiln run decides the same before its run directory (it has no exit-124
    # contract); with --keep, a run directory made before the refusal would
    # stay and change the inventory.
    result = subprocess.run([kiln, 'run', '--keep', '--disk=64M', *writable(REVIEW_SET), '--', 'true'],
                            capture_output=True, timeout=15)
    assert result.returncode != 0 and b'--disk' in result.stderr, result
    assert inventory() == before, 'kiln run left resources behind'
    print('PASS: kiln run --keep refuses the deep writable set at 64M before its run directory')

    # With DNS kiln writes /etc/resolv.conf without following the image's
    # symlink: one to /dev/shm/x or /tmp/x is replaced in the upper by a
    # regular file with the generated content, and its target never appears.
    # An image whose /etc is a symlink is refused before allocation.
    dns_image.mkdir(mode=0o755)
    subprocess.run(['cp', '-a', str(IMAGES / 'alpine') + '/.', str(dns_image)], check=True)
    resolv = dns_image / 'etc' / 'resolv.conf'
    for target in ['/dev/shm/x', '/tmp/x']:
        if resolv.is_symlink() or resolv.exists():
            resolv.unlink()
        resolv.symlink_to(target)
        os.lchown(resolv, SANDBOX_ROOT, SANDBOX_ROOT)
        result = subprocess.run([kiln, 'create', '--net=full', f'--image={dns_image.name}', *writable([])],
                                capture_output=True, timeout=30)
        assert result.returncode == 0, (target, result)
        identifier = result.stdout.decode().strip()
        try:
            upper = RUNS / identifier / 'upper' / 'etc' / 'resolv.conf'
            assert upper.is_file() and not upper.is_symlink(), (target, upper)
            script = (f'test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && grep -q "^nameserver " '
                      f'/etc/resolv.conf && test ! -e {target}')
            ran = subprocess.run([kiln, 'exec', identifier, '--', 'sh', '-c', script], stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=15)
            assert ran.returncode == 0, (target, ran)
        finally:
            subprocess.run([kiln, 'rm', identifier], check=True, timeout=30)
        assert os.readlink(resolv) == target, 'the image changed'
        assert inventory() == before, target
        print(f'PASS: an image whose /etc/resolv.conf is a symlink to {target} gets a regular generated file; '
              f'{target} is absent in the sandbox')
    (dns_image / 'etc').rename(dns_image / 'etc.real')
    (dns_image / 'etc').symlink_to('etc.real')
    for command, extra, tail in [('create', [], []), ('run', ['--keep'], ['--', 'true'])]:
        result = subprocess.run([kiln, command, *extra, '--net=full', f'--image={dns_image.name}', *tail],
                                capture_output=True, timeout=30)
        assert result.returncode == (124 if command == 'create' else 1), (command, result)
        assert b'invalid image for a sandbox with DNS' in result.stderr, (command, result)
        assert inventory() == before, command
        print(f'PASS: {command} --net=full refuses an image whose /etc is a symlink before allocation '
              f'(exit {result.returncode})')

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
    if dns_image.is_symlink() or dns_image.exists():
        shutil.rmtree(dns_image)
PY
