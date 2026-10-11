"""Packs kiln's image into a tar with its owners shifted back to normal IDs.

kiln's image is stored with every file owned by the sandbox ID range
(uid 2000000000 = root inside the sandbox). Docker and runc/crun without a user
namespace expect root-owned files, so the same tree is packed with
uid/gid - 2000000000. Setuid bits and modes are kept as they are.

usage: python3 -I rootfs-tar.py <image dir> <out.tar> <id base>
"""
import sys
import tarfile

src, out, base = sys.argv[1], sys.argv[2], int(sys.argv[3])


def shift(info):
    info.uid -= base
    info.gid -= base
    info.uname = info.gname = ""
    return info


with tarfile.open(out, "w") as tar:
    tar.add(src, arcname=".", filter=shift)
