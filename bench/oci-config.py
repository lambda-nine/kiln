"""Writes an OCI bundle config for the benchmark from `runc spec` output.

Same limits as kiln's defaults (512 MiB memory, no swap, 1 CPU, 128 PIDs).
The root filesystem is the unpacked Alpine image, read-only unless --rw;
runc and crun get no overlay, no seccomp profile and no user namespace,
which is what their bare `spec` asks for.

usage: python3 -I oci-config.py <runc spec template> <bundle dir>
           [--root PATH] [--rw] -- <command> [args...]
"""
import json
import os
import sys

template, bundle = sys.argv[1], sys.argv[2]
opts, args = sys.argv[3:sys.argv.index("--")], sys.argv[sys.argv.index("--") + 1:]
root = opts[opts.index("--root") + 1] if "--root" in opts else "rootfs"

with open(template) as f:
    spec = json.load(f)

# crun 1.14 (Ubuntu 24.04) rejects the newer version runc 1.3 writes.
spec["ociVersion"] = "1.0.2"
spec["process"]["terminal"] = False
spec["process"]["args"] = args
spec["root"] = {"path": root, "readonly": "--rw" not in opts}
spec["hostname"] = "kiln"
memory = 512 << 20
spec["linux"]["resources"] = {
    "memory": {"limit": memory, "swap": memory},
    "cpu": {"quota": 100000, "period": 100000},
    "pids": {"limit": 128},
}

os.makedirs(bundle, exist_ok=True)
with open(os.path.join(bundle, "config.json"), "w") as f:
    json.dump(spec, f, indent=2)
