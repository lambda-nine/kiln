"""Turns `runc spec` output into the bundle config the benchmark uses.

Same limits as kiln's defaults (512 MiB memory, no swap, 1 CPU, 128 PIDs) and
the command `true`. The root filesystem is the read-only unpacked Alpine
image; runc and crun get no overlay, no seccomp profile and no user
namespace, which is what their bare `spec` asks for.

usage: python3 -I oci-config.py <config.json>
"""
import json
import sys

path = sys.argv[1]
with open(path) as f:
    spec = json.load(f)

# crun 1.14 (Ubuntu 24.04) rejects the newer version runc 1.3 writes.
spec["ociVersion"] = "1.0.2"
spec["process"]["terminal"] = False
spec["process"]["args"] = ["true"]
spec["root"] = {"path": "rootfs", "readonly": True}
spec["hostname"] = "kiln"
memory = 512 << 20
spec["linux"]["resources"] = {
    "memory": {"limit": memory, "swap": memory},
    "cpu": {"quota": 100000, "period": 100000},
    "pids": {"limit": 128},
}

with open(path, "w") as f:
    json.dump(spec, f, indent=2)
