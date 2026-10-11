#!/usr/bin/env python3
"""Benchmark harness v2: randomized, reproducible runtime benchmarks.

    python3 -I bench/v2.py latency     --config C --out DIR --session S ...
    python3 -I bench/v2.py concurrency --config C --out DIR --session S ...
    python3 -I bench/v2.py memory      --config C --out DIR --session S ...
    python3 -I bench/v2.py summarize PATH [PATH ...] --out DIR --baseline CASE

Every run writes DIR/manifest.json (host, build and config fingerprint)
before the first measured command, then one JSON object per line to
DIR/records.jsonl as it goes, failures included. The order of everything
comes from --seed alone. See bench/README.md.

Standard library only; Python 3.12 or newer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import re
import secrets
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

SCHEMA = "kiln-bench-v2/1"
MANIFEST = "manifest.json"
RECORDS = "records.jsonl"
CONFIG_COPY = "config.json"
DEFAULT_TIMEOUT_S = 120.0
DEFAULT_OUTPUT_LIMIT = 4096
DEFAULT_SETTLE_S = 2.0
BOOTSTRAP_ITERATIONS = 10000


class HarnessError(Exception):
    """A usage or configuration problem; reported without a traceback."""


# ---------------------------------------------------------------------------
# Configuration

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class MemorySpec:
    start_argv: list[str]
    stop_argv: list[str]
    # "id": the sandbox is named by {id}; "stdout": the start command prints
    # the runtime's own ID (last non-empty stdout line) and {sandbox} is that.
    sandbox_id_from: str = "id"


@dataclass(frozen=True)
class Case:
    name: str
    argv: list[str]
    workload: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    version_argv: list[str] | None = None
    tier: str | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    memory: MemorySpec | None = None
    timeout_s: float = DEFAULT_TIMEOUT_S


@dataclass(frozen=True)
class Config:
    path: Path
    raw: bytes
    sha256: str
    variables: dict[str, str]
    cases: dict[str, Case]
    output_limit: int
    settle_s: float


def expand(argv: Sequence[str], values: dict[str, str], workload: Sequence[str]) -> list[str]:
    """Substitutes {name} placeholders. An argument that is exactly
    "{workload}" becomes the workload's arguments; inside a longer argument
    {workload} is the shell-quoted workload. Other braces ({{.Go}} templates,
    JSON) are left alone; an unknown {name} is an error."""
    out: list[str] = []
    for arg in argv:
        if arg == "{workload}":
            out.extend(expand(workload, values, []))
            continue

        def sub(m: re.Match[str], arg: str = arg) -> str:
            name = m.group(1)
            if name == "workload":
                return shlex.join(workload)
            if name not in values:
                raise HarnessError(f"unknown placeholder {{{name}}} in {arg!r}")
            return values[name]

        out.append(_PLACEHOLDER.sub(sub, arg))
    return out


def _argv(value: Any, where: str, *, optional: bool = False) -> list[str] | None:
    if value is None and optional:
        return None
    if not isinstance(value, list) or not value or not all(isinstance(a, str) for a in value):
        raise HarnessError(f"{where} must be a non-empty list of strings")
    return list(value)


def load_config(path: Path, overrides: dict[str, str] | None = None) -> Config:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"{path}: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("cases"), dict) or not data["cases"]:
        raise HarnessError(f"{path}: needs a non-empty \"cases\" object")
    variables = {str(k): str(v) for k, v in (data.get("vars") or {}).items()}
    variables.update(overrides or {})
    defaults = data.get("defaults") or {}
    workload = _argv(data.get("workload", ["true"]), "workload")
    assert workload is not None
    cases: dict[str, Case] = {}
    for name, spec in data["cases"].items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise HarnessError(f"case name {name!r} must match [A-Za-z0-9][A-Za-z0-9_.-]*")
        where = f"cases.{name}"
        argv = _argv(spec.get("argv"), f"{where}.argv")
        memory = None
        if spec.get("memory") is not None:
            m = spec["memory"]
            id_from = m.get("sandbox_id_from", "id")
            if id_from not in ("id", "stdout"):
                raise HarnessError(f"{where}.memory.sandbox_id_from must be \"id\" or \"stdout\"")
            memory = MemorySpec(
                start_argv=_argv(m.get("start_argv"), f"{where}.memory.start_argv") or [],
                stop_argv=_argv(m.get("stop_argv"), f"{where}.memory.stop_argv") or [],
                sandbox_id_from=id_from,
            )
        env = {**(defaults.get("env") or {}), **(spec.get("env") or {})}
        case = Case(
            name=name,
            argv=argv or [],
            workload=_argv(spec.get("workload", workload), f"{where}.workload") or [],
            cwd=spec.get("cwd"),
            env={str(k): str(v) for k, v in env.items()},
            version_argv=_argv(spec.get("version_argv"), f"{where}.version_argv", optional=True),
            tier=spec.get("tier"),
            capabilities=dict(spec.get("capabilities") or {}),
            memory=memory,
            timeout_s=float(spec.get("timeout_s", defaults.get("timeout_s", DEFAULT_TIMEOUT_S))),
        )
        # Catch typos in placeholders now, not halfway through a run.
        probe = {**variables, "id": "x", "sandbox": "x"}
        for argv_ in (case.argv, case.version_argv, memory and memory.start_argv, memory and memory.stop_argv):
            if argv_:
                expand(argv_, probe, case.workload)
        cases[name] = case
    return Config(
        path=path,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        variables=variables,
        cases=cases,
        output_limit=int(defaults.get("output_limit_bytes", DEFAULT_OUTPUT_LIMIT)),
        settle_s=float((data.get("memory") or {}).get("settle_s", DEFAULT_SETTLE_S)),
    )


def select_cases(config: Config, pattern: str | None) -> list[str]:
    """Case names matching the regex (re.search), in config order."""
    names = [n for n in config.cases if pattern is None or re.search(pattern, n)]
    if not names:
        raise HarnessError(f"no case matches {pattern!r}")
    return names


# ---------------------------------------------------------------------------
# Running one command


def _utc(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, timezone.utc).isoformat(timespec="microseconds")


def _read_bounded(f: Any, limit: int) -> tuple[str, int, bool]:
    size = f.seek(0, os.SEEK_END)
    f.seek(0)
    data = f.read(limit)
    return data.decode("utf-8", "replace"), size, size > limit


def invoke(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    output_limit: int = DEFAULT_OUTPUT_LIMIT,
    before_start: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Runs argv once without a shell and times it with time.monotonic_ns.

    The clock starts right before Popen and stops when waitpid returns.
    Output goes to temporary files, not pipes, so a command that leaves a
    process holding its stdout (docker run -d, runc run -d) can't stall the
    harness. A watchdog thread kills the child after timeout_s; it's armed
    before the clock starts, so the timed path is a plain blocking wait."""
    holder: list[subprocess.Popen[bytes]] = []
    fired = threading.Event()

    def on_timeout() -> None:
        fired.set()
        if holder:
            try:
                holder[0].kill()
            except OSError:
                pass

    timer = threading.Timer(timeout_s, on_timeout)
    timer.daemon = True
    full_env = {**os.environ, **env} if env else None
    error: str | None = None
    code: int | None = None
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        timer.start()
        try:
            if before_start is not None:
                before_start()
            wall0 = time.time_ns()
            t0 = time.monotonic_ns()
            try:
                proc = subprocess.Popen(
                    list(argv), cwd=cwd, env=full_env,
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                )
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                t1 = time.monotonic_ns()
                error = f"{type(exc).__name__}: {exc}"
            else:
                holder.append(proc)
                if fired.is_set():
                    proc.kill()
                code = proc.wait()
                t1 = time.monotonic_ns()
            wall1 = time.time_ns()
        finally:
            timer.cancel()
        stdout, stdout_bytes, stdout_trunc = _read_bounded(out, output_limit)
        stderr, stderr_bytes, stderr_trunc = _read_bounded(err, output_limit)
    timed_out = fired.is_set() and code is not None
    return {
        "argv": list(argv),
        "exit_code": code,
        "signal": -code if code is not None and code < 0 else None,
        "timed_out": timed_out,
        "error": error,
        "ok": error is None and not timed_out and code == 0,
        "elapsed_ns": t1 - t0,
        "start_mono_ns": t0,
        "end_mono_ns": t1,
        "start_utc": _utc(wall0),
        "end_utc": _utc(wall1),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_truncated": stdout_trunc,
        "stderr_truncated": stderr_trunc,
    }


class RecordWriter:
    """Appends one JSON object per line and flushes after each, so a crash
    loses at most the record being written."""

    def __init__(self, path: Path) -> None:
        self._f = path.open("a", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        with self._lock:
            self._f.write(line)
            self._f.flush()

    def close(self) -> None:
        self._f.close()


def read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Host facts


@dataclass(frozen=True)
class Host:
    proc: Path = Path("/proc")
    sys: Path = Path("/sys")
    etc: Path = Path("/etc")

    def read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def boot_id(self) -> str:
        text = self.read(self.proc / "sys/kernel/random/boot_id")
        return text.strip() if text else "unknown"

    def meminfo(self) -> dict[str, int] | None:
        """/proc/meminfo as {field: value}; values are kB except HugePages_*
        counts, exactly as the kernel prints them."""
        text = self.read(self.proc / "meminfo")
        if text is None:
            return None
        out: dict[str, int] = {}
        for line in text.splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                out[key.strip()] = int(parts[0])
        return out

    def cpu_stat(self) -> dict[str, list[int]] | None:
        """The cpu* lines and scheduler counters from /proc/stat."""
        text = self.read(self.proc / "stat")
        if text is None:
            return None
        out: dict[str, list[int]] = {}
        for line in text.splitlines():
            parts = line.split()
            if parts and (parts[0].startswith("cpu") or parts[0] in ("ctxt", "processes", "procs_running", "procs_blocked")):
                out[parts[0]] = [int(p) for p in parts[1:] if p.isdigit()]
        return out

    def loadavg(self) -> list[float] | None:
        try:
            return list(os.getloadavg())
        except OSError:
            return None

    def cpu_model(self) -> str:
        text = self.read(self.proc / "cpuinfo") or ""
        fields: dict[str, str] = {}
        for line in text.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields.setdefault(key.strip(), value.strip())
        for key in ("model name", "Model", "Hardware"):
            if key in fields:
                return fields[key]
        if "CPU implementer" in fields:
            return f"implementer {fields['CPU implementer']} part {fields.get('CPU part', '?')}"
        return platform.processor() or platform.machine()

    def cgroup_mode(self) -> str:
        root = self.sys / "fs/cgroup"
        if (root / "cgroup.controllers").exists():
            return "v2 (unified)"
        if (root / "unified").exists():
            return "hybrid"
        if root.exists():
            return "v1"
        return "unavailable"

    def governors(self) -> dict[str, int] | None:
        counts: dict[str, int] = {}
        for path in sorted(self.sys.glob("devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")):
            name = (self.read(path) or "").strip()
            counts[name] = counts.get(name, 0) + 1
        return counts or None

    def os_release(self) -> dict[str, str] | None:
        text = self.read(self.etc / "os-release")
        if text is None:
            return None
        out = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.startswith("#"):
                out[key.strip()] = value.strip().strip("\"'")
        return out


def used_kib(meminfo: dict[str, int] | None) -> int | None:
    if not meminfo or "MemTotal" not in meminfo or "MemAvailable" not in meminfo:
        return None
    return meminfo["MemTotal"] - meminfo["MemAvailable"]


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def executable_info(name: str, env: dict[str, str]) -> dict[str, Any]:
    path = name if os.sep in name else shutil.which(name, path=env.get("PATH", os.environ.get("PATH")))
    if path is None:
        return {"name": name, "error": "not found on PATH"}
    real = os.path.realpath(path)
    try:
        return {"name": name, "realpath": real, "sha256": _sha256_file(real)}
    except OSError as exc:
        return {"name": name, "realpath": real, "error": f"{type(exc).__name__}: {exc}"}


def git_info() -> dict[str, Any]:
    repo = Path(__file__).resolve().parent

    # safe.directory: under sudo, git otherwise refuses a repo owned by the user.
    def git(*args: str) -> str | None:
        try:
            r = subprocess.run(["git", "-c", f"safe.directory={repo}", "-C", str(repo), *args],
                               capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        return r.stdout if r.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain")
    return {
        "commit": commit.strip() if commit else None,
        "dirty": None if status is None else bool(status.strip()),
        "dirty_paths": None if status is None else [l[3:] for l in status.splitlines()][:200],
    }


# ---------------------------------------------------------------------------
# Run directories and manifests


@dataclass
class Run:
    """One execution of a measuring mode: its output directory, identity and
    the plan parameters that --resume must match."""

    mode: str
    out: Path
    session: str
    seed: int
    config: Config
    cases: list[str]
    params: dict[str, Any]
    host: Host
    resume: bool
    run_id: str = field(default_factory=lambda: secrets.token_hex(4))
    boot_id: str = "unknown"
    done: set[int] = field(default_factory=set)
    writer: RecordWriter | None = None

    def env(self, case: Case) -> dict[str, str]:
        return {**os.environ, **case.env}

    def values(self, **extra: str) -> dict[str, str]:
        return {**self.config.variables, **extra}

    def new_id(self, *parts: object) -> str:
        """A unique, safe sandbox/container name: lowercase letters, digits
        and dashes, unique per run segment (the run ID changes on resume)."""
        return "-".join(["kb", self.run_id, *(str(p) for p in parts)])

    def common(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "mode": self.mode, "session": self.session,
                "boot_id": self.boot_id, "run_id": self.run_id}

    def write(self, record: dict[str, Any]) -> None:
        assert self.writer is not None
        self.writer.write({**self.common(), **record})


def _identity(run: Run) -> dict[str, Any]:
    return {
        "mode": run.mode,
        "session": run.session,
        "seed": run.seed,
        "config_sha256": run.config.sha256,
        "cases": run.cases,
        "params": run.params,
        "boot_id": run.boot_id,
    }


def build_manifest(run: Run) -> dict[str, Any]:
    cfg = run.config
    executables: dict[str, dict[str, Any]] = {}
    versions: dict[str, Any] = {}
    for name in run.cases:
        case = cfg.cases[name]
        env = run.env(case)
        argvs = [case.argv, case.version_argv]
        if case.memory:
            argvs += [case.memory.start_argv, case.memory.stop_argv]
        for argv in argvs:
            if argv:
                exe = expand(argv[:1], run.values(id="x", sandbox="x"), case.workload)[0]
                if exe not in executables:
                    executables[exe] = executable_info(exe, env)
        if case.version_argv:
            argv = expand(case.version_argv, run.values(id=run.new_id("version"), sandbox="x"), case.workload)
            r = invoke(argv, cwd=case.cwd, env=case.env, timeout_s=30, output_limit=cfg.output_limit)
            versions[name] = {k: r[k] for k in ("argv", "exit_code", "ok", "error", "stdout", "stderr", "timed_out")}
        else:
            versions[name] = None
    meminfo = run.host.meminfo() or {}
    now = time.time_ns()
    return {
        "schema": SCHEMA,
        "created_utc": _utc(now),
        **_identity(run),
        "argv": sys.argv,
        "config_path": str(cfg.path),
        "vars": cfg.variables,
        "case_specs": {
            n: {"tier": cfg.cases[n].tier, "capabilities": cfg.cases[n].capabilities,
                "argv": cfg.cases[n].argv, "workload": cfg.cases[n].workload}
            for n in run.cases
        },
        "git": git_info(),
        "hostname": socket.gethostname(),
        "uname": platform.uname()._asdict(),
        "os_release": run.host.os_release(),
        "python": {"version": sys.version, "executable": sys.executable,
                   "implementation": platform.python_implementation()},
        "cpu": {"count": os.cpu_count(), "model": run.host.cpu_model(), "governors": run.host.governors()},
        "memory": {k: meminfo.get(k) for k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")},
        "cgroup_mode": run.host.cgroup_mode(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "root": is_root(),
        "executables": executables,
        "versions": versions,
        "segments": [{"run_id": run.run_id, "started_utc": _utc(now), "argv": sys.argv}],
    }


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def open_run(run: Run) -> None:
    """Creates the run directory and manifest, or checks a --resume against
    the existing manifest and notes which plan slots are already done."""
    run.boot_id = run.host.boot_id()
    manifest_path = run.out / MANIFEST
    if run.resume:
        if not manifest_path.exists():
            raise HarnessError(f"--resume: {manifest_path} does not exist")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        mine = _identity(run)
        for key, value in mine.items():
            if manifest.get(key) != value:
                raise HarnessError(
                    f"--resume refused: {key} differs (manifest {manifest.get(key)!r}, now {value!r})")
        copy = run.out / CONFIG_COPY
        if not copy.exists() or hashlib.sha256(copy.read_bytes()).hexdigest() != run.config.sha256:
            raise HarnessError(f"--resume refused: {copy} is missing or differs from {run.config.path}")
        slot_key = {"latency": "ordinal", "concurrency": "batch", "memory": "point"}[run.mode]
        done_kind = {"latency": "latency", "concurrency": "concurrency_batch", "memory": "memory_point"}[run.mode]
        run.done = {r[slot_key] for r in read_records(run.out / RECORDS) if r.get("kind") == done_kind}
        manifest.setdefault("segments", []).append(
            {"run_id": run.run_id, "started_utc": _utc(time.time_ns()), "argv": sys.argv,
             "git": git_info(), "slots_already_done": len(run.done)})
        _write_json(manifest_path, manifest)
    else:
        if run.out.exists():
            raise HarnessError(f"{run.out} already exists; pick a new --out or pass --resume")
        run.out.mkdir(parents=True)
        (run.out / CONFIG_COPY).write_bytes(run.config.raw)
        _write_json(manifest_path, build_manifest(run))
    run.writer = RecordWriter(run.out / RECORDS)


# ---------------------------------------------------------------------------
# Seeded plans


def balanced_orders(items: Sequence[str], n: int, rng: random.Random) -> list[list[str]]:
    """n orderings of items, each a permutation. Every block of len(items)
    consecutive orderings is a randomized Latin square, so each item also
    takes each position exactly once per block: no case is always first."""
    k = len(items)
    out: list[list[str]] = []
    while len(out) < n:
        rows, cols, syms = list(range(k)), list(range(k)), list(items)
        rng.shuffle(rows)
        rng.shuffle(cols)
        rng.shuffle(syms)
        out.extend([syms[(r + c) % k] for c in cols] for r in rows)
    return out[:n]


def latency_plan(cases: Sequence[str], gaps: Sequence[float], runs: int, warmups: int, seed: int) -> list[dict[str, Any]]:
    """Warmup rounds, then measured rounds. In every round each gap comes up
    once (in shuffled order) and, for each gap, every case runs once."""
    rng = random.Random(f"latency:{seed}")
    plan: list[dict[str, Any]] = []
    for warmup, rounds in ((True, warmups), (False, runs)):
        orders = {g: balanced_orders(cases, rounds, rng) for g in gaps}
        for rnd in range(rounds):
            gap_order = list(gaps)
            rng.shuffle(gap_order)
            for gap in gap_order:
                for pos, case in enumerate(orders[gap][rnd]):
                    plan.append({"ordinal": len(plan), "warmup": warmup, "round": rnd,
                                 "gap_ms": gap, "position": pos, "case": case})
    return plan


def concurrency_plan(cases: Sequence[str], levels: Sequence[int], batches: int, seed: int) -> list[dict[str, Any]]:
    """Each block runs every (case, level) pair once in shuffled order."""
    rng = random.Random(f"concurrency:{seed}")
    plan: list[dict[str, Any]] = []
    for block in range(batches):
        pairs = [(c, lv) for c in cases for lv in levels]
        rng.shuffle(pairs)
        for pos, (case, level) in enumerate(pairs):
            plan.append({"batch": len(plan), "block": block, "position": pos, "case": case, "level": level})
    return plan


def memory_plan(cases: Sequence[str], counts: Sequence[int], repeats: int, seed: int) -> list[dict[str, Any]]:
    """Each repeat measures every (case, count) pair once in shuffled order."""
    rng = random.Random(f"memory:{seed}")
    plan: list[dict[str, Any]] = []
    for repeat in range(repeats):
        pairs = [(c, n) for c in cases for n in counts]
        rng.shuffle(pairs)
        for pos, (case, count) in enumerate(pairs):
            plan.append({"point": len(plan), "repeat": repeat, "position": pos, "case": case, "count": count})
    return plan


# ---------------------------------------------------------------------------
# Modes


def run_latency(run: Run, plan: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"invocations": 0, "failures": 0}
    for slot in plan:
        if slot["ordinal"] in run.done:
            continue
        case = run.config.cases[slot["case"]]
        inv_id = run.new_id(f"{slot['ordinal']:06d}")
        argv = expand(case.argv, run.values(id=inv_id), case.workload)
        time.sleep(slot["gap_ms"] / 1000)
        result = invoke(argv, cwd=case.cwd, env=case.env, timeout_s=case.timeout_s,
                        output_limit=run.config.output_limit)
        run.write({"kind": "latency", **slot, "invocation_id": inv_id, **result})
        counts["invocations"] += 1
        counts["failures"] += not result["ok"]
    return counts


def _cpu_busy(before: dict[str, list[int]] | None, after: dict[str, list[int]] | None) -> float | None:
    if not before or not after or "cpu" not in before or "cpu" not in after:
        return None
    delta = [a - b for a, b in zip(after["cpu"], before["cpu"])]
    total = sum(delta[:8])  # user..steal; guest time is already in user
    idle = sum(delta[3:5])  # idle + iowait
    return (total - idle) / total if total > 0 else None


def run_batch(run: Run, case: Case, level: int, ids: list[str]) -> list[dict[str, Any]]:
    """Starts `level` commands at once: one thread per command waits on a
    barrier, then each times its own Popen-to-waitpid."""
    barrier = threading.Barrier(level, timeout=60)
    results: list[dict[str, Any] | None] = [None] * level

    def go() -> None:
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass

    def worker(k: int) -> None:
        argv = expand(case.argv, run.values(id=ids[k]), case.workload)
        results[k] = invoke(argv, cwd=case.cwd, env=case.env, timeout_s=case.timeout_s,
                            output_limit=run.config.output_limit, before_start=go)

    threads = [threading.Thread(target=worker, args=(k,), daemon=True) for k in range(level)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [r for r in results if r is not None]


def run_concurrency(run: Run, plan: list[dict[str, Any]], gap_ms: float) -> dict[str, int]:
    counts = {"invocations": 0, "failures": 0}
    for slot in plan:
        if slot["batch"] in run.done:
            continue
        case = run.config.cases[slot["case"]]
        level = slot["level"]
        ids = [run.new_id(f"b{slot['batch']:05d}", f"{k:03d}") for k in range(level)]
        time.sleep(gap_ms / 1000)
        host = run.host
        cpu0, mem0, load0 = host.cpu_stat(), host.meminfo(), host.loadavg()
        results = run_batch(run, case, level, ids)
        cpu1, mem1, load1 = host.cpu_stat(), host.meminfo(), host.loadavg()
        for k, (inv_id, r) in enumerate(zip(ids, results)):
            run.write({"kind": "concurrency_invocation", **slot, "slot": k, "invocation_id": inv_id, **r})
        ok = sum(r["ok"] for r in results)
        starts = [r["start_mono_ns"] for r in results]
        ends = [r["end_mono_ns"] for r in results]
        wall = max(ends) - min(starts)
        run.write({
            "kind": "concurrency_batch", **slot,
            "gap_ms": gap_ms,
            "invocation_ids": ids,
            "attempted": len(results),
            "successes": ok,
            "failures": len(results) - ok,
            "timeouts": sum(r["timed_out"] for r in results),
            "spawn_errors": sum(r["error"] is not None for r in results),
            "wall_ns": wall,
            "start_spread_ns": max(starts) - min(starts),
            "completions_per_s": ok / (wall / 1e9) if wall > 0 else None,
            "cpu_stat_before": cpu0, "cpu_stat_after": cpu1,
            "cpu_busy_fraction": _cpu_busy(cpu0, cpu1),
            "meminfo_before": mem0, "meminfo_after": mem1,
            "loadavg_before": load0, "loadavg_after": load1,
        })
        counts["invocations"] += len(results)
        counts["failures"] += len(results) - ok
    return counts


def settle(run: Run, settle_s: float) -> str:
    """As root: sync, drop the page cache, then wait. Otherwise just wait;
    the returned status says which happened."""
    status = "skipped: not root"
    if is_root():
        try:
            os.sync()
            (run.host.proc / "sys/vm/drop_caches").write_text("3\n")
            status = "dropped"
        except OSError as exc:
            status = f"failed: {type(exc).__name__}: {exc}"
    time.sleep(settle_s)
    return status


def run_memory_point(run: Run, slot: dict[str, Any], settle_s: float) -> dict[str, int]:
    case = run.config.cases[slot["case"]]
    spec = case.memory
    assert spec is not None
    started: list[dict[str, Any]] = []  # {"invocation_id", "sandbox", "ok"}
    point: dict[str, Any] = {"kind": "memory_point", **slot, "settle_s": settle_s, "root": is_root(),
                             "complete": False, "aborted": False, "error": None}
    failures = 0
    try:
        point["cache_drop_before"] = settle(run, settle_s)
        point["meminfo_before"] = run.host.meminfo()
        for k in range(slot["count"]):
            inv_id = run.new_id(f"m{slot['point']:05d}", f"{k:04d}")
            argv = expand(spec.start_argv, run.values(id=inv_id, sandbox=inv_id), case.workload)
            r = invoke(argv, cwd=case.cwd, env=case.env, timeout_s=case.timeout_s,
                       output_limit=run.config.output_limit)
            sandbox: str | None = inv_id
            if spec.sandbox_id_from == "stdout":
                lines = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
                sandbox = lines[-1] if r["ok"] and lines else None
            started.append({"invocation_id": inv_id, "sandbox": sandbox, "ok": r["ok"]})
            run.write({"kind": "memory_start", **slot, "slot": k, "invocation_id": inv_id,
                       "sandbox_id": sandbox, **r})
            if not r["ok"]:
                failures += 1
                point["aborted"] = True
                break
        point["cache_drop_after"] = settle(run, settle_s)
        point["meminfo_after"] = run.host.meminfo()
        point["complete"] = not point["aborted"]
    except BaseException as exc:
        point["aborted"] = True
        point["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        for k, s in reversed(list(enumerate(started))):
            if s["sandbox"] is None:
                run.write({"kind": "memory_stop", **slot, "slot": k, "invocation_id": s["invocation_id"],
                           "sandbox_id": None, "ok": False, "skipped": True,
                           "error": "start printed no sandbox ID; nothing to stop"})
                continue
            argv = expand(spec.stop_argv, run.values(id=s["invocation_id"], sandbox=s["sandbox"]), case.workload)
            r = invoke(argv, cwd=case.cwd, env=case.env, timeout_s=case.timeout_s,
                       output_limit=run.config.output_limit)
            run.write({"kind": "memory_stop", **slot, "slot": k, "invocation_id": s["invocation_id"],
                       "sandbox_id": s["sandbox"], "skipped": False, **r})
            failures += not r["ok"]
        point["count_running"] = sum(s["ok"] for s in started)
        point["sandbox_ids"] = [s["sandbox"] for s in started]
        point["invocation_ids"] = [s["invocation_id"] for s in started]
        before, after = used_kib(point.get("meminfo_before")), used_kib(point.get("meminfo_after"))
        point["used_kib_before"] = before
        point["used_kib_after"] = after
        point["used_delta_kib"] = after - before if before is not None and after is not None else None
        run.write(point)
    return {"invocations": len(started), "failures": failures}


def run_memory(run: Run, plan: list[dict[str, Any]], settle_s: float) -> dict[str, int]:
    counts = {"invocations": 0, "failures": 0}
    for slot in plan:
        if slot["point"] in run.done:
            continue
        c = run_memory_point(run, slot, settle_s)
        counts["invocations"] += c["invocations"]
        counts["failures"] += c["failures"]
    return counts


# ---------------------------------------------------------------------------
# Statistics


def percentile(values: Sequence[float], p: float) -> float:
    """Linear interpolation between closest ranks (NumPy's default, R type 7)."""
    if not values:
        raise ValueError("percentile of no values")
    xs = sorted(values)
    h = (len(xs) - 1) * p / 100
    lo = math.floor(h)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (h - lo) * (xs[hi] - xs[lo])


def describe(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {k: None for k in ("mean", "p50", "p95", "p99", "min", "max")}
    return {
        "mean": statistics.fmean(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "min": min(values),
        "max": max(values),
    }


def geomean(values: Sequence[float]) -> float:
    return math.exp(statistics.fmean(math.log(v) for v in values))


def bootstrap_ci(values: Sequence[float], seed: int, iterations: int = BOOTSTRAP_ITERATIONS) -> tuple[float, float]:
    """Percentile bootstrap 95% CI of the geometric mean, resampling the
    given values (one per session) with replacement."""
    rng = random.Random(f"bootstrap:{seed}")
    n = len(values)
    stats = [geomean([values[rng.randrange(n)] for _ in range(n)]) for _ in range(iterations)]
    return percentile(stats, 2.5), percentile(stats, 97.5)


def ols(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float] | None:
    """Ordinary least squares (slope, intercept), or None without two
    distinct x values."""
    if len(xs) < 2 or len(set(xs)) < 2:
        return None
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return slope, my - slope * mx


# ---------------------------------------------------------------------------
# Summaries


def _load_inputs(paths: Sequence[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.rglob("*.jsonl")))
        elif p.exists():
            files.append(p)
        else:
            raise HarnessError(f"{p} does not exist")
    seen: set[Path] = set()
    records: list[dict[str, Any]] = []
    used: list[str] = []
    for f in files:
        real = f.resolve()
        if real in seen:
            continue
        seen.add(real)
        used.append(str(f))
        records.extend(r for r in read_records(f) if r.get("schema") == SCHEMA)
    return records, used


def _ms(ns: float) -> float:
    return ns / 1e6


def summarize_latency(records: list[dict[str, Any]], baseline: str, seed: int, iterations: int) -> dict[str, Any]:
    groups: dict[tuple[str, str, float], list[dict[str, Any]]] = {}
    for r in records:
        if r.get("kind") == "latency" and not r.get("warmup"):
            groups.setdefault((r["case"], r["session"], float(r["gap_ms"])), []).append(r)
    rows = []
    medians: dict[tuple[str, str, float], float] = {}
    for (case, session, gap), rs in sorted(groups.items()):
        ok = [_ms(r["elapsed_ns"]) for r in rs if r["ok"]]
        rows.append({"case": case, "session": session, "gap_ms": gap, "n": len(rs),
                     "failures": len(rs) - len(ok), "ms": describe(ok)})
        if ok:
            medians[(case, session, gap)] = percentile(ok, 50)
    ratios = []
    for case, gap in sorted({(c, g) for c, _, g in medians}):
        if case == baseline:
            continue
        per_session = {s: medians[(case, s, gap)] / medians[(baseline, s, gap)]
                       for (c, s, g) in medians
                       if c == case and g == gap and (baseline, s, gap) in medians
                       and medians[(baseline, s, gap)] > 0}
        if not per_session:
            continue
        values = [per_session[s] for s in sorted(per_session)]
        entry: dict[str, Any] = {
            "case": case, "baseline": baseline, "gap_ms": gap,
            "paired_sessions": len(values),
            "session_median_ratios": dict(sorted(per_session.items())),
            "min": min(values), "median": statistics.median(values), "max": max(values),
            "geomean": geomean(values) if all(v > 0 for v in values) else None,
            "ci95": None,
        }
        if len(values) >= 2 and all(v > 0 for v in values):
            lo, hi = bootstrap_ci(values, seed, iterations)
            entry["ci95"] = {"low": lo, "high": hi, "statistic": "geometric mean of per-session median ratios",
                             "method": f"percentile bootstrap over sessions, {iterations} resamples, seed {seed}"}
            if len(values) < 5:
                entry["ci_note"] = f"only {len(values)} sessions; the interval is coarse"
        else:
            entry["ci_note"] = "no CI: needs at least 2 paired sessions (separate boots)"
        ratios.append(entry)
    return {"groups": rows, "ratios": ratios}


def summarize_concurrency(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    batches = [r for r in records if r.get("kind") == "concurrency_batch"]
    complete = {(r["session"], r["run_id"], r["batch"]) for r in batches}
    invs: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for r in records:
        if r.get("kind") == "concurrency_invocation" and (r["session"], r["run_id"], r["batch"]) in complete:
            invs.setdefault((r["case"], r["level"]), []).append(r)
    by_key: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for b in batches:
        by_key.setdefault((b["case"], b["level"]), []).append(b)
    rows = []
    for (case, level), bs in sorted(by_key.items()):
        tput = [b["completions_per_s"] for b in bs if b["completions_per_s"] is not None]
        ok_ms = [_ms(r["elapsed_ns"]) for r in invs.get((case, level), []) if r["ok"]]
        rows.append({
            "case": case, "level": level,
            "sessions": sorted({b["session"] for b in bs}),
            "batches": len(bs),
            "invocations": sum(b["attempted"] for b in bs),
            "failures": sum(b["failures"] for b in bs),
            "timeouts": sum(b["timeouts"] for b in bs),
            "completions_per_s": describe(tput),
            "batch_wall_ms_p50": percentile([_ms(b["wall_ns"]) for b in bs], 50),
            "invocation_ms": describe(ok_ms),
        })
    return rows


def summarize_memory(records: list[dict[str, Any]]) -> dict[str, Any]:
    series: dict[tuple[str, str, str, int], list[dict[str, Any]]] = {}
    excluded = 0
    for r in records:
        if r.get("kind") != "memory_point":
            continue
        if not r.get("complete") or r.get("used_delta_kib") is None:
            excluded += 1
            continue
        series.setdefault((r["case"], r["session"], r["run_id"], r["repeat"]), []).append(r)
    fits = []
    for (case, session, run_id, repeat), pts in sorted(series.items()):
        xs = [float(p["count_running"]) for p in pts]
        ys = [float(p["used_delta_kib"]) for p in pts]
        fit = ols(xs, ys)
        fits.append({"case": case, "session": session, "run_id": run_id, "repeat": repeat,
                     "points": len(pts), "counts": sorted(int(x) for x in xs),
                     "slope_kib_per_sandbox": fit[0] if fit else None,
                     "intercept_kib": fit[1] if fit else None})
    cases = []
    for case in sorted({f["case"] for f in fits}):
        slopes = [f["slope_kib_per_sandbox"] for f in fits if f["case"] == case and f["slope_kib_per_sandbox"] is not None]
        cases.append({
            "case": case,
            "fits": len(slopes),
            "sessions": sorted({f["session"] for f in fits if f["case"] == case}),
            "slope_kib_per_sandbox": {
                "mean": statistics.fmean(slopes) if slopes else None,
                "median": statistics.median(slopes) if slopes else None,
                "stdev": statistics.stdev(slopes) if len(slopes) > 1 else None,
                "min": min(slopes) if slopes else None,
                "max": max(slopes) if slopes else None,
            },
        })
    return {"fits": fits, "cases": cases, "excluded_points": excluded}


def _session_warnings(records: list[dict[str, Any]]) -> list[str]:
    boots: dict[str, set[str]] = {}
    for r in records:
        boots.setdefault(r.get("session", "?"), set()).add(r.get("boot_id", "unknown"))
    warnings = [f"session {s!r} spans {len(b)} boot IDs" for s, b in sorted(boots.items()) if len(b) > 1]
    owners: dict[str, list[str]] = {}
    for s, bs in boots.items():
        for b in bs:
            if b != "unknown":
                owners.setdefault(b, []).append(s)
    warnings += [f"sessions {sorted(ss)} share boot ID {b}; they are not independent replicates"
                 for b, ss in sorted(owners.items()) if len(ss) > 1]
    return warnings


def _f(x: Any, digits: int = 3) -> str:
    if x is None:
        return "–"
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    return str(x)


def render_markdown(summary: dict[str, Any]) -> str:
    out = ["# Benchmark summary", "",
           f"Baseline: `{summary['baseline']}`. Inputs: {', '.join(f'`{p}`' for p in summary['inputs'])}.", ""]
    for w in summary["warnings"]:
        out.append(f"> Warning: {w}")
    lat = summary["latency"]
    if lat["groups"]:
        out += ["## Latency (ms, successful invocations)", "",
                "p95/p99 are percentiles of individual invocations, not confidence intervals.", "",
                "| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |",
                "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for g in lat["groups"]:
            m = g["ms"]
            out.append(f"| {g['case']} | {g['session']} | {_f(g['gap_ms'], 1)} | {g['n']} | {g['failures']} | "
                       + " | ".join(_f(m[k]) for k in ("mean", "p50", "p95", "p99", "min", "max")) + " |")
        out.append("")
    if lat["ratios"]:
        out += [f"## Ratio to `{summary['baseline']}` (per-session median ratios)", "",
                "Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over "
                "sessions and appears only with at least 2 paired sessions.", "",
                "| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |",
                "|---|---:|---:|---:|---:|---:|---:|---|"]
        for r in lat["ratios"]:
            ci = (f"{_f(r['ci95']['low'])}–{_f(r['ci95']['high'])}" if r["ci95"]
                  else "none (fewer than 2 sessions)")
            if r["ci95"] and r.get("ci_note"):
                ci += f" ({r['ci_note']})"
            out.append(f"| {r['case']} | {_f(r['gap_ms'], 1)} | {r['paired_sessions']} | {_f(r['min'])} | "
                       f"{_f(r['median'])} | {_f(r['max'])} | {_f(r['geomean'])} | {ci} |")
        out.append("")
    if summary["concurrency"]:
        out += ["## Concurrency", "",
                "Throughput is successful completions per second of batch wall time; latency is per invocation (ms).", "",
                "| case | level | batches | invocations | failures | completions/s p50 | completions/s mean | "
                "inv p50 | inv p95 | inv p99 |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for c in summary["concurrency"]:
            out.append(f"| {c['case']} | {c['level']} | {c['batches']} | {c['invocations']} | {c['failures']} | "
                       f"{_f(c['completions_per_s']['p50'], 1)} | {_f(c['completions_per_s']['mean'], 1)} | "
                       f"{_f(c['invocation_ms']['p50'])} | {_f(c['invocation_ms']['p95'])} | "
                       f"{_f(c['invocation_ms']['p99'])} |")
        out.append("")
    mem = summary["memory"]
    if mem["cases"]:
        out += ["## Memory: OLS slope of used KiB growth vs running sandboxes", "",
                "Used = MemTotal − MemAvailable; one fit per case and repeat, summarized across repeats.", "",
                "| case | fits | sessions | mean KiB/sandbox | median | stdev | min | max |",
                "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for c in mem["cases"]:
            s = c["slope_kib_per_sandbox"]
            out.append(f"| {c['case']} | {c['fits']} | {len(c['sessions'])} | {_f(s['mean'], 0)} | "
                       f"{_f(s['median'], 0)} | {_f(s['stdev'], 0)} | {_f(s['min'], 0)} | {_f(s['max'], 0)} |")
        if mem["excluded_points"]:
            out.append(f"\n{mem['excluded_points']} incomplete or failed points were left out of the fits.")
        out.append("")
    return "\n".join(out)


def summarize(paths: Sequence[Path], out: Path, baseline: str, seed: int = 0,
              iterations: int = BOOTSTRAP_ITERATIONS) -> dict[str, Any]:
    records, used = _load_inputs(paths)
    if not records:
        raise HarnessError("no harness records found")
    summary = {
        "schema": SCHEMA,
        "inputs": used,
        "baseline": baseline,
        "warnings": _session_warnings(records),
        "latency": summarize_latency(records, baseline, seed, iterations),
        "concurrency": summarize_concurrency(records),
        "memory": summarize_memory(records),
    }
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "summary.json", summary)
    (out / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# CLI


def _numbers(kind: Callable[[str], Any], minimum: float) -> Callable[[str], list[Any]]:
    def parse(text: str) -> list[Any]:
        try:
            values = [kind(v) for v in text.split(",") if v.strip()]
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected comma-separated numbers, got {text!r}") from None
        if not values or any(v < minimum for v in values):
            raise argparse.ArgumentTypeError(f"expected numbers >= {minimum}, got {text!r}")
        if len(set(values)) != len(values):
            raise argparse.ArgumentTypeError(f"duplicate values in {text!r}")
        return values
    return parse


def _var(text: str) -> tuple[str, str]:
    name, sep, value = text.partition("=")
    if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise argparse.ArgumentTypeError(f"expected NAME=VALUE, got {text!r}")
    return name, value


def _nonneg_int(text: str) -> int:
    v = int(text)
    if v < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="v2.py", description=__doc__.split("\n\n")[0] if __doc__ else None)
    sub = p.add_subparsers(dest="mode", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", type=Path, required=True)
        sp.add_argument("--out", type=Path, required=True, help="new run directory")
        sp.add_argument("--session", required=True, help="replication unit, normally one per boot")
        sp.add_argument("--seed", type=int, required=True)
        sp.add_argument("--case", help="regex (re.search) selecting case names")
        sp.add_argument("--var", type=_var, action="append", default=[], metavar="NAME=VALUE",
                        help="override a config variable such as kiln")
        sp.add_argument("--resume", action="store_true",
                        help="append to an existing run with the same manifest identity")
        sp.add_argument("--proc-root", type=Path, default=Path("/proc"), help=argparse.SUPPRESS)

    lat = sub.add_parser("latency", help="sequential invocations, interleaved and gapped")
    common(lat)
    lat.add_argument("--runs", type=_nonneg_int, required=True)
    lat.add_argument("--warmups", type=_nonneg_int, required=True)
    lat.add_argument("--gap-ms", type=_numbers(float, 0), required=True, help="comma-separated pauses")

    con = sub.add_parser("concurrency", help="batches of simultaneous invocations")
    common(con)
    con.add_argument("--levels", type=_numbers(int, 1), required=True)
    con.add_argument("--batches", type=_nonneg_int, required=True)
    con.add_argument("--gap-ms", type=float, required=True, help="quiet pause before each batch")

    mem = sub.add_parser("memory", help="host memory growth with N idle sandboxes")
    common(mem)
    mem.add_argument("--counts", type=_numbers(int, 0), required=True)
    mem.add_argument("--repeats", type=_nonneg_int, required=True)
    mem.add_argument("--settle-s", type=float, help="wait after cache drop (default: config memory.settle_s)")

    summ = sub.add_parser("summarize", help="summary.json and summary.md from records")
    summ.add_argument("paths", type=Path, nargs="+", help="records.jsonl files or run directories")
    summ.add_argument("--out", type=Path, required=True)
    summ.add_argument("--baseline", required=True, help="case the others are compared to")
    summ.add_argument("--bootstrap-seed", type=int, default=0)
    summ.add_argument("--bootstrap-iterations", type=int, default=BOOTSTRAP_ITERATIONS)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "summarize":
            s = summarize(args.paths, args.out, args.baseline, args.bootstrap_seed, args.bootstrap_iterations)
            if not any(r["case"] == args.baseline for r in s["latency"]["groups"]) and s["latency"]["groups"]:
                print(f"warning: baseline {args.baseline!r} has no latency records", file=sys.stderr)
            print(f"wrote {args.out / 'summary.json'} and {args.out / 'summary.md'}", file=sys.stderr)
            return 0
        config = load_config(args.config, dict(args.var))
        cases = select_cases(config, args.case)
        if args.mode == "latency":
            params: dict[str, Any] = {"runs": args.runs, "warmups": args.warmups, "gap_ms": args.gap_ms}
        elif args.mode == "concurrency":
            params = {"levels": args.levels, "batches": args.batches, "gap_ms": args.gap_ms}
        else:
            missing = [c for c in cases if config.cases[c].memory is None]
            if missing:
                print(f"skipping cases without memory start/stop: {', '.join(missing)}", file=sys.stderr)
            cases = [c for c in cases if config.cases[c].memory is not None]
            if not cases:
                raise HarnessError("no selected case defines memory start/stop")
            settle_s = args.settle_s if args.settle_s is not None else config.settle_s
            params = {"counts": args.counts, "repeats": args.repeats, "settle_s": settle_s}
        run = Run(mode=args.mode, out=args.out, session=args.session, seed=args.seed, config=config,
                  cases=cases, params=params, host=Host(proc=args.proc_root), resume=args.resume)
        open_run(run)
        try:
            if args.mode == "latency":
                counts = run_latency(run, latency_plan(cases, args.gap_ms, args.runs, args.warmups, args.seed))
            elif args.mode == "concurrency":
                counts = run_concurrency(run, concurrency_plan(cases, args.levels, args.batches, args.seed),
                                         args.gap_ms)
            else:
                if not is_root():
                    print("not root: page cache is not dropped before memory readings", file=sys.stderr)
                counts = run_memory(run, memory_plan(cases, args.counts, args.repeats, args.seed),
                                    params["settle_s"])
        finally:
            assert run.writer is not None
            run.writer.close()
        print(f"{args.mode}: {counts['invocations']} invocations, {counts['failures']} failures "
              f"-> {args.out / RECORDS}", file=sys.stderr)
        return 0
    except HarnessError as exc:
        print(f"v2.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
