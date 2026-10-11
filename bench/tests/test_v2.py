"""Tests for bench/v2.py. No root and no runtimes: every case is a small
Python child process, and /proc is a fake directory.

    python3 -I -m unittest discover -s bench/tests -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

BENCH = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True  # keep bench/ free of __pycache__
_spec = importlib.util.spec_from_file_location("v2", BENCH / "v2.py")
assert _spec and _spec.loader
v2 = importlib.util.module_from_spec(_spec)
sys.modules["v2"] = v2
_spec.loader.exec_module(v2)

PY = sys.executable


def py(code: str, *args: str) -> list[str]:
    return [PY, "-I", "-c", code, *args]


def fake_proc(root: Path, boot_id: str = "boot-a", used_kib: int = 1000) -> Path:
    proc = root / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True, exist_ok=True)
    (proc / "sys/kernel/random/boot_id").write_text(boot_id + "\n")
    (proc / "meminfo").write_text(
        f"MemTotal:       16000 kB\nMemFree:         9000 kB\nMemAvailable:   {16000 - used_kib} kB\n"
        "SwapTotal:          0 kB\nHugePages_Total:       0\n")
    (proc / "stat").write_text("cpu  10 0 10 100 0 0 0 0 0 0\ncpu0 10 0 10 100 0 0 0 0 0 0\nctxt 5\n")
    return proc


def write_config(path: Path, cases: dict[str, Any], **extra: Any) -> Path:
    path.write_text(json.dumps({"cases": cases, "defaults": {"timeout_s": 30}, **extra}))
    return path


def run_main(*argv: str) -> tuple[int, str]:
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = v2.main(list(argv))
    return code, err.getvalue()


class Tmp(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()


class OrderingTest(unittest.TestCase):
    cases = ["a", "b", "c", "d"]

    def test_balanced_orders_are_latin_square_blocks(self) -> None:
        orders = v2.balanced_orders(self.cases, 8, __import__("random").Random(1))
        self.assertEqual(len(orders), 8)
        for order in orders:
            self.assertEqual(sorted(order), self.cases)
        for block in (orders[:4], orders[4:]):
            for pos in range(4):
                self.assertEqual(sorted(o[pos] for o in block), self.cases)

    def test_latency_plan_is_interleaved_seeded_and_complete(self) -> None:
        plan = v2.latency_plan(self.cases, [0.0, 50.0], runs=6, warmups=2, seed=42)
        self.assertEqual(plan, v2.latency_plan(self.cases, [0.0, 50.0], runs=6, warmups=2, seed=42))
        self.assertNotEqual(plan, v2.latency_plan(self.cases, [0.0, 50.0], runs=6, warmups=2, seed=43))
        self.assertEqual([s["ordinal"] for s in plan], list(range(len(plan))))
        self.assertEqual(len(plan), (6 + 2) * 2 * 4)
        groups: dict[tuple[bool, int, float], list[str]] = {}
        for s in plan:
            groups.setdefault((s["warmup"], s["round"], s["gap_ms"]), []).append(s["case"])
        self.assertEqual(len(groups), (6 + 2) * 2)
        for cases in groups.values():
            self.assertEqual(sorted(cases), self.cases)  # every case exactly once per round and gap
        # Warmups all come first and aren't counted as measured rounds.
        first_measured = next(i for i, s in enumerate(plan) if not s["warmup"])
        self.assertTrue(all(s["warmup"] for s in plan[:first_measured]))
        self.assertEqual(Counter(s["case"] for s in plan if not s["warmup"]), Counter({c: 12 for c in self.cases}))
        # Not blocks: no single case occupies a long run of consecutive slots.
        measured = [s["case"] for s in plan if not s["warmup"]]
        self.assertLess(max(len(list(g)) for _, g in __import__("itertools").groupby(measured)), 3)

    def test_concurrency_and_memory_plans(self) -> None:
        cplan = v2.concurrency_plan(["a", "b"], [1, 4, 16], batches=3, seed=5)
        self.assertEqual(cplan, v2.concurrency_plan(["a", "b"], [1, 4, 16], batches=3, seed=5))
        self.assertEqual(Counter((s["case"], s["level"]) for s in cplan), Counter({(c, l): 3 for c in "ab" for l in (1, 4, 16)}))
        mplan = v2.memory_plan(["a", "b"], [0, 10], repeats=4, seed=5)
        for r in range(4):
            self.assertEqual(sorted((s["case"], s["count"]) for s in mplan if s["repeat"] == r),
                             [("a", 0), ("a", 10), ("b", 0), ("b", 10)])
        orders = {tuple((s["case"], s["count"]) for s in mplan if s["repeat"] == r) for r in range(4)}
        self.assertGreater(len(orders), 1)


class ExpandTest(unittest.TestCase):
    def test_placeholders(self) -> None:
        argv = ["{kiln}", "run", "--name", "x-{id}", "--", "{workload}", "--format", "{{.Client.Version}}", "sh -c {workload}"]
        out = v2.expand(argv, {"kiln": "/k", "id": "kb-1"}, ["echo", "a b"])
        self.assertEqual(out, ["/k", "run", "--name", "x-kb-1", "--", "echo", "a b", "--format",
                               "{{.Client.Version}}", "sh -c echo 'a b'"])
        with self.assertRaises(v2.HarnessError):
            v2.expand(["{nope}"], {}, [])


class InvokeTest(unittest.TestCase):
    def test_timeout_kills_and_is_recorded(self) -> None:
        r = v2.invoke(py("import time; time.sleep(30)"), timeout_s=0.3)
        self.assertTrue(r["timed_out"])
        self.assertFalse(r["ok"])
        self.assertLess(r["elapsed_ns"], 10e9)

    def test_output_is_bounded(self) -> None:
        r = v2.invoke(py("print('x' * 10000)"), output_limit=100)
        self.assertTrue(r["ok"])
        self.assertEqual((len(r["stdout"]), r["stdout_bytes"], r["stdout_truncated"]), (100, 10001, True))


class StatsTest(unittest.TestCase):
    def test_percentiles_interpolate_between_ranks(self) -> None:
        self.assertEqual(v2.percentile([4, 1, 3, 2], 50), 2.5)
        self.assertAlmostEqual(v2.percentile([1, 2, 3, 4], 95), 3.85)
        self.assertEqual(v2.percentile([7], 99), 7)
        xs = list(range(1, 101))
        self.assertAlmostEqual(v2.percentile(xs, 99), 99.01)
        self.assertAlmostEqual(v2.percentile(xs, 95), statistics.quantiles(xs, n=20, method="inclusive")[-1])
        d = v2.describe([1.0, 2.0, 3.0, 10.0])
        self.assertEqual((d["min"], d["max"], d["mean"], d["p50"]), (1.0, 10.0, 4.0, 2.5))
        self.assertIsNone(v2.describe([])["p95"])

    def test_ols(self) -> None:
        slope, intercept = v2.ols([0, 10, 25, 50], [100 + 3 * x for x in (0, 10, 25, 50)])
        self.assertAlmostEqual(slope, 3)
        self.assertAlmostEqual(intercept, 100)
        self.assertIsNone(v2.ols([5, 5], [1, 2]))

    def _records(self, sessions: dict[str, tuple[float, float]]) -> list[dict[str, Any]]:
        out = []
        for session, (base_ms, case_ms) in sessions.items():
            for case, ms in (("base", base_ms), ("new", case_ms)):
                for k in range(5):
                    out.append({"schema": v2.SCHEMA, "kind": "latency", "warmup": False, "case": case,
                                "session": session, "boot_id": session, "run_id": "r", "gap_ms": 100.0,
                                "ok": True, "elapsed_ns": int((ms + k * 0.1) * 1e6)})
        return out

    def test_ci_needs_two_sessions(self) -> None:
        one = v2.summarize_latency(self._records({"s1": (10, 5)}), "base", 0, 500)
        (ratio,) = one["ratios"]
        self.assertEqual(ratio["paired_sessions"], 1)
        self.assertIsNone(ratio["ci95"])
        self.assertIn("at least 2", ratio["ci_note"])
        self.assertAlmostEqual(ratio["median"], 5.2 / 10.2)

        recs = self._records({"s1": (10, 5), "s2": (10, 6), "s3": (12, 6)})
        three = v2.summarize_latency(recs, "base", 0, 500)
        (ratio,) = three["ratios"]
        self.assertEqual(ratio["paired_sessions"], 3)
        self.assertIsNotNone(ratio["ci95"])
        self.assertLessEqual(ratio["ci95"]["low"], ratio["geomean"])
        self.assertGreaterEqual(ratio["ci95"]["high"], ratio["geomean"])
        self.assertEqual(ratio, v2.summarize_latency(recs, "base", 0, 500)["ratios"][0])  # deterministic

    def test_warmups_and_failures_in_latency_groups(self) -> None:
        recs = self._records({"s1": (10, 5)})
        recs.append({**recs[0], "warmup": True, "elapsed_ns": 10**12})
        recs.append({**recs[0], "ok": False, "exit_code": 1, "elapsed_ns": 10**12})
        groups = {g["case"]: g for g in v2.summarize_latency(recs, "base", 0, 10)["groups"]}
        self.assertEqual((groups["base"]["n"], groups["base"]["failures"]), (6, 1))
        self.assertLess(groups["base"]["ms"]["max"], 11)


class LatencyRunTest(Tmp):
    def config(self) -> Path:
        # The ok case prints its {id} so the test can check it arrived.
        return write_config(self.tmp / "cfg.json", {
            "ok": {"argv": py("import sys; print(sys.argv[1])", "{id}"), "version_argv": py("print('ok 1.0')")},
            "fail": {"argv": py("import sys; sys.stderr.write('boom'); sys.exit(3)", "{id}")},
            "missing": {"argv": [str(self.tmp / "no-such-binary"), "{id}"]},
        })

    def latency(self, out: Path, *extra: str, seed: str = "7") -> tuple[int, str]:
        return run_main("latency", "--config", str(self.config()), "--out", str(out), "--session", "s1",
                        "--runs", "3", "--warmups", "1", "--gap-ms", "0,1", "--seed", seed,
                        "--proc-root", str(fake_proc(self.tmp)), *extra)

    def test_records_failures_ids_and_manifest(self) -> None:
        artifact = self.tmp / "rootfs.tar"
        artifact.write_bytes(b"rootfs fixture")
        config = self.config()
        data = json.loads(config.read_text())
        data["artifacts"] = {"rootfs_tar": str(artifact)}
        config.write_text(json.dumps(data))
        out = self.tmp / "run"
        code, err = run_main("latency", "--config", str(config), "--out", str(out), "--session", "s1",
                             "--runs", "3", "--warmups", "1", "--gap-ms", "0,1", "--seed", "7",
                             "--proc-root", str(fake_proc(self.tmp)))
        self.assertEqual(code, 0, err)
        recs = v2.read_records(out / v2.RECORDS)
        self.assertEqual(len(recs), (3 + 1) * 2 * 3)
        self.assertEqual(len({r["invocation_id"] for r in recs}), len(recs))
        for r in recs:
            self.assertRegex(r["invocation_id"], r"^[a-z0-9-]+$")
            for key in ("exit_code", "elapsed_ns", "start_utc", "end_utc", "ordinal", "round", "position",
                        "case", "gap_ms", "session", "boot_id", "warmup", "stdout", "stderr"):
                self.assertIn(key, r)
            self.assertEqual(r["boot_id"], "boot-a")
        by_case = {c: [r for r in recs if r["case"] == c] for c in ("ok", "fail", "missing")}
        for r in by_case["ok"]:
            self.assertTrue(r["ok"])
            self.assertEqual(r["stdout"].strip(), r["invocation_id"])
        for r in by_case["fail"]:
            self.assertEqual((r["ok"], r["exit_code"], r["stderr"]), (False, 3, "boom"))
        for r in by_case["missing"]:
            self.assertFalse(r["ok"])
            self.assertIsNone(r["exit_code"])
            self.assertIn("FileNotFoundError", r["error"])
        self.assertEqual(sum(r["warmup"] for r in recs), 1 * 2 * 3)

        manifest = json.loads((out / v2.MANIFEST).read_text())
        for key in ("schema", "created_utc", "argv", "seed", "git", "hostname", "uname", "boot_id",
                    "os_release", "python", "cpu", "memory", "cgroup_mode", "config_sha256",
                    "executables", "versions"):
            self.assertIn(key, manifest)
        self.assertEqual(manifest["seed"], 7)
        self.assertEqual(manifest["versions"]["ok"]["stdout"].strip(), "ok 1.0")
        self.assertEqual(manifest["artifacts"]["rootfs_tar"]["bytes"], len(b"rootfs fixture"))
        self.assertEqual(len(manifest["artifacts"]["rootfs_tar"]["sha256"]), 64)
        self.assertIsNone(manifest["versions"]["fail"])
        exe = manifest["executables"][PY]
        self.assertEqual(len(exe["sha256"]), 64)
        self.assertIn("error", manifest["executables"][str(self.tmp / "no-such-binary")])
        self.assertEqual((out / v2.CONFIG_COPY).read_bytes(), (self.tmp / "cfg.json").read_bytes())

    def test_refuses_existing_dir_and_resumes_safely(self) -> None:
        out = self.tmp / "run"
        self.assertEqual(self.latency(out)[0], 0)
        code, err = self.latency(out)
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)
        code, err = self.latency(out, "--resume", seed="8")
        self.assertEqual(code, 2)
        self.assertIn("seed differs", err)

        # Lose the last 5 records, as if the run had been interrupted.
        path = out / v2.RECORDS
        lines = path.read_text().splitlines(keepends=True)
        path.write_text("".join(lines[:-5]))
        code, err = self.latency(out, "--resume")
        self.assertEqual(code, 0, err)
        recs = v2.read_records(path)
        self.assertEqual(sorted(r["ordinal"] for r in recs), list(range(24)))
        self.assertEqual(len({r["run_id"] for r in recs}), 2)
        self.assertEqual(len({r["invocation_id"] for r in recs}), 24)
        manifest = json.loads((out / v2.MANIFEST).read_text())
        self.assertEqual(len(manifest["segments"]), 2)
        self.assertEqual(manifest["segments"][1]["slots_already_done"], 19)

        code, _ = self.latency(self.tmp / "fresh", "--resume")
        self.assertEqual(code, 2)

    def test_cli_entry_point(self) -> None:
        out = self.tmp / "cli"
        r = subprocess.run([PY, "-I", str(BENCH / "v2.py"), "latency", "--config", str(self.config()),
                            "--out", str(out), "--session", "s1", "--runs", "1", "--warmups", "0",
                            "--gap-ms", "0", "--seed", "1", "--case", "^ok$"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        recs = v2.read_records(out / v2.RECORDS)
        self.assertEqual([x["case"] for x in recs], ["ok"])


class ConcurrencyTest(Tmp):
    def test_batches_count_successes_and_failures(self) -> None:
        cfg = write_config(self.tmp / "cfg.json", {
            "slow": {"argv": py("import time, sys; time.sleep(0.3); print(sys.argv[1])", "{id}")},
            "flaky": {"argv": py("import sys; sys.exit(int(sys.argv[1][-1]) % 2)", "{id}")},
        })
        out = self.tmp / "run"
        code, err = run_main("concurrency", "--config", str(cfg), "--out", str(out), "--session", "s1",
                             "--levels", "1,4", "--batches", "2", "--gap-ms", "0", "--seed", "3",
                             "--proc-root", str(fake_proc(self.tmp)))
        self.assertEqual(code, 0, err)
        recs = v2.read_records(out / v2.RECORDS)
        batches = [r for r in recs if r["kind"] == "concurrency_batch"]
        invs = [r for r in recs if r["kind"] == "concurrency_invocation"]
        self.assertEqual(len(batches), 2 * 2 * 2)
        self.assertEqual(len(invs), 2 * 2 * (1 + 4))
        self.assertEqual(len({r["invocation_id"] for r in invs}), len(invs))
        for b in batches:
            mine = [r for r in invs if r["batch"] == b["batch"]]
            self.assertEqual(len(mine), b["level"])
            self.assertEqual(b["attempted"], b["level"])
            self.assertEqual(b["successes"], sum(r["ok"] for r in mine))
            self.assertEqual(b["failures"], b["level"] - b["successes"])
            self.assertEqual(sorted(b["invocation_ids"]), sorted(r["invocation_id"] for r in mine))
            self.assertIn("cpu", b["cpu_stat_before"])
            self.assertEqual(b["meminfo_after"]["MemTotal"], 16000)
            if b["successes"]:
                self.assertAlmostEqual(b["completions_per_s"], b["successes"] / (b["wall_ns"] / 1e9))
            if b["case"] == "slow" and b["level"] == 4:
                # Four 0.3 s sleeps at once take well under 4 x 0.3 s.
                self.assertLess(b["wall_ns"], 0.9e9)
                self.assertEqual(b["failures"], 0)
        flaky = [b for b in batches if b["case"] == "flaky"]
        self.assertGreater(sum(b["failures"] for b in flaky), 0)
        self.assertGreater(sum(b["successes"] for b in flaky), 0)

        summary = v2.summarize([out], self.tmp / "sum", baseline="slow", iterations=10)
        rows = {(c["case"], c["level"]): c for c in summary["concurrency"]}
        self.assertEqual(rows[("slow", 4)]["invocations"], 8)
        self.assertEqual(rows[("flaky", 4)]["failures"], sum(b["failures"] for b in flaky if b["level"] == 4))
        self.assertIsNotNone(rows[("slow", 4)]["invocation_ms"]["p95"])


class MemoryTest(Tmp):
    START = ("import os, sys\n"
             "state, sid = sys.argv[1], sys.argv[2]\n"
             "if len(os.listdir(state)) >= 2: sys.exit('no room')\n"
             "open(os.path.join(state, sid), 'w').close()\n"
             "print(sid.upper() if len(sys.argv) > 3 else sid)\n")
    STOP = "import os, sys; os.remove(os.path.join(sys.argv[1], sys.argv[2]))"

    def run_memory(self, cases: dict[str, Any], counts: str) -> list[dict[str, Any]]:
        cfg = write_config(self.tmp / "cfg.json", cases, vars={"state": str(self.tmp / "state")})
        out = self.tmp / "run"
        code, err = run_main("memory", "--config", str(cfg), "--out", str(out), "--session", "s1",
                             "--counts", counts, "--repeats", "2", "--seed", "1", "--settle-s", "0",
                             "--proc-root", str(fake_proc(self.tmp)))
        self.assertEqual(code, 0, err)
        if not v2.is_root():
            self.assertIn("not root", err)
        return v2.read_records(out / v2.RECORDS)

    def test_cleanup_after_start_failure(self) -> None:
        (self.tmp / "state").mkdir()
        recs = self.run_memory({
            "fake": {"argv": ["true"], "memory": {"start_argv": py(self.START, "{state}", "{id}"),
                                                  "stop_argv": py(self.STOP, "{state}", "{id}")}},
            "noop": {"argv": ["true"]},
        }, "0,1,3")
        self.assertEqual(list((self.tmp / "state").iterdir()), [])  # everything started was stopped
        points = [r for r in recs if r["kind"] == "memory_point"]
        self.assertEqual(len(points), 3 * 2)
        self.assertEqual({p["case"] for p in points}, {"fake"})
        for p in points:
            self.assertIn("MemAvailable", p["meminfo_before"])
            self.assertEqual(p["cache_drop_before"], "dropped" if v2.is_root() else "skipped: not root")
            self.assertEqual(len(p["sandbox_ids"]), len(p["invocation_ids"]))
        three = [p for p in points if p["count"] == 3]
        for p in three:
            self.assertEqual((p["complete"], p["aborted"], p["count_running"]), (False, True, 2))
        starts = [r for r in recs if r["kind"] == "memory_start"]
        stops = [r for r in recs if r["kind"] == "memory_stop"]
        failed = [r for r in starts if not r["ok"]]
        self.assertEqual(len(failed), 2)
        self.assertIn("no room", failed[0]["stderr"])
        # Every start, the failed one included, gets a stop attempt.
        self.assertEqual(sorted(r["invocation_id"] for r in stops), sorted(r["invocation_id"] for r in starts))
        self.assertEqual(sum(not r["ok"] for r in stops), 2)  # the failed starts left nothing to remove

        summary = v2.summarize([self.tmp / "run"], self.tmp / "sum", baseline="fake", iterations=10)
        self.assertEqual(summary["memory"]["excluded_points"], 2)
        (fit_case,) = summary["memory"]["cases"]
        self.assertEqual(fit_case["fits"], 2)
        self.assertEqual(fit_case["slope_kib_per_sandbox"]["mean"], 0.0)  # fake meminfo never moves

    def test_sandbox_id_from_stdout(self) -> None:
        (self.tmp / "state").mkdir()
        stop = "import os, sys; os.remove(os.path.join(sys.argv[1], sys.argv[2].lower()))"
        recs = self.run_memory({
            "printed": {"argv": ["true"], "memory": {
                "start_argv": py(self.START, "{state}", "{id}", "upper"), "sandbox_id_from": "stdout",
                "stop_argv": py(stop, "{state}", "{sandbox}")}},
        }, "2")
        self.assertEqual(list((self.tmp / "state").iterdir()), [])
        stops = [r for r in recs if r["kind"] == "memory_stop"]
        self.assertTrue(all(r["ok"] and r["sandbox_id"] == r["invocation_id"].upper() for r in stops))


class SummaryTest(Tmp):
    def test_two_sessions_end_to_end(self) -> None:
        cfg = write_config(self.tmp / "cfg.json", {
            "base": {"argv": py("pass")},
            "new": {"argv": py("pass")},
        })
        for session in ("boot1", "boot2"):
            code, err = run_main("latency", "--config", str(cfg), "--out", str(self.tmp / session),
                                 "--session", session, "--runs", "3", "--warmups", "0", "--gap-ms", "0",
                                 "--seed", "1", "--proc-root", str(fake_proc(self.tmp / session[-1], session)))
            self.assertEqual(code, 0, err)
        out = self.tmp / "summary"
        code, err = run_main("summarize", str(self.tmp / "boot1"), str(self.tmp / "boot2" / v2.RECORDS),
                             "--out", str(out), "--baseline", "base", "--bootstrap-iterations", "200")
        self.assertEqual(code, 0, err)
        summary = json.loads((out / "summary.json").read_text())
        self.assertEqual(summary["warnings"], [])
        self.assertEqual(len(summary["latency"]["groups"]), 4)
        (ratio,) = summary["latency"]["ratios"]
        self.assertEqual((ratio["case"], ratio["paired_sessions"]), ("new", 2))
        self.assertIsNotNone(ratio["ci95"])
        md = (out / "summary.md").read_text()
        self.assertIn("| new | boot2 | 0.0 | 3 | 0 |", md)
        self.assertIn("not confidence intervals", md)
        self.assertIn("95% CI (sessions)", md)

        code, err = run_main("summarize", str(self.tmp / "boot1"), "--out", str(self.tmp / "one"),
                             "--baseline", "base")
        self.assertEqual(code, 0, err)
        md = (self.tmp / "one" / "summary.md").read_text()
        self.assertIn("none (fewer than 2 sessions)", md)


class ShippedConfigTest(unittest.TestCase):
    def test_current_cases(self) -> None:
        cfg = v2.load_config(BENCH / "v2-config.json")
        self.assertEqual(set(cfg.cases), {
            "kiln-none", "kiln-net", "docker-none", "docker-net",
            "podman-crun-none", "podman-crun-net", "podman-runc-none",
            "nerdctl-none", "nerdctl-net", "runc-none", "crun-none",
            "youki-none", "runsc-none",
        })
        tiers = {n: c.tier for n, c in cfg.cases.items()}
        for n in ("kiln-none", "kiln-net", "docker-none", "docker-net",
                  "podman-crun-none", "podman-crun-net", "podman-runc-none",
                  "nerdctl-none", "nerdctl-net"):
            self.assertEqual(tiers[n], "end-user-stack")
        for n in ("runc-none", "crun-none", "youki-none"):
            self.assertEqual(tiers[n], "low-level")
            self.assertIn("{id}", cfg.cases[n].argv)
            self.assertIsNotNone(cfg.cases[n].memory)
        self.assertEqual(tiers["runsc-none"], "strong-isolation")
        for n in ("docker-none", "docker-net", "podman-crun-none", "podman-crun-net",
                  "podman-runc-none", "nerdctl-none", "nerdctl-net"):
            argv = cfg.cases[n].argv
            self.assertEqual(argv[argv.index("--memory-swap") + 1], "512m")
            self.assertEqual(argv[argv.index("--memory") + 1], "512m")
            start = cfg.cases[n].memory.start_argv
            self.assertEqual(start[start.index("--memory-swap") + 1], "512m")
        self.assertTrue(all(c.memory for c in cfg.cases.values()))


if __name__ == "__main__":
    unittest.main()
