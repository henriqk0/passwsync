"""Tests of scripts/bench.sh report assembly (008 contracts/benchmarks.md, SC-005, FR-021).
Stub test outputs are fed through PASSWSYNC_BENCH_STUB_DIR, so no cargo command runs."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "scripts" / "bench.sh"
IDS = [f"B-{n:02d}" for n in range(1, 21)]


def line(bid, value=1, unit="ms", limit=2000, cmp="lt", source="001-SC-003",
         cls="measured", verdict="PASS"):
    return (f"BUDGET id={bid} value={value} unit={unit} limit={limit} cmp={cmp} "
            f"source={source} class={cls} verdict={verdict}")


def complete():
    return "\n".join(line(b) for b in IDS) + "\n"


class BenchReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stub = Path(self.tmp.name) / "stub"
        self.stub.mkdir()
        self.report = Path(self.tmp.name) / "report.txt"

    def run_bench(self, outputs, *args, env=None):
        for name, text in outputs.items():
            (self.stub / f"{name}.out").write_text(text, encoding="utf-8")
        full = dict(os.environ)
        full.update({"PASSWSYNC_BENCH_STUB_DIR": str(self.stub),
                     "PASSWSYNC_BENCH_REPORT": str(self.report)})
        full.pop("PASSWSYNC_REFERENCE_DEVICE", None)
        full.update(env or {})
        return subprocess.run(["bash", str(BENCH), *args], cwd=ROOT, capture_output=True,
                              text=True, env=full, check=False)

    def test_a_complete_set_exits_0_whatever_the_verdicts(self):
        text = complete().replace(line("B-02"), line("B-02", value=2500, verdict="OVER"))
        out = self.run_bench({"all": text})
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        report = self.report.read_text(encoding="utf-8")
        for bid in IDS:
            self.assertRegex(report, rf"(?m)^{bid} ")
        self.assertRegex(report, r"(?m)^B-02 .* OVER$")
        self.assertNotIn("NO-DATA", report)

    def test_a_missing_budget_is_no_data_and_exit_2(self):
        text = complete().replace(line("B-05") + "\n", "")
        out = self.run_bench({"all": text})
        self.assertEqual(out.returncode, 2, out.stdout)
        self.assertRegex(self.report.read_text(encoding="utf-8"), r"(?m)^B-05 .*NO-DATA")

    def test_malformed_lines_are_rejected(self):
        bad = complete().replace(line("B-06"), line("B-06").replace("unit=ms", "unit=parsecs"))
        bad = bad.replace(line("B-07"), line("B-07") + " extra=secret")
        out = self.run_bench({"all": bad})
        self.assertEqual(out.returncode, 2, out.stdout)
        report = self.report.read_text(encoding="utf-8")
        self.assertRegex(report, r"(?m)^B-06 .*NO-DATA")
        self.assertRegex(report, r"(?m)^B-07 .*NO-DATA")
        self.assertIn("rejected malformed BUDGET line", report)

    def test_a_failing_assertion_does_not_lose_its_line(self):
        text = complete() + "thread 'x' panicked at perf.rs:10:5:\ntest result: FAILED. 0 passed; 1 failed\n"
        out = self.run_bench({"all": text})
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_the_machine_block_and_the_informational_footer(self):
        out = self.run_bench({"all": complete()})
        report = self.report.read_text(encoding="utf-8")
        for key in ("cpu:", "cores:", "memtotal:", "kernel:", "rustc:", "profile: release",
                    "reference: no", "date:"):
            self.assertIn(key, report)
        self.assertIn("informational: timing verdicts are binding only on reference hardware", report)
        self.assertEqual(out.stdout.strip(), report.strip())
        out = self.run_bench({"all": complete()}, env={"PASSWSYNC_REFERENCE_DEVICE": "laptop"})
        report = self.report.read_text(encoding="utf-8")
        self.assertIn("reference: laptop", report)
        self.assertNotIn("informational:", report)

    def test_known_measurement_prints_become_rows(self):
        text = complete()
        for bid in ("B-10", "B-14", "B-15", "B-16"):
            text = text.replace(line(bid) + "\n", "")
        text += ("RSS +12288 KiB for 6 services in one process\n"
                 "idle CPU 0.020 %/service, RSS 9000 KiB/service, growth 512 KiB\n"
                 "10 000-entry wallet synced in 1.5s\n")
        out = self.run_bench({"all": text})
        self.assertEqual(out.returncode, 0, out.stdout)
        report = self.report.read_text(encoding="utf-8")
        self.assertRegex(report, r"(?m)^B-10 .* 2048 KiB .* PASS$")
        self.assertRegex(report, r"(?m)^B-14 .* 0.020 % .* PASS$")
        self.assertRegex(report, r"(?m)^B-15 .* 512 KiB .* PASS$")
        self.assertRegex(report, r"(?m)^B-16 .* 1500 ms .* PASS$")

    def test_lines_after_the_libtest_prefix_are_collected(self):
        text = "\n".join(f"test x::y ... {line(b)}" for b in IDS) + "\n"
        out = self.run_bench({"all": text})
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("NO-DATA", self.report.read_text(encoding="utf-8"))

    def test_usage_error_exits_64(self):
        self.assertEqual(self.run_bench({}, "--bogus").returncode, 64)

    def test_output_contains_no_credential_like_text(self):
        out = self.run_bench({"all": complete() + "password=hunter2 MARKER-x\n"})
        report = self.report.read_text(encoding="utf-8")
        for needle in ("hunter2", "MARKER", "password"):
            self.assertNotIn(needle, report)
            self.assertNotIn(needle, out.stdout)


if __name__ == "__main__":
    unittest.main()
