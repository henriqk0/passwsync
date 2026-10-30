"""android/verify.sh CLI (contracts/verify.md): options, exit codes, step lines, summary, tool
lookup, and the deny/audit/lock-diff steps against stubbed tools. Only cheap steps are run
here (`--only`), each with its own work directory."""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import GOOD, REPO

VERIFY = REPO / "android" / "verify.sh"
STEP_LINE = re.compile(r"^(PASS|FAIL|SKIPPED|MISSING) ([a-z-]+)( .*)?$")
BASE_TOOLS = ["bash", "env", "dirname", "basename", "mkdir", "rm", "date", "cat", "tee", "sed",
              "grep", "awk", "sort", "comm", "head", "tail", "wc", "find", "cp", "tr", "mktemp",
              "ls", "cut", "xargs", "uniq", "stat", "git", "python3", "cargo", "rustc", "nm"]


class Verify(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="verify-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.work = self.tmp / "work"

    def run_verify(self, *args, env=None, path=None):
        full = dict(os.environ)
        full["VERIFY_WORK_DIR"] = str(self.work)
        if path is not None:
            full["PATH"] = path
        full.update(env or {})
        done = subprocess.run(["bash", str(VERIFY), *args], cwd=REPO, env=full,
                              capture_output=True, text=True, timeout=600)
        return done.returncode, done.stdout, done.stderr

    def tool_dir(self, exclude=(), extra=None):
        """A PATH directory with symlinks to the base tools minus `exclude`, plus stubs."""
        directory = self.tmp / "bin"
        directory.mkdir(exist_ok=True)
        for tool in BASE_TOOLS + ["xmllint"]:
            real = shutil.which(tool)
            if tool not in exclude and real and not (directory / tool).exists():
                (directory / tool).symlink_to(real)
        for name, script in (extra or {}).items():
            path = directory / name
            if path.exists() or path.is_symlink():
                path.unlink()
            path.write_text("#!/bin/bash\n" + script, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(directory)

    def step_lines(self, out):
        return [line for line in out.splitlines() if STEP_LINE.match(line)]

    def summary(self):
        return (self.work / "summary.txt").read_text(encoding="utf-8").splitlines()

    def broken_tree(self):
        tree = self.tmp / "android"
        shutil.copytree(GOOD, tree)
        layout = tree / "app/src/main/res/layout/screen_unlock.xml"
        layout.write_text(layout.read_text(encoding="utf-8").replace("</LinearLayout>", ""), encoding="utf-8")
        return tree

    # --- CLI ---
    def test_help(self):
        code, out, _ = self.run_verify("--help")
        self.assertEqual(code, 0)
        self.assertIn("usage: android/verify.sh", out)
        for step in ("tools", "xml-wellformed", "mutations", "lock-diff", "ktlint"):
            self.assertIn(step, out)

    def test_unknown_option_is_64_with_usage_on_stderr(self):
        code, out, err = self.run_verify("--bogus")
        self.assertEqual(code, 64)
        self.assertIn("usage:", err)
        self.assertEqual(out, "")

    def test_unknown_step_is_64(self):
        code, _, err = self.run_verify("--only", "no-such-step")
        self.assertEqual(code, 64)
        self.assertIn("unknown step", err)

    def test_only_xml_wellformed_on_a_broken_tree_fails(self):
        code, out, _ = self.run_verify("--only", "xml-wellformed", env={"VERIFY_ANDROID_DIR": str(self.broken_tree())})
        self.assertEqual(code, 1, out)
        self.assertEqual(len(self.step_lines(out)), 1)
        self.assertTrue(self.step_lines(out)[0].startswith("FAIL xml-wellformed"), out)
        self.assertEqual(self.summary()[-1], "RESULT 1")

    def test_only_is_never_0(self):
        code, out, _ = self.run_verify("--only", "xml-wellformed", env={"VERIFY_ANDROID_DIR": str(GOOD)})
        self.assertEqual(code, 2, out)
        self.assertTrue(self.step_lines(out)[0].startswith("PASS xml-wellformed"), out)
        self.assertEqual(self.summary()[-1], "RESULT 2")

    def test_quick_is_never_0(self):
        code, out, _ = self.run_verify("--quick", "--only", "xml-wellformed,manifest-policy",
                                       env={"VERIFY_ANDROID_DIR": str(GOOD)})
        self.assertEqual(code, 2, out)
        self.assertEqual([l.split()[0] for l in self.step_lines(out)], ["PASS", "PASS"])

    def test_missing_xmllint(self):
        code, out, _ = self.run_verify("--only", "tools", path=self.tool_dir(exclude=("xmllint",)))
        self.assertEqual(code, 2, out)
        self.assertIn("MISSING tools xmllint", out)

    def test_ktlint_absent_is_skipped_and_does_not_lower_the_status(self):
        path = self.tool_dir(exclude=("ktlint",))
        code, out, _ = self.run_verify("--only", "ktlint,xml-wellformed", path=path,
                                       env={"VERIFY_ANDROID_DIR": str(GOOD)})
        self.assertIn("SKIPPED ktlint (not installed)", out)
        self.assertEqual(code, 2, out)
        self.assertEqual(self.summary()[-1], "RESULT 2")

    def test_each_step_prints_exactly_one_status_line_and_the_summary_lists_it(self):
        code, out, _ = self.run_verify("--only", "uniffi-pin,xml-wellformed,ktlint",
                                       env={"VERIFY_ANDROID_DIR": str(GOOD)})
        lines = self.step_lines(out)
        self.assertEqual([STEP_LINE.match(l).group(2) for l in lines], ["uniffi-pin", "xml-wellformed", "ktlint"])
        summary = self.summary()
        self.assertEqual(summary[-1], f"RESULT {code}")
        for step in ("uniffi-pin", "xml-wellformed", "ktlint"):
            self.assertTrue(any(re.match(rf"^(PASS|FAIL|SKIPPED|MISSING) {step} \d+s$", s) for s in summary), summary)
        for sub in ("kotlin", "mut", "logs"):
            self.assertTrue((self.work / sub).is_dir())
        self.assertTrue((self.work / "logs/xml-wellformed.log").is_file())

    def test_the_work_directory_is_recreated(self):
        self.work.mkdir(parents=True)
        (self.work / "stale.txt").write_text("x")
        self.run_verify("--only", "uniffi-pin")
        self.assertFalse((self.work / "stale.txt").exists())

    # --- tools lookup ---
    def test_cargo_deny_and_audit_are_found_in_cargo_home(self):
        home = self.tmp / "cargo-home"
        (home / "bin").mkdir(parents=True)
        for tool in ("cargo-deny", "cargo-audit"):
            stub = home / "bin" / tool
            stub.write_text("#!/bin/bash\nexit 0\n")
            stub.chmod(0o755)
        path = self.tool_dir(exclude=("cargo-deny", "cargo-audit"))
        code, out, _ = self.run_verify("--only", "tools", path=path, env={"CARGO_HOME": str(home)})
        self.assertIn(f"cargo-deny={home}/bin/cargo-deny", out)
        self.assertIn(f"cargo-audit={home}/bin/cargo-audit", out)
        self.assertTrue(self.step_lines(out)[0].startswith("PASS tools"), out)
        self.assertEqual(code, 2)

    def test_cargo_deny_missing_everywhere(self):
        home = self.tmp / "empty-home"
        (home / "bin").mkdir(parents=True)
        code, out, _ = self.run_verify("--only", "tools", path=self.tool_dir(), env={"CARGO_HOME": str(home)})
        self.assertIn("MISSING tools", out)
        self.assertIn("cargo-deny", out)
        self.assertEqual(code, 2)

    # --- stubbed deny / audit ---
    def stub_cargo(self, rc_deny=0, rc_audit=0):
        log = self.tmp / "cargo-args.log"
        script = f"""echo "$*" >> {log}
case "$1" in
  deny) exit {rc_deny} ;;
  audit) exit {rc_audit} ;;
  *) exec {shutil.which('cargo')} "$@" ;;
esac
"""
        home = self.tmp / "stub-home"
        (home / "bin").mkdir(parents=True, exist_ok=True)
        for tool in ("cargo-deny", "cargo-audit"):
            stub = home / "bin" / tool
            stub.write_text("#!/bin/bash\nexit 0\n")
            stub.chmod(0o755)
        return self.tool_dir(extra={"cargo": script}), log, {"CARGO_HOME": str(home)}

    def test_deny_passes_and_checks_both_workspaces(self):
        path, log, env = self.stub_cargo()
        code, out, _ = self.run_verify("--only", "deny", path=path, env=env)
        self.assertTrue(self.step_lines(out)[0].startswith("PASS deny"), out)
        calls = log.read_text().splitlines()
        self.assertIn("deny --offline check", calls)
        self.assertIn("deny --offline --manifest-path tools/uniffi-bindgen/Cargo.toml check", calls)
        self.assertEqual(code, 2)

    def test_deny_failure_fails(self):
        path, _, env = self.stub_cargo(rc_deny=1)
        code, out, _ = self.run_verify("--only", "deny", path=path, env=env)
        self.assertEqual(code, 1)
        self.assertTrue(self.step_lines(out)[0].startswith("FAIL deny"), out)

    def test_audit_uses_the_two_ignores_and_prints_the_db_date(self):
        path, log, env = self.stub_cargo()
        db = Path(env["CARGO_HOME"]) / "advisory-db"
        db.mkdir()
        code, out, _ = self.run_verify("--only", "audit", path=path, env=env)
        line = self.step_lines(out)[0]
        self.assertTrue(line.startswith("PASS audit"), out)
        self.assertRegex(line, r"advisory-db \d{4}-\d{2}-\d{2}")
        calls = log.read_text().splitlines()
        self.assertIn("audit --no-fetch --deny warnings --ignore RUSTSEC-2023-0089", calls)
        self.assertIn("audit --no-fetch --deny warnings --ignore RUSTSEC-2026-0374 --file tools/uniffi-bindgen/Cargo.lock", calls)

    def test_audit_failure_fails(self):
        path, _, env = self.stub_cargo(rc_audit=1)
        (Path(env["CARGO_HOME"]) / "advisory-db").mkdir()
        code, out, _ = self.run_verify("--only", "audit", path=path, env=env)
        self.assertEqual(code, 1)
        self.assertTrue(self.step_lines(out)[0].startswith("FAIL audit"), out)

    # --- lock-diff ---
    def new_packages(self):
        def packages(text):
            out, name = set(), None
            for line in text.splitlines():
                if line.startswith("name = "):
                    name = line.split('"')[1]
                elif line.startswith("version = ") and name:
                    out.add(f"{name} {line.split(chr(34))[1]}")
                    name = None
            return out
        main = subprocess.run(["git", "show", "main:Cargo.lock"], cwd=REPO, capture_output=True, text=True, check=True).stdout
        return sorted(packages((REPO / "Cargo.lock").read_text()) - packages(main))

    def test_lock_diff_passes_with_exactly_the_reviewed_set(self):
        reviewed = self.tmp / "reviewed.txt"
        reviewed.write_text("# header\n" + "\n".join(self.new_packages()) + "\n")
        code, out, _ = self.run_verify("--only", "lock-diff", env={"VERIFY_REVIEWED_CRATES": str(reviewed)})
        self.assertTrue(self.step_lines(out)[0].startswith("PASS lock-diff"), out)

    def test_lock_diff_fails_on_an_unreviewed_or_stale_entry(self):
        new = self.new_packages()
        reviewed = self.tmp / "reviewed.txt"
        reviewed.write_text("# header\n" + "\n".join(new[1:] + ["ghost 9.9.9"]) + "\n")
        code, out, _ = self.run_verify("--only", "lock-diff", env={"VERIFY_REVIEWED_CRATES": str(reviewed)})
        self.assertEqual(code, 1)
        line = self.step_lines(out)[0]
        self.assertTrue(line.startswith("FAIL lock-diff"), out)
        if new:
            self.assertIn(new[0].split()[0], line)
        self.assertIn("ghost", line)


if __name__ == "__main__":
    unittest.main()
