"""Self-tests of scripts/gate.sh (008 contracts/gate-script.md, research R17-R19, SC-009).

They exercise the CLI, the step runner (through PASSWSYNC_GATE_SELFTEST, which runs only a
synthetic step so the real steps, including `policy` that runs these tests, are skipped) and
the pure checks through the hidden `--selftest <name>` option. Nothing here builds the
workspace."""

import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "gate.sh"
FIXTURES = ROOT / "scripts" / "tests" / "fixtures"
STEPS = [
    "toolchain", "fmt", "clippy", "test", "budgets", "fuzz", "release-isolation",
    "unsafe-scope", "audit", "deny", "policy",
]
CARGO_BIN = Path.home() / ".cargo" / "bin"


def gate(*args, env=None):
    full = dict(os.environ)
    full.pop("PASSWSYNC_GATE_SELFTEST", None)
    full.update(env or {})
    return subprocess.run(
        ["bash", str(GATE), *args], cwd=ROOT, capture_output=True, text=True, env=full,
        check=False,
    )


def tool(name):
    found = shutil.which(name) or (CARGO_BIN / name if (CARGO_BIN / name).exists() else None)
    return str(found) if found else None


def ignore_ids(path):
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = []
    for item in data.get("advisories", {}).get("ignore", []):
        out.append(item["id"] if isinstance(item, dict) else item)
    return sorted(out)


class GateCliTest(unittest.TestCase):
    def test_list_prints_the_eleven_steps_in_order(self):
        out = gate("--list")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split(), STEPS)

    def test_a_failing_step_gives_exit_1_and_names_the_step(self):
        out = gate(env={"PASSWSYNC_GATE_SELFTEST": "fail"})
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertRegex(out.stdout, r"\[gate\] selftest +FAIL")
        self.assertRegex(out.stdout, r"\[gate\] result +FAIL")
        for step in STEPS:
            self.assertNotRegex(out.stdout, rf"\[gate\] {step} ")

    def test_a_missing_tool_gives_exit_2_without_fail(self):
        out = gate(env={"PASSWSYNC_GATE_SELFTEST": "missing"})
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertRegex(out.stdout, r"\[gate\] selftest +MISSING")
        self.assertNotRegex(out.stdout, r"\[gate\] \S+ +FAIL")

    def test_unknown_arguments_exit_64(self):
        self.assertEqual(gate("--bogus").returncode, 64)
        self.assertEqual(gate("--selftest", "no-such-check").returncode, 64)


class GatePureChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_audit_ignore_ids_come_from_both_deny_files(self):
        for manifest, deny in [
            ("Cargo.toml", ROOT / "deny.toml"),
            ("tools/uniffi-bindgen/Cargo.toml", ROOT / "tools" / "uniffi-bindgen" / "deny.toml"),
        ]:
            out = gate("--selftest", "ignore-ids", str(deny))
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(sorted(out.stdout.split()), ignore_ids(deny), manifest)
            self.assertTrue(ignore_ids(deny), f"{deny} has no ignore entries")

    def test_the_fuzz_target_array_matches_the_directory(self):
        out = gate("--selftest", "fuzz-targets")
        self.assertEqual(out.returncode, 0, out.stderr)
        files = sorted(
            p.stem[len("fuzz_"):] for p in (ROOT / "crates" / "hardening" / "tests").glob("fuzz_*.rs")
        )
        self.assertEqual(sorted(out.stdout.split()), files)
        self.assertGreaterEqual(len(files), 16)

    def test_a_target_without_its_pass_line_fails_the_fuzz_check(self):
        (self.dir / "fuzz_a.rs").write_text("", encoding="utf-8")
        (self.dir / "fuzz_b.rs").write_text("", encoding="utf-8")
        log = self.dir / "log"
        good = "FUZZ target=a seed=0x1 inputs=10000 accepted=1 rejected=1 result=PASS\n" \
               "FUZZ target=b seed=0x1 inputs=10000 accepted=1 rejected=1 result=PASS\n"
        log.write_text(good, encoding="utf-8")
        self.assertEqual(gate("--selftest", "fuzz-lines", str(self.dir), str(log)).returncode, 0)
        log.write_text(good.splitlines()[0] + "\n", encoding="utf-8")
        out = gate("--selftest", "fuzz-lines", str(self.dir), str(log))
        self.assertEqual(out.returncode, 1)
        self.assertIn("b", out.stdout)

    def test_release_isolation_scan_rejects_test_only_code(self):
        clean = self.dir / "clean.txt"
        clean.write_text("passwsyncd v0.1.0\n0000 T passwsyncd::main\nvault_core v0.1.0\n",
                         encoding="utf-8")
        self.assertEqual(gate("--selftest", "isolation-scan", str(clean)).returncode, 0)
        for bad in [
            "0000 T vault_core::testkit::decode_payload\n",
            "hardening v0.1.0 (/x/crates/hardening)\n",
            'vault-core feature "testkit"\n',
        ]:
            path = self.dir / "bad.txt"
            path.write_text("passwsyncd v0.1.0\n" + bad, encoding="utf-8")
            out = gate("--selftest", "isolation-scan", str(path))
            self.assertEqual(out.returncode, 1, bad)

    def test_deny_policy_keys_are_enforced(self):
        out = gate("--selftest", "deny-keys", str(ROOT / "deny.toml"))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        text = (ROOT / "deny.toml").read_text(encoding="utf-8")
        for key, value in [
            ("yanked", '"deny"'), ("unmaintained", '"all"'), ("unsound", '"all"'),
            ("unknown-registry", '"deny"'), ("unknown-git", '"deny"'),
        ]:
            weak = self.dir / "deny.toml"
            weak.write_text(text.replace(f"{key} = {value}", f"{key} = \"warn\""), encoding="utf-8")
            out = gate("--selftest", "deny-keys", str(weak))
            self.assertEqual(out.returncode, 1, key)

    def test_the_deny_fixture_policy_equals_the_repository_policy(self):
        self.assertEqual(
            (FIXTURES / "deny-ws" / "deny.toml").read_bytes(), (ROOT / "deny.toml").read_bytes()
        )

    @unittest.skipUnless(tool("cargo-audit"), "cargo-audit not installed")
    def test_the_advisory_fixture_fails_cargo_audit(self):
        out = subprocess.run(
            [tool("cargo-audit"), "audit", "--no-fetch", "--file",
             str(FIXTURES / "advisory.lock")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(out.returncode, 0, out.stdout)

    @unittest.skipUnless(tool("cargo-deny"), "cargo-deny not installed")
    def test_the_deny_fixture_fails_bans_and_licenses(self):
        out = subprocess.run(
            [tool("cargo-deny"), "--offline", "--manifest-path",
             str(FIXTURES / "deny-ws" / "Cargo.toml"), "check", "bans", "licenses"],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("banned", out.stderr)
        self.assertIn("license", out.stderr)


if __name__ == "__main__":
    unittest.main()
