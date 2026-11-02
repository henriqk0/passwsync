"""Negative and positive tests of scripts/check_threat_model.py (008
contracts/threat-model-structure.md, TM1-TM13, SC-008). Every negative case mutates the valid
fixture once and expects exit 1 with the exact `FAIL TMn`."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_threat_model.py"
VALID = ROOT / "scripts" / "tests" / "fixtures" / "threat-model" / "valid.md"
REAL = ROOT / "docs" / "threat-model.md"

FIXED_ROW = (
    "| F-001 | http_request | bare LF | Low | Fixed | "
    "crates/hardening/tests/regress_008.rs::f_001_bare_lf_in_the_request_head_is_rejected |"
)
OPEN_ROW = "| F-002 | wallet_payload | alias | Low | Open | vault-core maintainer |"

# (rule, old, new): replace the first occurrence of `old` by `new` in the valid fixture.
MUTATIONS = [
    ("TM1", "## 2. Severity scale", "## 2. Severity"),
    ("TM1", "## 7. Out-of-model inputs\n\nSame-user files.\n\n", ""),
    ("TM1", "## 10. Change log", "## 10. History"),
    ("TM2", "### B-04 LAN discovery", "### B-04 LAN"),
    ("TM2", "| T-B11-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |\n",
     "| T-B11-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |\n\n"
     "### B-12 Extra\n\n| Id | STRIDE | Threat | Mitigation | Reference | Status |\n"
     "|----|--------|--------|------------|-----------|--------|\n"
     "| T-B12-1 | S | x | y | 002 FR-001 | Mitigated |\n"),
    ("TM3", "| T-B02-6 | E |", "| T-B02-6 | D |"),
    ("TM4", "| T-B03-1 | S | threat |", "| T-B03-1 | S |  |"),
    ("TM4", "| T-B03-2 | T |", "| T-B3-2 | T |"),
    ("TM4", "| T-B03-3 | R |", "| T-B03-2 | R |"),
    ("TM4", "| T-B03-4 | I |", "| T-B03-4 | X |"),
    ("TM5", "| T-B04-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh |",
     "| T-B04-1 | S | threat | checked | see the code |"),
    ("TM5", "| T-B04-3 | R | repudiation | N/A: single-user tool |", "| T-B04-3 | R | repudiation | N/A |"),
    ("TM6", "| T-B05-1 | S | threat | checked | crates/vault-core/tests/tamper.rs,",
     "| T-B05-1 | S | threat | checked | crates/vault-core/tests/no_such_file.rs,"),
    ("TM7", "| Residual (RR-01) |", "| Residual (RR-99) |"),
    ("TM8", "| RR-02 | risk | specs/003-device-identity-pairing/spec.md | reason | Low |",
     "| RR-02 | risk | specs/003-device-identity-pairing/spec.md | reason | Critical |"),
    ("TM8", "| RR-03 | risk | specs/003-device-identity-pairing/spec.md | reason | Low | maintainer |",
     "| RR-03 | risk | specs/003-device-identity-pairing/spec.md | reason | Low |  |"),
    ("TM8", "| RR-04 | risk | specs/004-wallet-sync-protocol/plan.md | reason | Low | maintainer | when fixed |",
     "| RR-04 | risk | specs/004-wallet-sync-protocol/plan.md | reason | Low | maintainer |  |"),
    ("TM9", "| RR-05 | risk |", "| RR-50 | risk |"),
    ("TM9", "| RR-06 | risk | specs/005-wallet-sharing/plan.md |", "| RR-06 | risk | specs/005-wallet-sharing/spec.md |"),
    ("TM10", "| RR-11 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Pending approval |",
     "| RR-11 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Accepted |"),
    ("TM11", "| RR-16 | RUSTSEC-2023-0089 | deny.toml |", "| RR-16 | advisory | specs/008-hardening-audit/research.md |"),
    ("TM12", FIXED_ROW, FIXED_ROW.replace("regress_008.rs::f_001", "regress_009.rs::f_001")),
    ("TM12", OPEN_ROW, "| F-002 | wallet_payload | alias | Low | Open |  |"),
    ("TM12", FIXED_ROW, "| F-000 | - | none found | Low | Fixed | n/a |\n" + FIXED_ROW.replace("F-001", "F-003").replace("Fixed", "Fixed").replace("crates/hardening", "crates/nope")),
    ("TM13", "| A-07 | Pairing code |", "| A-07 | Something else |"),
    ("TM13", "| X-08 | CI contributor from a fork |", "| X-08 | Somebody |"),
]


def run(path, *extra):
    return subprocess.run(
        [sys.executable, "-I", str(CHECKER), str(path), *extra],
        capture_output=True, text=True, check=False,
    )


class CheckThreatModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.valid = VALID.read_text(encoding="utf-8")

    def write(self, text):
        path = Path(self.tmp.name) / "threat-model.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_valid_fixture_passes(self):
        out = run(VALID)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(out.stdout.strip(), "PASS")

    def test_every_rule_rejects_its_fixture(self):
        for rule, old, new in MUTATIONS:
            with self.subTest(rule=rule, new=new[:60]):
                self.assertIn(old, self.valid, f"{rule}: anchor missing")
                out = run(self.write(self.valid.replace(old, new, 1)))
                self.assertEqual(out.returncode, 1, f"{rule}: {out.stdout}{out.stderr}")
                self.assertIn(f"FAIL {rule}:", out.stdout, f"{rule}: {out.stdout}")

    def test_every_rule_has_a_negative_fixture(self):
        rules = {rule for rule, _, _ in MUTATIONS}
        self.assertEqual(rules, {f"TM{n}" for n in range(1, 14)})

    def test_an_empty_audit_is_the_single_f000_row(self):
        table_start = self.valid.index(FIXED_ROW)
        text = self.valid.replace(FIXED_ROW + "\n" + OPEN_ROW, "| F-000 | - | none found | Low | Fixed | n/a |")
        self.assertNotEqual(text, self.valid, table_start)
        out = run(self.write(text))
        self.assertEqual(out.returncode, 0, out.stdout)
        bad = text.replace("| F-000 | - | none found |", "| F-004 | - | none found |")
        out = run(self.write(bad))
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("FAIL TM12:", out.stdout)

    def test_usage_errors_exit_64(self):
        self.assertEqual(run(Path(self.tmp.name) / "absent.md").returncode, 64)
        self.assertEqual(run(VALID, "extra").returncode, 64)

    @unittest.skipUnless(REAL.exists(), "threat model not written yet")
    def test_the_real_threat_model_passes(self):
        out = run(REAL)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


if __name__ == "__main__":
    unittest.main()
