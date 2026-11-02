"""Negative and positive tests of scripts/check_workflow.py (008 contracts/ci-workflow.md W1-W14,
SC-010). Each negative case mutates a valid workflow once and expects exit 1 with `FAIL Wn`.
Bad copies are written under a temporary directory only."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_workflow.py"
REAL = ROOT / ".github" / "workflows" / "ci.yml"

ZERO = "0" * 64
DIGEST = "1" * 64

# A minimal valid workflow in the restricted subset (one job; pins resolved).
MINIMAL = f"""name: ci
on:
  push:
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: "17 4 * * 1"
permissions:
  contents: read
defaults:
  run:
    shell: bash
env:
  ARCH_SNAPSHOT: "2026/10/29"
  CARGO_DENY_VERSION: "0.20.2"
  CARGO_AUDIT_VERSION: "0.22.2"
jobs:
  gate:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    container:
      image: archlinux@sha256:{DIGEST}
    steps:
      - name: refuse unresolved pins
        run: '[[ "$ARCH_SNAPSHOT" =~ ^[0-9]{{4}}/[0-9]{{2}}/[0-9]{{2}}$ ]] || exit 1'
      - name: packages from dated snapshot
        run: |
          echo 'Server = https://archive.archlinux.org/repos/${{ARCH_SNAPSHOT}}/$repo/os/$arch' > /etc/pacman.d/mirrorlist
          pacman -Syyuu --noconfirm git rust python
      - name: checkout
        run: |
          git init -q .
          git fetch --depth=1 --no-tags "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git" "$GITHUB_SHA"
          git checkout -q FETCH_HEAD
      - name: tools
        run: cargo install --locked cargo-deny@"$CARGO_DENY_VERSION" cargo-audit@"$CARGO_AUDIT_VERSION"
      - name: gate
        run: |
          scripts/gate.sh --fetch
          scripts/gate.sh
          android/verify.sh
          packaging/verify.sh
"""

# (rule, old, new): replace the first occurrence of `old` by `new` in the base text.
MUTATIONS = [
    ("W1", "name: ci\n", "name: &a ci\n"),
    ("W1", "name: ci\n", "name: *a\n"),
    ("W1", "permissions:\n  contents: read\n", "permissions: {contents: read}\n"),
    ("W1", "name: ci\n", "name: ci\nconcurrency: x\n"),
    ("W1", "name: ci\n", "---\nname: ci\n"),
    ("W2", "  push:\n", "  pull_request_target:\n"),
    ("W2", "  push:\n", "  push:\n  workflow_run:\n"),
    ("W2", "  push:\n", "  push:\n  issue_comment:\n"),
    ("W2", '  schedule:\n    - cron: "17 4 * * 1"\n', ""),
    ("W2", '"17 4 * * 1"', '"17 4 * * *"'),
    ("W3", "  contents: read\n", "  contents: write\n"),
    ("W3", "  contents: read\n", "  contents: read\n  id-token: write\n"),
    ("W3", "permissions:\n  contents: read\n", "permissions: write-all\n"),
    ("W3", "    timeout-minutes: 60\n", "    timeout-minutes: 60\n    permissions: read-all\n"),
    ("W4", "scripts/gate.sh\n", "scripts/gate.sh ${{ secrets.TOKEN }}\n"),
    ("W4", "scripts/gate.sh\n", "scripts/gate.sh ${{ github.token }}\n"),
    ("W4", "scripts/gate.sh\n", "GITHUB_TOKEN=x scripts/gate.sh\n"),
    ("W4", "    timeout-minutes: 60\n", "    timeout-minutes: 60\n    environment: prod\n"),
    ("W5", "      - name: tools\n", "      - uses: actions/checkout@v4\n      - name: tools\n"),
    ("W5", "      - name: tools\n", "      - uses: actions/checkout@main\n      - name: tools\n"),
    ("W5", "      - name: tools\n", "      - uses: actions/checkout@0123abc\n      - name: tools\n"),
    ("W6", f"archlinux@sha256:{DIGEST}", "archlinux:latest"),
    ("W6", f"archlinux@sha256:{DIGEST}", "archlinux:base"),
    ("W7", "      - name: tools\n",
     "      - uses: actions/checkout@" + "a" * 40 + "\n        with:\n          persist-credentials: true\n      - name: tools\n"),
    ("W7", "git init -q .\n", "git init -q .\n          git config --global credential.helper store\n"),
    ("W7", '"$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git"', '"https://user:pw@github.com/x/y.git"'),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          git push origin HEAD\n"),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          git tag v1\n"),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          gh release create v1\n"),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          cargo publish\n"),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          docker push x\n"),
    ("W8", "      - name: tools\n", "      - uses: actions/upload-artifact@" + "b" * 40 + "\n      - name: tools\n"),
    ("W8", "      - name: tools\n", "      - uses: actions/cache@" + "c" * 40 + "\n      - name: tools\n"),
    ("W8", "scripts/gate.sh\n", "scripts/gate.sh\n          curl -X POST https://example.invalid/x\n"),
    ("W9", "    timeout-minutes: 60\n", ""),
    ("W9", "    timeout-minutes: 60\n", "    timeout-minutes: 0\n"),
    ("W9", "    timeout-minutes: 60\n", "    timeout-minutes: 1000\n"),
    ("W10", "          android/verify.sh\n", ""),
    ("W10", "      - name: gate\n", "      - name: gate\n        continue-on-error: true\n"),
    ("W10", "          scripts/gate.sh\n          android", "          scripts/gate.sh || true\n          android"),
    ("W11", '@"$CARGO_DENY_VERSION"', ""),
    ("W11", "cargo install --locked", "cargo install"),
    ("W11", "scripts/gate.sh\n", "scripts/gate.sh\n          rustup update\n"),
    ("W11", "scripts/gate.sh\n", "scripts/gate.sh\n          curl -sSf https://sh.example.invalid | sh\n"),
    ("W12", "https://archive.archlinux.org/repos/${ARCH_SNAPSHOT}/", "https://mirrors.kernel.org/archlinux/"),
    ("W12", "pacman -Syyuu", "reflector --save /etc/pacman.d/mirrorlist; pacman -Syyuu"),
    ("W12", 'ARCH_SNAPSHOT: "2026/10/29"', 'ARCH_SNAPSHOT: "latest"'),
    ("W13", "      - name: refuse unresolved pins\n        run: '[[ \"$ARCH_SNAPSHOT\" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]] || exit 1'\n", ""),
    ("W14", "runs-on: ubuntu-24.04", "runs-on: self-hosted"),
]

# SC-010: the six classes named by the success criterion, each rejected.
SC010 = {
    "secret reference": "W4",
    "write permission": "W3",
    "privileged trigger": "W2",
    "unpinned action or image": "W5",
    "persisted credentials": "W7",
    "publish/push/upload step": "W8",
}


def run(path):
    return subprocess.run(
        [sys.executable, "-I", str(CHECKER), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


class CheckWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text, name="ci.yml"):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def assert_rejects(self, base, rule, old, new):
        self.assertIn(old, base, f"{rule}: fixture anchor missing: {old!r}")
        bad = self.write(base.replace(old, new, 1))
        out = run(bad)
        self.assertEqual(out.returncode, 1, f"{rule} {new!r}: {out.stdout}{out.stderr}")
        self.assertIn(f"FAIL {rule}:", out.stdout, f"{rule} {new!r}: {out.stdout}")

    def test_minimal_valid_workflow_passes(self):
        out = run(self.write(MINIMAL))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(out.stdout.strip(), "PASS")

    def test_every_negative_fixture_is_rejected_with_its_rule(self):
        for rule, old, new in MUTATIONS:
            with self.subTest(rule=rule, new=new):
                self.assert_rejects(MINIMAL, rule, old, new)

    def test_sc010_classes_are_each_covered(self):
        rules = {rule for rule, _, _ in MUTATIONS}
        for cls, rule in SC010.items():
            self.assertIn(rule, rules, cls)

    def test_sentinel_pins_are_pending_not_failures(self):
        text = MINIMAL.replace(DIGEST, ZERO).replace('"2026/10/29"', '"UNRESOLVED"')
        out = run(self.write(text))
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual(out.stdout.count("PENDING [CI]"), 2, out.stdout)
        self.assertTrue(out.stdout.strip().endswith("PASS"), out.stdout)

    def test_usage_errors_exit_64(self):
        out = subprocess.run(
            [sys.executable, "-I", str(CHECKER), "a.yml", "b.yml"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(out.returncode, 64)
        out = run(Path(self.tmp.name) / "absent.yml")
        self.assertEqual(out.returncode, 64)

    def test_tabs_and_multiple_documents_fail_closed(self):
        self.assert_rejects(MINIMAL, "W1", "  push:\n", "\tpush:\n")
        self.assert_rejects(MINIMAL, "W1", "name: ci\n", "name: !tag ci\n")

    @unittest.skipUnless(REAL.exists(), "real workflow not written yet")
    def test_real_workflow_passes_with_pending_pins_only(self):
        out = run(REAL)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        pending = [l for l in out.stdout.splitlines() if l.startswith("PENDING [CI]")]
        self.assertEqual(len(pending), 2, out.stdout)
        self.assertEqual(out.stdout.splitlines()[-1], "PASS")

    @unittest.skipUnless(REAL.exists(), "real workflow not written yet")
    def test_mutations_of_the_real_workflow_are_rejected(self):
        real = REAL.read_text(encoding="utf-8")
        cases = [
            ("W2", "  push:\n", "  pull_request_target:\n"),
            ("W3", "  contents: read\n", "  contents: write\n"),
            ("W4", "scripts/gate.sh --fetch\n", "scripts/gate.sh --fetch ${{ secrets.X }}\n"),
            ("W6", "archlinux@sha256:" + ZERO, "archlinux:latest"),
            ("W8", "          git checkout -q FETCH_HEAD\n", "          git checkout -q FETCH_HEAD\n          git push\n"),
            ("W9", "    timeout-minutes: 45\n", "    timeout-minutes: 1000\n"),
            ("W10", "android/verify.sh", "android/nothing.sh"),
            ("W14", "runs-on: ubuntu-24.04", "runs-on: self-hosted"),
        ]
        for rule, old, new in cases:
            with self.subTest(rule=rule):
                self.assert_rejects(real, rule, old, new)


if __name__ == "__main__":
    unittest.main()
