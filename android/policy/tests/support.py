"""Shared helpers of the policy unit tests (stdlib only; run with `python3 -I`).

Every negative test starts from a copy of the known-good fixture tree, applies exactly one
violation and runs one checker in-process.
"""

import contextlib
import importlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
POLICY = TESTS.parent
GOOD = TESTS / "fixtures" / "good"
BINDINGS = "bindings"
INVENTORY = GOOD / "bindings-inventory.txt"
REPO = POLICY.parent.parent

if str(POLICY) not in sys.path:
    sys.path.insert(0, str(POLICY))


def copy_good() -> Path:
    """A fresh copy of the good fixture in a new temporary directory (caller removes it)."""
    root = Path(tempfile.mkdtemp(prefix="policy-")) / "android"
    shutil.copytree(GOOD, root)
    return root


def mutate(path: Path, find: str, replace: str) -> None:
    """Replaces the first occurrence of `find`; a missing `find` is a broken test."""
    text = path.read_text(encoding="utf-8")
    if find not in text:
        raise AssertionError(f"{find!r} not found in {path}")
    path.write_text(text.replace(find, replace, 1), encoding="utf-8")


def run_checker(name: str, root: Path, *args: str):
    """Runs `<name>.main([root, *args])`; returns (exit code, stdout lines)."""
    module = importlib.import_module(name)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            code = module.main([str(root), *args])
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue().splitlines()


def rule_ids(lines):
    return [line.split(":", 1)[0] for line in lines if ":" in line]


class PolicyCase(unittest.TestCase):
    """Base class: `self.tree()` gives a fresh good tree removed after the test."""

    checker = ""
    extra_args: tuple = ()

    def tree(self) -> Path:
        root = copy_good()
        self.addCleanup(shutil.rmtree, root.parent, ignore_errors=True)
        return root

    def run_on(self, root: Path):
        return run_checker(self.checker, root, *self.extra_args_for(root))

    def extra_args_for(self, root: Path):
        return list(self.extra_args)

    def assertPasses(self, root: Path):
        code, lines = self.run_on(root)
        self.assertEqual((code, lines), (0, []))

    def assertFails(self, root: Path, rule: str):
        """Exit 1 and `rule` is the first token of an output line."""
        code, lines = self.run_on(root)
        self.assertEqual(code, 1, lines)
        self.assertIn(rule, rule_ids(lines), lines)
        return lines
