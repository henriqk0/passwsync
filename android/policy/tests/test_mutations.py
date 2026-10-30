"""mutations.py: the harness applies exactly one mutation to a copy of the tree, runs the
owning checker and requires exit 1 with a line starting with the mutation's rule id; it
reports undetected mutations, detection under another id, and rules without a mutation."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from support import GOOD, INVENTORY

import mutations
from mutations import Mutation

MAN = "app/src/main/AndroidManifest.xml"
PERM = '<uses-permission android:name="android.permission.INTERNET" />'
BINDING = "io/github/henriqk0/passwsync/core/passwsync_ffi.kt"


class Harness(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="mut-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.android = GOOD
        self.bindings = GOOD / "bindings"

    def run_one(self, mutation):
        return mutations.run_one(mutation, self.android, self.bindings, self.work, inventory=INVENTORY)

    def test_owner_by_prefix(self):
        self.assertEqual(mutations.owner("M4"), "check_manifest")
        self.assertEqual(mutations.owner("X2"), "check_manifest")
        self.assertEqual(mutations.owner("G7"), "check_manifest")
        self.assertEqual(mutations.owner("S12"), "check_sources")
        self.assertEqual(mutations.owner("B5"), "check_bindings")

    def test_a_detected_mutation_passes(self):
        ok, detail = self.run_one(Mutation("M1", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"'))
        self.assertTrue(ok, detail)

    def test_an_undetected_mutation_fails(self):
        ok, detail = self.run_one(Mutation("G7", "app/proguard-rules.pro", "replace", "# JNA", "# jna"))
        self.assertFalse(ok)
        self.assertIn("not detected", detail)

    def test_detection_under_another_id_fails(self):
        ok, detail = self.run_one(Mutation("M2", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"'))
        self.assertFalse(ok)
        self.assertIn("M1", detail)

    def test_a_find_that_does_not_apply_fails(self):
        ok, detail = self.run_one(Mutation("M1", MAN, "replace", "no such text", "x"))
        self.assertFalse(ok)
        self.assertIn("does not apply", detail)

    def test_insert_after(self):
        ok, detail = self.run_one(Mutation("M4", MAN, "insert_after", PERM, '\n    <uses-permission android:name="android.permission.VIBRATE" />'))
        self.assertTrue(ok, detail)

    def test_add_file(self):
        code = 'package io.github.henriqk0.passwsync\n\nval u = java.net.URL("http://example.org")\n'
        ok, detail = self.run_one(Mutation("S7", "app/src/main/kotlin/io/github/henriqk0/passwsync/Net.kt", "add_file", "", code))
        self.assertTrue(ok, detail)

    def test_delete_file(self):
        ok, detail = self.run_one(Mutation("M2", "app/src/main/res/xml/data_extraction_rules.xml", "delete_file"))
        self.assertTrue(ok, detail)

    def test_binding_mutations_apply_to_the_bindings(self):
        ok, detail = self.run_one(Mutation("B2", BINDING, "replace", "`password`: kotlin.ByteArray, `confirm`", "`password`: kotlin.String, `confirm`"))
        self.assertTrue(ok, detail)

    def test_the_tree_is_never_modified_and_copies_are_removed(self):
        before = (GOOD / MAN).read_text(encoding="utf-8")
        self.run_one(Mutation("M1", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"'))
        self.assertEqual((GOOD / MAN).read_text(encoding="utf-8"), before)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            Mutation("M1", MAN, "rename")
        with self.assertRaises(ValueError):
            Mutation("Q1", MAN, "replace", "a", "b")

    def test_coverage_reports_rules_without_mutation(self):
        some = [Mutation("M1", MAN, "replace", "a", "b"), Mutation("S7", "x.kt", "add_file", "", "")]
        missing = mutations.coverage(some, ["M1", "M2", "S7", "B1"])
        self.assertEqual(missing, ["M2", "B1"])

    def test_rule_list_is_the_three_checkers(self):
        rules = mutations.all_rules()
        self.assertEqual(len(rules), 13 + 7 + 7 + 17 + 6)
        self.assertIn("M13", rules)
        self.assertIn("S17", rules)
        self.assertIn("B6", rules)

    def test_run_all_collects_failures_and_coverage(self):
        good = Mutation("M1", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"')
        bad = Mutation("M3", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"')
        failures = mutations.run_all([good, bad], self.android, self.bindings, self.work,
                                     inventory=INVENTORY, rules=["M1", "M3", "M9"])
        text = "\n".join(failures)
        self.assertIn("M3", text)
        self.assertIn("no mutation for M9", text)
        self.assertNotIn("M1 ", text.replace("M1:", ""))

    def test_a_failing_baseline_is_reported(self):
        broken = self.work / "broken"
        shutil.copytree(GOOD, broken)
        path = broken / MAN
        path.write_text(path.read_text(encoding="utf-8").replace('android:allowBackup="false"', 'android:allowBackup="true"'), encoding="utf-8")
        failures = mutations.run_all([], broken, broken / "bindings", self.work / "w", inventory=INVENTORY, rules=[])
        self.assertTrue(any("baseline" in f for f in failures), failures)

    def test_main_exit_codes(self):
        from unittest import mock
        out = io.StringIO()
        with mock.patch.object(mutations, "MUTATIONS", []), contextlib.redirect_stdout(out):
            code = mutations.main([str(GOOD), str(GOOD / "bindings"), str(self.work), "--inventory", str(INVENTORY)])
        # Without mutations every rule is uncovered.
        self.assertEqual(code, 1)
        self.assertIn("no mutation for M1", out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mutations.main([]), 64)


if __name__ == "__main__":
    unittest.main()
