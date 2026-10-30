"""common.py: Kotlin stripping, finding format, exit codes, DTD rejection."""

import io
import contextlib
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401  (puts android/policy on sys.path)
import common


class StripKotlin(unittest.TestCase):
    def test_line_comments(self):
        self.assertEqual(common.strip_kotlin("a // WebView\nb").split("\n"), ["a ", "b"])

    def test_block_comments_nested_and_multiline(self):
        text = "a /* x /* WebView */ y\n z */ b"
        out = common.strip_kotlin(text)
        self.assertNotIn("WebView", out)
        self.assertIn("a", out)
        self.assertIn("b", out)
        self.assertEqual(out.count("\n"), 1, "line count kept")

    def test_string_literals_are_emptied(self):
        out = common.strip_kotlin('val u = "java.net.URL(\\"x\\")"; f()')
        self.assertNotIn("java.net.URL", out)
        self.assertIn('val u = ""; f()', out)

    def test_raw_strings_are_emptied(self):
        out = common.strip_kotlin('val r = """WebView\n"quoted" Log.d""" + g()')
        self.assertNotIn("WebView", out)
        self.assertNotIn("Log.d", out)
        self.assertIn("+ g()", out)
        self.assertEqual(out.count("\n"), 1)

    def test_comment_markers_inside_strings_are_not_comments(self):
        out = common.strip_kotlin('val s = "http://x" ; Log.d(t)')
        self.assertIn("Log.d(t)", out)

    def test_char_literals(self):
        out = common.strip_kotlin("val q = '\"'; WebView()")
        self.assertIn("WebView()", out)

    def test_string_in_comment_and_comment_in_string(self):
        out = common.strip_kotlin('// "unterminated\nreal() /* " */ more()')
        self.assertIn("real()", out)
        self.assertIn("more()", out)


class Findings(unittest.TestCase):
    def test_format(self):
        self.assertEqual(str(common.Finding("M1", "allowBackup must be false")),
                         "M1: allowBackup must be false")

    def test_rule_id_is_validated(self):
        with self.assertRaises(ValueError):
            common.Finding("m1", "x")
        with self.assertRaises(ValueError):
            common.Finding("M", "x")

    def report(self, findings):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = common.report(findings)
        return code, out.getvalue().splitlines()

    def test_exit_code_one_when_any_finding(self):
        code, lines = self.report([common.Finding("S7", "java.net.URL in a.kt"),
                                   common.Finding("S8", "println in b.kt")])
        self.assertEqual(code, 1)
        self.assertEqual(lines, ["S7: java.net.URL in a.kt", "S8: println in b.kt"])

    def test_exit_code_zero_and_silent_otherwise(self):
        self.assertEqual(self.report([]), (0, []))


class Xml(unittest.TestCase):
    def write(self, text):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "f.xml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_doctype_and_entity_are_detected(self):
        self.assertTrue(common.has_dtd('<?xml version="1.0"?><!DOCTYPE a []><a/>'))
        self.assertTrue(common.has_dtd('<!ENTITY x "y">'))
        self.assertFalse(common.has_dtd("<a><b/></a>"))

    def test_parse_rejects_dtd(self):
        path = self.write('<?xml version="1.0"?>\n<!DOCTYPE a [<!ENTITY e "x">]>\n<a>&e;</a>')
        with self.assertRaises(common.XmlError):
            common.parse_xml(path)

    def test_parse_rejects_malformed(self):
        with self.assertRaises(common.XmlError):
            common.parse_xml(self.write("<a><b></a>"))

    def test_parse_returns_the_root(self):
        root = common.parse_xml(self.write('<a xmlns:android="http://schemas.android.com/apk/res/android" android:x="1"/>'))
        self.assertEqual(root.get(common.android("x")), "1")


class Usage(unittest.TestCase):
    def test_wrong_arguments_are_a_usage_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = common.run_main([], "check_x.py", lambda root: [])
        self.assertEqual(code, 64)
        self.assertIn("usage", err.getvalue())

    def test_missing_directory_is_a_usage_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = common.run_main(["/nonexistent/dir"], "check_x.py", lambda root: [])
        self.assertEqual(code, 64)


if __name__ == "__main__":
    unittest.main()
