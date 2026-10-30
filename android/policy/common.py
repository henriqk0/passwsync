"""Shared helpers of the Android policy checkers (contracts/android-policy.md).

Python 3 stdlib only; every checker runs as `python3 -I <checker>.py <dir>`. A finding is
printed as `<RULE>: <message>`; a checker exits 1 when it has any finding, 0 otherwise and
64 on a usage error.
"""

import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
RULE_ID = re.compile(r"^[A-Z][0-9]+$")


def android(attr: str) -> str:
    """The ElementTree name of `android:<attr>`."""
    return f"{{{ANDROID_NS}}}{attr}"


class Finding:
    __slots__ = ("rule", "message")

    def __init__(self, rule: str, message: str):
        if not RULE_ID.match(rule):
            raise ValueError(f"invalid rule id {rule!r}")
        self.rule = rule
        self.message = message

    def __str__(self) -> str:
        return f"{self.rule}: {self.message}"

    def __repr__(self) -> str:
        return f"Finding({self.rule!r}, {self.message!r})"


def report(findings) -> int:
    for finding in findings:
        print(str(finding))
    return 1 if findings else 0


def run_main(argv, program: str, check) -> int:
    """`check(root: Path) -> list[Finding]` over the single directory argument."""
    if len(argv) != 1 or argv[0].startswith("-"):
        print(f"usage: python3 -I {program} <dir>", file=sys.stderr)
        return 64
    root = Path(argv[0])
    if not root.is_dir():
        print(f"usage: python3 -I {program} <dir> ({root} is not a directory)", file=sys.stderr)
        return 64
    return report(check(root))


# --- Kotlin -----------------------------------------------------------------------------


def strip_kotlin(text: str) -> str:
    """Removes comments (`//`, nested `/* */`) and empties string literals (`"..."`,
    `\"\"\"...\"\"\"`) and char literals, keeping every newline so line numbers stay valid.
    String templates are emptied with their string: rules scan code, not text."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif c == "/" and nxt == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
            out.append(" ")
        elif text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end < 0 else end + 3
            while end < n and text[end] == '"':
                end += 1
            out.append('""' + "\n" * text.count("\n", i, end))
            i = end
        elif c == '"':
            i += 1
            while i < n and text[i] not in '"\n':
                i += 2 if text[i] == "\\" else 1
            out.append('""')
            i += 1 if i < n and text[i] == '"' else 0
        elif c == "'":
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
                while j < n and text[j] != "'" and j - i < 10:
                    j += 1
            else:
                j += 1
            if j < n and text[j] == "'":
                out.append("' '")
                i = j + 1
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def block_after(text: str, start: int):
    """(open, close) indexes of the `{...}` block whose `{` is the first at or after
    `start`, or None."""
    open_at = text.find("{", start)
    if open_at < 0:
        return None
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return open_at, i
    return open_at, len(text)


# --- XML --------------------------------------------------------------------------------

DTD = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class XmlError(Exception):
    pass


def has_dtd(text: str) -> bool:
    return bool(DTD.search(text))


def parse_xml(path: Path):
    """The root element; DOCTYPE/ENTITY declarations and malformed XML raise XmlError."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise XmlError(f"{path.name}: cannot be read ({error.__class__.__name__})") from None
    if has_dtd(text):
        raise XmlError(f"{path.name}: DOCTYPE or ENTITY declaration")
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        raise XmlError(f"{path.name}: not well-formed ({error})") from None


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
