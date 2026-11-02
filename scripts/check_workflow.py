#!/usr/bin/env python3
"""Policy check of the CI workflow (008 contracts/ci-workflow.md, rules W1-W14).

Usage: python3 scripts/check_workflow.py [.github/workflows/ci.yml]

Reads a restricted YAML subset only (block mappings and sequences, plain or quoted scalars,
`|` block scalars); anchors, aliases, tags, flow collections, tabs and multiple documents are
rejected, so the checker never interprets YAML it did not anticipate (fail closed).

Prints `PASS` (after one `PENDING [CI] <pin>` line per unresolved pin) or one
`FAIL Wn: <detail>` line per violation. Exit 0 pass, 1 fail, 64 usage. Python 3 stdlib only.
"""

import re
import sys
from pathlib import Path

ZERO_DIGEST = "0" * 64
TOP_KEYS = {"name", "on", "permissions", "defaults", "env", "jobs"}
TRIGGERS = {"push", "pull_request", "workflow_dispatch", "schedule"}
VERIFY_CALLS = ("scripts/gate.sh", "android/verify.sh", "packaging/verify.sh")
REFUSE_STEP = "refuse unresolved pins"


class YamlError(Exception):
    pass


# --- restricted YAML reader -----------------------------------------------------------------


def strip_comment(text):
    """Removes a trailing ` #...` comment outside quotes."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def scalar(text, lineno):
    text = text.strip()
    if not text:
        return ""
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise YamlError(f"line {lineno}: unterminated quote")
        return text[1:-1].replace("''", "'")
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise YamlError(f"line {lineno}: unterminated quote")
        body = text[1:-1]
        return body.replace('\\"', '"').replace("\\\\", "\\")
    if text[0] in "&*!{[%@`|>":
        raise YamlError(f"line {lineno}: anchors, aliases, tags and flow collections are not allowed")
    if re.search(r"\s[&*!]\S", " " + text) and not text.startswith(("$", "[")):
        if re.match(r"^[&*!]", text):
            raise YamlError(f"line {lineno}: anchors, aliases and tags are not allowed")
    return text


def split_key(content, lineno):
    """`key: value` or `key:` (key plain or quoted). Returns (key, rest) or None."""
    m = re.match(r"""^("([^"\\]|\\.)*"|'([^']|'')*'|[^\s'"#:][^:#]*?)\s*:(\s+(.*))?$""", content)
    if not m:
        return None
    key = scalar(m.group(1), lineno)
    return key, (m.group(5) or "").strip()


class Line:
    def __init__(self, lineno, indent, content):
        self.lineno = lineno
        self.indent = indent
        self.content = content


def tokenize(text):
    if "\t" in text:
        raise YamlError("tabs are not allowed")
    raw = text.split("\n")
    lines = []
    for number, line in enumerate(raw, 1):
        if line.strip() in ("---", "..."):
            raise YamlError(f"line {number}: multiple documents are not allowed")
        lines.append((number, line))
    return lines


class Reader:
    def __init__(self, text):
        self.raw = tokenize(text)
        self.pos = 0

    def peek(self):
        """Next non-blank, non-comment line as Line, or None."""
        while self.pos < len(self.raw):
            number, line = self.raw[self.pos]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                self.pos += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            return Line(number, indent, strip_comment(line[indent:]))
        return None

    def block_scalar(self, parent_indent):
        out = []
        block_indent = None
        while self.pos < len(self.raw):
            number, line = self.raw[self.pos]
            if line.strip() == "":
                out.append("")
                self.pos += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = indent
            if indent < block_indent:
                raise YamlError(f"line {number}: bad block indentation")
            out.append(line[block_indent:])
            self.pos += 1
        while out and out[-1] == "":
            out.pop()
        return "\n".join(out) + "\n"

    def value_after_key(self, rest, indent, lineno):
        if rest in ("|", "|-"):
            return self.block_scalar(indent)
        if rest in (">", ">-") or rest.startswith(("|+", ">+")):
            raise YamlError(f"line {lineno}: folded block scalars are not allowed")
        if rest:
            return scalar(rest, lineno)
        nxt = self.peek()
        if nxt is None or nxt.indent < indent:
            return None
        if nxt.indent == indent:
            if nxt.content.startswith("- ") or nxt.content == "-":
                return self.sequence(indent)
            return None
        return self.node(nxt.indent)

    def node(self, indent):
        line = self.peek()
        if line is None:
            return None
        if line.indent != indent:
            raise YamlError(f"line {line.lineno}: unexpected indentation")
        if line.content.startswith("- ") or line.content == "-":
            return self.sequence(indent)
        return self.mapping(indent)

    def mapping(self, indent, first=None):
        out = {}
        while True:
            if first is not None:
                line, first = first, None
            else:
                line = self.peek()
                if line is None or line.indent < indent:
                    return out
                if line.indent > indent:
                    raise YamlError(f"line {line.lineno}: unexpected indentation")
                if line.content.startswith("- ") or line.content == "-":
                    return out
                self.pos += 1
            parts = split_key(line.content, line.lineno)
            if parts is None:
                raise YamlError(f"line {line.lineno}: expected 'key: value'")
            key, rest = parts
            if key in out:
                raise YamlError(f"line {line.lineno}: duplicate key {key!r}")
            out[key] = self.value_after_key(rest, indent, line.lineno)

    def sequence(self, indent):
        out = []
        while True:
            line = self.peek()
            if line is None or line.indent != indent:
                return out
            if not (line.content.startswith("- ") or line.content == "-"):
                return out
            self.pos += 1
            rest = line.content[1:].lstrip(" ")
            if not rest:
                nxt = self.peek()
                out.append(self.node(nxt.indent) if nxt and nxt.indent > indent else None)
                continue
            inner = indent + (len(line.content) - len(rest))
            if split_key(rest, line.lineno) is not None:
                out.append(self.mapping(inner, first=Line(line.lineno, inner, rest)))
            else:
                out.append(scalar(rest, line.lineno))


def parse(text):
    reader = Reader(text)
    doc = reader.node(0)
    if reader.peek() is not None:
        raise YamlError(f"line {reader.peek().lineno}: trailing content")
    if not isinstance(doc, dict):
        raise YamlError("top level is not a mapping")
    return doc


# --- rules ----------------------------------------------------------------------------------


def walk(node, path=()):
    """Yields (path, key_or_None, value) for every mapping entry and every scalar."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield path, key, value
            yield from walk(value, path + (key,))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk(value, path + (i,))
    elif isinstance(node, str):
        yield path, None, node


def strings(doc):
    return [v for _, k, v in walk(doc) if k is None and isinstance(v, str)]


def run_texts(doc):
    out = []
    for job in (doc.get("jobs") or {}).values():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                out.append(step["run"])
    return out


def check(doc, text):
    fails = []
    pending = []

    def fail(rule, detail):
        fails.append(f"FAIL {rule}: {detail}")

    # W1 top-level keys.
    extra = set(doc) - TOP_KEYS
    if extra:
        fail("W1", f"top-level keys not allowed: {sorted(extra)}")

    # W2 triggers.
    on = doc.get("on")
    if not isinstance(on, dict):
        fail("W2", "'on' must be a mapping of triggers")
    else:
        keys = set(on)
        if keys != TRIGGERS:
            fail("W2", f"triggers must be exactly {sorted(TRIGGERS)}, got {sorted(keys)}")
        schedule = on.get("schedule")
        crons = schedule if isinstance(schedule, list) else []
        weekly = re.compile(r"^([0-5]?\d) ([01]?\d|2[0-3]) \* \* [0-6]$")
        if len(crons) != 1 or not isinstance(crons[0], dict) or set(crons[0]) != {"cron"} or not weekly.match(str(crons[0]["cron"])):
            fail("W2", "schedule must be exactly one weekly cron")

    # W3 permissions.
    if doc.get("permissions") != {"contents": "read"}:
        fail("W3", "top-level permissions must be exactly 'contents: read'")
    for name, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict) and "permissions" in job and job["permissions"] != {"contents": "read"}:
            fail("W3", f"job {name}: permissions differ from 'contents: read'")
    for path, key, value in walk(doc):
        if key is not None and "permissions" in path + (key,) and isinstance(value, str):
            if value in ("write", "write-all", "read-all") or key in ("write-all",):
                fail("W3", f"permission value {value!r} not allowed")

    # W4 secrets and tokens.
    for token in ("secrets.", "secrets[", "github.token", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN"):
        if token in text:
            fail("W4", f"forbidden reference {token!r}")
    for _, key, _ in walk(doc):
        if key == "environment":
            fail("W4", "'environment:' is not allowed")

    # W5 action pins.
    uses = [v for _, k, v in walk(doc) if k == "uses"]
    for value in uses:
        value = str(value)
        if value.startswith("./"):
            fail("W5", f"local action {value!r} not allowed")
        elif value.startswith("docker://"):
            if not re.fullmatch(r"docker://[\w./-]+@sha256:[0-9a-f]{64}", value):
                fail("W5", f"docker action {value!r} not pinned by digest")
        elif not re.fullmatch(r"[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}", value):
            fail("W5", f"action {value!r} not pinned by a 40-hex commit")

    # W6 images.
    for path, key, value in walk(doc):
        if key in ("image", "container") and isinstance(value, str):
            m = re.fullmatch(r"[\w./-]+@sha256:([0-9a-f]{64})", value)
            if not m:
                fail("W6", f"image {value!r} not pinned by digest")
            elif m.group(1) == ZERO_DIGEST:
                pin = f"PENDING [CI] image {value}"
                if pin not in pending:
                    pending.append(pin)

    # W7 credentials.
    for _, key, value in walk(doc):
        if key == "persist-credentials" and str(value) != "false":
            fail("W7", "persist-credentials must be false")
    for value in uses:
        if str(value).startswith("actions/checkout@"):
            pass  # checked below via the step's `with`
    for job in (doc.get("jobs") or {}).values():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout@"):
                if (step.get("with") or {}).get("persist-credentials") != "false":
                    fail("W7", "actions/checkout must set persist-credentials: false")
    for s in strings(doc):
        if re.search(r"git\s+config[^\n]*credential", s) or "http.extraheader" in s or re.search(r"https?://[^\s/\"']*@", s):
            fail("W7", "a step stores or embeds credentials")
            break

    # W8 publishing steps.
    forbidden = [
        (r"git\s+push", "git push"), (r"git\s+tag", "git tag"), (r"(^|[\s;&|(])gh\s", "gh"),
        (r"cargo\s+publish", "cargo publish"), (r"docker\s+push", "docker push"),
        (r"docker\s+login", "docker login"), (r"\btwine\b", "twine"), (r"npm\s+publish", "npm publish"),
        (r"upload-artifact", "upload-artifact"), (r"actions/cache", "actions/cache"),
        (r"/releases", "/releases"), (r"curl\b[^\n]*(-X|--request)\s*(POST|PUT|PATCH|DELETE)", "curl write"),
        (r"--upload-file", "--upload-file"),
    ]
    for s in strings(doc):
        for pattern, label in forbidden:
            if re.search(pattern, s):
                fail("W8", f"publishing step not allowed: {label}")

    # W9 timeouts.
    for name, job in (doc.get("jobs") or {}).items():
        value = (job or {}).get("timeout-minutes") if isinstance(job, dict) else None
        if value is None or not re.fullmatch(r"\d+", str(value)) or not 1 <= int(value) <= 120:
            fail("W9", f"job {name}: timeout-minutes must be an integer in 1..120")

    # W10 verify calls, no masking.
    runs = run_texts(doc)
    for call in VERIFY_CALLS:
        if not any(re.search(rf"(^|\s){re.escape(call)}(\s|$)", r) for r in runs):
            fail("W10", f"{call} is never invoked")
    for _, key, _ in walk(doc):
        if key == "continue-on-error":
            fail("W10", "continue-on-error is not allowed")
    for r in runs:
        if re.search(r"\|\|\s*true\b", r) or re.search(r"set\s+\+e\b", r):
            fail("W10", "a step masks failures ('|| true' or 'set +e')")
            break

    # W11 pinned tool installs.
    env = doc.get("env") or {}
    for r in runs:
        for m in re.finditer(r"cargo\s+install([^\n;&|]*)", r):
            args = m.group(1)
            if "--locked" not in args.split():
                fail("W11", "cargo install without --locked")
            crates = [a for a in args.split() if not a.startswith("-")]
            for crate in crates:
                pin = re.fullmatch(r'[\w-]+@(\d+\.\d+\.\d+|"\$(\w+)"|\$(\w+))', crate)
                var = pin and (pin.group(2) or pin.group(3))
                if not pin or (var and not re.fullmatch(r"\d+\.\d+\.\d+", str(env.get(var, "")))):
                    fail("W11", f"cargo install of {crate!r} not pinned to an exact version")
            if not crates:
                fail("W11", "cargo install without a pinned crate")
        if re.search(r"\brustup\b", r):
            fail("W11", "rustup is not allowed")
        if re.search(r"(curl|wget)\b[^\n]*\|\s*(ba)?sh\b", r):
            fail("W11", "piping a download into a shell is not allowed")
        for tool in ("pip install", "npm install"):
            if tool in r:
                fail("W11", f"{tool} is not allowed")
        for m in re.finditer(r"apt-get\s+install([^\n;&|]*)", r):
            pkgs = [a for a in m.group(1).split() if not a.startswith("-")]
            if not pkgs or any("=" not in p for p in pkgs):
                fail("W11", "apt-get install without exact versions")

    # W12 package sources.
    snapshot = str(env.get("ARCH_SNAPSHOT", ""))
    if snapshot == "UNRESOLVED":
        pending.append("PENDING [CI] ARCH_SNAPSHOT=UNRESOLVED")
    elif not re.fullmatch(r"\d{4}/\d{2}/\d{2}", snapshot):
        fail("W12", "ARCH_SNAPSHOT must be YYYY/MM/DD or UNRESOLVED")
    for s in strings(doc):
        for bad in ("mirrors.kernel.org", "pacman-mirrors", "reflector"):
            if bad in s:
                fail("W12", f"package source {bad!r} not allowed")
        for m in re.finditer(r"Server\s*=\s*(\S+)", s):
            url = m.group(1)
            if not re.match(r"https://archive\.archlinux\.org/repos/(\d{4}/\d{2}/\d{2}|\$\{ARCH_SNAPSHOT\})/", url):
                fail("W12", f"pacman server {url!r} is not a dated archive snapshot")
        if re.search(r"pacman\s+-S", s) and "archive.archlinux.org" not in text:
            fail("W12", "pacman runs without the dated archive snapshot")

    # W13 refuse step first.
    for name, job in (doc.get("jobs") or {}).items():
        steps = (job or {}).get("steps") if isinstance(job, dict) else None
        first = steps[0] if isinstance(steps, list) and steps else None
        if not (isinstance(first, dict) and first.get("name") == REFUSE_STEP and "ARCH_SNAPSHOT" in str(first.get("run", ""))):
            fail("W13", f"job {name}: first step must be '{REFUSE_STEP}'")

    # W14 hosted runners.
    for name, job in (doc.get("jobs") or {}).items():
        runs_on = (job or {}).get("runs-on") if isinstance(job, dict) else None
        if not isinstance(runs_on, str) or not re.fullmatch(r"ubuntu-[\w.]+", runs_on):
            fail("W14", f"job {name}: runs-on must be a GitHub-hosted ubuntu label")

    return fails, pending


def main(argv):
    if len(argv) > 1:
        print("usage: check_workflow.py [workflow.yml]", file=sys.stderr)
        return 64
    path = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        print(f"usage: cannot read {path}", file=sys.stderr)
        return 64
    try:
        doc = parse(text)
    except YamlError as error:
        print(f"FAIL W1: {error}")
        return 1
    fails, pending = check(doc, text)
    if fails:
        for line in dict.fromkeys(fails):
            print(line)
        return 1
    for line in pending:
        print(line)
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
