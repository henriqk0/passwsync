#!/usr/bin/env python3
"""Structure check of the system threat model (008 contracts/threat-model-structure.md,
rules TM1-TM13).

Usage: python3 scripts/check_threat_model.py [docs/threat-model.md]

Prints `PASS` or one `FAIL TMn: <detail>` line per violation. Exit 0 pass, 1 fail, 64 usage.
Python 3 stdlib only (re, tomllib, pathlib). Paths in the document are repository paths.
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_TSV = ROOT / "scripts" / "threat_model_required.tsv"
DENY_FILES = [ROOT / "deny.toml", ROOT / "tools" / "uniffi-bindgen" / "deny.toml"]

SKELETON = [
    "# Threat Model",
    "## 1. Scope and method",
    "## 2. Severity scale",
    "## 3. Assets",
    "## 4. Actors",
    "## 5. Data flows and trust boundaries",
    "## 6. Threats by boundary",
    "## 7. Out-of-model inputs",
    "## 8. Residual-risk register",
    "## 9. Audit findings",
    "## 10. Change log",
]
BOUNDARIES = [
    "B-01 Wallet at rest",
    "B-02 Process memory and OS",
    "B-03 Loopback HTTP service and browser",
    "B-04 LAN discovery",
    "B-05 Pairing",
    "B-06 Paired channel",
    "B-07 Wallet sync",
    "B-08 Sharing",
    "B-09 Android app and platform",
    "B-10 Packaging and service manager",
    "B-11 Build, dependency and CI supply chain",
]
ASSETS = ["master password", "derived key", "decrypted credential", "wallet file",
          "device private key", "pin", "pairing code", "invite code", "session token",
          "sync record"]
ACTORS = ["remote lan attacker", "malicious paired device", "other local os user",
          "malicious web page", "same-user malware", "thief of a powered-off device",
          "compromised dependency", "ci contributor from a fork"]
SEVERITIES = {"High", "Medium", "Low"}
RR_STATUS = {"Accepted", "Pending approval", "Open"}

REF_PATTERNS = [
    r"\b\d{3} (FR|SC)-\d{3}[a-z]?\b",
    r"crates/[\w-]+/tests/[\w/]+\.rs(::\w+)?",
    r"(scripts|android|packaging)/[\w/.-]+",
    r"\bRR-\d{2}\b",
    r"\bF-\d{3}\b",
    r"\b\d{3} R\d+\b",
]
PATH_PATTERN = re.compile(
    r"(crates/[\w-]+/(tests|src)/[\w/]+\.rs|(?:scripts|android|packaging|specs|docs)/[\w/.-]*[\w/-]|deny\.toml|tools/uniffi-bindgen/deny\.toml|\.github/workflows/ci\.yml)"
)


def cells(line):
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [c.strip() for c in inner.split("|")]


def sections(lines):
    """Headings (level, text, index) in order."""
    out = []
    fence = False
    for i, line in enumerate(lines):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^(#{1,6}) (.*\S)\s*$", line)
        if m:
            out.append((len(m.group(1)), line.strip(), i))
    return out


def tables(lines, start, end):
    """Pipe tables between line indexes: list of (header, rows[(lineno, cells)])."""
    out = []
    i = start
    while i < end:
        if lines[i].lstrip().startswith("|"):
            header = cells(lines[i])
            j = i + 1
            if j < end and re.match(r"^\s*\|[\s:|-]+\|?\s*$", lines[j]):
                j += 1
            rows = []
            while j < end and lines[j].lstrip().startswith("|"):
                rows.append((j + 1, cells(lines[j])))
                j += 1
            out.append((header, rows))
            i = j
        else:
            i += 1
    return out


def repo_paths(text):
    for m in PATH_PATTERN.finditer(text):
        yield m.group(0).rstrip(".,")


def path_exists(path):
    return (ROOT / path).exists()


def check(text):
    fails = []

    def fail(rule, detail):
        fails.append(f"FAIL {rule}: {detail}")

    lines = text.split("\n")
    heads = sections(lines)
    top = [h for lvl, h, _ in heads if lvl <= 2]
    if top != SKELETON:
        fail("TM1", f"headings differ from the skeleton: {top}")
    index = {h: i for lvl, h, i in heads if lvl <= 2}

    def span(heading):
        if heading not in index:
            return None
        start = index[heading]
        later = [i for lvl, h, i in heads if lvl <= 2 and i > start]
        return start + 1, (min(later) if later else len(lines))

    def section_tables(heading):
        s = span(heading)
        return tables(lines, *s) if s else []

    # TM13 assets and actors.
    for heading, required, name in [
        ("## 3. Assets", ASSETS, "asset"),
        ("## 4. Actors", ACTORS, "actor"),
    ]:
        tabs = section_tables(heading)
        rows = [c for _, rs in tabs[:1] for _, c in rs]
        listed = " ".join(c[1].lower() for c in rows if len(c) > 1)
        for want in required:
            if want not in listed:
                fail("TM13", f"required {name} missing: {want}")
        for c in rows:
            if any(not x for x in c):
                fail("TM13", f"empty cell in the {name} table")

    # §8 register.
    register = {}
    reg_rows = []
    for _, rs in section_tables("## 8. Residual-risk register")[:1]:
        reg_rows = rs
    for lineno, c in reg_rows:
        if len(c) != 8:
            fail("TM8", f"line {lineno}: register row needs 8 cells")
            continue
        rid, risk, source, _rationale, severity, owner, closing, status = c
        if not re.fullmatch(r"RR-\d{2}", rid) or rid in register:
            fail("TM8", f"line {lineno}: bad or duplicate id {rid!r}")
        register[rid] = c
        if not source or not owner or not closing:
            fail("TM8", f"{rid}: source, owner and closing condition are required")
        if severity not in SEVERITIES:
            fail("TM8", f"{rid}: severity must be High, Medium or Low")
        if status not in RR_STATUS:
            fail("TM8", f"{rid}: status must be Accepted, Pending approval or Open")
        paths = list(repo_paths(source))
        if not paths or not all(path_exists(p) for p in paths):
            fail("TM8", f"{rid}: source must name an existing repository file")

    # TM9 / TM10 required entries.
    for raw in REQUIRED_TSV.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        rid, source, anchor = parts[0], parts[1], parts[2]
        flag = parts[3] if len(parts) > 3 else ""
        row = register.get(rid)
        if row is None:
            fail("TM9", f"required register entry {rid} missing")
            continue
        if source not in row[2]:
            fail("TM9", f"{rid}: source cell must name {source}")
        try:
            if anchor not in (ROOT / source).read_text(encoding="utf-8"):
                fail("TM9", f"{rid}: anchor phrase gone from {source} (stale list)")
        except OSError:
            fail("TM9", f"{rid}: source {source} unreadable")
        if flag == "pending" and row[7] != "Pending approval":
            fail("TM10", f"{rid} must stay 'Pending approval' (008 never grants approval)")

    # TM11 advisory ignores.
    register_text = " ".join(" ".join(c[1:3]) for _, c in reg_rows)
    for deny in DENY_FILES:
        data = tomllib.loads(deny.read_text(encoding="utf-8"))
        for item in data.get("advisories", {}).get("ignore", []):
            aid = item["id"] if isinstance(item, dict) else item
            if aid not in register_text:
                fail("TM11", f"ignored advisory {aid} ({deny.relative_to(ROOT)}) not in the register")

    # §5 boundary list and §6 boundaries (TM2-TM7).
    flow_ids = [c[0] for _, rs in section_tables("## 5. Data flows and trust boundaries")[:1] for _, c in rs]
    if flow_ids != [b[:4] for b in BOUNDARIES]:
        fail("TM2", "the boundary table of section 5 must list B-01..B-11 in order")
    s6 = span("## 6. Threats by boundary")
    sub = [(h, i) for lvl, h, i in heads if lvl == 3 and s6 and s6[0] <= i < s6[1]]
    if [h[4:] for h, _ in sub] != BOUNDARIES:
        fail("TM2", f"boundary headings differ: {[h for h, _ in sub]}")
    seen_ids = set()
    for k, (heading, start) in enumerate(sub):
        end = sub[k + 1][1] if k + 1 < len(sub) else s6[1]
        number = heading[6:8]
        letters = set()
        rows = [r for _, rs in tables(lines, start + 1, end)[:1] for r in rs]
        for lineno, c in rows:
            if len(c) != 6 or any(not x for x in c):
                fail("TM4", f"line {lineno}: threat rows need 6 non-empty cells")
                continue
            tid, stride, _threat, mitigation, reference, status = c
            if not re.fullmatch(rf"T-B{number}-\d+", tid):
                fail("TM4", f"line {lineno}: bad threat id {tid!r}")
            if tid in seen_ids:
                fail("TM4", f"line {lineno}: duplicate threat id {tid}")
            seen_ids.add(tid)
            if stride not in "STRIDE" or len(stride) != 1:
                fail("TM4", f"line {lineno}: STRIDE must be one of S T R I D E")
            letters.add(stride)
            if mitigation.startswith("N/A") and not re.match(r"^N/A:\s*\S", mitigation):
                fail("TM5", f"{tid}: N/A needs a reason")
            if status == "N/A" and not mitigation.startswith("N/A:"):
                fail("TM5", f"{tid}: status N/A needs an 'N/A: <reason>' mitigation")
            if not any(re.search(p, reference) for p in REF_PATTERNS):
                fail("TM5", f"{tid}: no valid reference")
            for path in repo_paths(reference):
                if not path_exists(path.split("::")[0]):
                    fail("TM6", f"{tid}: referenced path {path} does not exist")
            m = re.fullmatch(r"Residual \((RR-\d{2})\)", status)
            if m:
                if m.group(1) not in register:
                    fail("TM7", f"{tid}: {m.group(1)} is not in the register")
            elif status not in ("Mitigated", "N/A"):
                fail("TM4", f"{tid}: status must be Mitigated, Residual (RR-nn) or N/A")
        missing = set("STRIDE") - letters
        if missing:
            fail("TM3", f"{heading[4:]} lacks STRIDE {''.join(sorted(missing))}")

    # TM12 findings.
    find_rows = [r for _, rs in section_tables("## 9. Audit findings")[:1] for r in rs]
    ids = [c[0] for _, c in find_rows if c]
    if "F-000" in ids and len(find_rows) != 1:
        fail("TM12", "the F-000 (empty audit) row must be the only row")
    for lineno, c in find_rows:
        if len(c) != 6:
            fail("TM12", f"line {lineno}: finding rows need 6 cells")
            continue
        fid, _target, _finding, severity, status, test = c
        if not re.fullmatch(r"F-\d{3}", fid):
            fail("TM12", f"line {lineno}: bad finding id {fid!r}")
        if fid == "F-000":
            continue
        if c[2] == "none found":
            fail("TM12", f"line {lineno}: an empty audit is written only as F-000")
        if status == "Fixed":
            m = re.fullmatch(r"(crates/[\w-]+/tests/regress_008\.rs)::(f_\d{3}_\w+)", test)
            if not m or not path_exists(m.group(1)) or \
                    f"fn {m.group(2)}(" not in (ROOT / m.group(1)).read_text(encoding="utf-8"):
                fail("TM12", f"{fid}: Fixed needs an existing regress_008.rs::f_nnn_* test")
            elif not m.group(2).startswith("f_" + fid[2:]):
                fail("TM12", f"{fid}: regression test name must start with f_{fid[2:]}")
        elif status == "Open":
            if not test or severity not in SEVERITIES:
                fail("TM12", f"{fid}: Open needs an owner and a severity")
        else:
            fail("TM12", f"{fid}: status must be Fixed or Open")
    return fails


def main(argv):
    if len(argv) > 1:
        print("usage: check_threat_model.py [docs/threat-model.md]", file=sys.stderr)
        return 64
    path = Path(argv[0]) if argv else ROOT / "docs" / "threat-model.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        print(f"usage: cannot read {path}", file=sys.stderr)
        return 64
    fails = check(text)
    if fails:
        for line in dict.fromkeys(fails):
            print(line)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
