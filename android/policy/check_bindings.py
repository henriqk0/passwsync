"""Generated-binding rules B1-B6 of contracts/android-policy.md section 5, over the Kotlin that
uniffi-bindgen generated on the host. Exported names are those UniFFI writes with backticks.

usage: python3 -I check_bindings.py <kotlin-dir> [--inventory FILE] [--contract FILE]
  --inventory  `Type::method` list (default crates/passwsync-ffi/tests/api_inventory.txt)
  --contract   ffi-api.md whose section 4 lists the CoreError variants
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Finding, block_after, report, strip_kotlin  # noqa: E402

RULES = [f"B{i}" for i in range(1, 7)]

REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_INVENTORY = REPO / "crates/passwsync-ffi/tests/api_inventory.txt"
DEFAULT_CONTRACT = REPO / "specs/007-android-app/contracts/ffi-api.md"
PACKAGE = "io.github.henriqk0.passwsync.core"
LIBRARY = "passwsync_ffi"
IMPORT_PREFIXES = ("com.sun.jna.", "java.", "kotlin.")
SECRET_NAME = re.compile(r"password|secret|code|plaintext|key", re.I)
TEXT_ALLOWED = {("InvitationView", "code"), ("PairingView", "code")}
SECRET_PARAMS = {
    "createWallet": ("password", "confirm"),
    "unlockWallet": ("password",),
    "changePassword": ("current", "new", "confirm"),
    "joinPairing": ("code",),
    "redeemInvitation": ("code",),
    "openReceived": ("password",),
    "openPendingWithPassword": ("password",),
    "resolvePasswordChoice": ("password",),
    "seal": ("plaintext",),
    "open": ("sealed",),
    "setSensitive": ("value",),
}
BYTES = "kotlin.ByteArray"
SUMMARY_FIELDS = ["id", "title", "username", "url", "conflicted"]
PASSWORD_RECORDS = {"RevealTicket", "CredentialInput"}

FUN = re.compile(r"\bfun\s+`(\w+)`\s*\(")
PARAM = re.compile(r"`(\w+)`\s*:\s*([^,]+)")
FIELD = re.compile(r"\bva[rl]\s+`(\w+)`\s*:\s*([^,\n]+)")


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def args_of(text: str, open_paren: int):
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i], i
    return text[open_paren + 1:], len(text)


def functions(body: str):
    """(name, [(param, type)], return type) of every backticked `fun` in `body`."""
    out = []
    for match in FUN.finditer(body):
        params, close = args_of(body, match.end() - 1)
        rest = body[close + 1:close + 200]
        ret = re.match(r"\s*:\s*([\w.<>?, ]+?)\s*(\{|=|\n|$)", rest)
        out.append((match.group(1),
                    [(p, t.strip()) for p, t in PARAM.findall(params)],
                    ret.group(1).strip() if ret else "Unit"))
    return out


def blocks(code: str, header: str):
    """(name, body) of each top-level declaration matching `header` (a regex with one group)."""
    for match in re.finditer(header, code, re.M):
        span = block_after(code, match.end())
        if span:
            yield match.group(1), code[span[0]:span[1]]


def contract_errors(path: Path):
    text = path.read_text(encoding="utf-8")
    start = text.index("has exactly 37 variants")
    end = text.index("`reason` values", start)
    names = []
    for token in re.findall(r"`([^`]+)`", text[start:end]):
        name = re.match(r"([A-Z]\w*)", token)
        if name and "::" not in token:
            names.append(name.group(1))
    return names


def inventory(path: Path):
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")}


def check(root: Path, inventory_path: Path, contract_path: Path):
    out = []
    files = sorted(root.rglob("*.kt"))
    if not files:
        return [Finding("B1", f"no generated Kotlin under {root}")]
    exported, records, variants = set(), {}, None
    for path in files:
        raw = path.read_text(encoding="utf-8")
        code = strip_kotlin(raw)
        name = path.name
        # B1
        package = re.search(r"^package\s+([\w.]+)", code, re.M)
        if not package or package.group(1) != PACKAGE:
            out.append(Finding("B1", f"{name}: package must be {PACKAGE}"))
        for imported in re.findall(r"^import\s+([\w.*]+)", code, re.M):
            if not imported.startswith(IMPORT_PREFIXES):
                out.append(Finding("B1", f"{name}: import {imported} is not allowed"))
        libraries = set(re.findall(r'componentName\s*=\s*"([^"]*)"', raw))
        finder = re.search(r"fun findLibraryName\(.*?\n\s*return\s+\"([^\"]*)\"", raw, re.S)
        if finder:
            libraries.add(finder.group(1))
        if libraries != {LIBRARY}:
            out.append(Finding("B1", f"{name}: library name must be {LIBRARY} (found {sorted(libraries)})"))
        # B6
        if re.search(r"\bsuspend\s+fun\b", code):
            out.append(Finding("B6", f"{name}: suspend fun (async export)"))
        if re.search(r"\bFlow\s*<|kotlinx\.coroutines", code):
            out.append(Finding("B6", f"{name}: Flow or coroutines"))

        methods = []
        for iface, body in blocks(code, r"^public interface (\w+)[^{\n]*"):
            if iface.startswith(("Ffi", "Uniffi")):
                continue
            owner = iface.removesuffix("Interface")
            for fn in functions(body):
                exported.add(f"{owner}::{snake(fn[0])}")
                methods.append((owner, fn))
        for cls, body in blocks(code, r"^open class (\w+)[^{\n]*"):
            for _, companion in blocks(body, r"(companion) object\s*"):
                for fn in functions(companion):
                    exported.add(f"{cls}::{snake(fn[0])}")
                    methods.append((cls, fn))
        for match in re.finditer(r"^(?:public\s+)?fun\s+`(\w+)`", code, re.M):
            exported.add(f"fn::{snake(match.group(1))}")
        for match in re.finditer(r"^data class (\w+)\s*\(", code, re.M):
            fields, _ = args_of(code, match.end() - 1)
            records[match.group(1)] = [(f, t.strip()) for f, t in FIELD.findall(fields)]
        for _, body in blocks(code, r"^sealed class (CoreException)\b[^{\n]*"):
            variants = re.findall(r"\bclass\s+(\w+)\s*\([^)]*\)\s*:\s*CoreException\b", body)

        # B2 parameters
        for owner, (fn, params, ret) in methods:
            types = dict(params)
            for param in SECRET_PARAMS.get(fn, ()):
                if param in types and types[param] != BYTES:
                    out.append(Finding("B2", f"{owner}.{fn}: {param} must be ByteArray (found {types[param]})"))
            if fn in ("seal", "open") and ret != BYTES:
                out.append(Finding("B2", f"{owner}.{fn} must return ByteArray"))
            for param, ty in params:
                if SECRET_NAME.search(param) and "String" in ty:
                    out.append(Finding("B2", f"{owner}.{fn}: secret parameter {param} is {ty}"))

    # B2, B3 records
    for record, fields in records.items():
        for field, ty in fields:
            if SECRET_NAME.search(field) and "String" in ty and (record, field) not in TEXT_ALLOWED:
                out.append(Finding("B2", f"{record}.{field} is a secret as {ty}"))
            if field == "password" and record not in PASSWORD_RECORDS:
                out.append(Finding("B3", f"{record} must not have a password field"))
    if "CredentialInput" in records and dict(records["CredentialInput"]).get("password") != BYTES + "?":
        out.append(Finding("B2", "CredentialInput.password must be ByteArray?"))
    if "RevealTicket" in records and dict(records["RevealTicket"]).get("password") != BYTES:
        out.append(Finding("B3", "RevealTicket.password must be ByteArray"))
    if "CredentialSummary" in records and [f for f, _ in records["CredentialSummary"]] != SUMMARY_FIELDS:
        out.append(Finding("B3", f"CredentialSummary fields must be exactly {SUMMARY_FIELDS}"))

    # B4
    listed = inventory(inventory_path)
    extra, missing = sorted(exported - listed), sorted(listed - exported)
    if extra or missing:
        out.append(Finding("B4", f"exported methods differ from the inventory (extra {extra}, missing {missing})"))
    # B5
    expected = contract_errors(contract_path)
    if variants is None:
        out.append(Finding("B5", "no CoreException in the bindings"))
    elif sorted(variants) != sorted(expected) or len(variants) != len(set(variants)):
        out.append(Finding("B5", f"CoreException variants differ from the contract (extra "
                                 f"{sorted(set(variants) - set(expected))}, missing {sorted(set(expected) - set(variants))})"))
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = "usage: python3 -I check_bindings.py <kotlin-dir> [--inventory FILE] [--contract FILE]"
    options = {"--inventory": DEFAULT_INVENTORY, "--contract": DEFAULT_CONTRACT}
    positional = []
    while argv:
        arg = argv.pop(0)
        if arg in options and argv:
            options[arg] = Path(argv.pop(0))
        elif arg.startswith("-"):
            print(usage, file=sys.stderr)
            return 64
        else:
            positional.append(arg)
    if len(positional) != 1 or not Path(positional[0]).is_dir() or not all(p.is_file() for p in options.values()):
        print(usage, file=sys.stderr)
        return 64
    return report(check(Path(positional[0]), options["--inventory"], options["--contract"]))


if __name__ == "__main__":
    sys.exit(main())
