#!/usr/bin/env bash
# Benchmark report of the passwsync resource budgets (008 contracts/benchmarks.md, research
# R13; quickstart H-14 and M-1). Never run by scripts/gate.sh or CI.
#
#   scripts/bench.sh                 run every measurement, write target/bench/report.txt
#   env PASSWSYNC_REFERENCE_DEVICE=laptop   mark the run as the reference laptop (default: no)
#
# Runs the `#[ignore]`d release measurement tests with `--ignored --nocapture
# --test-threads=1` and the deterministic BUDGET files the same way, collects every `BUDGET`
# line (a failing assertion does not lose its line, it was printed first) and turns the value
# lines printed by the 002-004 measurement tests in crates/passwsyncd/tests (unchanged in 008)
# into rows. Writes a machine block plus one row per budget B-01..B-20, prints the report.
# Exit: 0 report complete (any verdicts), 1 build or harness error, 2 some budget NO-DATA,
# 64 usage. Offline (--frozen --offline). Test hooks: PASSWSYNC_BENCH_STUB_DIR (read
# `*.out` files instead of running cargo), PASSWSYNC_BENCH_REPORT (report path).
set -u -o pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:$PATH"

if (($#)); then
    echo "usage: scripts/bench.sh   (env PASSWSYNC_REFERENCE_DEVICE=laptop on the reference laptop)" >&2
    exit 64
fi

REPORT=${PASSWSYNC_BENCH_REPORT:-$ROOT/target/bench/report.txt}
REFERENCE=${PASSWSYNC_REFERENCE_DEVICE:-no}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# label | cargo test arguments | test-binary arguments
RUNS=(
    "vault-core-perf|-p vault-core --test perf|--ignored"
    "idle-service|-p hardening --test bench_idle_service|--ignored"
    "budgets|-p hardening --test budgets|"
    "net-resources|-p device-link-net --test resources|--include-ignored"
    "resources-network|-p passwsyncd --test resources_network|--ignored"
    "resources-sync|-p passwsyncd --test resources_sync|--include-ignored"
    "sync-perf|-p passwsyncd --test sync_perf|--ignored"
)

harness_error=0
if [[ -n ${PASSWSYNC_BENCH_STUB_DIR:-} ]]; then
    cp "$PASSWSYNC_BENCH_STUB_DIR"/*.out "$WORK"/ 2>/dev/null
else
    for run in "${RUNS[@]}"; do
        IFS='|' read -r label cargo_args test_args <<<"$run"
        # shellcheck disable=SC2086 # word splitting of the fixed argument lists is intended
        cargo test --frozen --offline --release $cargo_args -- $test_args --nocapture \
            --test-threads=1 >"$WORK/$label.out" 2>&1
        if grep -aqE '^error(\[E[0-9]+\])?: (could not compile|failed to|no test target)' "$WORK/$label.out"; then
            echo "bench: $label did not build" >&2
            harness_error=1
        fi
    done
fi

mkdir -p "$(dirname "$REPORT")"
python3 -I - "$WORK" "$REPORT" "$REFERENCE" <<'PY'
import os, platform, re, subprocess, sys, time
from pathlib import Path

work, report, reference = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
NAMES = {
    "B-01": "unlock default KDF, median of 9", "B-02": "unlock default KDF, worst of 9",
    "B-03": "time per wrong guess at the default KDF", "B-04": "unlock at the service KDF cap",
    "B-05": "list 10,000 credentials", "B-06": "search 10,000 credentials",
    "B-07": "peak memory, 10,000 credentials", "B-08": "idle service memory",
    "B-09": "idle service periodic wake-ups", "B-10": "networking idle memory, 5 peers",
    "B-11": "networking idle CPU", "B-12": "wake-ups per peer per 30 s",
    "B-13": "idle sync traffic per peer per hour", "B-14": "idle sync CPU",
    "B-15": "idle sync memory growth", "B-16": "sync of 10,000 credentials differing by one",
    "B-17": "same, peak additional memory", "B-18": "transfer buffer per transfer",
    "B-19": "concurrent transfers", "B-20": "parser bounds differing from the spec",
}
STRICT = re.compile(
    r"^BUDGET id=(B-\d{2}) value=(\d+(?:\.\d+)?) unit=(ms|s|B|KiB|MB|MiB|%|count) "
    r"limit=(\d+(?:\.\d+)?) cmp=(lt|le|ge|eq|info) source=(\d{3}-(?:SC|FR)-\d{3}) "
    r"class=(deterministic|measured) verdict=(PASS|OVER|INFO)$")

def verdict(value, limit, cmp):
    v, l = float(value), float(limit)
    ok = {"lt": v < l, "le": v <= l, "ge": v >= l, "eq": v == l}.get(cmp)
    return "INFO" if ok is None else ("PASS" if ok else "OVER")

def row(bid, value, unit, limit, cmp, source, cls="measured"):
    return {"id": bid, "value": value, "unit": unit, "limit": limit, "cmp": cmp,
            "source": source, "class": cls, "verdict": verdict(value, limit, cmp)}

def ms(text):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(s|ms|µs|us|ns)", text)
    if not m:
        return None
    scale = {"s": 1000, "ms": 1, "µs": 0.001, "us": 0.001, "ns": 0.000001}[m.group(2)]
    return f"{float(m.group(1)) * scale:.0f}"

rows, rejected = {}, 0
text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(work.glob("*.out")))
for line in text.splitlines():
    # With --nocapture libtest may print `test name ... ` before the test's first line.
    at = line.find("BUDGET id=")
    if at < 0 and line.startswith("BUDGET"):
        at = 0
    if at >= 0:
        line = line[at:]
        m = STRICT.match(line.rstrip())
        if not m:
            rejected += 1
            continue
        bid, value, unit, limit, cmp, source, cls, verd = m.groups()
        rows.setdefault(bid, {"id": bid, "value": value, "unit": unit, "limit": limit,
                              "cmp": cmp, "source": source, "class": cls, "verdict": verd})
        continue
    # Value lines of the unchanged 002-004 measurement tests (crates/passwsyncd/tests).
    m = re.search(r"RSS \+(\d+) KiB for 6 services in one process", line)
    if m:
        rows.setdefault("B-10", row("B-10", str(int(m.group(1)) // 6), "KiB", "10240", "lt", "003-SC-007"))
    m = re.search(r"idle CPU (\d+(?:\.\d+)?) %/service, RSS \d+ KiB/service, growth (\d+) KiB", line)
    if m:
        rows.setdefault("B-14", row("B-14", m.group(1), "%", "1", "lt", "004-SC-006"))
        rows.setdefault("B-15", row("B-15", m.group(2), "KiB", "8192", "lt", "004-SC-006"))
    m = re.search(r"10 000-entry wallet synced in (\S+)", line)
    if m and ms(m.group(1)) is not None:
        rows.setdefault("B-16", row("B-16", ms(m.group(1)), "ms", "10000", "lt", "004-SC-008"))

def first(path, key):
    try:
        for l in Path(path).read_text().splitlines():
            if l.startswith(key):
                return l.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"

try:
    rustc = subprocess.run(["rustc", "-V"], capture_output=True, text=True).stdout.strip()
except OSError:
    rustc = "unknown"
out = [
    "passwsync benchmark report (008 contracts/benchmarks.md)",
    f"cpu: {first('/proc/cpuinfo', 'model name')}",
    f"cores: {os.cpu_count()}",
    f"memtotal: {first('/proc/meminfo', 'MemTotal')}",
    f"kernel: {platform.release()}",
    f"rustc: {rustc}",
    "profile: release",
    f"reference: {reference}",
    f"date: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC",
    "",
    "id budget | value unit limit cmp source class verdict",
]
missing = 0
for n in range(1, 21):
    bid = f"B-{n:02d}"
    r = rows.get(bid)
    if r is None:
        missing += 1
        out.append(f"{bid} {NAMES[bid]} | - - - - - - NO-DATA")
    else:
        out.append(f"{bid} {NAMES[bid]} | {r['value']} {r['unit']} {r['limit']} {r['cmp']} "
                   f"{r['source']} {r['class']} {r['verdict']}")
if rejected:
    out.append(f"note: rejected malformed BUDGET line(s): {rejected}")
if reference != "laptop":
    out.append("informational: timing verdicts are binding only on reference hardware")
report.write_text("\n".join(out) + "\n", encoding="utf-8")
print("\n".join(out))
sys.exit(2 if missing else 0)
PY
status=$?
if ((harness_error)) || ((status != 0 && status != 2)); then
    exit 1
fi
exit $status
