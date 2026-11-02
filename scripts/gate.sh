#!/usr/bin/env bash
# The one offline gate of passwsync (008 contracts/gate-script.md, research R17-R19).
#
#   scripts/gate.sh            run every step offline (default)
#   scripts/gate.sh --fetch    networked, one time: cargo fetch --locked (root and
#                              tools/uniffi-bindgen), refresh the cargo-audit and cargo-deny
#                              advisory databases; then exit 0/1
#   scripts/gate.sh --list     print the step names and exit 0
#
# Each step prints one `[gate] <step> <PASS|FAIL|MISSING|SKIP> <detail>` line; a FAIL also
# prints the last 40 lines of that step's log. Exit: 0 all PASS, 1 any FAIL, 2 any MISSING and
# no FAIL, 64 usage. Environment: PASSWSYNC_FUZZ_SEED / PASSWSYNC_FUZZ_ITERS pass through to
# the fuzz step; PASSWSYNC_GATE_SELFTEST=fail|missing runs only one synthetic step (self-test,
# the real steps are skipped). Same script on the host and in CI (CI adds `--fetch` first).
# Never writes outside its temporary log directory and target/; never commits or pushes.
set -u -o pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=never

STEPS=(toolchain fmt clippy test budgets fuzz release-isolation unsafe-scope audit deny policy)
# The fuzz targets, one per crates/hardening/tests/fuzz_<target>.rs (cross-checked by the
# fuzz step, so a new target file cannot be forgotten here).
FUZZ_TARGETS=(wallet_header wallet_payload wallet_unlock frame hello channel_payload discovery
    pairing_initiator pairing_joiner channel_responder channel_dialer sync_ctl sync_reassembly
    sync_copy share_msg http_request ffi_args)
FUZZ_LIMIT_S=300
CARGO_OFF=(--frozen --offline)
AUDIT_DB=$HOME/.cargo/advisory-db
DENY_DBS=$HOME/.cargo/advisory-dbs

PASS=0 FAIL=1 MISSING=2 SKIP=3
DETAIL=""

usage() {
    echo "usage: scripts/gate.sh [--fetch | --list]" >&2
    exit 64
}

# --- pure checks (also reached through the hidden --selftest option) ------------------------

# Advisory ids of `[advisories] ignore` in a deny.toml, one per line.
ignore_ids() {
    python3 -I -c '
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
for item in data.get("advisories", {}).get("ignore", []):
    print(item["id"] if isinstance(item, dict) else item)
' "$1"
}

# 0 when the deny.toml keeps every advisory kind and source rule at deny.
deny_keys() {
    python3 -I -c '
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
adv, src = data.get("advisories", {}), data.get("sources", {})
want = [(adv, "yanked", "deny"), (adv, "unmaintained", "all"), (adv, "unsound", "all"),
        (src, "unknown-registry", "deny"), (src, "unknown-git", "deny")]
bad = [k for table, k, v in want if table.get(k) != v]
print("weak keys: " + " ".join(bad) if bad else "deny keys ok")
sys.exit(1 if bad else 0)
' "$1"
}

# Every fuzz_<t>.rs in $1 has a `FUZZ target=<t> ... result=PASS` line in log $2.
fuzz_lines() {
    local dir=$1 log=$2 file name missing=()
    for file in "$dir"/fuzz_*.rs; do
        [[ -e $file ]] || continue
        name=$(basename "$file" .rs)
        name=${name#fuzz_}
        grep -aqE "^FUZZ target=$name .* result=PASS$" "$log" || missing+=("$name")
    done
    if ((${#missing[@]})); then
        echo "no PASS line for: ${missing[*]}"
        return 1
    fi
}

# The FUZZ_TARGETS array equals the fuzz_*.rs files.
fuzz_crosscheck() {
    local listed files
    listed=$(printf '%s\n' "${FUZZ_TARGETS[@]}" | sort)
    files=$(find crates/hardening/tests -maxdepth 1 -name 'fuzz_*.rs' -printf '%f\n' |
        sed 's/^fuzz_//; s/\.rs$//' | sort)
    if [[ $listed != "$files" ]]; then
        echo "FUZZ_TARGETS differs from crates/hardening/tests/fuzz_*.rs:"
        diff <(echo "$listed") <(echo "$files")
        return 1
    fi
}

# 1 when a cargo tree or nm listing shows test-only code: `testkit::` symbols, a `testkit`
# feature, or the `hardening` package / crate root (`passwsyncd::hardening` is a product
# module and does not match).
isolation_scan() {
    if grep -anE 'testkit::|feature "testkit"|(^|[^:[:alnum:]_])hardening( v[0-9]|::)' "$1"; then
        return 1
    fi
}

selftest() {
    case "${1:-}" in
    ignore-ids) ignore_ids "${2:?deny.toml}" ;;
    deny-keys) deny_keys "${2:?deny.toml}" ;;
    fuzz-targets) printf '%s\n' "${FUZZ_TARGETS[@]}" ;;
    fuzz-lines) fuzz_lines "${2:?dir}" "${3:?log}" ;;
    isolation-scan) isolation_scan "${2:?file}" ;;
    *)
        echo "unknown self-test: ${1:-}" >&2
        exit 64
        ;;
    esac
}

# --- steps ----------------------------------------------------------------------------------

db_date() { git -C "$1" log -1 --format=%cs 2>/dev/null; }

deny_db() { find "$DENY_DBS" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1; }

step_toolchain() {
    local missing=() t
    for t in rustc cargo cargo-deny cargo-audit python3 nm git; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    [[ -d $AUDIT_DB ]] || missing+=("cargo-audit advisory DB")
    [[ -n $(deny_db) ]] || missing+=("cargo-deny advisory DB")
    if ((${#missing[@]})); then
        DETAIL="missing: ${missing[*]} (run scripts/gate.sh --fetch once)"
        return $MISSING
    fi
    DETAIL="$(rustc -V | cut -d' ' -f1-2); $(cargo deny --version); $(cargo audit --version);"
    DETAIL+=" $(python3 -V); advisory-db $(db_date "$AUDIT_DB") (audit), $(db_date "$(deny_db)") (deny)"
}

step_fmt() { cargo fmt --all --check; }

step_clippy() {
    cargo clippy "${CARGO_OFF[@]}" --workspace --all-targets --all-features -- -D warnings
}

step_test() {
    cargo test "${CARGO_OFF[@]}" --workspace --all-features --exclude hardening
}

step_budgets() {
    if [[ ! -f crates/hardening/tests/budgets.rs ]]; then
        DETAIL="crates/hardening/tests/budgets.rs absent"
        return $MISSING
    fi
    cargo test "${CARGO_OFF[@]}" --release -p hardening --lib --test budgets --test leakage
}

step_fuzz() {
    local log=$1 tests=() t start elapsed inputs
    fuzz_crosscheck || { DETAIL="target list out of date"; return $FAIL; }
    for t in "${FUZZ_TARGETS[@]}"; do tests+=(--test "fuzz_$t"); done
    cargo test "${CARGO_OFF[@]}" --release -p hardening "${tests[@]}" --no-run ||
        { DETAIL="build failed"; return $FAIL; }
    start=$SECONDS
    cargo test "${CARGO_OFF[@]}" --release -p hardening "${tests[@]}" -- --nocapture \
        >"$log.run" 2>&1
    local rc=$?
    elapsed=$((SECONDS - start))
    cat "$log.run"
    if ((rc != 0)); then
        DETAIL="a fuzz target failed ($(grep -a -m1 '^FUZZ-FAIL' "$log.run" | cut -d' ' -f2-5))"
        return $FAIL
    fi
    fuzz_lines crates/hardening/tests "$log.run" || { DETAIL="missing target lines"; return $FAIL; }
    inputs=$(grep -a '^FUZZ ' "$log.run" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^inputs=/) {sub(/inputs=/, "", $i); s+=$i}} END {print s+0}')
    DETAIL="${#FUZZ_TARGETS[@]} targets, $inputs inputs, ${elapsed} s"
    if ((elapsed >= FUZZ_LIMIT_S)); then
        DETAIL+=" (limit ${FUZZ_LIMIT_S} s)"
        return $FAIL
    fi
}

step_release-isolation() {
    local log=$1 crate tree=$log.tree syms=$log.syms artifact
    : >"$tree"
    for crate in passwsyncd passwsync-ffi; do
        cargo tree "${CARGO_OFF[@]}" -e features,normal,build --target all -p "$crate" >>"$tree" ||
            { DETAIL="cargo tree -p $crate failed"; return $FAIL; }
    done
    if ! isolation_scan "$tree"; then
        DETAIL="test-only package or feature in a release dependency graph"
        return $FAIL
    fi
    # Built exactly as packaging/PKGBUILD and android/build-rust.sh (host target) do.
    cargo build "${CARGO_OFF[@]}" --release -p passwsyncd --bin passwsyncd ||
        { DETAIL="release build of passwsyncd failed"; return $FAIL; }
    cargo build "${CARGO_OFF[@]}" --release -p passwsync-ffi ||
        { DETAIL="release build of passwsync-ffi failed"; return $FAIL; }
    : >"$syms"
    local out=${CARGO_TARGET_DIR:-target}/release
    for artifact in "$out/passwsyncd" "$out/libpasswsync_ffi.so"; do
        [[ -f $artifact ]] || { DETAIL="$artifact not built"; return $FAIL; }
        nm -C "$artifact" >>"$syms" 2>/dev/null
        nm -C -D "$artifact" >>"$syms" 2>/dev/null
    done
    if ! isolation_scan "$syms"; then
        DETAIL="test-only symbol in a release artifact"
        return $FAIL
    fi
    DETAIL="no testkit feature or hardening package; $(wc -l <"$syms") symbols scanned"
}

step_unsafe-scope() {
    cargo test "${CARGO_OFF[@]}" -p passwsync-ffi --test unsafe_scope
}

audit_one() { # lock deny.toml
    local args=() id
    while IFS= read -r id; do
        [[ -n $id ]] && args+=(--ignore "$id")
    done < <(ignore_ids "$2")
    cargo audit --no-fetch --deny warnings "${args[@]}" --file "$1"
}

step_audit() {
    [[ -d $AUDIT_DB ]] || { DETAIL="advisory DB absent"; return $MISSING; }
    audit_one Cargo.lock deny.toml || { DETAIL="root lock"; return $FAIL; }
    audit_one tools/uniffi-bindgen/Cargo.lock tools/uniffi-bindgen/deny.toml ||
        { DETAIL="uniffi-bindgen lock"; return $FAIL; }
    DETAIL="2 locks clean; advisory DB $(db_date "$AUDIT_DB")"
}

step_deny() {
    local dups
    [[ -n $(deny_db) ]] || { DETAIL="advisory DB absent"; return $MISSING; }
    cargo deny --offline check || { DETAIL="root workspace"; return $FAIL; }
    cargo deny --offline --manifest-path tools/uniffi-bindgen/Cargo.toml check ||
        { DETAIL="uniffi-bindgen"; return $FAIL; }
    dups=$(cargo tree "${CARGO_OFF[@]}" --duplicates --depth 0 -e normal,build 2>/dev/null |
        grep -cE '^[[:alnum:]_-]+ v')
    DETAIL="2 manifests clean; duplicates=$dups (warning only)"
}

step_policy() {
    local wf pending script
    wf=$(python3 -I scripts/check_workflow.py) || { echo "$wf"; DETAIL="workflow policy"; return $FAIL; }
    echo "$wf"
    pending=$(grep -c '^PENDING \[CI\]' <<<"$wf")
    if [[ ! -f scripts/check_threat_model.py || ! -f docs/threat-model.md ]]; then
        DETAIL="threat-model checker or document absent"
        return $MISSING
    fi
    python3 -I scripts/check_threat_model.py || { DETAIL="threat model"; return $FAIL; }
    python3 -m unittest discover -s scripts/tests -t . || { DETAIL="checker unit tests"; return $FAIL; }
    if cargo audit --no-fetch --file scripts/tests/fixtures/advisory.lock; then
        DETAIL="advisory fixture passed cargo audit (must fail)"
        return $FAIL
    fi
    if cargo deny --offline --manifest-path scripts/tests/fixtures/deny-ws/Cargo.toml \
        check bans licenses; then
        DETAIL="deny fixture passed bans/licenses (must fail)"
        return $FAIL
    fi
    cmp -s deny.toml scripts/tests/fixtures/deny-ws/deny.toml ||
        { DETAIL="fixture deny.toml differs from deny.toml"; return $FAIL; }
    deny_keys deny.toml && deny_keys tools/uniffi-bindgen/deny.toml ||
        { DETAIL="deny.toml policy keys weakened"; return $FAIL; }
    for script in scripts/*.sh; do
        bash -n "$script" || { DETAIL="bash -n $script"; return $FAIL; }
    done
    DETAIL="workflow: $pending pins PENDING [CI]; threat model PASS; fixtures fail as required"
}

step_selftest() {
    case "$PASSWSYNC_GATE_SELFTEST" in
    fail)
        echo "synthetic failure"
        DETAIL="synthetic failure"
        return $FAIL
        ;;
    missing)
        DETAIL="synthetic missing tool"
        return $MISSING
        ;;
    *)
        echo "PASSWSYNC_GATE_SELFTEST must be fail or missing" >&2
        exit 64
        ;;
    esac
}

# --- runner ---------------------------------------------------------------------------------

LOGS=""
cleanup() { [[ -n $LOGS && ${KEEP_LOGS:-0} == 0 ]] && rm -rf "$LOGS"; }

NPASS=0 NFAIL=0 NMISSING=0
run_step() {
    local name=$1 log rc word
    log=$LOGS/$name.log
    DETAIL=""
    "step_$name" "$log" >"$log" 2>&1
    rc=$?
    case $rc in
    "$PASS") word=PASS NPASS=$((NPASS + 1)) ;;
    "$MISSING") word=MISSING NMISSING=$((NMISSING + 1)) ;;
    "$SKIP") word=SKIP ;;
    *) word=FAIL NFAIL=$((NFAIL + 1)) ;;
    esac
    printf '[gate] %-18s %-7s %s\n' "$name" "$word" "$DETAIL"
    if [[ $word == FAIL ]]; then
        KEEP_LOGS=1
        echo "[gate] log: $log (last 40 lines)"
        tail -n 40 "$log" | sed 's/^/    /'
    fi
}

fetch() {
    local rc=0 id args=()
    cargo fetch --locked || rc=1
    cargo fetch --locked --manifest-path tools/uniffi-bindgen/Cargo.toml || rc=1
    cargo deny fetch db || rc=1
    while IFS= read -r id; do args+=(--ignore "$id"); done < <(ignore_ids deny.toml)
    # cargo audit has no fetch-only mode: a run refreshes (or clones) its database; its verdict
    # is the offline `audit` step's job.
    cargo audit "${args[@]}" --file Cargo.lock >/dev/null 2>&1
    [[ -d $AUDIT_DB ]] || rc=1
    echo "[gate] fetch $([[ $rc == 0 ]] && echo PASS || echo FAIL)"
    return $rc
}

main() {
    case "${1:-}" in
    "") ;;
    --list)
        (($# == 1)) || usage
        printf '%s\n' "${STEPS[@]}"
        exit 0
        ;;
    --fetch)
        (($# == 1)) || usage
        fetch
        exit $?
        ;;
    --selftest)
        shift
        selftest "$@"
        exit $?
        ;;
    *) usage ;;
    esac
    LOGS=$(mktemp -d)
    KEEP_LOGS=0
    trap cleanup EXIT
    if [[ -n ${PASSWSYNC_GATE_SELFTEST:-} ]]; then
        run_step selftest
    else
        local step
        for step in "${STEPS[@]}"; do run_step "$step"; done
    fi
    local result=PASS code=0
    if ((NFAIL)); then
        result=FAIL code=1
    elif ((NMISSING)); then
        result=MISSING code=2
    fi
    printf '[gate] %-18s %-7s (%d PASS, %d FAIL, %d MISSING)\n' result "$result" "$NPASS" "$NFAIL" "$NMISSING"
    exit $code
}

main "$@"
