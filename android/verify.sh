#!/usr/bin/env bash
# Offline host gate of the Android app (specs/007-android-app/contracts/verify.md).
# No network, no Android SDK/NDK: every Cargo call is --frozen --offline, every Python call
# is `python3 -I`. Each step prints exactly one `PASS|FAIL|SKIPPED|MISSING <step> <detail>`
# line; the exit status is 0 (all PASS, ktlint may be SKIPPED), 1 (any FAIL), 2 (a required
# tool MISSING, or --quick/--only) or 64 (usage).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

ANDROID=${VERIFY_ANDROID_DIR:-$ROOT/android}
WORK=${VERIFY_WORK_DIR:-$ROOT/target/android-verify}
REVIEWED=${VERIFY_REVIEWED_CRATES:-$ROOT/android/policy/reviewed-crates.txt}
POLICY=$ROOT/android/policy
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
CDYLIB=$TARGET/debug/libpasswsync_ffi.so
TOOL_HOME=${CARGO_HOME:-$HOME/.cargo}
export CARGO_NET_OFFLINE=true

STEPS=(tools passwsyncd-tests-unchanged fmt-clippy workspace-tests unsafe-scope host-cdylib
    bindgen uniffi-pin bindings xml-wellformed manifest-policy source-policy policy-unit
    mutations deny audit lock-diff ktlint)

usage() {
    cat <<EOF
usage: android/verify.sh [--quick] [--keep-work] [--only STEP[,STEP...]] [--help]

  --quick      cargo test only for host-runtime, passwsync-ffi and passwsyncd (status at best 2)
  --keep-work  keep target/android-verify/ (it is kept anyway; recreated at the next start)
  --only       run only the named steps (status at best 2)
  --help       this text

steps: ${STEPS[*]}
exit: 0 all PASS (ktlint may be SKIPPED), 1 any FAIL, 2 MISSING tool or partial run, 64 usage
EOF
}

QUICK=0
ONLY=""
while (($#)); do
    case "$1" in
    --help | -h)
        usage
        exit 0
        ;;
    --quick) QUICK=1 ;;
    --keep-work) ;;
    --only)
        if (($# < 2)); then
            usage >&2
            exit 64
        fi
        ONLY=$2
        shift
        ;;
    --only=*) ONLY=${1#--only=} ;;
    *)
        usage >&2
        exit 64
        ;;
    esac
    shift
done

SELECTED=("${STEPS[@]}")
if [[ -n $ONLY ]]; then
    IFS=, read -r -a SELECTED <<<"$ONLY"
    for step in "${SELECTED[@]}"; do
        known=0
        for s in "${STEPS[@]}"; do [[ $s == "$step" ]] && known=1; done
        if ((!known)); then
            echo "unknown step: $step" >&2
            usage >&2
            exit 64
        fi
    done
fi

rm -rf "$WORK"
mkdir -p "$WORK/kotlin" "$WORK/mut" "$WORK/logs"
SUMMARY=$WORK/summary.txt
: >"$SUMMARY"

DETAIL=""
# Step results: 0 PASS, 1 FAIL, 2 MISSING, 3 SKIPPED.
PASS=0 FAIL=1 MISSING=2 SKIPPED=3

have() { command -v "$1" >/dev/null 2>&1; }

# Resolves cargo-deny/cargo-audit on PATH, then in $CARGO_HOME/bin (prepended to PATH).
resolve() {
    local tool=$1
    if have "$tool"; then
        command -v "$tool"
    elif [[ -x $TOOL_HOME/bin/$tool ]]; then
        echo "$TOOL_HOME/bin/$tool"
    else
        return 1
    fi
}

use_tool_home() {
    case ":$PATH:" in
    *":$TOOL_HOME/bin:"*) ;;
    *) PATH="$TOOL_HOME/bin:$PATH" ;;
    esac
}

# --- 1-5 -------------------------------------------------------------------------------

step_tools() {
    local missing=() found=() tool path
    for tool in cargo python3 xmllint; do
        have "$tool" || missing+=("$tool")
    done
    for tool in cargo-deny cargo-audit; do
        if path=$(resolve "$tool"); then
            found+=("$tool=$path")
        else
            missing+=("$tool")
        fi
    done
    have ktlint && found+=("ktlint=$(command -v ktlint)") || found+=("ktlint=absent(optional)")
    if ((${#missing[@]})); then
        DETAIL="${missing[*]}"
        return $MISSING
    fi
    DETAIL="${found[*]}"
}

step_passwsyncd-tests-unchanged() {
    if ! git diff --quiet main -- crates/passwsyncd/tests; then
        DETAIL="crates/passwsyncd/tests differs from main"
        return $FAIL
    fi
    local untracked
    untracked=$(git ls-files --others --exclude-standard -- crates/passwsyncd/tests)
    if [[ -n $untracked ]]; then
        DETAIL="untracked files in crates/passwsyncd/tests"
        return $FAIL
    fi
    DETAIL="no change vs main"
}

step_fmt-clippy() {
    have cargo || { DETAIL=cargo; return $MISSING; }
    cargo fmt --all --check || { DETAIL="cargo fmt --check"; return $FAIL; }
    cargo clippy --frozen --offline --workspace --all-targets --all-features -- -D warnings ||
        { DETAIL="cargo clippy"; return $FAIL; }
    DETAIL="fmt and clippy clean"
}

step_workspace-tests() {
    have cargo || { DETAIL=cargo; return $MISSING; }
    local scope=(--workspace)
    ((QUICK)) && scope=(-p host-runtime -p passwsync-ffi -p passwsyncd)
    cargo test --frozen --offline "${scope[@]}" --all-features || { DETAIL="cargo test ${scope[*]}"; return $FAIL; }
    DETAIL="cargo test ${scope[*]}"
}

step_unsafe-scope() {
    local hits=() file
    while IFS= read -r file; do
        if grep -nw unsafe "$file" | grep -vqE '^[0-9]+:[[:space:]]*//'; then
            hits+=("$file")
        fi
    done < <(grep -rlw unsafe crates/*/src || true)
    printf '%s\n' "${hits[@]}"
    if [[ ${hits[*]} != "crates/passwsync-ffi/src/memprotect.rs" ]]; then
        DETAIL="unsafe outside memprotect.rs: ${hits[*]}"
        return $FAIL
    fi
    DETAIL="unsafe only in crates/passwsync-ffi/src/memprotect.rs"
}

# --- 6-9 -------------------------------------------------------------------------------

step_host-cdylib() {
    have cargo || { DETAIL=cargo; return $MISSING; }
    have nm || { DETAIL=nm; return $MISSING; }
    cargo build --frozen --offline -p passwsync-ffi || { DETAIL="cargo build"; return $FAIL; }
    [[ -f $CDYLIB ]] || { DETAIL="$CDYLIB missing"; return $FAIL; }
    local symbols count
    symbols=$(nm -D --defined-only "$CDYLIB") || { DETAIL="nm failed"; return $FAIL; }
    count=$(grep -c ' uniffi_passwsync_ffi_' <<<"$symbols" || true)
    if ((count == 0)); then
        DETAIL="no uniffi_passwsync_ffi_* symbol"
        return $FAIL
    fi
    if grep -q ' JNI_OnLoad$' <<<"$symbols"; then
        DETAIL="JNI_OnLoad is exported"
        return $FAIL
    fi
    DETAIL="$count uniffi_passwsync_ffi_* symbols, no JNI_OnLoad"
}

step_bindgen() {
    have cargo || { DETAIL=cargo; return $MISSING; }
    [[ -f $CDYLIB ]] || { DETAIL="$CDYLIB missing (run host-cdylib)"; return $FAIL; }
    rm -rf "$WORK/kotlin" && mkdir -p "$WORK/kotlin"
    cargo run --frozen --offline --manifest-path tools/uniffi-bindgen/Cargo.toml -- generate \
        --library "$CDYLIB" --config tools/uniffi-bindgen/bindgen.toml --language kotlin \
        --no-format --out-dir "$WORK/kotlin" || { DETAIL="uniffi-bindgen failed"; return $FAIL; }
    local files
    files=$(find "$WORK/kotlin" -name '*.kt' | wc -l)
    ((files > 0)) || { DETAIL="no .kt generated"; return $FAIL; }
    DETAIL="$files Kotlin file(s) in ${WORK#"$ROOT"/}/kotlin"
}

lock_version() {
    awk -v want="$2" '$0 == "name = \"" want "\"" { getline; gsub(/version = |"/, ""); print }' "$1"
}

step_uniffi-pin() {
    local root tool
    root=$(lock_version Cargo.lock uniffi)
    tool=$(lock_version tools/uniffi-bindgen/Cargo.lock uniffi)
    echo "root=$root tool=$tool"
    if [[ $root != 0.32.2 || $tool != 0.32.2 ]]; then
        DETAIL="uniffi root=$root tools/uniffi-bindgen=$tool (want 0.32.2)"
        return $FAIL
    fi
    DETAIL="uniffi 0.32.2 in both locks"
}

step_bindings() {
    have python3 || { DETAIL=python3; return $MISSING; }
    python3 -I "$POLICY/check_bindings.py" "$WORK/kotlin" || { DETAIL="B rules (see logs/bindings.log)"; return $FAIL; }
    DETAIL="B1-B6"
}

# --- 10-14 -----------------------------------------------------------------------------

step_xml-wellformed() {
    have xmllint || { DETAIL=xmllint; return $MISSING; }
    local main=$ANDROID/app/src/main files=()
    [[ -f $main/AndroidManifest.xml ]] || { DETAIL="no AndroidManifest.xml under ${ANDROID#"$ROOT"/}"; return $FAIL; }
    files+=("$main/AndroidManifest.xml")
    if [[ -d $main/res ]]; then
        while IFS= read -r file; do files+=("$file"); done < <(find "$main/res" -name '*.xml' | sort)
    fi
    xmllint --noout --nonet "${files[@]}" || { DETAIL="xmllint errors (see logs/xml-wellformed.log)"; return $FAIL; }
    DETAIL="${#files[@]} files"
}

step_manifest-policy() {
    have python3 || { DETAIL=python3; return $MISSING; }
    python3 -I "$POLICY/check_manifest.py" "$ANDROID" || { DETAIL="M/X/G rules (see logs/manifest-policy.log)"; return $FAIL; }
    DETAIL="M1-M13 X1-X7 G1-G7"
}

step_source-policy() {
    have python3 || { DETAIL=python3; return $MISSING; }
    python3 -I "$POLICY/check_sources.py" "$ANDROID" || { DETAIL="S rules (see logs/source-policy.log)"; return $FAIL; }
    DETAIL="S1-S17"
}

step_policy-unit() {
    have python3 || { DETAIL=python3; return $MISSING; }
    python3 -I -m unittest discover -s "$POLICY/tests" || { DETAIL="unittest failures"; return $FAIL; }
    DETAIL="android/policy/tests"
}

step_mutations() {
    have python3 || { DETAIL=python3; return $MISSING; }
    python3 -I "$POLICY/mutations.py" "$ANDROID" "$WORK/kotlin" "$WORK/mut" ||
        { DETAIL="undetected mutations or uncovered rules (see logs/mutations.log)"; return $FAIL; }
    DETAIL="every rule has a detected mutation"
}

# --- 15-18 -----------------------------------------------------------------------------

step_deny() {
    resolve cargo-deny >/dev/null || { DETAIL=cargo-deny; return $MISSING; }
    use_tool_home
    cargo deny --offline check || { DETAIL="root (see logs/deny.log)"; return $FAIL; }
    cargo deny --offline --manifest-path tools/uniffi-bindgen/Cargo.toml check ||
        { DETAIL="tools/uniffi-bindgen (see logs/deny.log)"; return $FAIL; }
    DETAIL="root and tools/uniffi-bindgen"
}

advisory_date() {
    local db=$TOOL_HOME/advisory-db
    if [[ -d $db/.git ]]; then
        git -C "$db" log -1 --format=%cs
    elif [[ -d $db ]]; then
        date -r "$db" +%F
    else
        echo none
    fi
}

step_audit() {
    resolve cargo-audit >/dev/null || { DETAIL=cargo-audit; return $MISSING; }
    use_tool_home
    local date
    date=$(advisory_date)
    cargo audit --no-fetch --deny warnings --ignore RUSTSEC-2023-0089 ||
        { DETAIL="root (advisory-db $date)"; return $FAIL; }
    cargo audit --no-fetch --deny warnings --ignore RUSTSEC-2026-0374 --file tools/uniffi-bindgen/Cargo.lock ||
        { DETAIL="tools/uniffi-bindgen (advisory-db $date)"; return $FAIL; }
    DETAIL="no advisory (advisory-db $date)"
}

lock_packages() {
    awk '/^name = /{ n = $3 } /^version = /{ if (n != "") print n " " $3; n = "" }' | tr -d '"' | sort -u
}

step_lock-diff() {
    local new reviewed unreviewed stale
    new=$(git show main:Cargo.lock | lock_packages | comm -13 - <(lock_packages <Cargo.lock)) ||
        { DETAIL="cannot read main:Cargo.lock"; return $FAIL; }
    reviewed=$(grep -vE '^[[:space:]]*(#|$)' "$REVIEWED" | sed 's/[[:space:]]\+/ /g; s/ $//' | sort -u || true)
    unreviewed=$(comm -23 <(echo "$new" | sed '/^$/d') <(echo "$reviewed" | sed '/^$/d') | tr '\n' ' ')
    stale=$(comm -13 <(echo "$new" | sed '/^$/d') <(echo "$reviewed" | sed '/^$/d') | tr '\n' ' ')
    echo "new packages:"
    echo "$new"
    if [[ -n $unreviewed || -n $stale ]]; then
        DETAIL="unreviewed: ${unreviewed:-none}; listed but not new: ${stale:-none}"
        return $FAIL
    fi
    DETAIL="$(echo "$new" | sed '/^$/d' | wc -l) new packages, all reviewed"
}

step_ktlint() {
    if ! have ktlint; then
        DETAIL="(not installed)"
        return $SKIPPED
    fi
    ktlint "${ANDROID#"$ROOT"/}/app/src/**/*.kt" || { DETAIL="lint errors"; return $FAIL; }
    DETAIL="clean"
}

# --- driver ----------------------------------------------------------------------------

worst=0
missing_any=0
for step in "${SELECTED[@]}"; do
    DETAIL=""
    start=$SECONDS
    if "step_$step" >"$WORK/logs/$step.log" 2>&1; then rc=0; else rc=$?; fi
    case $rc in
    0) status=PASS ;;
    2) status=MISSING; missing_any=1 ;;
    3) status=SKIPPED ;;
    *) status=FAIL; worst=1 ;;
    esac
    echo "$status $step${DETAIL:+ $DETAIL}"
    echo "$status $step $((SECONDS - start))s" >>"$SUMMARY"
done

if ((worst)); then
    result=1
elif ((missing_any)) || ((QUICK)) || [[ -n $ONLY ]]; then
    result=2
else
    result=0
fi
echo "RESULT $result" >>"$SUMMARY"
echo "RESULT $result"
exit "$result"
