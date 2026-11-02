#!/usr/bin/env bash
# Defect-injection check (008 SC-003, research R11; quickstart H-5). Manual [H], slow (one
# release rebuild per defect); not part of scripts/gate.sh.
#
# For each patch in scripts/defects/: copy the working tree (without target/ and .git/) into
# a temporary directory, apply the patch there, run only the matching fuzz target with a
# separate CARGO_TARGET_DIR, and expect it to FAIL. Prints one
# `INJECT <name> DETECTED|MISSED` line per defect. Exit 0 only if every defect is detected,
# 1 otherwise, 64 on usage. Never touches the working tree; offline (--frozen --offline).
set -u -o pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEFECTS=(wallet_header frame sync_ctl share_msg http_request)

if (($#)); then
    echo "usage: scripts/inject_defects.sh" >&2
    exit 64
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR=$WORK/target

detected=0
for name in "${DEFECTS[@]}"; do
    copy=$WORK/$name
    mkdir -p "$copy"
    tar -C "$ROOT" --exclude=./target --exclude=./.git -cf - . | tar -C "$copy" -xf -
    if ! (cd "$copy" && patch -p1 -s <"$ROOT/scripts/defects/$name.patch"); then
        echo "INJECT $name MISSED (patch does not apply)"
        continue
    fi
    log=$WORK/$name.log
    if (cd "$copy" && cargo test --frozen --offline --release -p hardening --test "fuzz_$name" \
        -- --nocapture >"$log" 2>&1); then
        echo "INJECT $name MISSED (fuzz target passed)"
    elif grep -aq '^FUZZ-FAIL' "$log"; then
        echo "INJECT $name DETECTED $(grep -a -m1 '^FUZZ-FAIL' "$log" | sed 's/ detail=.*//')"
        detected=$((detected + 1))
    else
        echo "INJECT $name MISSED (build or harness error; last lines follow)"
        tail -n 20 "$log"
    fi
    rm -rf "$copy"
done

echo "INJECT result $detected of ${#DEFECTS[@]} detected"
((detected == ${#DEFECTS[@]}))
