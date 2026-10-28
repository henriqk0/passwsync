#!/bin/bash
# Reproducibility (verify.md binary-paths, repro-dirs, repro-package; FR-025, SC-003).
#   reproducible.sh [all]        build A (with check()) then run every case below
#   reproducible.sh paths WORK   A's binary contains no build/src/cache/home path
#   reproducible.sh dirs WORK    build B elsewhere with a hostile environment: binary A == B
#   reproducible.sh package WORK build C in A's path from fresh inputs >= 1 s later: package A == C
# WORK holds build A (out/a) made by the shared driver (lib.sh vb_build); every build runs
# offline (lib.sh `offline`). Needs CARGO_HOME with a filled cache (verify.sh --fetch).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
mode=${1:-all}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct HEAD)}
export PACKAGER=${PACKAGER:-'passwsync verify <verify@invalid>'} LC_ALL=C TZ=UTC
: "${CARGO_HOME:?CARGO_HOME must point at the verification cache}"

if [ "$mode" = all ]; then
    work=$(mktemp -d "${TMPDIR:-/tmp}/passwsync-repro.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    if vb_build "$work" "$root" a a; then t_pass "build A (with check())"; else
        t_fail "build A (with check())"
        tail -n 20 "$work/a.log" | sed 's/^/#   /'
        run_suite
    fi
else
    work=${2:?usage: reproducible.sh paths|dirs|package WORK}
fi

if ! vb_pkg "$work" a >/dev/null; then t_fail "package A present"; run_suite; fi
pkg_a=$(vb_pkg "$work" a)
vb_bin "$work" a "$work/bin.a" || t_fail "extract binary A"

if [ "$mode" = all ] || [ "$mode" = paths ]; then
    for p in "$work/a" "$work/a/src" "$CARGO_HOME" "$HOME" "$root"; do
        grep -qaF -- "$p" "$work/bin.a" && t_fail "binary-paths: binary contains $p" ||
            t_pass "binary-paths: binary free of $p"
    done
fi

if [ "$mode" = all ] || [ "$mode" = dirs ]; then
    if (vb_hostile_env && vb_build "$work" "$root" b/start-dir-of-another-length b --nocheck); then
        t_pass "repro-dirs: build B (other directory, hostile environment) succeeds"
        vb_bin "$work" b "$work/bin.b"
        ha=$(sha256sum <"$work/bin.a" | cut -d' ' -f1)
        hb=$(sha256sum <"$work/bin.b" | cut -d' ' -f1)
        if [ "$ha" = "$hb" ]; then
            t_pass "repro-dirs: sha256(passwsyncd) A == B ($ha)"
        else
            t_fail "repro-dirs: sha256(passwsyncd) A == B"
            printf '#   A %s\n#   B %s\n#   hint: diffoscope the two binaries\n' "$ha" "$hb"
        fi
    else
        t_fail "repro-dirs: build B (other directory, hostile environment) succeeds"
        tail -n 20 "$work/b.log" | sed 's/^/#   /'
    fi
fi

if [ "$mode" = all ] || [ "$mode" = package ]; then
    sleep 1
    if vb_build "$work" "$root" a c --nocheck; then
        t_pass "repro-package: build C (A's path, fresh copy, later) succeeds"
        pa=$(sha256sum <"$pkg_a" | cut -d' ' -f1)
        pc=$(sha256sum <"$(vb_pkg "$work" c)" | cut -d' ' -f1)
        if [ "$pa" = "$pc" ]; then
            t_pass "repro-package: sha256(package) A == C ($pa)"
        else
            t_fail "repro-package: sha256(package) A == C"
            printf '#   A %s\n#   C %s\n#   hint: diffoscope the two packages\n' "$pa" "$pc"
        fi
    else
        t_fail "repro-package: build C succeeds"
        tail -n 20 "$work/c.log" | sed 's/^/#   /'
    fi
fi

run_suite
