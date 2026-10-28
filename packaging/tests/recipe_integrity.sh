#!/bin/bash
# US1 scenarios 2 and 3 (verify.md checksum-tamper, lock-mismatch): a tampered archive or an
# archive whose Cargo.lock disagrees with a manifest stops makepkg before any compile.
# Runs makepkg inside `unshare --user --map-current-user --net`. The repository PKGBUILD is
# never edited: each case uses a staged copy (tests/lib.sh stage_recipe).
# Usage: recipe_integrity.sh [tamper|lock|all]   (needs CARGO_HOME with a filled cache for "lock")
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
which=${1:-all}

if [ ! -f "$root/packaging/PKGBUILD" ]; then
    t_fail "PKGBUILD exists"
    run_suite
fi

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
ver=$(pkg_version "$root")
arch_name=passwsync-$ver.tar.gz
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct HEAD)}
mkdir -p "$w/archive"
make_archive "$root" "$w/archive/$arch_name" "$ver" "$SOURCE_DATE_EPOCH"

no_target() { # dir: no target/ anywhere under src/
    [ -z "$(find "$1/src" -type d -name target 2>/dev/null)" ]
}

if [ "$which" = all ] || [ "$which" = tamper ]; then
    # (a) pinned sum of the real archive, then one byte of the archive changed.
    stage_recipe "$root" "$w/t" "$w/archive/$arch_name"
    size=$(stat -c %s "$w/t/$arch_name")
    off=$((size / 2))
    orig=$(dd if="$w/t/$arch_name" bs=1 skip="$off" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
    printf "\\$(printf '%03o' $(((orig + 1) % 256)))" |
        dd of="$w/t/$arch_name" bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
    [ "$(sha256sum <"$w/t/$arch_name")" != "$(sha256sum <"$w/archive/$arch_name")" ] &&
        t_pass "tamper: archive differs from the pinned one" || t_fail "tamper: archive differs from the pinned one"
    rc=0
    makepkg_offline "$w/t" >"$w/t.log" 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && t_pass "tamper: makepkg fails" || t_fail "tamper: makepkg fails"
    assert_contains "$(cat "$w/t.log")" "$arch_name ... FAILED" "tamper: fails in source verification"
    assert_contains "$(cat "$w/t.log")" "did not pass the validity check" "tamper: validity check message"
    no_target "$w/t" && t_pass "tamper: nothing compiled (no target/)" || t_fail "tamper: nothing compiled (no target/)"
    [ ! -d "$w/t/src/passwsync-$ver" ] && t_pass "tamper: archive not extracted" || t_fail "tamper: archive not extracted"
fi

if [ "$which" = all ] || [ "$which" = lock ]; then
    # (b) a manifest that disagrees with Cargo.lock (passwsyncd version bumped).
    mkdir -p "$w/x"
    tar -xzf "$w/archive/$arch_name" -C "$w/x"
    sed -i '0,/^version = /s/^version = .*/version = "9.9.9"/' "$w/x/passwsync-$ver/crates/passwsyncd/Cargo.toml"
    lock_sum=$(sha256sum <"$w/x/passwsync-$ver/Cargo.lock")
    (cd "$w/x" && LC_ALL=C tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 \
        --numeric-owner -cf - "passwsync-$ver" | gzip -n -9) >"$w/lock-$arch_name"
    mkdir -p "$w/lockarch"
    mv "$w/lock-$arch_name" "$w/lockarch/$arch_name"
    stage_recipe "$root" "$w/l" "$w/lockarch/$arch_name"
    rc=0
    makepkg_offline "$w/l" >"$w/l.log" 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && t_pass "lock: makepkg fails" || t_fail "lock: makepkg fails"
    log=$(cat "$w/l.log")
    assert_contains "$log" "Passed" "lock: source verification passed (fails later, in prepare)"
    assert_contains "$log" "--locked" "lock: cargo refuses to update the lock file"
    [ -f "$w/l/src/passwsync-$ver/Cargo.lock" ] &&
        assert_eq "$lock_sum" "$(sha256sum <"$w/l/src/passwsync-$ver/Cargo.lock")" "lock: Cargo.lock not rewritten" ||
        t_fail "lock: Cargo.lock present in src"
    no_target "$w/l" && t_pass "lock: nothing compiled (no target/)" || t_fail "lock: nothing compiled (no target/)"
fi

run_suite
