#!/bin/bash
# Offline verification entry point for the passwsync Arch package (contracts/verify.md).
#   packaging/verify.sh               run every check
#   packaging/verify.sh --skip-build  static checks and script tests only; never exits 0
#   packaging/verify.sh --fetch       one-time: fill the dependency cache (network), then exit
# Exit: 0 all PASS, 1 any FAIL, 2 incomplete (MISSING tool or --skip-build), 64 usage.
set -u -o pipefail

usage() {
    printf 'usage: packaging/verify.sh [--skip-build | --fetch]\n' >&2
    exit 64
}

mode=all
case $# in
0) ;;
1)
    case $1 in
    --skip-build) mode=skip ;;
    --fetch) mode=fetch ;;
    *) usage ;;
    esac
    ;;
*) usage ;;
esac

# Self-test hook for tests/verify_cli.sh: runs one synthetic check that can only end MISSING
# or FAIL (never PASS), so the exit-code paths are testable without real tool failures.
selftest=${PASSWSYNC_VERIFY_SELFTEST:-}
case $selftest in
'' | missing | fail) ;;
*) usage ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd) || exit 1
cd "$root" || exit 1
pk=$root/packaging
tests=$pk/tests
# shellcheck source=packaging/tests/lib.sh
. "$tests/lib.sh"

export LC_ALL=C TZ=UTC
cache=${PASSWSYNC_VERIFY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/passwsync-verify}
export CARGO_HOME=$cache/cargo
export CARGO_NET_OFFLINE=true
SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct HEAD) || exit 1
export SOURCE_DATE_EPOCH
export PACKAGER='passwsync verify <verify@invalid>'

work=$(mktemp -d "${TMPDIR:-/tmp}/passwsync-verify.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/logs"
logdir=${PASSWSYNC_VERIFY_LOGDIR:-$work/logs}
mkdir -p "$logdir"

n_pass=0 n_fail=0 n_missing=0 n_skip=0

# Inside a check function: `reason TEXT` sets the text printed after the id;
# return 0 PASS, 1 FAIL, 2 MISSING, 3 SKIP.
reason() { printf '%s' "$*" >"$work/reason"; }
need() { # tool...: MISSING unless every tool is on PATH
    local t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || {
            reason "$t not installed"
            return 2
        }
    done
}

run_check() { # id function
    local id=$1 fn=$2 rc=0 why
    current=$id
    : >"$work/reason"
    "$fn" >"$logdir/$id.log" 2>&1 </dev/null || rc=$?
    why=$(cat "$work/reason")
    case $rc in
    0)
        n_pass=$((n_pass + 1))
        printf 'PASS %s%s\n' "$id" "${why:+ $why}"
        ;;
    2)
        n_missing=$((n_missing + 1))
        printf 'MISSING %s: %s\n' "$id" "${why:-required tool missing}"
        ;;
    3)
        n_skip=$((n_skip + 1))
        printf 'SKIP %s: %s\n' "$id" "${why:-skipped}"
        ;;
    *)
        n_fail=$((n_fail + 1))
        printf 'FAIL %s: %s\n' "$id" "${why:-see log $id.log}"
        ;;
    esac
}

skip_check() { # id reason
    n_skip=$((n_skip + 1))
    printf 'SKIP %s: %s\n' "$1" "$2"
}

check_selftest() {
    case $selftest in
    missing) need passwsync-verify-selftest-no-such-tool || return ;;
    esac
    reason "self-test failure"
    return 1
}

# ---- checks ---------------------------------------------------------------------------

suite() { # test script args...: PASS when the suite exits 0
    bash "$tests/$1" "${@:2}" || {
        reason "$(grep -m1 '^not ok' "$logdir/$current.log" 2>/dev/null || printf 'tests/%s failed' "$1")"
        return 1
    }
}

need_cache() {
    [ -d "$CARGO_HOME/registry" ] || {
        reason "dependency cache $CARGO_HOME (run packaging/verify.sh --fetch once)"
        return 2
    }
}

check_recipe_syntax() {
    bash -n "$pk/PKGBUILD" || { reason "bash -n PKGBUILD"; return 1; }
    bash -n "$pk/passwsync.install" || { reason "bash -n passwsync.install"; return 1; }
    sh -n "$pk/passwsync-open" || { reason "sh -n passwsync-open"; return 1; }
}

check_srcinfo() { need makepkg || return; suite srcinfo.sh; }
check_recipe_fields() { suite recipe_fields.sh; }

# namcap (recipe or package): no E: line; every W: tag listed in README "Lint notes".
namcap_judge() { # namcap -m output file
    local out=$1 tag bad=
    if grep -qE '(^| )E: ' "$out"; then
        reason "namcap error: $(grep -m1 -E '(^| )E: ' "$out")"
        return 1
    fi
    for tag in $(sed -nE 's/.* W: ([A-Za-z0-9_-]+).*/\1/p' "$out" | sort -u); do
        sed -n '/^## Lint notes/,/^## /p' "$pk/README.md" | grep -qF -- "$tag" || bad="$bad $tag"
    done
    [ -z "$bad" ] || { reason "unjustified namcap warnings:$bad"; return 1; }
}
check_namcap_recipe() {
    need namcap || { reason "namcap not installed (pacman -S namcap)"; return 2; }
    mkdir -p "$work/namcap" && cp "$pk/PKGBUILD" "$pk/passwsync.install" "$work/namcap/"
    (cd "$work/namcap" && namcap -m PKGBUILD) >"$work/namcap/out" 2>&1
    cat "$work/namcap/out"
    namcap_judge "$work/namcap/out"
}

check_shellcheck() {
    command -v shellcheck >/dev/null 2>&1 || { reason "not installed (optional)"; return 3; }
    shellcheck -s bash -x "$pk/PKGBUILD" "$pk/passwsync.install" "$pk/verify.sh" "$tests"/*.sh || {
        reason "shellcheck -s bash"
        return 1
    }
    shellcheck -s sh "$pk/passwsync-open" || { reason "shellcheck -s sh passwsync-open"; return 1; }
}

# systemd-analyze verify needs an existing ExecStart= binary: a copy points it at the built
# binary (full run) or /usr/bin/true (--skip-build); unit-directives asserts the real path.
check_unit_verify() {
    need systemd-analyze || return
    local bin=/usr/bin/true
    if [ "$mode" = all ] && [ -x "$work/built/passwsyncd" ]; then bin=$work/built/passwsyncd; fi
    mkdir -p "$work/unitv"
    sed "s|^ExecStart=/usr/bin/passwsyncd\$|ExecStart=$bin|" "$pk/passwsyncd.service" >"$work/unitv/passwsyncd.service"
    systemd-analyze --user verify "$work/unitv/passwsyncd.service" >"$work/unitv/out" 2>&1
    local rc=$?
    cat "$work/unitv/out"
    [ "$rc" -eq 0 ] && [ ! -s "$work/unitv/out" ] || { reason "systemd-analyze --user verify reported problems"; return 1; }
    [ "$bin" = /usr/bin/true ] && reason "ExecStart=/usr/bin/true stand-in"
    return 0
}

check_unit_security() {
    need systemd-analyze || return
    local out rc=0 x
    out=$(systemd-analyze --user security --offline=yes --threshold=15 "$pk/passwsyncd.service" 2>&1) || rc=$?
    printf '%s\n' "$out"
    x=$(printf '%s\n' "$out" | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')
    [ "$rc" -eq 0 ] && [ -n "$x" ] && awk -v x="$x" 'BEGIN { exit !(x <= 1.5) }' || {
        reason "exposure=${x:-unknown} (threshold 1.5)"
        return 1
    }
    reason "exposure=$x"
}

check_unit_directives() { suite unit_directives.sh; }
check_desktop_validate() { need desktop-file-validate || return; suite desktop_entry.sh; }
check_launcher_tests() { suite launcher.sh; }
check_install_tests() { suite install_script.sh; }
check_no_config_writes() { suite no_config_writes.sh; }

check_confinement_probe() {
    need systemd-run findmnt ss || return
    local rc=0
    bash "$tests/confinement_probe.sh" || rc=$?
    case $rc in
    0) return 0 ;;
    2)
        reason "$(sed -n 's/^MISSING: //p' "$logdir/$current.log" | head -n1)"
        return 2
        ;;
    *)
        reason "$(grep -m1 '^not ok' "$logdir/$current.log" || printf 'probe failed')"
        return 1
        ;;
    esac
}

# ---- build checks (shared build driver: tests/lib.sh vb_*) ------------------------------

build_state=none # none | ok | fail
need_build() { # MISSING when the build could not be attempted, FAIL when it failed
    need makepkg unshare fakeroot bsdtar || return
    need_cache || return
    case $build_state in
    ok) return 0 ;;
    fail) reason "build A failed (log: build-a.log)"; return 1 ;;
    *) reason "build A was not attempted"; return 1 ;;
    esac
}

# Build A (with check()) runs before the checks are printed, so unit-verify can use its binary.
prebuild() {
    command -v makepkg >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1 &&
        command -v fakeroot >/dev/null 2>&1 && command -v bsdtar >/dev/null 2>&1 &&
        [ -d "$CARGO_HOME/registry" ] || return 0
    if vb_build "$work" "$root" a a; then
        build_state=ok
        mkdir -p "$work/built"
        vb_bin "$work" a "$work/built/passwsyncd" && chmod 0755 "$work/built/passwsyncd" || build_state=fail
    else
        build_state=fail
    fi
    cp "$work/a.log" "$logdir/build-a.log" 2>/dev/null || :
}

check_build() {
    need_build || return
    reason "offline, with check(): $(basename "$(vb_pkg "$work" a)")"
}

check_namcap_package() {
    need namcap || { reason "namcap not installed (pacman -S namcap)"; return 2; }
    need_build || return
    namcap -m "$(vb_pkg "$work" a)" >"$work/namcap-package.out" 2>&1
    cat "$work/namcap-package.out"
    namcap_judge "$work/namcap-package.out"
}

check_package_contents() { need_build || return; suite package_contents.sh "$(vb_pkg "$work" a)"; }
check_binary_paths() { need_build || return; suite reproducible.sh paths "$work"; }
check_repro_dirs() {
    need_build || return
    suite reproducible.sh dirs "$work" || return
    cp "$work/b.log" "$logdir/build-b.log" 2>/dev/null || :
}
check_repro_package() {
    need_build || return
    suite reproducible.sh package "$work" || return
    cp "$work/c.log" "$logdir/build-c.log" 2>/dev/null || :
}

check_checksum_tamper() { need makepkg unshare || return; suite recipe_integrity.sh tamper; }
check_lock_mismatch() {
    need makepkg unshare || return
    need_cache || return
    suite recipe_integrity.sh lock
}

# Static checks and script tests, in contract order.
static_checks=(
    recipe-syntax:check_recipe_syntax
    srcinfo:check_srcinfo
    recipe-fields:check_recipe_fields
    namcap-recipe:check_namcap_recipe
    shellcheck:check_shellcheck
    unit-verify:check_unit_verify
    unit-security:check_unit_security
    unit-directives:check_unit_directives
    desktop-validate:check_desktop_validate
    launcher-tests:check_launcher_tests
    install-tests:check_install_tests
    no-config-writes:check_no_config_writes
    confinement-probe:check_confinement_probe
)
# Checks that need builds (skipped with --skip-build).
build_checks=(
    checksum-tamper:check_checksum_tamper
    lock-mismatch:check_lock_mismatch
    build:check_build
    namcap-package:check_namcap_package
    package-contents:check_package_contents
    binary-paths:check_binary_paths
    repro-dirs:check_repro_dirs
    repro-package:check_repro_package
)

# ---- main -----------------------------------------------------------------------------

# --fetch: the only step that uses the network. Fills $CARGO_HOME from Cargo.lock (--locked:
# fails instead of changing the lock file), for the same host target as the recipe's prepare().
check_fetch() {
    need cargo rustc || return
    local host
    host=$(rustc -vV | sed -n 's/^host: //p')
    mkdir -p "$CARGO_HOME" || return 1
    CARGO_NET_OFFLINE=false cargo fetch --locked --target "$host" \
        --manifest-path "$root/Cargo.toml" || {
        reason "cargo fetch --locked failed (network or lock mismatch)"
        return 1
    }
    reason "cache=$CARGO_HOME"
}

if [ "$mode" = fetch ]; then
    run_check fetch check_fetch
    printf 'SUMMARY pass=%d fail=%d missing=%d skip=%d\n' "$n_pass" "$n_fail" "$n_missing" "$n_skip"
    [ "$n_pass" -eq 1 ] && exit 0
    [ "$n_missing" -gt 0 ] && exit 2
    exit 1
fi

if [ -n "$selftest" ]; then
    run_check selftest check_selftest
else
    [ "$mode" = all ] && prebuild
    for c in "${static_checks[@]}"; do
        run_check "${c%%:*}" "${c#*:}"
    done
    for c in "${build_checks[@]}"; do
        if [ "$mode" = skip ]; then
            skip_check "${c%%:*}" "--skip-build"
        else
            run_check "${c%%:*}" "${c#*:}"
        fi
    done
fi

printf 'SUMMARY pass=%d fail=%d missing=%d skip=%d\n' "$n_pass" "$n_fail" "$n_missing" "$n_skip"
if [ "$n_fail" -gt 0 ]; then
    exit 1
elif [ "$n_missing" -gt 0 ] || [ "$mode" = skip ]; then
    exit 2
fi
exit 0
