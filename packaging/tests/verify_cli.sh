#!/bin/bash
# verify.sh command line, exit codes, output format and token hygiene (contracts/verify.md).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
cd "$root" || exit 1

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
mkdir -p "$w/tmp"
token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

V=packaging/verify.sh
run_v() { # out-file args... ; prints exit code
    local out=$1 rc=0
    shift
    env TMPDIR="$w/tmp" PASSWSYNC_VERIFY_CACHE="$w/cache" \
        PASSWSYNC_PROBE_TOKEN="$token" PASSWSYNC_PROBE_URL="http://127.0.0.1:27471/launch/$token" \
        bash "$V" "$@" >"$out" 2>&1 || rc=$?
    printf '%s' "$rc"
}

[ -f "$V" ] && t_pass "verify.sh exists" || t_fail "verify.sh exists"

for bad in --bogus -x extra "--skip-build --bogus" "--fetch --skip-build"; do
    # shellcheck disable=SC2086
    rc=$(run_v "$w/o" $bad)
    assert_eq 64 "$rc" "usage error for: $bad"
    assert_contains "$(cat "$w/o")" "usage:" "usage text for: $bad"
done

rc=$(run_v "$w/skip" --skip-build)
[ "$rc" != 0 ] && t_pass "--skip-build never exits 0 (got $rc)" || t_fail "--skip-build never exits 0"
[ "$rc" = 1 ] || [ "$rc" = 2 ] && t_pass "--skip-build exit is 1 or 2" || t_fail "--skip-build exit is 1 or 2 (got $rc)"
assert_eq 1 "$(grep -c '^SUMMARY ' "$w/skip")" "exactly one SUMMARY line"
grep -qE '^SUMMARY pass=[0-9]+ fail=[0-9]+ missing=[0-9]+ skip=[0-9]+$' <(tail -n1 "$w/skip") &&
    t_pass "SUMMARY is the last line, contract format" || t_fail "SUMMARY is the last line, contract format"
bad_lines=$(grep -vE '^(PASS [a-z0-9-]+( .*)?|FAIL [a-z0-9-]+: .+|MISSING [a-z0-9-]+: .+|SKIP [a-z0-9-]+: .+|SUMMARY .*)$' "$w/skip" || true)
assert_eq "" "$bad_lines" "every output line is a status or summary line"

rc=$(env PASSWSYNC_VERIFY_SELFTEST=missing TMPDIR="$w/tmp" PASSWSYNC_PROBE_TOKEN="$token" bash "$V" >"$w/miss" 2>&1; echo $?)
assert_eq 2 "$rc" "a missing tool gives exit 2"
grep -qE '^MISSING selftest: ' "$w/miss" && t_pass "missing tool reported as MISSING" || t_fail "missing tool reported as MISSING"
rc=$(env PASSWSYNC_VERIFY_SELFTEST=fail TMPDIR="$w/tmp" PASSWSYNC_PROBE_TOKEN="$token" bash "$V" >"$w/fail" 2>&1; echo $?)
assert_eq 1 "$rc" "a failing check gives exit 1"
grep -qE '^FAIL selftest: ' "$w/fail" && t_pass "failing check reported as FAIL" || t_fail "failing check reported as FAIL"
rc=$(env PASSWSYNC_VERIFY_SELFTEST=pass TMPDIR="$w/tmp" bash "$V" >"$w/o" 2>&1; echo $?)
assert_eq 64 "$rc" "the self-test hook cannot produce a pass"

all=$(cat "$w/skip" "$w/miss" "$w/fail")
assert_not_contains "$all" "$token" "output never contains a token from the environment"
assert_eq "" "$(ls -A "$w/tmp")" "work directories removed on exit"
[ ! -e "$w/cache" ] && t_pass "--skip-build does not create the cache" || t_fail "--skip-build does not create the cache"

run_suite
