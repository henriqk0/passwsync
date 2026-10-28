#!/bin/bash
# Self-test of packaging/tests/lib.sh.
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT

# A failing assertion must be detected by run_suite (in a child shell).
out=$(bash -c ". '$here/lib.sh'; assert_eq a b 'mismatch'; run_suite" 2>&1)
rc=$?
assert_eq 1 "$rc" "run_suite exits 1 after a failed assertion"
assert_contains "$out" "not ok 1 - mismatch" "failed assertion prints not ok"
out=$(bash -c ". '$here/lib.sh'; run_suite" 2>&1)
assert_eq 1 "$?" "run_suite exits 1 when no case ran"
out=$(bash -c ". '$here/lib.sh'; assert_eq a a ok; assert_contains abc b c; assert_not_contains abc z n; run_suite" 2>&1)
assert_eq 0 "$?" "run_suite exits 0 when all pass"
out=$(bash -c ". '$here/lib.sh'; assert_contains abc z m; assert_not_contains abc b n; run_suite" 2>&1)
assert_contains "$out" "# 2 of 2 failed" "contains/not_contains detect failures"

assert_exit 3 "assert_exit sees the code" bash -c 'exit 3'

# snapshot: detects content, mode and new files; identical when unchanged.
mkdir -p "$w/h/a"
printf x >"$w/h/a/f"
chmod 0600 "$w/h/a/f"
s1=$(snapshot "$w/h")
assert_eq "$s1" "$(snapshot "$w/h")" "snapshot stable"
assert_contains "$s1" "a/f	f	600	$(id -u)	1	$(printf x | sha256sum | cut -d' ' -f1)" "snapshot line format"
chmod 0640 "$w/h/a/f"
[ "$s1" != "$(snapshot "$w/h")" ] && t_pass "snapshot sees mode change" || t_fail "snapshot sees mode change"
chmod 0600 "$w/h/a/f"
printf y >"$w/h/a/f"
[ "$s1" != "$(snapshot "$w/h")" ] && t_pass "snapshot sees content change" || t_fail "snapshot sees content change"

# make_stub: logs argv with an empty PATH and runs its body.
stub_init "$w/stubs" "$w/stub.log"
make_stub systemctl 'exit 7'
rc=0
env -i PATH="$w/stubs" /bin/bash -c 'systemctl --user start "a b"' || rc=$?
assert_eq 7 "$rc" "stub body runs"
assert_eq "systemctl --user start a b" "$(cat "$w/stub.log")" "stub logs argv"

# link_tools
link_tools "$w/bin" cat
[ -x "$w/bin/cat" ] && t_pass "link_tools links a tool" || t_fail "link_tools links a tool"

# make_archive: deterministic, prefixed, includes untracked, excludes ignored.
mkdir -p "$w/repo"
git -C "$w/repo" init -q
printf 'target/\n' >"$w/repo/.gitignore"
printf a >"$w/repo/tracked"
git -C "$w/repo" add .gitignore tracked
git -C "$w/repo" -c user.name=t -c user.email=t@invalid commit -qm init
printf b >"$w/repo/untracked"
mkdir -p "$w/repo/target"
printf c >"$w/repo/target/junk"
make_archive "$w/repo" "$w/a1.tar.gz" 9.9
sleep 1
make_archive "$w/repo" "$w/a2.tar.gz" 9.9
assert_eq "$(sha256sum <"$w/a1.tar.gz")" "$(sha256sum <"$w/a2.tar.gz")" "make_archive is deterministic"
list=$(tar -tzf "$w/a1.tar.gz" | sort | tr '\n' ' ')
assert_eq "passwsync-9.9/.gitignore passwsync-9.9/tracked passwsync-9.9/untracked " "$list" "make_archive contents"

run_suite
