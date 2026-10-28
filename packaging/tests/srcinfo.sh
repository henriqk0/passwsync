#!/bin/bash
# packaging/.SRCINFO equals `makepkg --printsrcinfo` of packaging/PKGBUILD (verify.md srcinfo).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
cp "$root/packaging/PKGBUILD" "$root/packaging/passwsync.install" "$w/" 2>/dev/null
rc=0
(cd "$w" && LC_ALL=C makepkg --printsrcinfo >"$w/SRCINFO" 2>"$w/err") || rc=$?
assert_eq 0 "$rc" "makepkg --printsrcinfo succeeds"
[ -f "$root/packaging/.SRCINFO" ] && t_pass ".SRCINFO exists" || t_fail ".SRCINFO exists"
if diff -u "$root/packaging/.SRCINFO" "$w/SRCINFO" >"$w/diff" 2>&1; then
    t_pass ".SRCINFO is in sync with PKGBUILD"
else
    t_fail ".SRCINFO is in sync with PKGBUILD"
    sed 's/^/#   /' "$w/diff" | head -n 20
fi

run_suite
