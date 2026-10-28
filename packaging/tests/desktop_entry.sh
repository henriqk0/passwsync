#!/bin/bash
# passwsync.desktop (verify.md desktop-validate, FR-020, contracts/launcher.md).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
D=${1:-$root/packaging/passwsync.desktop}

if [ ! -f "$D" ]; then t_fail "passwsync.desktop exists"; run_suite; fi

out=$(desktop-file-validate "$D" 2>&1)
assert_eq 0 "$?" "desktop-file-validate exits 0"
assert_eq "" "$out" "desktop-file-validate prints nothing"
body=$(grep -vE '^[[:space:]]*(#.*)?$' "$D")
assert_eq "[Desktop Entry]" "$(printf '%s\n' "$body" | head -n1)" "single [Desktop Entry] group first"
assert_eq 1 "$(printf '%s\n' "$body" | grep -c '^\[')" "exactly one group"
assert_eq "Exec=/usr/bin/passwsync-open" "$(printf '%s\n' "$body" | grep '^Exec=')" "Exec=/usr/bin/passwsync-open"
assert_eq "Type=Application" "$(printf '%s\n' "$body" | grep '^Type=')" "Type=Application"
assert_eq "Terminal=false" "$(printf '%s\n' "$body" | grep '^Terminal=')" "Terminal=false"
for k in 'X-GNOME-Autostart' 'MimeType=' 'Hidden=' 'NoDisplay=true' 'OnlyShowIn=' 'NotShowIn=' 'DBusActivatable=' 'TryExec=' 'Actions='; do
    printf '%s\n' "$body" | grep -qF "$k" && t_fail "no $k" || t_pass "no $k"
done
printf '%s\n' "$body" | grep -qE '%[uUfFdDnNk]' && t_fail "no field codes" || t_pass "no field codes"

run_suite
