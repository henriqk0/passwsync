#!/bin/bash
# Exact package contents (verify.md package-contents, contracts/pkgbuild.md "Package file
# list", FR-015, FR-004). Usage: package_contents.sh PACKAGE
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
pkg=${1:-}

if [ -z "$pkg" ] || [ ! -f "$pkg" ]; then t_fail "package file given and present"; run_suite; fi

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT

# Regular files (non-directories) with their mode, metadata excluded.
bsdtar -tvf "$pkg" >"$w/list" || t_fail "bsdtar can list the package"
got=$(awk '$1 !~ /^d/ { print $1, $NF }' "$w/list" | grep -vE ' \.(PKGINFO|BUILDINFO|MTREE|INSTALL)$' | LC_ALL=C sort -k2)
want=$(LC_ALL=C sort -k2 <<'EOF'
-rwxr-xr-x usr/bin/passwsyncd
-rwxr-xr-x usr/bin/passwsync-open
-rw-r--r-- usr/lib/systemd/user/passwsyncd.service
-rw-r--r-- usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf
-rw-r--r-- usr/share/applications/passwsync.desktop
-rw-r--r-- usr/share/doc/passwsync/README.md
-rw-r--r-- usr/share/licenses/passwsync/LICENSE
EOF
)
assert_eq "$want" "$got" "exactly the FR-015 files with their modes"
for m in .PKGINFO .BUILDINFO .MTREE .INSTALL; do
    grep -qE " $m\$" "$w/list" && t_pass "metadata $m present" || t_fail "metadata $m present"
done
bad=$(awk '{ print $NF }' "$w/list" | grep -E '^(home|root|etc|var|srv|opt|tmp)(/|$)' || true)
assert_eq "" "$bad" "nothing under home/, root/, etc/, var/, srv/, opt/, tmp/"
sys=$(awk '$1 !~ /^d/ { print $NF }' "$w/list" | grep '^usr/lib/systemd/system/' | grep -v '^usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf$' || true)
assert_eq "" "$sys" "no system unit"
owners=$(awk '{ print $3 ":" $4 }' "$w/list" | sort -u | tr '\n' ' ')
assert_eq "root:root " "$owners" "every entry owned by root:root"

# Installed sources are byte-identical to packaging/ (and .INSTALL to the install script).
bsdtar -xf "$pkg" -C "$w" 2>/dev/null
cmp -s "$w/.INSTALL" "$root/packaging/passwsync.install" && t_pass ".INSTALL equals packaging/passwsync.install" ||
    t_fail ".INSTALL equals packaging/passwsync.install"
for pair in "usr/bin/passwsync-open:packaging/passwsync-open" \
    "usr/lib/systemd/user/passwsyncd.service:packaging/passwsyncd.service" \
    "usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf:packaging/passwsync-memlock.conf" \
    "usr/share/applications/passwsync.desktop:packaging/passwsync.desktop" \
    "usr/share/doc/passwsync/README.md:packaging/README.md" "usr/share/licenses/passwsync/LICENSE:LICENSE"; do
    cmp -s "$w/${pair%%:*}" "$root/${pair#*:}" && t_pass "${pair%%:*} equals ${pair#*:}" || t_fail "${pair%%:*} equals ${pair#*:}"
done

# Stripped binary, no debug package, no debug sections.
ft=$(file -b "$w/usr/bin/passwsyncd")
assert_contains "$ft" "ELF 64-bit" "passwsyncd is an ELF binary"
case $ft in *"not stripped"*) t_fail "passwsyncd is stripped" ;; *stripped*) t_pass "passwsyncd is stripped" ;; *) t_fail "passwsyncd is stripped" ;; esac
assert_eq "" "$(ls "$(dirname "$pkg")" | grep -- '-debug-' || true)" "no -debug package"
grep -q '^depend = ' "$w/.PKGINFO" &&
    assert_eq "gcc-libs glibc systemd xdg-utils " "$(sed -n 's/^depend = //p' "$w/.PKGINFO" | sort | tr '\n' ' ')" ".PKGINFO depends"
grep -q '^backup = ' "$w/.PKGINFO" && t_fail "no backup files" || t_pass "no backup files"

run_suite
