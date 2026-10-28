#!/bin/bash
# SC-005 / FR-016 / FR-027 static guard (verify.md no-config-writes): no packaging file writes a
# passwsync configuration or sets a networking key; no packaged path under /home or /root; no
# change to crates/, Cargo.toml or Cargo.lock against main. Mutation self-test first.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
pk=$root/packaging
files=(PKGBUILD passwsync.install passwsync-open passwsyncd.service passwsync-memlock.conf passwsync.desktop)

WRITE='(>|(^|[^A-Za-z_-])(tee|cp|mv|touch|install|dd|truncate|ln|rm)([[:space:]]|$)|sed[[:space:]]+(-[a-zA-Z]*i|--in-place))'
CONF='passwsync/config'
NET='(^|[^A-Za-z_])(networking|lan)[[:space:]]*='

scan() { # file: prints offending lines
    grep -nE "$WRITE" "$1" | grep -F "$CONF" | sed 's/^/config-write: /'
    grep -nE "$NET" "$1" | sed 's/^/networking-key: /'
}

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT

# 1. Mutation self-test: an injected write or networking key must be flagged in every file.
n=0
for f in "${files[@]}"; do
    [ -f "$pk/$f" ] || continue
    n=$((n + 1))
    { cat "$pk/$f"; printf '%s\n' "printf 'x' >> ~/.config/passwsync/config"; } >"$w/$f.w"
    [ -n "$(scan "$w/$f.w")" ] && t_pass "mutant config write flagged in $f" || t_fail "mutant config write flagged in $f"
    { cat "$pk/$f"; printf 'networking = on\n'; } >"$w/$f.n"
    [ -n "$(scan "$w/$f.n")" ] && t_pass "mutant networking key flagged in $f" || t_fail "mutant networking key flagged in $f"
    { cat "$pk/$f"; printf '%s\n' "sed -i s/off/on/ \"\$HOME/.config/passwsync/config\""; } >"$w/$f.s"
    [ -n "$(scan "$w/$f.s")" ] && t_pass "mutant sed -i flagged in $f" || t_fail "mutant sed -i flagged in $f"
done
[ "$n" -gt 0 ] && t_pass "at least one packaging file present" || t_fail "at least one packaging file present"

# 2. The real files.
for f in "${files[@]}"; do
    if [ -f "$pk/$f" ]; then
        assert_eq "" "$(scan "$pk/$f")" "no config write or networking key in $f"
    else
        printf '# not present yet: %s\n' "$f"
    fi
done
if [ -f "$pk/PKGBUILD" ]; then
    body=$(bash -c '. "$1" >/dev/null 2>&1; declare -f package' _ "$pk/PKGBUILD")
    printf '%s\n' "$body" | grep -qE '\$pkgdir/+(home|root)(/|")|\$HOME|~/' &&
        t_fail "package() installs nothing under /home or /root" || t_pass "package() installs nothing under /home or /root"
fi

# 3. FR-027: no change to the Rust tree.
assert_eq "" "$(git -C "$root" diff --stat main -- crates Cargo.toml Cargo.lock)" "no diff against main in crates/, Cargo.toml, Cargo.lock"
assert_eq "" "$(git -C "$root" status --porcelain -- crates Cargo.toml Cargo.lock)" "no uncommitted change in crates/, Cargo.toml, Cargo.lock"

run_suite
