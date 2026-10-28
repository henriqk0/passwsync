#!/bin/bash
# PKGBUILD metadata and functions (contracts/pkgbuild.md "Metadata"/"Functions"; verify.md
# recipe-fields; FR-001, FR-002, FR-004, FR-005).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
P=${1:-$root/packaging/PKGBUILD}

if [ ! -f "$P" ]; then
    t_fail "PKGBUILD exists"
    run_suite
fi

# Source in a child shell (our own file) and print the values the checks need.
vals=$(bash -c '
    set -u
    . "$1" >/dev/null 2>&1 || exit 1
    printf "pkgname=%s\n" "$pkgname"
    printf "pkgver=%s\n" "$pkgver"
    printf "pkgrel=%s\n" "$pkgrel"
    printf "url=%s\n" "$url"
    printf "arch=%s\n" "${arch[*]}"
    printf "license=%s\n" "${license[*]}"
    printf "depends=%s\n" "$(printf "%s\n" "${depends[@]}" | sort | tr "\n" " ")"
    printf "makedepends=%s\n" "${makedepends[*]}"
    printf "optdepends=%s\n" "${optdepends[*]}"
    printf "options=%s\n" "${options[*]}"
    printf "install=%s\n" "${install:-}"
    printf "nsource=%s\n" "${#source[@]}"
    printf "source=%s\n" "${source[0]:-}"
    printf "nsums=%s\n" "${#sha256sums[@]}"
    printf "sum=%s\n" "${sha256sums[0]:-}"
    for v in backup provides conflicts noextract; do
        declare -p "$v" >/dev/null 2>&1 && printf "forbidden=%s\n" "$v"
    done
    declare -F pkgver >/dev/null && printf "forbidden=pkgver()\n"
    for f in prepare build check package; do declare -F "$f" >/dev/null || printf "nofunc=%s\n" "$f"; done
    exit 0
' _ "$P")
assert_eq 0 "$?" "PKGBUILD sources cleanly"
val() { printf '%s\n' "$vals" | sed -n "s/^$1=//p" | head -n1; }

assert_eq passwsync "$(val pkgname)" "pkgname"
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/crates/passwsyncd/Cargo.toml" | head -n1)
assert_eq "$ver" "$(val pkgver)" "pkgver equals the passwsyncd crate version"
assert_eq 1 "$(val pkgrel)" "pkgrel"
assert_eq https://github.com/henriqk0/passwsync "$(val url)" "url"
assert_eq x86_64 "$(val arch)" "arch"
assert_eq MPL-2.0 "$(val license)" "license"
assert_eq "gcc-libs glibc systemd xdg-utils " "$(val depends)" "depends"
assert_eq cargo "$(val makedepends)" "makedepends"
assert_contains "$(val optdepends)" "libnotify:" "optdepends libnotify"
assert_eq "!debug !lto" "$(val options)" "options !debug !lto"
assert_eq passwsync.install "$(val install)" "install file"
assert_eq 1 "$(val nsource)" "exactly one source"
assert_eq "passwsync-$ver.tar.gz::https://github.com/henriqk0/passwsync/archive/refs/tags/v$ver.tar.gz" \
    "$(val source)" "source is the tag archive"
assert_eq 1 "$(val nsums)" "exactly one sha256sums entry"
printf '%s' "$(val sum)" | grep -qE '^[0-9a-f]{64}$' && t_pass "sha256sums is 64 hex" || t_fail "sha256sums is 64 hex"
assert_eq "" "$(printf '%s\n' "$vals" | sed -n 's/^forbidden=//p' | tr '\n' ' ')" "no backup/provides/conflicts/noextract/pkgver()"
assert_eq "" "$(printf '%s\n' "$vals" | sed -n 's/^nofunc=//p' | tr '\n' ' ')" "prepare/build/check/package defined"

text=$(cat "$P")
assert_not_contains "$text" "SKIP" "no SKIP"
assert_not_contains "$text" "git+" "no git+ source"
grep -qE '^[^#]*-git' "$P" && t_fail "no -git" || t_pass "no -git"

body_prepare=$(bash -c '. "$1" >/dev/null 2>&1; declare -f prepare' _ "$P")
body_build=$(bash -c '. "$1" >/dev/null 2>&1; declare -f build' _ "$P")
body_check=$(bash -c '. "$1" >/dev/null 2>&1; declare -f check' _ "$P")
body_package=$(bash -c '. "$1" >/dev/null 2>&1; declare -f package' _ "$P")

for f in prepare build check package; do
    b=$(eval "printf '%s' \"\$body_$f\"")
    assert_contains "$b" 'cd "$pkgname-$pkgver"' "$f() enters the source directory"
    assert_contains "$b" "RUSTUP_TOOLCHAIN=stable" "$f() exports RUSTUP_TOOLCHAIN=stable"
done
assert_contains "$body_prepare" 'cargo fetch --locked --target "$(rustc -vV | sed -n '"'"'s/host: //p'"'"')"' "prepare() cargo fetch --locked for the host"
assert_contains "$body_build" "cargo build --frozen --release -p passwsyncd --bin passwsyncd" "build() builds only passwsyncd, frozen"
assert_eq 1 "$(printf '%s\n' "$body_build" | grep -cE '^[[:space:]]*cargo ')" "build() runs one cargo command"
assert_contains "$body_check" "cargo test --frozen --workspace" "check() runs the workspace suite, frozen"
for kv in CARGO_TARGET_DIR=target CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    CARGO_PROFILE_RELEASE_DEBUG=false CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_INCREMENTAL=false; do
    assert_contains "$body_build" "export $kv" "build() sets $kv"
done
rf=$(printf '%s\n' "$body_build" | grep -E 'RUSTFLAGS=' || true)
assert_eq 1 "$(printf '%s\n' "$rf" | grep -c 'RUSTFLAGS=')" "build() assigns RUSTFLAGS once"
assert_not_contains "$rf" '$RUSTFLAGS' "RUSTFLAGS replaced, not appended"
assert_not_contains "$rf" '${RUSTFLAGS' "RUSTFLAGS replaced, not appended (braced)"
for p in '$HOME=' '$startdir=' '${CARGO_HOME:-$HOME/.cargo}=/cargo' '$srcdir=/build'; do
    assert_contains "$rf" "--remap-path-prefix=$p" "RUSTFLAGS remaps $p"
done
# The most specific prefix must be last (rustc: the last matching remap wins).
last=$(printf '%s\n' "$rf" | grep -o -- '--remap-path-prefix=[^ "]*' | tail -n1)
assert_eq '--remap-path-prefix=$srcdir=/build' "$last" "srcdir remap is the last (most specific)"
assert_eq 7 "$(printf '%s\n' "$body_package" | grep -c 'install -')" "package() has the 7 install commands"
assert_not_contains "$body_package" "cargo" "package() does not build"

# FR-005: the check() comment lists exactly the #[ignore]d tests plus the memlock self-skip test.
want=$(
    cd "$root" && grep -rn '#\[ignore' crates | while IFS=: read -r file line _; do
        name=$(awk -v l="$line" 'NR > l && match($0, /fn [a-z0-9_]+/) { print substr($0, RSTART + 3, RLENGTH - 3); exit }' "$file")
        crate=${file#crates/}
        crate=${crate%%/*}
        base=$(basename "$file" .rs)
        printf '%s/%s::%s\n' "$crate" "$base" "$name"
    done
    printf 'passwsyncd/startup::real_binary_starts_when_the_memlock_limit_allows\n'
)
want=$(printf '%s\n' "$want" | LC_ALL=C sort -u)
got=$(sed -n '/^check()/,/^}/p' "$P" | sed -nE 's/^[[:space:]]*#[[:space:]]+([a-z0-9-]+\/[a-z0-9_]+::[a-z0-9_]+).*/\1/p' | LC_ALL=C sort -u)
assert_eq "$want" "$got" "check() comment names exactly the skipped tests (FR-005)"
got_n=$(sed -n '/^check()/,/^}/p' "$P" | grep -cE '^[[:space:]]*#[[:space:]]+[a-z0-9-]+/[a-z0-9_]+::[a-z0-9_]+ +\(.+\)')
assert_eq "$(printf '%s\n' "$want" | grep -c .)" "$got_n" "each skipped test has a (reason)"

run_suite
