# shellcheck shell=bash
# Shared helpers for the packaging test suites (contracts/verify.md "Work layout").
# Source this file; then call assertions; end the suite with `run_suite`.
# Assertions never abort the suite: each prints `ok <n> - <msg>` or `not ok <n> - <msg>`.

_t_n=0
_t_fail=0

_t_report() { # status msg
    _t_n=$((_t_n + 1))
    if [ "$1" = ok ]; then
        printf 'ok %d - %s\n' "$_t_n" "$2"
    else
        _t_fail=$((_t_fail + 1))
        printf 'not ok %d - %s\n' "$_t_n" "$2"
    fi
}

t_pass() { _t_report ok "$1"; }
t_fail() { _t_report fail "$1"; }

assert_eq() { # want got msg
    if [ "$1" = "$2" ]; then
        _t_report ok "$3"
    else
        _t_report fail "$3"
        printf '#   want: %s\n#   got:  %s\n' "$1" "$2"
    fi
}

assert_contains() { # haystack needle msg
    case "$1" in
    *"$2"*) _t_report ok "$3" ;;
    *) _t_report fail "$3"; printf '#   missing: %s\n' "$2" ;;
    esac
}

assert_not_contains() { # haystack needle msg
    case "$1" in
    *"$2"*) _t_report fail "$3"; printf '#   unexpected text present\n' ;;
    *) _t_report ok "$3" ;;
    esac
}

assert_exit() { # want msg cmd...
    local want=$1 msg=$2 got=0
    shift 2
    "$@" >/dev/null 2>&1 || got=$?
    assert_eq "$want" "$got" "$msg (exit)"
}

# snapshot DIR: sorted "path type mode uid size sha256" listing of everything under DIR.
snapshot() {
    local dir=$1 p
    (
        cd "$dir" || exit 1
        find . -mindepth 1 -printf '%P\t%y\t%m\t%U\t%s\n' | LC_ALL=C sort | while IFS= read -r p; do
            local path=${p%%$'\t'*}
            if [ -f "$path" ] && [ ! -L "$path" ]; then
                printf '%s\t%s\n' "$p" "$(sha256sum <"$path" | cut -d' ' -f1)"
            else
                printf '%s\t-\n' "$p"
            fi
        done
    )
}

# stub_init DIR LOG: private stub directory and the file every stub appends its argv to.
stub_init() {
    STUB_DIR=$1
    STUB_LOG=$2
    mkdir -p "$STUB_DIR"
    : >"$STUB_LOG"
}

# make_stub NAME [BODY]: executable stub in $STUB_DIR that logs "NAME argv..." to $STUB_LOG
# using only shell builtins, then runs BODY (bash). Works with an empty PATH.
make_stub() {
    local name=$1 body=${2:-}
    {
        printf '#!/bin/bash\n'
        printf "printf '%%s\\\\n' \"%s \$*\" >>'%s'\n" "$name" "$STUB_LOG"
        printf '%s\n' "$body"
    } >"$STUB_DIR/$name"
    chmod 0755 "$STUB_DIR/$name"
}

# link_tools DIR TOOL...: symlink real tools into DIR (to build a private PATH).
link_tools() {
    local dir=$1 t real
    shift
    mkdir -p "$dir"
    for t in "$@"; do
        real=$(command -v "$t") || return 1
        ln -sf "$real" "$dir/$t"
    done
}

# make_archive REPO OUT VER [EPOCH]: deterministic tar.gz of the working tree (R3) with every
# path below passwsync-VER/; includes untracked, non-ignored files; excludes target/.
make_archive() {
    local repo=$1 out=$2 ver=$3 epoch=${4:-}
    [ -n "$epoch" ] || epoch=$(git -C "$repo" log -1 --format=%ct HEAD)
    (
        cd "$repo" || exit 1
        git ls-files -z --cached --others --exclude-standard |
            while IFS= read -r -d '' f; do
                [ -e "$f" ] && printf '%s\0' "$f"
            done |
            LC_ALL=C tar --null -T - --sort=name --mtime="@$epoch" --owner=0 --group=0 \
                --numeric-owner --mode='go-w' --transform "s,^,passwsync-$ver/," -cf - |
            gzip -n -9
    ) >"$out"
}

# pkg_version REPO: pkgver from the PKGBUILD (falls back to the passwsyncd crate version).
pkg_version() {
    local v
    v=$(sed -n 's/^pkgver=//p' "$1/packaging/PKGBUILD" 2>/dev/null)
    [ -n "$v" ] || v=$(sed -n 's/^version = "\(.*\)"/\1/p' "$1/crates/passwsyncd/Cargo.toml" | head -n1)
    printf '%s' "$v"
}

# stage_recipe REPO DIR ARCHIVE: start directory with a PKGBUILD copy whose sha256sums is
# replaced by the archive's sum (in the copy only), the .install file and the archive.
stage_recipe() {
    local repo=$1 dir=$2 archive=$3 sum
    mkdir -p "$dir"
    sum=$(sha256sum <"$archive" | cut -d' ' -f1)
    sed "s/^sha256sums=.*/sha256sums=('$sum')/" "$repo/packaging/PKGBUILD" >"$dir/PKGBUILD"
    [ -f "$repo/packaging/passwsync.install" ] && cp "$repo/packaging/passwsync.install" "$dir/"
    cp "$archive" "$dir/"
}

# offline CMD...: run CMD as the current uid/gid in a new network namespace that has only a
# loopback interface (brought up, so the test suite can bind 127.0.0.1) and no route out.
# An outer user namespace maps the caller to root only to run `ip link set lo up`; the inner
# one maps back to the caller's uid/gid, so makepkg does not run as root.
offline() {
    local uid gid
    uid=$(id -u)
    gid=$(id -g)
    unshare --user --map-root-user --net -- /bin/sh -c \
        'ip link set lo up && u=$1 && g=$2 && shift 2 && exec unshare --user --map-user="$u" --map-group="$g" -- "$@"' \
        offline "$uid" "$gid" "$@"
}

# makepkg_offline DIR ARGS...: makepkg in DIR (start dir) inside `offline`, with the fixed
# verification environment (contracts/verify.md "Environment"). Packages go to $PKG_OUT
# (default DIR/out). The caller exports CARGO_HOME and SOURCE_DATE_EPOCH.
makepkg_offline() {
    local dir=$1 out
    shift
    out=${PKG_OUT:-$dir/out}
    mkdir -p "$out"
    (
        cd "$dir" || exit 1
        export BUILDDIR="$dir" SRCDEST="$dir" PKGDEST="$out" SRCPKGDEST="$out" LOGDEST="$dir" \
            CARGO_NET_OFFLINE=true LC_ALL=C TZ=UTC \
            PACKAGER="${PACKAGER:-passwsync verify <verify@invalid>}"
        offline makepkg --noconfirm --noprogressbar "$@"
    )
}

# ---- shared build driver (verify.md "Work layout"; R3, R16) ----------------------------
# WORK/archive/passwsync-VER.tar.gz built once; start dirs WORK/a, WORK/b/...; packages in
# WORK/out/{a,b,c}; makepkg logs in WORK/<out>.log. The caller exports CARGO_HOME (filled by
# verify.sh --fetch) and SOURCE_DATE_EPOCH.

vb_archive() { # WORK REPO -> prints archive path
    local ver
    ver=$(pkg_version "$2")
    mkdir -p "$1/archive"
    [ -f "$1/archive/passwsync-$ver.tar.gz" ] ||
        make_archive "$2" "$1/archive/passwsync-$ver.tar.gz" "$ver" "$SOURCE_DATE_EPOCH" || return 1
    printf '%s' "$1/archive/passwsync-$ver.tar.gz"
}

vb_build() { # WORK REPO START OUT [makepkg args]: fresh start dir from the archive, build
    local work=$1 repo=$2 start=$3 out=$4 archive
    shift 4
    archive=$(vb_archive "$work" "$repo") || return 1
    rm -rf "${work:?}/$start" "${work:?}/out/$out"
    stage_recipe "$repo" "$work/$start" "$archive"
    PKG_OUT=$work/out/$out makepkg_offline "$work/$start" "$@" >"$work/$out.log" 2>&1
}

vb_pkg() { # WORK OUT -> path of the built package (not a -debug one)
    local f
    for f in "$1/out/$2"/passwsync-[0-9]*.pkg.tar.*; do
        [ -f "$f" ] && printf '%s' "$f" && return 0
    done
    return 1
}

vb_bin() { # WORK OUT DEST: extract usr/bin/passwsyncd of that package to DEST
    local p
    p=$(vb_pkg "$1" "$2") || return 1
    bsdtar -xOf "$p" usr/bin/passwsyncd >"$3"
}

# Hostile builder environment for build B (edge case "modified global build configuration").
vb_hostile_env() {
    export RUSTFLAGS=-g CFLAGS='-O0 -g' CXXFLAGS='-O0 -g' CARGO_PROFILE_RELEASE_LTO=false \
        CARGO_PROFILE_RELEASE_DEBUG=2 CARGO_PROFILE_RELEASE_STRIP=none \
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS=256 CARGO_PROFILE_RELEASE_OPT_LEVEL=0
}

# run_suite: print the summary and exit non-zero if any case failed (or none ran).
run_suite() {
    printf '1..%d\n' "$_t_n"
    if [ "$_t_fail" -ne 0 ] || [ "$_t_n" -eq 0 ]; then
        printf '# %d of %d failed\n' "$_t_fail" "$_t_n"
        exit 1
    fi
    exit 0
}
