#!/bin/bash
# passwsync.install hooks (contracts/pkgbuild.md ".install"; FR-016..FR-019; SC-004):
# printf-only, no external command, the person's files untouched, required messages present.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
I=${1:-$root/packaging/passwsync.install}

if [ ! -f "$I" ]; then
    t_fail "passwsync.install exists"
    run_suite
fi

w=$(mktemp -d)
trap 'chmod -R u+rwx "$w" 2>/dev/null; rm -rf "$w"' EXIT
h=$w/home
mkdir -p "$h/.config/passwsync" "$h/.local/share/passwsync/wallets" "$h/.local/share/passwsync/sync" \
    "$h/.local/share/passwsync/received" "$w/run/passwsync"
for f in config device-id device-key peers; do printf '%s-%s\n' "$f" "$RANDOM" >"$h/.config/passwsync/$f"; done
printf 'networking = off\n' >>"$h/.config/passwsync/config"
head -c 512 /dev/urandom >"$h/.local/share/passwsync/wallets/a.pwsw"
head -c 64 /dev/urandom >"$h/.local/share/passwsync/sync/state"
head -c 64 /dev/urandom >"$h/.local/share/passwsync/received/inv-1"
printf 'http://127.0.0.1:27471/launch/%064d\n' 0 >"$w/run/passwsync/launch-url"
chmod 0600 "$h"/.config/passwsync/* "$h"/.local/share/passwsync/*/* "$w/run/passwsync/launch-url"
chmod 0700 "$h/.config/passwsync" "$h/.local/share/passwsync" "$h"/.local/share/passwsync/* "$w/run/passwsync"

stub_init "$w/stubs" "$w/stub.log"
for s in systemctl rm mv cp mkdir chmod chown sed tee install ln find sudo runuser su cat touch \
    truncate dd printf echo env sh bash; do
    make_stub "$s" 'exit 0'
done

snap() { snapshot "$h"; printf -- "-- run\n"; snapshot "$w/run"; }
before=$(snap)
run_hook() { # fn args... -> stdout in $w/out, rc echoed
    local rc=0
    (cd "$h" && env -i HOME="$h" XDG_RUNTIME_DIR="$w/run" PATH="$w/stubs" /bin/bash -c '. "$1"; shift; "$@"' _ "$I" "$@") \
        >"$w/out" 2>"$w/err" || rc=$?
    printf '%s' "$rc"
}

for call in "post_install 0.1.0-1" "post_upgrade 0.1.0-2 0.1.0-1" "post_remove 0.1.0-1"; do
    fn=${call%% *}
    # shellcheck disable=SC2086
    rc=$(run_hook $call)
    assert_eq 0 "$rc" "$fn exits 0"
    assert_eq "" "$(cat "$w/err")" "$fn writes nothing to stderr"
    assert_eq "" "$(cat "$w/stub.log")" "$fn runs no external command"
    out=$(tr 'A-Z' 'a-z' <"$w/out")
    printf '%s\n' "$out" >"$w/out.$fn"
    assert_not_contains "$out" "networking = " "$fn gives no config assignment"
    assert_not_contains "$out" "network =" "$fn gives no network assignment"
    [ "$before" = "$(snap)" ] && t_pass "$fn leaves the stand-in home and runtime dir identical" ||
        t_fail "$fn leaves the stand-in home and runtime dir identical"
done

o=$(cat "$w/out.post_install")
for p in "networking is off" "~/.config/passwsync/config" "systemctl --user enable --now passwsyncd.service" \
    "passwsync-open" "log out and log back in" "never enabled or started automatically"; do
    assert_contains "$o" "$p" "post_install mentions: $p"
done
o=$(cat "$w/out.post_upgrade")
for p in "systemctl --user restart passwsyncd.service" "locks all wallets" "not restarted automatically"; do
    assert_contains "$o" "$p" "post_upgrade mentions: $p"
done
o=$(cat "$w/out.post_remove")
for p in "~/.config/passwsync" "~/.local/share/passwsync" "\$xdg_runtime_dir/passwsync" "kept" "your decision" \
    "systemctl --user disable --now passwsyncd.service"; do
    assert_contains "$o" "$p" "post_remove mentions: $p"
done

# Static: only the three hooks, made only of printf lines.
defs=$(bash -c '. "$1"; declare -F | cut -d" " -f3 | sort | tr "\n" " "' _ "$I")
assert_eq "post_install post_remove post_upgrade " "$defs" "defines exactly post_install/post_upgrade/post_remove"
extra=$(grep -vE '^[[:space:]]*(#.*|$|printf .*|post_(install|upgrade|remove)\(\) \{|\})$' "$I" || true)
assert_eq "" "$extra" "every body line is a printf builtin call"
grep -nE '>|<|\$\(|`|;|&&|\|' "$I" | grep -vE '^[0-9]+:[[:space:]]*#' >"$w/meta" || true
assert_eq "" "$(cat "$w/meta")" "no redirection, substitution, pipe or command chaining"

run_suite
