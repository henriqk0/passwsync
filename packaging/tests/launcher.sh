#!/bin/bash
# passwsync-open test matrix L1-L13 (contracts/launcher.md) with stubbed systemctl, xdg-open,
# notify-send and id on a private PATH, a stand-in XDG_RUNTIME_DIR and HOME, random tokens.
# Cases run in parallel (the invalid-file cases each wait for the 10 s deadline).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
L=${1:-$root/packaging/passwsync-open}

if [ ! -f "$L" ]; then t_fail "passwsync-open exists"; run_suite; fi
[ -x "$L" ] && t_pass "passwsync-open is executable" || t_fail "passwsync-open is executable"
assert_eq '#!/bin/sh' "$(head -n1 "$L")" "POSIX sh shebang"
sh -n "$L" && t_pass "sh -n passes" || t_fail "sh -n passes"
grep -qE '^[^#]*set +-[a-z]*x' "$L" && t_fail "never set -x" || t_pass "never set -x"

w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
myuid=$(id -u)

newtok() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

stub() { # dir name log body
    {
        printf '#!/bin/bash\n'
        printf 'printf "%%s\\n" "$*" >>%q\n' "$3"
        printf '%s\n' "$4"
    } >"$1/$2"
    chmod 0755 "$1/$2"
}

# setup C: case directory with bin/ (private PATH), run/passwsync, home/, logs and a token.
setup() {
    c=$w/$1
    mkdir -p "$c/bin" "$c/run/passwsync" "$c/home/.config/passwsync"
    chmod 0700 "$c/run/passwsync"
    printf 'keep\n' >"$c/home/.config/passwsync/config"
    link_tools "$c/bin" stat cat sleep
    tok=$(newtok)
    url="http://127.0.0.1:27471/launch/$tok"
    lf=$c/run/passwsync/launch-url
    printf '3' >"$c/active_rc"
    printf '0' >"$c/start_rc"
    printf '0' >"$c/open_rc"
    printf '%s' "$myuid" >"$c/uid"
    : >"$c/systemctl.log"
    : >"$c/open.log"
    : >"$c/notify.log"
    stub "$c/bin" systemctl "$c/systemctl.log" "
case \"\$*\" in
*is-active*) exit \$(<'$c/active_rc') ;;
*' start '*)
    if [ -f '$c/start_writes' ]; then
        ( /usr/bin/sleep 1; printf '%s\n' '$url' >'$lf.tmp'; /usr/bin/chmod 0600 '$lf.tmp'; /usr/bin/mv '$lf.tmp' '$lf' ) </dev/null >/dev/null 2>&1 &
    fi
    exit \$(<'$c/start_rc') ;;
esac
exit 0"
    stub "$c/bin" xdg-open "$c/open.log" "
if [ \"\$(<'$c/open_rc')\" != 0 ]; then printf 'xdg-open: cannot open %s\n' \"\$1\" >&2; exit \$(<'$c/open_rc'); fi
exit 0"
    stub "$c/bin" notify-send "$c/notify.log" "exit 0"
    stub "$c/bin" id "$c/id.log" "printf '%s\n' \"\$(<'$c/uid')\""
}

write_valid() { printf '%s\n' "$url" >"$lf"; chmod 0600 "$lf"; }

# run_l [args...]: runs the launcher for the current case; sets rc, dur (ms).
run_l() {
    local t0 t1
    before_home=$(snapshot "$c/home")
    t0=$(date +%s%N)
    rc=0
    env -i PATH="$c/bin" HOME="$c/home" ${xrd-XDG_RUNTIME_DIR="$c/run"} "$L" "$@" \
        >"$c/stdout" 2>"$c/stderr" </dev/null || rc=$?
    t1=$(date +%s%N)
    dur=$(((t1 - t0) / 1000000))
}

# Results of a case go to $c/res as "ok|fail<TAB>msg".
r() { printf '%s\t%s\n' "$1" "$2" >>"$c/res"; }
req() { [ "$2" = "$3" ] && r ok "$1: $4" || r fail "$1: $4 (want $2, got $3)"; }
opens() { grep -c . "$c/open.log" || true; }
common() { # case-id: token hygiene, no forbidden systemctl verbs, home unchanged (L13)
    local f
    for f in stdout stderr notify.log systemctl.log; do
        grep -qF "$tok" "$c/$f" && r fail "$1: token leaked to $f" || r ok "$1: no token in $f"
        grep -qF "127.0.0.1" "$c/$f" && r fail "$1: address leaked to $f" || r ok "$1: no address in $f"
    done
    grep -qE '(^| )(enable|restart|stop|daemon-reload|disable)( |$)' "$c/systemctl.log" &&
        r fail "$1: forbidden systemctl verb" || r ok "$1: only is-active/start used"
    [ "$before_home" = "$(snapshot "$c/home")" ] && r ok "$1: L13 home unchanged" || r fail "$1: L13 home unchanged"
    [ ! -s "$c/stdout" ] && r ok "$1: nothing on stdout" || r fail "$1: nothing on stdout"
}
msg_has() { grep -qF "$2" "$c/stderr" && r ok "$1: message '$2'" || r fail "$1: message '$2'"; }

E_TIMEOUT='the service did not provide a launch address within 10 seconds; check: systemctl --user status passwsyncd.service'
E_INVALID='the launch file is not safe to use (owner, permissions or format); check: systemctl --user status passwsyncd.service'
E_OPENER='no browser could be opened (xdg-open failed); set a default browser and try again'
E_ENV='cannot start: XDG_RUNTIME_DIR, systemctl or xdg-open is missing'
E_USAGE='usage: passwsync-open (no arguments)'

case_L1() {
    setup L1; printf 0 >"$c/active_rc"; write_valid; run_l
    req L1 0 "$rc" "exit 0"; req L1 1 "$(opens)" "one opener call"
    req L1 "$url" "$(cat "$c/open.log")" "opener got the URL"
    grep -q 'start' "$c/systemctl.log" && r fail "L1: no start" || r ok "L1: no start"
    common L1
}
case_L2() {
    setup L2; : >"$c/start_writes"; run_l
    req L2 0 "$rc" "exit 0"; req L2 1 "$(opens)" "one opener call"
    req L2 1 "$(grep -c -- '--user start passwsyncd.service' "$c/systemctl.log")" "start once"
    common L2
}
case_L3() {
    setup L3; run_l
    req L3 1 "$rc" "exit 1 (E-TIMEOUT)"; req L3 0 "$(opens)" "no opener call"
    [ "$dur" -ge 10000 ] && [ "$dur" -lt 12000 ] && r ok "L3: waited >=10 s and <12 s ($dur ms)" || r fail "L3: waited >=10 s and <12 s ($dur ms)"
    msg_has L3 "passwsync-open: $E_TIMEOUT"
    grep -qF "$E_TIMEOUT" "$c/notify.log" && r ok "L3: notify-send called" || r fail "L3: notify-send called"
    common L3
}
case_L4() {
    setup L4; printf 0 >"$c/active_rc"; printf '%s\n' "$url" >"$c/real"; chmod 0600 "$c/real"; ln -s "$c/real" "$lf"; run_l
    req L4 1 "$rc" "symlink: exit 1"; req L4 0 "$(opens)" "symlink: no opener call"; msg_has L4 "$E_INVALID"; common L4
}
case_L5() { # $1 = mode
    setup "L5_$1"; printf 0 >"$c/active_rc"; write_valid; chmod "$1" "$lf"; run_l
    req "L5 $1" 1 "$rc" "exit 1"; req "L5 $1" 0 "$(opens)" "no opener call"; common "L5 $1"
}
case_L6() {
    setup L6; printf 0 >"$c/active_rc"; write_valid; printf '%s' $((myuid + 1)) >"$c/uid"; run_l
    req L6 1 "$rc" "other owner: exit 1"; req L6 0 "$(opens)" "other owner: no opener call"; common L6
}
case_L7() { # $1 = variant
    setup "L7_$1"; printf 0 >"$c/active_rc"
    local hex=$tok
    case $1 in
    https) printf 'https://127.0.0.1:27471/launch/%s\n' "$hex" >"$lf" ;;
    localhost) printf 'http://localhost:27471/launch/%s\n' "$hex" >"$lf" ;;
    upper) printf 'http://127.0.0.1:27471/launch/%s\n' "$(printf '%s' "$hex" | tr a-f A-F | sed 's/^./A/')" >"$lf" ;;
    hex63) printf 'http://127.0.0.1:27471/launch/%s\n' "${hex:0:63}" >"$lf" ;;
    port80) printf 'http://127.0.0.1:80/launch/%s\n' "$hex" >"$lf" ;;
    port70000) printf 'http://127.0.0.1:70000/launch/%s\n' "$hex" >"$lf" ;;
    garbage) printf 'http://127.0.0.1:27471/launch/%sx\n' "$hex" >"$lf" ;;
    twolines) printf 'http://127.0.0.1:27471/launch/%s\nhttp://127.0.0.1:27471/launch/%s\n' "$hex" "$hex" >"$lf" ;;
    nonl) printf 'http://127.0.0.1:27471/launch/%s' "$hex" >"$lf" ;;
    esac
    chmod 0600 "$lf"; run_l
    req "L7 $1" 1 "$rc" "exit 1"; req "L7 $1" 0 "$(opens)" "no opener call"; common "L7 $1"
}
case_L8() {
    setup L8; printf 1 >"$c/start_rc"; write_valid; run_l
    req L8 0 "$rc" "start fails, valid file: exit 0"; req L8 1 "$(opens)" "one opener call"; common L8
}
case_L9() {
    setup L9; printf 0 >"$c/active_rc"; printf 1 >"$c/open_rc"; write_valid; run_l
    req L9 3 "$rc" "opener fails: exit 3"; msg_has L9 "$E_OPENER"; common L9
}
case_L10() { # $1 = variant
    setup "L10_$1"; printf 0 >"$c/active_rc"; write_valid
    case $1 in
    unset) xrd= ;;
    relative) xrd="XDG_RUNTIME_DIR=run" ;;
    noopener) rm "$c/bin/xdg-open" ;;
    nosystemctl) rm "$c/bin/systemctl" ;;
    esac
    run_l; unset xrd
    req "L10 $1" 2 "$rc" "exit 2"; req "L10 $1" 0 "$(opens)" "no opener call"; msg_has "L10 $1" "$E_ENV"; common "L10 $1"
}
case_L11() {
    setup L11; printf 0 >"$c/active_rc"; write_valid; run_l --help
    req L11 2 "$rc" "argument: exit 2"; req L11 0 "$(opens)" "no opener call"; msg_has L11 "$E_USAGE"; common L11
}
case_L12() { # no notify-send: errors on stderr, same exit codes
    setup L12; printf 0 >"$c/active_rc"; printf 1 >"$c/open_rc"; write_valid; rm "$c/bin/notify-send"; run_l
    req L12 3 "$rc" "exit 3 without notify-send"; msg_has L12 "$E_OPENER"; common L12
}

cases=(L1 L2 L3 L4 "L5 0640" "L5 0604" L6 L8 L9 "L10 unset" "L10 relative" "L10 noopener" "L10 nosystemctl" L11 L12)
for v in https localhost upper hex63 port80 port70000 garbage twolines nonl; do cases+=("L7 $v"); done
pids=()
for cs in "${cases[@]}"; do
    # shellcheck disable=SC2086
    (case_${cs%% *} $( [ "${cs#* }" != "$cs" ] && printf '%s' "${cs#* }")) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

for res in "$w"/*/res; do
    while IFS=$'\t' read -r st m; do
        [ "$st" = ok ] && t_pass "$m" || t_fail "$m"
    done <"$res"
done
[ "$(ls "$w"/*/res | wc -l)" -eq "${#cases[@]}" ] && t_pass "every case reported" || t_fail "every case reported"

run_suite
