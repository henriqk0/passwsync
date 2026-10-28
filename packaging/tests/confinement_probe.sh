#!/bin/bash
# Confinement probes P1-P5 (contracts/verify.md "Confinement probes", FR-012): the [Service]
# sandbox directives of packaging/passwsyncd.service, unchanged (same-path binds), applied
# through the real user manager (`systemd-run --user --pipe --wait`) to a stand-in command.
#
# Side effect, by design: ~/.config/passwsync, ~/.local/share/passwsync and
# $XDG_RUNTIME_DIR/passwsync are created (mode 0700) only if absent, and afterwards only the
# directories this script created are removed, with rmdir (never if not empty). Nothing is
# written into them (P4 uses `test -w`). Exit 2 when the user manager is unavailable.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
U=$root/packaging/passwsyncd.service

if [ ! -f "$U" ]; then t_fail "passwsyncd.service exists"; run_suite; fi
for t in systemd-run findmnt ss; do
    command -v "$t" >/dev/null 2>&1 || { printf 'MISSING: %s\n' "$t"; exit 2; }
done
case ${XDG_RUNTIME_DIR:-} in /*) ;; *) printf 'MISSING: XDG_RUNTIME_DIR\n'; exit 2 ;; esac
case $HOME in /?*) ;; *) printf 'MISSING: HOME\n'; exit 2 ;; esac
if ! systemd-run --user --quiet --wait --pipe --collect /bin/true </dev/null >/dev/null 2>&1; then
    printf 'MISSING: systemd user manager unavailable\n'
    exit 2
fi

# Create the bind sources only where absent; remember exactly what was created.
created=()
cleanup() {
    local i
    for ((i = ${#created[@]} - 1; i >= 0; i--)); do
        rmdir -- "${created[$i]}" 2>/dev/null || printf '# kept (not empty): %s\n' "${created[$i]}"
    done
    [ -n "${w:-}" ] && rm -rf "$w"
}
trap cleanup EXIT
ensure_dir() { # absolute path: create missing components one by one, mode 0700
    local p=$1 parts=() cur=
    while [ ! -e "$p" ]; do
        parts=("$p" "${parts[@]}")
        p=$(dirname "$p")
    done
    for cur in "${parts[@]}"; do
        mkdir -m 0700 -- "$cur" || return 1
        created+=("$cur")
    done
}
cfg=$HOME/.config/passwsync
dat=$HOME/.local/share/passwsync
run=$XDG_RUNTIME_DIR/passwsync
for d in "$cfg" "$dat" "$run"; do
    ensure_dir "$d" || { t_fail "create $d"; run_suite; }
done
w=$(mktemp -d)

# props UNIT: one systemd-run -p argument per [Service] sandbox directive (specifiers expanded).
props() {
    awk '
        /^[[:space:]]*([#;].*)?$/ { next }
        /^\[.*\]/ { sec = $0; next }
        sec == "[Service]" { print }
    ' "$1" | grep -vE '^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|Restart|Limit|Kill|TimeoutStopSec|UMask|Type)' |
        sed -e "s|%h|$HOME|g" -e "s|%t|$XDG_RUNTIME_DIR|g"
}

# The stand-in: prints "ok Pn" / "not ok Pn" for each probe.
probe_script=$(cat <<'EOF'
h=$1; cfg=$2; dat=$3; run=$4
r() { if "$@"; then echo "ok $P"; else echo "not ok $P"; fi; }
p1() {
    findmnt --noheadings --output TARGET --target "$h" --types tmpfs >/dev/null 2>&1 || return 1
    [ "$(ls -A "$h" | sort | tr '\n' ' ')" = ".config .local " ]
}
p2() {
    head -n1 /proc/net/tcp >/dev/null 2>&1 || return 1
    # Expanded by the shell itself (no fork), so only this shell's pid may be listed.
    set -- /proc/[0-9]*
    for d in "$@"; do
        [ "$d" = "/proc/$$" ] && continue
        echo "# visible foreign pid ${d#/proc/}" >&2
        return 1
    done
}
p3() {
    for c in "ulimit -a" "ls -A /" "ss -4 -tln"; do
        sh -c "$c" >/dev/null 2>&1; s=$?
        [ "$s" -ge 128 ] && { echo "# '$c' killed by signal $((s - 128))" >&2; return 1; }
    done
    return 0
}
p4() {
    test -w "$cfg" && test -w "$dat" && test -w "$run" && ! test -w "$h" && ! test -w /usr && ! test -w /etc
}
# `ss` opens an AF_NETLINK (sock_diag) socket. `ip` cannot be used: iproute2's `ip` calls
# capset() at start-up, which @privileged denies (SIGSYS, measured); passwsyncd does not.
p5() { ss -4 -tln >/dev/null 2>&1; }
P=P1 r p1; P=P2 r p2; P=P3 r p3; P=P4 r p4; P=P5 r p5
EOF
)

probe() { # unit-file -> probe output in $w/out, systemd-run rc echoed
    local args=() line rc=0
    while IFS= read -r line; do args+=(-p "$line"); done < <(props "$1")
    systemd-run --user --quiet --wait --pipe --collect --expand-environment=no "${args[@]}" \
        /bin/sh -c "$probe_script" probe "$HOME" "$cfg" "$dat" "$run" </dev/null >"$w/out" 2>"$w/err" || rc=$?
    printf '%s' "$rc"
}

rc=$(probe "$U")
assert_eq 0 "$rc" "stand-in runs to completion under the unit's sandbox"
for p in P1 P2 P3 P4 P5; do
    grep -qx "ok $p" "$w/out" && t_pass "probe $p" || { t_fail "probe $p"; sed 's/^/#   /' "$w/err" | head -n 5; }
done

# Mutation self-check: a weaker unit must fail the matching probe.
sed 's/^ProtectHome=tmpfs/ProtectHome=read-only/' "$U" >"$w/m1.service"
probe "$w/m1.service" >/dev/null
grep -qx "not ok P1" "$w/out" && t_pass "mutant ProtectHome=read-only fails P1" || t_fail "mutant ProtectHome=read-only fails P1"
sed '/^\[Service\]/a ProcSubset=pid' "$U" >"$w/m2.service"
probe "$w/m2.service" >/dev/null
grep -qx "not ok P2" "$w/out" && t_pass "mutant ProcSubset=pid fails P2" || t_fail "mutant ProcSubset=pid fails P2"
sed '/^PrivatePIDs=/d' "$U" >"$w/m3.service"
probe "$w/m3.service" >/dev/null
grep -qx "not ok P2" "$w/out" && t_pass "mutant without PrivatePIDs fails P2 (ProtectProc ineffective)" ||
    t_fail "mutant without PrivatePIDs fails P2 (ProtectProc ineffective)"

run_suite
