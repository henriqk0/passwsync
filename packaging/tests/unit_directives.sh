#!/bin/bash
# Directive rules D1-D12 of contracts/unit-file.md for packaging/passwsyncd.service, the exact
# content of packaging/passwsync-memlock.conf, and a mutation self-check (each rule broken in a
# copy must be detected).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/tests/lib.sh
. "$here/lib.sh"
U=${1:-$root/packaging/passwsyncd.service}
M=${2:-$root/packaging/passwsync-memlock.conf}

PRE1="ExecStartPre=+/usr/bin/sh -c 'if [ \"\$\${XDG_CONFIG_HOME:-\$\$HOME/.config}\" != \"\$\$HOME/.config\" ] || [ \"\$\${XDG_DATA_HOME:-\$\$HOME/.local/share}\" != \"\$\$HOME/.local/share\" ]; then echo \"path: custom XDG_CONFIG_HOME/XDG_DATA_HOME need a unit override, see /usr/share/doc/passwsync/README.md\" >&2; exit 2; fi; exec /usr/bin/mkdir -p -m 0700 \"\$\$HOME/.config/passwsync\" \"\$\$HOME/.local/share/passwsync\" \"\$\$XDG_RUNTIME_DIR/passwsync\"'"
PRE2="ExecStartPre=/usr/bin/findmnt --noheadings --output TARGET --target %h --types tmpfs"

# norm FILE: "Section|Key=Value" per directive, comments and blank lines removed.
norm() {
    awk '
        /^[[:space:]]*([#;].*)?$/ { next }
        /^\[.*\][[:space:]]*$/ { sec = $0; gsub(/[][[:space:]]/, "", sec); next }
        { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); print sec "|" $0 }
    ' "$1"
}

secs() { sed -n 's/^\[\(.*\)\][[:space:]]*$/\1/p' "$1" | tr '\n' ' '; }

# rules UNIT: prints one "Dn: reason" line per violated rule (nothing when compliant).
rules() {
    local n
    n=$(norm "$1")
    vals() { printf '%s\n' "$n" | sed -n "s/^$1|$2=//p"; }
    cnt() { printf '%s\n' "$n" | grep -c "^$1|$2=" ; }
    one() { # rule section key value
        [ "$(cnt "$2" "$3")" = 1 ] && [ "$(vals "$2" "$3")" = "$4" ] || printf '%s: %s=%s expected once in [%s]\n' "$1" "$3" "$4" "$2"
    }
    secs_have=$(secs "$1")
    [ "$secs_have" = "Unit Service Install " ] || printf 'D0: sections are [%s], expected Unit Service Install\n' "$secs_have"

    one D1 Service ExecStart /usr/bin/passwsyncd
    [ "$(printf '%s\n' "$n" | grep -c '|ExecStart=')" = 1 ] || printf 'D1: more than one ExecStart=\n'
    one D2 Service Type exec
    one D3 Service LimitMEMLOCK 256M
    one D3 Service LimitCORE 0
    one D3 Service UMask 0077
    for kv in NoNewPrivileges=yes CapabilityBoundingSet= AmbientCapabilities= RestrictSUIDSGID=yes \
        LockPersonality=yes MemoryDenyWriteExecute=yes RestrictRealtime=yes SystemCallArchitectures=native; do
        one D4 Service "${kv%%=*}" "${kv#*=}"
    done
    [ "$(vals Service SystemCallFilter | tr '\n' '|')" = "@system-service|~@privileged @resources|" ] ||
        printf 'D5: SystemCallFilter lines must be exactly @system-service then ~@privileged @resources\n'
    for kv in PrivateUsers=yes PrivateTmp=yes PrivateDevices=yes PrivateIPC=yes PrivatePIDs=yes ProtectSystem=strict \
        ProtectHome=tmpfs ProtectKernelTunables=yes ProtectKernelModules=yes ProtectKernelLogs=yes \
        ProtectControlGroups=yes ProtectClock=yes ProtectHostname=yes ProtectProc=invisible \
        KeyringMode=private RestrictNamespaces=yes; do
        one D6 Service "${kv%%=*}" "${kv#*=}"
    done
    one D7 Service BindPaths "%h/.config/passwsync %h/.local/share/passwsync %t/passwsync"
    [ "$(printf '%s\n' "$n" | grep -cE '\|([A-Za-z]*Directory|TemporaryFileSystem|BindPaths|ReadWritePaths)=')" = 1 ] ||
        printf 'D7: extra write grant (BindPaths/ReadWritePaths/*Directory=/TemporaryFileSystem=)\n'
    one D8 Service RestrictAddressFamilies "AF_INET AF_NETLINK"
    printf '%s\n' "$n" | grep -q '|ProcSubset=' && printf 'D8: ProcSubset= is forbidden (peer-UID check)\n'
    one D9 Service Restart on-failure
    one D9 Service RestartPreventExitStatus "2 3 4"
    one D9 Unit StartLimitIntervalSec 5min
    one D9 Unit StartLimitBurst 5
    one D9 Service KillSignal SIGTERM
    secs_of() { # value -> seconds (supports N, Ns, Nmin)
        case $1 in
        *min) printf '%s' $((${1%min} * 60)) ;;
        *s) printf '%s' "${1%s}" ;;
        *[!0-9]* | '') printf '%s' -1 ;;
        *) printf '%s' "$1" ;;
        esac
    }
    rs=$(vals Service RestartSec)
    { [ "$(cnt Service RestartSec)" = 1 ] && [ "$(secs_of "$rs")" -ge 5 ]; } || printf 'D9: RestartSec >= 5s once\n'
    ts=$(vals Service TimeoutStopSec)
    { [ "$(cnt Service TimeoutStopSec)" = 1 ] && [ "$(secs_of "$ts")" -ge 10 ]; } || printf 'D9: TimeoutStopSec >= 10s once\n'
    pre=$(printf '%s\n' "$n" | sed -n 's/^Service|\(ExecStartPre=.*\)$/\1/p')
    [ "$pre" = "$PRE1"$'\n'"$PRE2" ] || printf 'D10: ExecStartPre lines differ from the contract\n'
    printf '%s\n' "$n" | grep -E '\|(User|Group|ListenStream|ListenDatagram|Sockets|Environment|EnvironmentFile|PassEnvironment|StandardOutput|StandardError|LogLevelMax|IPAddressAllow|IPAddressDeny|SystemCallErrorNumber)=' |
        sed 's/^/D11: forbidden /'
    printf '%s\n' "$n" | grep -E '\|AmbientCapabilities=.+' | sed 's/^/D11: forbidden /'
    [ "$(printf '%s\n' "$n" | grep '^Install|')" = "Install|WantedBy=default.target" ] ||
        printf 'D12: [Install] must hold only WantedBy=default.target\n'
}

dropin_ok() {
    [ "$(grep -vE '^[[:space:]]*(#.*)?$' "$1")" = $'[Service]\nLimitMEMLOCK=256M' ] || return 1
    # comments only before [Service]
    ! sed -n '/^\[Service\]/,$p' "$1" | grep -q '^#'
}

if [ ! -f "$U" ]; then t_fail "passwsyncd.service exists"; run_suite; fi

out=$(rules "$U")
for r in D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 D10 D11 D12; do
    v=$(printf '%s\n' "$out" | grep "^$r:" || true)
    assert_eq "" "$v" "unit rule $r"
done
if [ -f "$M" ]; then
    dropin_ok "$M" && t_pass "memlock drop-in has exactly [Service] LimitMEMLOCK=256M" ||
        t_fail "memlock drop-in has exactly [Service] LimitMEMLOCK=256M"
else
    t_fail "passwsync-memlock.conf exists"
fi

# Mutation self-check: every broken copy must be flagged with its rule.
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
mutate() { # rule sed-expression
    sed "$2" "$U" >"$w/m.service"
    if cmp -s "$U" "$w/m.service"; then
        t_fail "mutant $1 changed the unit"
        return
    fi
    rules "$w/m.service" | grep -q "^$1:" && t_pass "mutant detected: $1 ($2)" || t_fail "mutant detected: $1 ($2)"
}
mutate D1 's|^ExecStart=/usr/bin/passwsyncd|ExecStart=/home/me/.cargo/bin/passwsyncd|'
mutate D1 '/^\[Service\]/a ExecStart=/usr/bin/true'
mutate D2 's/^Type=exec/Type=simple/'
mutate D3 's/^LimitCORE=0/LimitCORE=infinity/'
mutate D3 's/^UMask=0077/UMask=0022/'
mutate D4 's/^NoNewPrivileges=yes/NoNewPrivileges=no/'
mutate D4 's/^CapabilityBoundingSet=$/CapabilityBoundingSet=CAP_IPC_LOCK/'
mutate D5 '/^SystemCallFilter=~/d'
mutate D6 's/^ProtectHome=tmpfs/ProtectHome=read-only/'
mutate D6 '/^\[Service\]/a ProtectSystem=full'
mutate D6 '/^PrivatePIDs=/d'
mutate D7 '/^\[Service\]/a ReadWritePaths=%h'
mutate D7 '/^\[Service\]/a StateDirectory=passwsync'
mutate D8 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX/'
mutate D8 '/^\[Service\]/a ProcSubset=pid'
mutate D9 's/^RestartPreventExitStatus=.*/RestartPreventExitStatus=2 3/'
mutate D9 's/^Restart=on-failure/Restart=always/'
mutate D9 's/^TimeoutStopSec=.*/TimeoutStopSec=3s/'
mutate D10 '/^ExecStartPre=\/usr\/bin\/findmnt/d'
mutate D10 's/^ExecStartPre=+/ExecStartPre=/'
mutate D11 '/^\[Service\]/a Environment=RUST_LOG=debug'
mutate D11 '/^\[Service\]/a StandardOutput=file:/tmp/x'
mutate D11 '/^\[Service\]/a User=root'
mutate D12 '$a Alias=passwsync.service'
if [ -f "$M" ]; then
    { cat "$M"; printf 'LimitNOFILE=1\n'; } >"$w/m.conf"
    dropin_ok "$w/m.conf" && t_fail "drop-in mutant detected (extra limit)" || t_pass "drop-in mutant detected (extra limit)"
    sed 's/256M/infinity/' "$M" >"$w/m.conf"
    dropin_ok "$w/m.conf" && t_fail "drop-in mutant detected (value)" || t_pass "drop-in mutant detected (value)"
fi

run_suite
