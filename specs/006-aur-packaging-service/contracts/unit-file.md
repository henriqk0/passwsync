# Contract: `passwsyncd.service` (user unit) and `passwsync-memlock.conf` (manager drop-in)

Normative for `packaging/passwsyncd.service`, `packaging/passwsync-memlock.conf` and the
directive check `packaging/tests/unit_directives.sh`. Rationale: [research.md](../research.md)
R7-R12.

## Installed paths

| Source | Installed as | Mode |
|--------|--------------|------|
| `packaging/passwsyncd.service` | `/usr/lib/systemd/user/passwsyncd.service` | 0644 |
| `packaging/passwsync-memlock.conf` | `/usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf` | 0644 |

No system unit, no socket unit, no timer, no `[Install]` alias.

## `passwsyncd.service` (reference content)

```ini
[Unit]
Description=passwsync local password service (loopback web UI)
Documentation=file:/usr/share/doc/passwsync/README.md
StartLimitIntervalSec=5min
StartLimitBurst=5

[Service]
Type=exec
ExecStartPre=+/usr/bin/sh -c 'if [ "$${XDG_CONFIG_HOME:-$$HOME/.config}" != "$$HOME/.config" ] || [ "$${XDG_DATA_HOME:-$$HOME/.local/share}" != "$$HOME/.local/share" ]; then echo "path: custom XDG_CONFIG_HOME/XDG_DATA_HOME need a unit override, see /usr/share/doc/passwsync/README.md" >&2; exit 2; fi; exec /usr/bin/mkdir -p -m 0700 "$$HOME/.config/passwsync" "$$HOME/.local/share/passwsync" "$$XDG_RUNTIME_DIR/passwsync"'
ExecStartPre=/usr/bin/findmnt --noheadings --output TARGET --target %h --types tmpfs
ExecStart=/usr/bin/passwsyncd
Restart=on-failure
RestartPreventExitStatus=2 3 4
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=15s

# Limits (FR-007); the service still checks them itself and fails closed (exit 3).
LimitMEMLOCK=256M
LimitCORE=0
UMask=0077

# No privileges (FR-008)
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# File system, devices, kernel (FR-009, FR-011)
PrivateUsers=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
PrivatePIDs=yes
ProtectSystem=strict
ProtectHome=tmpfs
BindPaths=%h/.config/passwsync %h/.local/share/passwsync %t/passwsync
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
KeyringMode=private
RestrictNamespaces=yes

# Sockets (FR-010): IPv4 for the loopback UI and, when the person enables it, the LAN
# listener/discovery; netlink for interface listing. No AF_UNIX, no AF_INET6.
RestrictAddressFamilies=AF_INET AF_NETLINK

[Install]
WantedBy=default.target
```

Comments may differ; directives and values are normative.

## Implementation corrections (006 implement, 2026-10-28, measured on systemd 262)

- `ReadWritePaths=%t/passwsync` replaced by a third `BindPaths=` entry: `ProtectHome=tmpfs` also
  hides `/run/user`, so the read-write grant cannot be resolved inside the namespace and the unit
  fails with status 226/NAMESPACE (`/run/user/<uid>/passwsync: No such file or directory`).
- `PrivatePIDs=yes` added (systemd >= 257): without a PID namespace the user manager cannot
  mount a fresh `/proc`, so `ProtectProc=invisible` silently had no effect (every host PID was
  visible). With it, `/proc` is mounted `hidepid=invisible` and only the service is visible.
  Offline exposure stays 1.1.

## Directive check (FR-024, SC-002)

`unit_directives.sh` parses the unit (after stripping comments and blank lines) and fails
unless:

| Rule | Requirement |
|------|-------------|
| D1 | `ExecStart=/usr/bin/passwsyncd` exactly (absolute path, no arguments), exactly one `ExecStart=` |
| D2 | `Type=exec` |
| D3 | `LimitMEMLOCK=256M`, `LimitCORE=0`, `UMask=0077` |
| D4 | `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `AmbientCapabilities=` (empty), `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native` |
| D5 | `SystemCallFilter=` lines are exactly `@system-service` then `~@privileged @resources` |
| D6 | `PrivateUsers=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateIPC=yes`, `PrivatePIDs=yes`, `ProtectSystem=strict`, `ProtectHome=tmpfs`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `KeyringMode=private`, `RestrictNamespaces=yes` |
| D7 | `BindPaths=%h/.config/passwsync %h/.local/share/passwsync %t/passwsync` is the only write grant (no other `BindPaths`, no `ReadWritePaths`, `*Directory=`, `TemporaryFileSystem=`) |
| D8 | `RestrictAddressFamilies=AF_INET AF_NETLINK` exactly; no `ProcSubset=` (peer-UID check) |
| D9 | `Restart=on-failure`, `RestartPreventExitStatus=2 3 4`, `RestartSec` ≥ 5 s, `StartLimitIntervalSec=5min`, `StartLimitBurst=5`, `KillSignal=SIGTERM`, `TimeoutStopSec` ≥ 10 s |
| D10 | exactly the two `ExecStartPre=` lines above, in that order (first prefixed `+`, second unprefixed) |
| D11 | forbidden anywhere: `User=`, `Group=`, `ListenStream`, `ListenDatagram`, `Sockets=`, `Environment=`, `EnvironmentFile=`, `PassEnvironment=`, `StandardOutput=`, `StandardError=`, `LogLevelMax=`, `IPAddressAllow=`, `IPAddressDeny=`, `AmbientCapabilities=` with a value, `SystemCallErrorNumber=` |
| D12 | `[Install]` has only `WantedBy=default.target` |

Restart scope (FR-013): `RestartPreventExitStatus` covers the main process only. A failing
`ExecStartPre=` (the custom-XDG refusal, the findmnt probe, the `mkdir`) is retried under
`StartLimitBurst=5` / `StartLimitIntervalSec=5min` and then stops; this is the accepted
behaviour, not a bypass of the exit 2/3/4 rule.

## Confinement regression map (FR-012)

Every confinement directive, the 002-005 behaviour it could affect, and the check that covers
it. "probe" is `tests/confinement_probe.sh` (runs under `systemd-run --user`, see
[verify.md](verify.md)); "M" is a manual check in [quickstart.md](../quickstart.md).

| Directive(s) | Could affect | Covered by |
|--------------|--------------|------------|
| `LimitMEMLOCK`, `LimitCORE`, `UMask` | 002 FR-028..031 protections (exit 3 path), owner-only files | D3; M2 |
| `NoNewPrivileges`, empty capability sets, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`, `SystemCallArchitectures` | service start and runtime | D4; M3 |
| `SystemCallFilter` (`@system-service` minus `@privileged @resources`) | any syscall the service uses (`mlockall`, `prlimit64`, clock, threads, sockets); a violation is SIGSYS | D5; probe P3; M3, M7, M9 |
| `PrivateUsers` | 002 FR-007a peer-UID check (UIDs in `/proc/net/tcp`) | D6; probe P2; M8 |
| `PrivateTmp`, `PrivateIPC`, `PrivatePIDs`, `PrivateDevices`, `KeyringMode`, `RestrictNamespaces` | start-up and runtime (no service use of these resources) | D6; M3 |
| `ProtectSystem=strict`, `ProtectHome=tmpfs`, `BindPaths` | first-run directory creation (FR-011), wallet and sync/share files (002-005) | D7; probe P1, P4; M3, M5 |
| `ProtectProc=invisible` (no `ProcSubset=`), `PrivatePIDs=yes` | peer-UID check reads `/proc/net/tcp`; service runs as PID 1 of its namespace (has SIGTERM/SIGINT/SIGHUP handlers, no children) | D6, D8; probe P2; M2 (stop) |
| `ProtectKernel*`, `ProtectControlGroups`, `ProtectHostname`, `ProtectClock` | suspend detection (002 FR-020a) reads the wall and monotonic clocks only (no D-Bus, no sysfs writes); clock writes are denied | D6; M7 |
| `RestrictAddressFamilies=AF_INET AF_NETLINK` | loopback UI, LAN listener and discovery (003-005), interface listing (`getifaddrs`) | D8; probe P5 (netlink); M3 (loopback bind, not automatable without a listener tool), M9 (LAN listener) |
| `Restart*`, `KillSignal`, `TimeoutStopSec` | shutdown locks every wallet (002), restart policy | D9; M2 and the stop row of the table below |
| `ExecStartPre` (sandboxed probe, unsandboxed `+` step) | first-run creation, custom-XDG refusal, fail-closed sandbox | D10; probe P1; M3, M10 |

## Analysis gates

- `systemd-analyze --user verify <copy>` exits 0 (copy has `ExecStart=` pointing at an
  existing binary; research R16).
- `systemd-analyze --user security --offline=yes --threshold=15 <unit>` exits 0 and the
  printed overall exposure is ≤ 1.5 (planned value 1.1).

## `passwsync-memlock.conf`

Exact content (comments allowed only as `#` lines before `[Service]`):

```ini
# passwsync: let each user's systemd manager grant passwsyncd.service its 256 MiB
# locked-memory limit. Raises no other limit and grants no capability.
[Service]
LimitMEMLOCK=256M
```

Check: after removing comment/blank lines the file is exactly the two lines
`[Service]` and `LimitMEMLOCK=256M`.

## Behaviour guarantees (manual on-host checks, FR-026)

| Situation | Expected |
|-----------|----------|
| no re-login since install | unit fails, `status=3`, log `protection failed: memlock-limit`, not restarted |
| fresh account, after re-login, `systemctl --user start passwsyncd` | dirs created 0700, `ss -tlnp` shows only `127.0.0.1:27471` |
| `XDG_DATA_HOME=/elsewhere` in the manager environment | unit fails with the `path:` message |
| manual instance already running | unit exits 4, not restarted |
| networking on in config | `0.0.0.0:27472/tcp` and `0.0.0.0:27473/udp` listen; pairing and sync work |
| other OS user connects to `127.0.0.1:27471` | refused (peer-UID check under `PrivateUsers=yes`) |
| `find /proc/$(systemctl --user show -p MainPID --value passwsyncd)/root$HOME -maxdepth 3` | only `.config/passwsync`, `.local/share/passwsync` (and their parents) |
| stop | `stopping` logged, all wallets locked, exit 0 within 15 s |
