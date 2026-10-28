# Implementation Plan: AUR Packaging of the Local Service

**Branch**: `feat/006-aur-packaging-service` | **Date**: 2026-10-28 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/006-aur-packaging-service/spec.md`

## Summary

Make `passwsyncd` (002-005) installable from the AUR without changing it. A new `packaging/`
directory holds a source-building `PKGBUILD` (one pinned tag archive, SHA-256, `cargo fetch
--locked` then `--frozen` build/test, fixed release settings and path remapping, stripped, no
debug package), a message-only `passwsync.install`, a hardened **user** unit
`passwsyncd.service` (measured offline exposure **1.1** ≤ 1.5: `PrivateUsers`, strict read-only
system, empty private home with only the two passwsync directories bound in, `AF_INET` +
`AF_NETLINK` only, `@system-service` minus `@privileged @resources`, no capabilities,
256 MiB memlock, no core dumps, bounded restart excluding exit 2/3/4), a `user@.service` drop-in
raising only the user manager's memlock limit to 256 MiB, a desktop entry and a POSIX `sh`
launcher `passwsync-open` that starts (never enables) the unit, validates the launch file and
hands the address only to `xdg-open`. One offline entry point, `packaging/verify.sh`, runs
recipe/package lint, unit verify + security, directive checks, confinement probes under the user manager, desktop validation, shell test
suites (launcher with stubbed `systemctl`/`xdg-open`, install hooks in a sandboxed stand-in
home), checksum-tamper and lock-mismatch builds, and a three-build reproducibility comparison
inside a network-less namespace. **No Rust code changes, no new crate.**

## Technical Context

**Language/Version**: bash (PKGBUILD, `.install`, verification), POSIX `sh` (launcher), systemd
unit syntax (systemd ≥ 256; planned against 262), freedesktop Desktop Entry 1.5; the packaged
service is the existing Rust workspace (stable, edition 2024, MSRV 1.85)

**Primary Dependencies**: runtime `glibc`, `gcc-libs`, `systemd`, `xdg-utils`, optional
`libnotify`; build `cargo` (Arch `rust` or `rustup`); verification `makepkg` (pacman),
`namcap`, `systemd-analyze`, `desktop-file-validate`, `bsdtar`, `unshare` (util-linux),
optional `shellcheck`. No new Rust crate, `Cargo.lock` unchanged.

**Storage**: N/A (the package owns no user data; data-model §4 lists what it must not touch)

**Testing**: shell test suites under `packaging/tests/` driven by `packaging/verify.sh`
(stubs on `PATH`, stand-in homes, snapshot diffs; the one exception is `confinement_probe.sh`,
which runs the unit's sandbox through the real user manager); existing `cargo test --frozen --workspace`
runs in `check()`. TDD: each suite is written first against an empty/absent artifact and must
fail (Red) before the artifact is written.

**Target Platform**: Arch Linux x86_64 with systemd user manager, cgroup v2, unprivileged user
namespaces

**Project Type**: distribution packaging for an existing local service

**Performance Goals**: launcher opens the UI ≤ 10 s after a cold start (spec US3); full
`verify.sh` dominated by three release builds (minutes); `--skip-build` < 30 s

**Constraints**: offline verification (no network after `--fetch`); exposure ≤ 1.5; package
never enables/starts/stops services, never touches home directories, never writes config;
binary bit-identical across build directories; package identical for same build path

**Scale/Scope**: 7 installed files, 3 AUR files, 1 entry point, 12 test scripts plus the helper `lib.sh`

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment (pre-design) | Post-design |
|-----------|-------------------------|-------------|
| I. Security-First | Adds defense in depth only; never relaxes 002 protections (service still self-checks memlock/core/dumpable, exit 3). Supply chain: one pinned archive, SHA-256, `--locked`/`--frozen`, no `-git`, no prebuilt. Launch token handed only to the opener; opener output discarded; never logged. Networking never enabled by the package. | PASS. Exposure measured 1.1. Accepted residuals (network access, `AF_INET`, netlink, no IP allow-list in user manager, full `/proc` subset for peer-UID check) each justified in research R8/R10. Unsandboxed `+` pre-step limited to an env check and `mkdir -p` of the passwsync dirs (R11). |
| II. Simplicity | Plain files + shell; no packaging framework, no extra crates, no Rust subcommand. | PASS. One unit, one drop-in, one launcher script; verification is one script plus focused test scripts. |
| III. TDD (non-negotiable) | Every testable artifact has a test written first: directive check (D1-D12), launcher matrix (L1-L13), install hooks, package contents, reproducibility. Rust untouched; its suite runs in `check()`. | PASS. Contracts define the test matrices; tasks will order tests before artifacts. |
| IV. Hexagonal | No domain code touched; packaging is an outer adapter around the binary. | PASS (N/A). |
| V. Resource Efficiency | Fat LTO + codegen-units=1 + stripped: smaller binary means fewer pages pinned by `mlockall`. No extra resident process (launcher exits). | PASS. |
| VI. Decentralization | Nothing added that needs a server; AUR is only the distribution channel. | PASS. |
| Workflow gates | Dependencies minimal: none added to the Rust tree; verification tools are developer-only. | PASS. |

No violations; Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/006-aur-packaging-service/
├── plan.md              # This file
├── research.md          # Phase 0: R1-R17 decisions (with measured systemd-analyze results)
├── data-model.md        # Phase 1: file/artifact inventory, relationships, protected data
├── quickstart.md        # Phase 1: validation guide incl. manual on-host checks (FR-026)
├── contracts/
│   ├── unit-file.md     # passwsyncd.service + user@.service drop-in, directive rules D1-D12
│   ├── pkgbuild.md      # PKGBUILD, .SRCINFO, .install, exact package file list
│   ├── launcher.md      # passwsync-open algorithm, errors, test matrix; desktop entry
│   └── verify.md        # verify.sh CLI, checks, exit codes, work layout
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks; not created here)
```

### Source Code (repository root)

```text
packaging/
├── PKGBUILD                 # AUR recipe (copied to AUR repo)
├── .SRCINFO                 # makepkg --printsrcinfo output (copied to AUR repo)
├── passwsync.install        # printf-only hooks (copied to AUR repo)
├── passwsyncd.service       # → /usr/lib/systemd/user/
├── passwsync-memlock.conf   # → /usr/lib/systemd/system/user@.service.d/
├── passwsync.desktop        # → /usr/share/applications/
├── passwsync-open           # → /usr/bin/ (POSIX sh)
├── README.md                # → /usr/share/doc/passwsync/ (usage, XDG override, lint notes, manual checks)
├── verify.sh                # offline verification entry point
└── tests/
    ├── lib.sh                # assert helpers, snapshot(), make_stub(), make_archive()
    ├── lib_selftest.sh       # self-test of lib.sh
    ├── verify_cli.sh         # verify.sh arguments, exit codes, output, token hygiene
    ├── recipe_fields.sh      # PKGBUILD fields, check() skip list vs #[ignore] set
    ├── recipe_integrity.sh   # checksum-tamper, lock-mismatch (no compile)
    ├── srcinfo.sh            # .SRCINFO equals makepkg --printsrcinfo
    ├── unit_directives.sh    # D1-D12 + drop-in exact content
    ├── confinement_probe.sh  # P1-P5 under systemd-run --user (FR-012)
    ├── no_config_writes.sh   # SC-005 static guard + mutation self-test
    ├── launcher.sh           # L1-L13 with stubbed systemctl/xdg-open/notify-send/id
    ├── desktop_entry.sh      # desktop-file-validate and forbidden keys
    ├── install_script.sh     # hooks in sandboxed stand-in home, phrase checks
    ├── package_contents.sh   # exact file list, modes, .INSTALL identity
    └── reproducible.sh       # tamper, lock-mismatch, builds A/B/C, hostile-env build B
README.md                    # + short "Install on Arch Linux" section pointing to packaging/README.md
docs/roadmap.md              # 006 status updated after implementation
```

No change under `crates/`; `Cargo.toml`/`Cargo.lock` unchanged.

**Structure Decision**: a single top-level `packaging/` directory holds every packaging source
and its tests, because the installed files must come from the checksummed release archive
(R1) and only three of them are copied to the AUR repository. Tests are shell scripts (the
artifacts are shell/unit files; no test-only crate, per "no new crates unless essential").

## Design Decisions (summary; details in research.md)

1. **Memlock**: drop-in `LimitMEMLOCK=256M` for `user@.service` + unit `LimitMEMLOCK=256M`;
   effective after re-login; until then exit 3, not restarted (R7).
2. **Home view**: `ProtectHome=tmpfs` + `BindPaths` of exactly the two default passwsync dirs;
   an unsandboxed pre-step refuses custom XDG dirs (exit 2, no fallback) and `mkdir -p -m 0700`
   creates missing dirs; a sandboxed `findmnt` probe makes the unit fail if the namespace was
   not applied; the probe uses `findmnt --target` because `ProtectHome=tmpfs` mounts on `/home`
   (measured, R11). Offline FR-012 coverage: `confinement-probe` runs the sandbox through
   `systemd-run --user` (P1-P5, verify.md) and the regression map ties every directive to a check.
3. **Syscalls/sockets**: `@system-service` − `@privileged @resources` (rustix uses
   `prlimit64`), kill on violation; `AF_INET AF_NETLINK` only; no `ProcSubset=pid` because of
   `/proc/net/tcp` (R9, R10).
4. **Restart**: `on-failure`, never for 2/3/4, 5 s delay, ≤ 5 starts/5 min, SIGTERM,
   15 s stop timeout (R12).
5. **Recipe**: one source, SHA-256 (placeholder of the previous release in-repo; rewritten only
   in temp copies by verification), `RUSTUP_TOOLCHAIN=stable`, replaced `RUSTFLAGS` with
   `--remap-path-prefix`, `CARGO_PROFILE_RELEASE_*` env (highest precedence), `--frozen`,
   `!debug !lto`, check runs the whole workspace suite (R2, R4-R6).
6. **Launcher**: POSIX sh; start-not-enable; 10 s poll; `stat`-based no-follow ownership/mode
   check; exact regex + exact size; `xdg-open` with all output to `/dev/null`; fixed,
   token-free messages on stderr + optional `notify-send`; exit 0/1/2/3 (R13).
7. **Install hooks**: `printf` builtins only, proven with an empty-PATH stub sandbox (R15).
8. **Verification**: `verify.sh` exit 0 only when everything passed; 2 = incomplete
   (missing tool or `--skip-build`); builds in `unshare --user --map-current-user --net` with a
   dedicated pre-fetched `CARGO_HOME`, fixed `SOURCE_DATE_EPOCH`/`PACKAGER`/locale (R3, R16).
9. **Daemon**: unchanged (R17).

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| `namcap` (and `shellcheck`) not installed on the dev host | `verify.sh` reports `MISSING` and exits 2, never 0; quickstart lists the install command |
| fakeroot or makepkg misbehaves inside `unshare --net` | `build` check FAILs (no silent fallback); if it happens, fall back is to document and run makepkg with `--frozen` + `CARGO_NET_OFFLINE=true` only, recorded as a spec deviation |
| Binaries differ between build dirs despite remapping (e.g. metadata hash) | `repro-dirs` catches it; investigate with `diffoscope`; options: add `--remap-path-prefix` for `$startdir`, set `CARGO_ENCODED_RUSTFLAGS`, or build through a fixed symlinked path |
| A dependency calls a syscall outside the filter → SIGSYS | manual check M3/M7/M9; fix by adding the single named call with justification |
| `PrivateUsers` changes `/proc/net/tcp` UIDs unexpectedly | manual checks M6/M8 (UI works for the person, refused for others) |
| Admin already raised memlock higher; drop-in lowers it | README documents adding a later-sorting drop-in |
| `ExecStartPre` failures are retried despite `RestartPreventExitStatus` | bounded by start limit (5 in 5 min); documented |

## Complexity Tracking

None.
