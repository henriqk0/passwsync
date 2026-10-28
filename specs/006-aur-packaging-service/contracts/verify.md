# Contract: offline verification entry point `packaging/verify.sh`

Normative for `packaging/verify.sh` and `packaging/tests/*`. Rationale:
[research.md](../research.md) R3, R4, R16. Implements FR-024, FR-025, SC-001 to SC-006.

## Command line

```text
packaging/verify.sh               # run every check (from the repository root)
packaging/verify.sh --skip-build  # static checks and script tests only; never exits 0
packaging/verify.sh --fetch       # one-time: fill the dependency cache (uses the network), then exit
```

Any other argument → usage, exit 64.

## Environment

| Variable | Default | Use |
|----------|---------|-----|
| `PASSWSYNC_VERIFY_CACHE` | `${XDG_CACHE_HOME:-$HOME/.cache}/passwsync-verify` | holds `cargo/` (the `CARGO_HOME` for every build) |
| `TMPDIR` | `/tmp` | work directories (`mktemp -d`), removed on exit |

All builds run with `CARGO_HOME=$PASSWSYNC_VERIFY_CACHE/cargo`, `CARGO_NET_OFFLINE=true`,
`SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)`, `PACKAGER='passwsync verify <verify@invalid>'`,
`LC_ALL=C`, `TZ=UTC`, a fresh `makepkg` config is not required (the recipe overrides the Rust
settings itself), and inside `unshare --user --map-current-user --net` (no network).

Implementation note (2026-10-28): a bare `unshare --user --map-current-user --net` leaves the
loopback interface down, so the workspace test suite in `check()` cannot bind `127.0.0.1`.
Builds therefore run through `tests/lib.sh offline`: an outer `unshare --user --map-root-user
--net` only runs `ip link set lo up`, then an inner `unshare --user --map-user=<uid>
--map-group=<gid>` runs makepkg as the caller (not root). The namespace still has no route
out (only `lo`). `PASSWSYNC_VERIFY_SELFTEST=missing|fail` (test hook for `tests/verify_cli.sh`)
runs one synthetic check that can only end MISSING or FAIL; `PASSWSYNC_VERIFY_LOGDIR` keeps
per-check logs.

## Output

One line per check, in this order, then a summary line:

```text
PASS recipe-syntax
PASS srcinfo
MISSING namcap-recipe: namcap not installed (pacman -S namcap)
PASS unit-verify
PASS unit-security exposure=1.1
...
SUMMARY pass=14 fail=0 missing=1 skip=1
```

Status words: `PASS`, `FAIL <id>: <reason>`, `MISSING <id>: <tool>`, `SKIP <id>: <reason>`.
Output never contains a launch token (tests use random tokens and assert this).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | every required check PASS |
| 1 | at least one FAIL |
| 2 | no FAIL, but a required tool was MISSING or `--skip-build` was used |
| 64 | usage error |

## Checks

| Id | Required tool | Pass condition | Covers |
|----|---------------|----------------|--------|
| `recipe-syntax` | bash | `bash -n packaging/PKGBUILD packaging/passwsync.install`; `sh -n packaging/passwsync-open` | FR-024 |
| `srcinfo` | makepkg | `makepkg --printsrcinfo` (in a copy) equals `packaging/.SRCINFO` | FR-001 |
| `recipe-fields` | — | one `source` entry with the tag URL; one 64-hex `sha256sums`; no `SKIP`, no `git+`, no `pkgver()`; `options` has `!debug`; the `check()` comment names exactly the `#[ignore]`d tests found by `grep -rn '#\[ignore' crates` plus the memlock self-skip test (FR-005) | FR-001, FR-002, FR-004, FR-005 |
| `namcap-recipe` | namcap | no `E:`; every `W:` tag listed in README "Lint notes" | US1-1 |
| `shellcheck` | shellcheck (optional: SKIP if absent) | `shellcheck -s sh passwsync-open`, `-s bash` for the rest | quality |
| `unit-verify` | systemd-analyze | `--user verify` on a copy with `ExecStart` → built binary (or `/usr/bin/true` with `--skip-build`) | FR-024 |
| `unit-security` | systemd-analyze | `--user security --offline=yes --threshold=15` exits 0; prints exposure | SC-002 |
| `unit-directives` | — | `tests/unit_directives.sh` (rules D1-D12, drop-in exact content) | FR-007-FR-011, FR-013 |
| `desktop-validate` | desktop-file-validate | no output, exit 0, plus forbidden-key checks | FR-020 |
| `launcher-tests` | — | `tests/launcher.sh` L1-L13 | FR-021-FR-023, SC-006 |
| `install-tests` | — | `tests/install_script.sh` | FR-016-FR-019, SC-004 |
| `no-config-writes` | — | no packaging file contains a write to a `passwsync/config` path or a networking key; the check's own mutation self-test (an injected write must be detected) passes | SC-005 |
| `confinement-probe` | systemd-run (user manager, unprivileged user namespaces), iproute2 (`ss`) | `tests/confinement_probe.sh`: the unit's `[Service]` sandbox directives (same-path binds) are applied via `systemd-run --user --pipe --wait` to a stand-in command (no memlock); the two passwsync directories are created only if absent and removed only if the probe created them; nothing is written into them; probes P1-P5 all pass (below) | FR-012, SC-008 (automated part) |
| `checksum-tamper` | makepkg | a recipe copy with a local archive whose byte differs from the pinned sum: makepkg fails during source verification and `src/` contains no `target/` | US1-2 |
| `lock-mismatch` | makepkg | an archive whose `Cargo.lock` disagrees with a manifest: `prepare()`/`build()` fail (`--locked`/`--frozen`) | US1-3 |
| `build` | makepkg, unshare | build A (with `check()`) succeeds offline | US1, FR-003, FR-005 |
| `namcap-package` | namcap | no `E:`; every `W:` justified | US1-4 |
| `package-contents` | bsdtar | `tests/package_contents.sh` (exact file list, modes, `.INSTALL`) | FR-015 |
| `binary-paths` | — | `grep -aF` finds neither the build directory, the `srcdir`, the cache path nor `$HOME` in the binary | US5-3 |
| `repro-dirs` | makepkg, unshare | builds B in a different directory (`--nocheck`) with a hostile builder environment (`RUSTFLAGS=-g`, `CFLAGS=-O0 -g`, `CARGO_PROFILE_RELEASE_LTO=false`, `CARGO_PROFILE_RELEASE_DEBUG=2`, `CARGO_PROFILE_RELEASE_STRIP=none`): `sha256(passwsyncd)` A = B | FR-025a, edge "modified global build configuration" |
| `repro-package` | makepkg, unshare | build C from a second fresh copy of the inputs in A's directory path, ≥ 1 s later (`--nocheck`): `sha256(package)` A = C | FR-025b |

With `--skip-build`, the checks from `checksum-tamper` onward are `SKIP` (exit 2 at best).
`checksum-tamper` and `lock-mismatch` stop before compilation and are cheap; the three full
builds dominate the run time.

## Confinement probes (`confinement-probe`, FR-012)

`tests/confinement_probe.sh` reads the `[Service]` directives of `packaging/passwsyncd.service`
(except `ExecStart*`, `Restart*`, `Limit*`, `Kill*`, `TimeoutStopSec`, `UMask`) and runs a
stand-in with them through `systemd-run --user --pipe --wait`. `BindPaths`
keeps the unit's same-path form (`%h/.config/passwsync`, `%h/.local/share/passwsync`,
`%t/passwsync`); the stand-in runs with `--expand-environment=no`. Mutation self-check: `ProtectHome=read-only` fails P1, `ProcSubset=pid` and a copy without `PrivatePIDs=yes` fail P2. Measured on systemd 262 (planning host, 2026-10-28): the same-path form with the
full directive set exits 0; a source under `$HOME` fails with status 226 under
`ProtectHome=tmpfs`, and a source under `/tmp` fails under `PrivateTmp=yes`, so the probe cannot
use a separate source directory.

Side effect, by design: the probe creates the two passwsync directories with mode 0700 if they
are absent (what the unit's own pre-start step does) and removes, with empty-directory removal,
only the ones it created. It never writes into them: P4 uses access checks (`test -w`), not
writes. Each probe prints `ok P<n>` or `not ok P<n>`:

| Probe | Inside the sandbox | Covers |
|-------|--------------------|--------|
| P1 | `findmnt --target $HOME --types tmpfs` exits 0, and `ls -A $HOME` lists only `.config` and `.local` (the parents of the bound directories) | ProtectHome=tmpfs view (unit `ExecStartPre` probe) |
| P2 | `/proc/net/tcp` is readable and no `/proc/<pid>` other than the probe's own is listed | peer-UID input (`ProtectProc`, no `ProcSubset`) |
| P3 | the stand-in runs to completion (`ulimit -a`, `ls`, `ss`) with no SIGSYS | `SystemCallFilter` covers what the shell and tools call |
| P4 | `test -w` is true for the three bound dirs and false for `$HOME`, `/usr` and `/etc` | `BindPaths`, `ProtectSystem=strict` |
| P5 | `ss -4 -tln` exits 0 (opens an `AF_NETLINK` socket; `ip` is not usable because iproute2's `ip` calls `capset()`, denied by `~@privileged`, measured) | `RestrictAddressFamilies` allows netlink interface listing |

`ulimit -l` is not asserted (the user manager cannot grant 256 MiB; the memlock check is D3 and
manual M2). Requires `systemd-run` (systemd) and `ip` (iproute2). If `systemd-run --user` cannot
run, the check prints `MISSING confinement-probe: systemd user manager unavailable` and the entry
point exits 2.

## Work layout (per run)

```text
$TMPDIR/passwsync-verify.XXXX/
├── archive/passwsync-<ver>.tar.gz   # R3, built once
├── a/  b/                           # start dirs: PKGBUILD copy (local sha256), .install, archive
└── out/{a,b,c}/                     # PKGDEST per build
```

Build C reuses path `…/a/` after it is deleted and recreated from a fresh copy.
