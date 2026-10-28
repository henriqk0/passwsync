# Tasks: AUR Packaging of the Local Service

**Input**: Design documents from `/specs/006-aur-packaging-service/`
**Prerequisites**: plan.md, spec.md (US1-US5, FR-001..FR-027, SC-001..SC-008), research.md (R1-R17), data-model.md, contracts/ (unit-file.md, pkgbuild.md, launcher.md, verify.md), quickstart.md
**Tests**: MANDATORY (Constitution III, TDD). Every artifact is preceded by a shell test task that MUST be run and seen to FAIL (red) against the absent/empty artifact before the artifact task starts. Refactor with tests green. A test task and its artifact task never run in parallel.
**Organization**: By user story. Priority order: US1 build from a verifiable recipe (P1), US2 confined user service (P1), US4 upgrade/removal without data loss (P1), US3 desktop launcher (P2), US5 reproducible build (P2). Spec numbering is kept for labels; the phase order follows priority and dependencies. Test helpers and the `verify.sh` skeleton live in Phase 2.
**Security rules for every task**: no file under `packaging/` writes a passwsync configuration or turns networking on (SC-005); no launch address or token is ever printed, logged, stored or passed anywhere except to `xdg-open` (FR-022); install hooks only `printf` (FR-016); the package never enables, starts or stops a service and never touches a home directory; **no change under `crates/`**, `Cargo.toml` and `Cargo.lock` unchanged, no new crate (FR-027).

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repo root. `PK` = `packaging`, `PT` = `packaging/tests`.
- Test tasks write the test only (red); the next numbered artifact task makes it green. Tests run directly (`bash packaging/tests/<name>.sh`) until `verify.sh` wires them in.
- **(MANUAL)** = needs a real Arch host with a systemd user session, a re-login, a second OS user or a second device. Cannot run in this environment; stays unchecked until a person runs it and records "Not run here" with the automated equivalents.
- **(ENV-BLOCKED)** = automated, but depends on a tool absent from the dev host (`namcap`, optionally `shellcheck`) or on the network (`--fetch`, AUR publish). Write the check so it reports `MISSING` (exit 2, never 0); the task completes only when the tool is installed and the check shows PASS; until then record "Not run here" in `packaging/README.md` "Lint notes".

---

## Phase 1: Setup

- [X] T001 Snapshot the baseline: run `cargo test --frozen --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`; record green and record `sha256sum Cargo.lock` (must be identical at the end, T040) (PR description, no file)
- [X] T002 [P] Record which verification tools exist on this host: `command -v makepkg namcap systemd-analyze desktop-file-validate bsdtar unshare shellcheck fakeroot`; note the missing ones (expected: `namcap`, maybe `shellcheck`) in the PR description; they drive the ENV-BLOCKED flags below
- [X] T003 Create the empty tree `packaging/` and `packaging/tests/` and confirm `git status` shows nothing under `crates/` (no source file is created yet; later tasks add files)

---

## Phase 2: Foundational (blocks all user stories)

- [X] T004 Write `packaging/tests/lib.sh`: helpers `assert_eq`, `assert_contains`, `assert_not_contains`, `assert_exit`, `snapshot DIR` (sorted path, mode, owner, sha256 listing), `make_stub NAME BODY` (executable stub on a private `PATH` that logs argv to a file), `make_archive` (tar.gz of the working tree with `Cargo.lock`, fixed mtime), a `run_suite` counter that prints `ok`/`not ok` per case and exits non-zero on any failure. Add a self-test `packaging/tests/lib_selftest.sh` that must pass; contract: verify.md "Work layout"
- [X] T005a [test] Write failing test `packaging/tests/verify_cli.sh` FIRST (red: `verify.sh` absent): usage exit 64, `--skip-build` never exits 0, a stubbed missing tool gives exit 2, a stubbed failing check gives exit 1, output never contains a random token passed in the environment. T005b (next, never in parallel) writes the skeleton below, which makes it green.
- [X] T005b [skeleton] Write `packaging/verify.sh` skeleton per contracts/verify.md: argument parsing (`--skip-build`, `--fetch`, other -> usage, exit 64), per-check output lines `PASS|FAIL <id>: ..|MISSING <id>: ..|SKIP <id>: ..`, `SUMMARY pass= fail= missing= skip=`, exit codes 0/1/2/64, `mktemp -d` work dir removed on exit, environment (`PASSWSYNC_VERIFY_CACHE`, `CARGO_HOME`, `CARGO_NET_OFFLINE=true`, `SOURCE_DATE_EPOCH`, `PACKAGER`, `LC_ALL=C`, `TZ=UTC`); no checks registered yet. Makes T005a green.
- [ ] T006 [P] (ENV-BLOCKED: network) Implement `verify.sh --fetch` in `packaging/verify.sh`: `cargo fetch --locked` into `$PASSWSYNC_VERIFY_CACHE/cargo` then exit; this is the only network step. Run it once when online and record the result; offline environments record "Not run here"
  - Status 2026-10-28: implemented and run here (network available): `PASS fetch`, cache filled, Cargo.lock unchanged. Left unchecked per the implement instruction for ENV-BLOCKED tasks; can be checked by the reviewer.

**Checkpoint**: helpers and the entry point exist; checks are added one by one in the phases below.

---

## Phase 3: User Story 1 - Build and install from source with a verifiable recipe (P1)

**Goal**: a pinned, checksummed, locked, deterministic source recipe. **Independent test**: recipe-syntax, srcinfo, recipe-fields, checksum-tamper, lock-mismatch pass; full build and package checks land in Phase 7 because they need every installed file.

- [X] T007 [US1] Write failing test `packaging/tests/recipe_fields.sh` (verify.md `recipe-fields`, pkgbuild.md "Metadata"/"Functions"): exactly one `source` entry with the tag URL; exactly one 64-hex `sha256sums` entry; no `SKIP`, no `git+`, no `pkgver()`; `options` contains `!debug` and `!lto`; `prepare()` runs `cargo fetch --locked`; `build()`/`check()` use `--frozen`; `build()` only `-p passwsyncd`; `RUSTUP_TOOLCHAIN=stable`; `RUSTFLAGS` replaced with `--remap-path-prefix` for srcdir/startdir/`$CARGO_HOME`/`$HOME`; `CARGO_PROFILE_RELEASE_*` set (fat LTO, codegen-units=1, strip, panic as per R4-R6); `check()` runs the workspace suite and any skipped test is listed by name with a reason (FR-005); `makedepends` has `cargo`; `depends` per plan; `install=passwsync.install`; `check()` comment names exactly the `#[ignore]`d tests and the memlock self-skip test, compared with `grep -rn '#\[ignore' crates` (FR-005). Red: `PKGBUILD` absent
- [X] T008 [US1] Write failing test `packaging/tests/recipe_integrity.sh` for the two integrity cases (US1 scenarios 2 and 3; verify.md `checksum-tamper`, `lock-mismatch`): (a) a recipe copy with a local archive whose byte differs from the pinned sum makes `makepkg` fail during source verification and `src/` contains no `target/`; (b) an archive whose `Cargo.lock` disagrees with a manifest makes `prepare()`/`build()` fail and `Cargo.lock` is not rewritten; both stop before any compile and run inside `unshare --user --map-current-user --net`. Use `make_archive` and a temp PKGBUILD copy with the local `file://` source and local sum (the repository PKGBUILD is never edited). Red: `PKGBUILD` absent
- [X] T009 [US1] Create `packaging/PKGBUILD` per contracts/pkgbuild.md: `pkgname=passwsync`, `pkgver`, `pkgrel=1`, `arch=(x86_64)`, `license`, one source (tag archive URL), all-zero placeholder `sha256sums` (fails closed, R2), `depends=(glibc gcc-libs systemd xdg-utils)`, `optdepends=('libnotify: desktop notifications from passwsync-open')`, `makedepends=(cargo)`, `options=(!debug !lto)`, `install=passwsync.install`, `prepare()`, `build()`, `check()`, `package()` installing exactly the FR-015 file list (binary 0755, unit/drop-in/desktop 0644, launcher 0755, LICENSE, README.md under `/usr/share/doc/passwsync/`). Makes T007 green; T008 green once the temp-copy flow works
- [X] T010 [US1] Create a placeholder `packaging/passwsync.install` (empty hook functions only) so `makepkg` parses the recipe. Precondition (Constitution III): the red test `packaging/tests/install_script.sh` (T021) is written and seen failing against the absent file before this task; the test file may be written in Phase 3 because it only reads the file. No step before T034 needs a working install file (T007, T008, T011 stop before the package stage). Phase 5 replaces the content test-first
- [X] T011 [US1] Generate `packaging/.SRCINFO` with `makepkg --printsrcinfo` (run from a copy, output copied back); write failing test first in `packaging/tests/srcinfo.sh` (copy PKGBUILD, `makepkg --printsrcinfo`, diff against `packaging/.SRCINFO`), see it fail while `.SRCINFO` is absent, then create the file. Must stay in sync after every PKGBUILD edit (re-run T011's test)
- [X] T012 [US1] Wire `recipe-syntax` (`bash -n packaging/PKGBUILD packaging/passwsync.install`, `sh -n packaging/passwsync-open` skipped until it exists), `srcinfo`, `recipe-fields`, `checksum-tamper`, `lock-mismatch` into `packaging/verify.sh` with the contract ids; re-run `packaging/tests/verify_cli.sh`
- [ ] T013 [P] [US1] (ENV-BLOCKED: `namcap` not installed) Add `namcap-recipe` to `packaging/verify.sh`: `namcap packaging/PKGBUILD` in a copy; no `E:` lines; every `W:` tag must appear in `packaging/README.md` "Lint notes". When `namcap` is absent the check prints `MISSING namcap-recipe: namcap not installed (pacman -S namcap)` and `verify.sh` exits 2. Record "Not run here" in "Lint notes" (T052) until a host with `namcap` runs it
  - Status 2026-10-28: check implemented (`namcap -m`, E: fails, W: tags must be listed in README "Lint notes"); reports `MISSING namcap-recipe` here (namcap not installed). Not run here.
- [ ] T014 [P] [US1] (ENV-BLOCKED: `shellcheck` optional) Add `shellcheck` check to `packaging/verify.sh`: `shellcheck -s bash` for PKGBUILD/install/verify/tests, `-s sh` for `passwsync-open`; reports `SKIP shellcheck: not installed` when absent (not a failure)
  - Status 2026-10-28: check implemented; reports `SKIP shellcheck: not installed (optional)`. Not run here.

**Checkpoint**: US1 recipe checks green offline; full build is Phase 7.

---

## Phase 4: User Story 2 - Run the service confined, networking still off (P1)

**Goal**: hardened user unit + manager memlock drop-in, exposure <= 1.5 (measured 1.1). **Independent test**: `unit-verify`, `unit-security`, `unit-directives` and `confinement-probe` pass.

- [X] T015 [US2] Write failing test `packaging/tests/unit_directives.sh` implementing rules D1-D12 of contracts/unit-file.md exactly (one assertion group per rule): D1 absolute `ExecStart=/usr/bin/passwsyncd`, one only; D2 `Type=exec`; D3 `LimitMEMLOCK=256M`, `LimitCORE=0`, `UMask=0077`; D4 no-privilege directives; D5 `SystemCallFilter` lines exactly `@system-service` then `~@privileged @resources`; D6 private/protect directives incl. `ProtectHome=tmpfs`; D7 `BindPaths`/`ReadWritePaths` are the only write grants; D8 `RestrictAddressFamilies=AF_INET AF_NETLINK` exactly, no `ProcSubset=`; D9 restart policy (`RestartPreventExitStatus=2 3 4`, `RestartSec`>=5, 5 starts/5 min, `KillSignal=SIGTERM`, `TimeoutStopSec`>=10); D10 the two `ExecStartPre=` lines in order (first `+`); D11 forbidden keys (`User=`, `Group=`, `Listen*`, `Sockets=`, `Environment*`, `StandardOutput=`, `StandardError=`, log-level keys, ...); D12 `[Install]` only `WantedBy=default.target`; plus exact content of `passwsync-memlock.conf` (only `[Service]` `LimitMEMLOCK=256M`, nothing else). Mutation self-check: copy the unit, break each rule, assert the test fails. Red: unit absent
- [X] T015a [US2] [P] Write failing test `packaging/tests/confinement_probe.sh` (verify.md "Confinement probes", unit-file.md regression map, FR-012): read the unit's `[Service]` directives unchanged (same-path `BindPaths`/`ReadWritePaths`; a separate source directory is not possible, see verify.md "Confinement probes"), run a stand-in through `systemd-run --user --pipe --wait` and print `ok|not ok P1..P5`; create the two passwsync directories only if absent and remove only the ones it created (empty-directory removal); never write into them (P4 uses `test -w`). Mutation self-check: a copy with `ProtectHome=read-only` must fail P1, a copy with `ProcSubset=pid` must fail P2. Red: unit absent (exit non-zero). This check runs on a host with a working user manager (it works on the planning host), so it is automated, not MANUAL
- [X] T016 [US2] Create `packaging/passwsyncd.service` with the reference content of contracts/unit-file.md (FR-006..FR-011, FR-013, FR-014; `%h`/`%t` specifiers; sandboxed `findmnt` probe pre-step and unsandboxed `+` env check and `mkdir -p -m 0700`, R11). Makes T015 green for the unit
- [X] T017 [US2] Create `packaging/passwsync-memlock.conf` per contracts/unit-file.md (drop-in for `user@.service`, only `LimitMEMLOCK=256M`). Makes the drop-in assertions of T015 green
- [X] T018 [US2] Add `unit-verify`, `unit-security`, `unit-directives` to `packaging/verify.sh`: `systemd-analyze --user verify` on a copy whose `ExecStart` points at the built binary (or `/usr/bin/true` with `--skip-build`), `systemd-analyze --user security --offline=yes --threshold=15` exits 0 and prints `exposure=<x>` (SC-002, expect 1.1), `bash packaging/tests/unit_directives.sh`; `confinement-probe` = `bash packaging/tests/confinement_probe.sh` (T015a; P1-P5; without `systemd-run --user` it prints `MISSING`, exit 2). Missing `systemd-analyze` -> `MISSING`, exit 2. Run and record the measured exposure in `packaging/README.md` (T052)
- [X] T019 [P] [US2] Write failing test `packaging/tests/no_config_writes.sh` (verify.md `no-config-writes`, SC-005, FR-016, FR-027): no packaging file (`PKGBUILD`, `passwsync.install`, `passwsync-open`, unit, drop-in, desktop) contains a write (`>`, `>>`, `tee`, `cp`, `mv`, `sed -i`, `touch`, `install`) to a `passwsync/config` path or any networking key (`networking`, `lan`), and no path in the package list is under `/home` or `/root`; `git diff --stat main -- crates Cargo.toml Cargo.lock` is empty. Add as `no-config-writes` in `packaging/verify.sh`. Red first: a mutation self-test copies each packaging file to a temp directory with an injected `>> ~/.config/passwsync/config` line and an injected `networking = on` line, and asserts the check flags each copy (the check must fail on the mutants before the real files are judged). The real-file pass then guards every later artifact (re-run after each); its git-diff guard runs against `main`
- [ ] T020 [US2] (MANUAL) Confinement checks M2, M3, M4, M5, M7, M8, M9, M10 of `specs/006-aur-packaging-service/quickstart.md` on a real Arch host (memlock exit 3 before re-login without restart loop, loopback-only listening, home view, live exposure, suspend auto-lock, second-user refusal under `PrivateUsers`, networking on with pairing/sync/sharing, custom XDG refused). Record results in the PR; "Not run here" with the automated equivalents T015/T015a/T018 until done (FR-012, SC-008)
  - Status: Not run here (needs a real login session/second user/second device). Automated equivalents green: unit-directives, confinement-probe (P1-P5), unit-security 1.1.

**Checkpoint**: unit and drop-in verified offline; exposure <= 1.5.

---

## Phase 5: User Story 4 - Upgrade and remove without losing wallets (P1)

**Goal**: message-only install hooks. **Independent test**: `install-tests` pass in a sandboxed stand-in home.

- [X] T021 [US4] Write failing test `packaging/tests/install_script.sh` (contracts/pkgbuild.md ".install", FR-016..FR-019, SC-004): source `packaging/passwsync.install` in a sandbox with a stand-in `HOME` populated with passwsync config/data/runtime files and with `PATH` empty except stubs that log any call (`systemctl`, `rm`, `mv`, `cp`, `touch`, `mkdir`, `sed`, `cat`...). For `post_install`, `post_upgrade`, `pre_remove`/`post_remove` (with and without "remove configuration"): exit 0, only `printf` builtin output, zero stub calls (proves builtin-only, R15), `snapshot` of the home identical before/after, never mentions enabling networking automatically. Phrase checks: post-install states networking off by default and enabled only by editing the person's own config file, gives the enable-at-login command and the launcher, says the memory limit applies after next login (FR-017); post-upgrade says restarting applies the new version and locks all wallets (FR-018); post-remove names `~/.config/passwsync`, `~/.local/share/passwsync` and the runtime directory, says they were kept, gives `systemctl --user disable --now passwsyncd.service` (FR-019). Red: placeholder hooks print nothing
- [X] T022 [US4] Write the final `packaging/passwsync.install` (printf-only hooks, no external command, no home access) per contracts/pkgbuild.md. Makes T021 green; re-run T011 `srcinfo` and T019 `no-config-writes`
- [X] T023 [US4] Add `install-tests` to `packaging/verify.sh` (`bash packaging/tests/install_script.sh`)
- [ ] T024 [US4] (MANUAL) On a real Arch host run M1, M11 and M12 from `specs/006-aur-packaging-service/quickstart.md` (install message, nothing enabled; upgrade while running keeps PID and prints the restart message; `pacman -Rns` keeps every passwsync file, sha256 unchanged). "Not run here" until done (SC-004 real-host half)
  - Status: Not run here. Automated equivalent green: install-tests (empty-PATH stubs, home snapshot identical).

**Checkpoint**: US4 offline-complete; pairs with Phase 7 package-contents (no file under `/home`).

---

## Phase 6: User Story 3 - Open the UI from the desktop (P2)

**Goal**: POSIX launcher + desktop entry. **Independent test**: `launcher-tests` L1-L13 and `desktop-validate` pass.

- [X] T025 [US3] Write failing test `packaging/tests/launcher.sh` implementing the matrix L1-L13 of contracts/launcher.md with stubs for `systemctl`, `xdg-open`, `notify-send`, `id` on a private `PATH`, a stand-in `XDG_RUNTIME_DIR` and random tokens: L1 active+valid (one opener call, no `start`); L2 inactive, `start` creates the file after 1 s (one `start passwsyncd.service`, never `enable`); L3 timeout exit 1 after >=10 s and <12 s, message names `systemctl --user status passwsyncd.service`; L4 symlink; L5 modes 0640/0604; L6 other owner; L7 all bad contents (`https://`, `localhost`, uppercase hex, 63 hex, ports 80 and 70000, trailing garbage, two lines, no trailing newline); L8 `start` fails but valid file exists; L9 opener fails and prints the URL: exit 3, launcher stderr lacks the token; L10 `XDG_RUNTIME_DIR` unset/relative and `xdg-open` absent: exit 2; L11 any argument exit 2; L12 no `notify-send`; L13 stand-in home snapshot identical. In every case assert no token/address in launcher stdout/stderr/notify argv or any file (SC-006, FR-022). Red: launcher absent
- [X] T026 [US3] Create `packaging/passwsync-open` (POSIX `sh`, `#!/bin/sh`, mode 0755) following the normative algorithm order, errors and exit codes 0/1/2/3 of contracts/launcher.md (start never enable, 10 s poll, `stat`-based no-follow ownership and mode check, exact regex and exact size, `xdg-open` with all output to `/dev/null`, fixed token-free messages on stderr plus optional `notify-send`). Makes T025 green; `sh -n` passes; re-run T019
- [X] T027 [P] [US3] Write failing test `packaging/tests/desktop_entry.sh` (verify.md `desktop-validate`, FR-020, contracts/launcher.md "passwsync.desktop"): `desktop-file-validate` prints nothing and exits 0; `Exec=passwsync-open`; `Type=Application`; no `X-GNOME-Autostart*`, no `MimeType=`, no `Hidden`/`NoDisplay=true`; no `%u`/`%U`/`%f` field codes. Red: entry absent
- [X] T028 [US3] Create `packaging/passwsync.desktop` per contracts/launcher.md. Makes T027 green
- [X] T029 [US3] Add `launcher-tests` and `desktop-validate` to `packaging/verify.sh`; enable the `sh -n packaging/passwsync-open` part of `recipe-syntax` (T012). Missing `desktop-file-validate` -> `MISSING`, exit 2
- [ ] T030 [US3] (MANUAL) M6 (menu entry with the service stopped opens the UI in under 10 s, `journalctl --user -b | grep -c launch/` is 0) and the "no default browser" edge case on a real Arch host. "Not run here" until done (US3, SC-007)
  - Status: Not run here. Automated equivalent green: launcher-tests L1-L13 (329 assertions), desktop-validate.

**Checkpoint**: launcher and desktop entry verified offline.

---

## Phase 7: User Story 5 - Reproducible build, and package assembly (P2; also closes US1 scenarios 4-5)

**Goal**: build offline, check exact package contents, prove determinism. Needs every installed file from Phases 3-6. **Independent test**: `build`, `package-contents`, `binary-paths`, `repro-dirs`, `repro-package` pass.

- [X] T031 [US1] Write failing test `packaging/tests/package_contents.sh` (verify.md `package-contents`, contracts/pkgbuild.md "Package file list", FR-015): `bsdtar -tvf` of the built package lists exactly `usr/bin/passwsyncd` (0755), `usr/bin/passwsync-open` (0755), `usr/lib/systemd/user/passwsyncd.service` (0644), `usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf` (0644), `usr/share/applications/passwsync.desktop` (0644), `usr/share/licenses/passwsync/LICENSE`, `usr/share/doc/passwsync/README.md`, plus the package metadata files and `.INSTALL` identical to `packaging/passwsync.install`; nothing under `home/`, `root/`, `etc/`, no system service, no `.build`-path leftovers; the binary is stripped (`file` shows stripped) and no `-debug` package exists. Takes the package path as `$1`. Red: no package yet
- [X] T032 [US5] Write failing test `packaging/tests/reproducible.sh` (verify.md, FR-025, SC-003): builds A, B (different start directory, `--nocheck`) and C (A's directory path recreated from a second fresh copy, >= 1 s later, `--nocheck`) inside `unshare --user --map-current-user --net` with the fixed environment of verify.md; asserts `sha256(passwsyncd)` A == B (repro-dirs; build B runs with the hostile builder environment of verify.md, edge case "modified global build configuration") and `sha256(package)` A == C (repro-package); on difference prints both hashes and the hint to run `diffoscope`. Also asserts `binary-paths`: `grep -aF` finds neither the build directory, `srcdir`, the cargo cache path nor `$HOME` in the binary. Red: recipe cannot build offline yet / script lacks the build driver
- [X] T033 [US5] Implement in `packaging/verify.sh` the shared build driver (R3, R16): build the archive once into `$work/archive/passwsync-<ver>.tar.gz` from the git tree with fixed mtimes, copy PKGBUILD/.install/archive into `a/` and `b/` with the local sha256 substituted in the copies only, run `makepkg` per build in `unshare --user --map-current-user --net` with `CARGO_HOME=$PASSWSYNC_VERIFY_CACHE/cargo`, `PKGDEST=out/{a,b,c}`; add checks `build` (A with `check()`, US1 scenario 5: offline), `namcap-package`, `package-contents`, `binary-paths`, `repro-dirs`, `repro-package`. With `--skip-build` every check from `checksum-tamper` onward prints `SKIP` and exit is at best 2. If `fakeroot`/`makepkg` cannot run inside `--net`, the `build` check FAILs (no silent fallback; plan Risks)
- [ ] T034 [US1] Run `bash packaging/verify.sh --fetch` (needs network, T006) then `bash packaging/verify.sh`; fix recipe nondeterminism if `repro-dirs` fails (plan Risks: extra `--remap-path-prefix`, `CARGO_ENCODED_RUSTFLAGS`, fixed symlinked path), re-running T007 and T011 after each PKGBUILD edit. Record `SUMMARY` line in the PR (ENV-BLOCKED if the cache or network is unavailable: record "Not run here")
  - Status 2026-10-28: run here. `--fetch` PASS; full `verify.sh`: `SUMMARY pass=18 fail=0 missing=2 skip=1`, exit 2 (missing = namcap-recipe, namcap-package; skip = shellcheck). build (with check(), 200 test groups ok), package-contents, binary-paths, repro-dirs (binary sha256 5932dbf8...), repro-package (package sha256 9a7bd9a2...) all PASS. Left unchecked per instruction (exit is 2, not 0, until namcap runs).
- [ ] T035 [P] [US1] (ENV-BLOCKED: `namcap` not installed) Run `namcap-package` on the built package: no `E:` lines; every `W:` justified in `packaging/README.md` "Lint notes" (expected: LICENSE installed from the source tree, to be confirmed). Until `namcap` is installed record "Not run here"; `verify.sh` exits 2 meanwhile, never 0 (SC-001 cannot be declared met)
  - Status: check implemented; `MISSING namcap-package` (namcap not installed). Not run here.

**Checkpoint**: full `verify.sh` passes on a host with every tool (exit 0), or exits 2 with named MISSING tools.

---

## Phase 8: Polish and cross-cutting

- [X] T036 Write `packaging/README.md` (installed to `/usr/share/doc/passwsync/`: usage, enabling the service and the launcher, requirement for unprivileged user namespaces, how to override with a later-sorting drop-in if memlock is higher, XDG override limitation (R11), "Lint notes" with every justified `W:` or "Not run here", measured exposure 1.1, the manual checks M1-M12 and SC-007/SC-008, release steps `updpkgsums` / `makepkg --printsrcinfo`, AUR publish is manual). Re-run T011 (no effect) and T019
- [X] T037 [P] Add a short "Install on Arch Linux" section to `README.md` pointing to `packaging/README.md` (no behaviour change)
- [X] T038 [P] Update the 006 status in `docs/roadmap.md` after implementation (honest: manual and ENV-BLOCKED items listed as pending)
- [X] T039 Wire the final check order of verify.md into `packaging/verify.sh` (recipe-syntax, srcinfo, recipe-fields, namcap-recipe, shellcheck, unit-verify, unit-security, unit-directives, desktop-validate, launcher-tests, install-tests, no-config-writes, confinement-probe, checksum-tamper, lock-mismatch, build, namcap-package, package-contents, binary-paths, repro-dirs, repro-package) and re-run `packaging/tests/verify_cli.sh`
- [X] T040 Run `bash packaging/verify.sh --skip-build` (must finish under 30 s, exit 2) and the full `bash packaging/verify.sh`; run `cargo test --frozen --workspace` and clippy; confirm `git diff --stat -- crates Cargo.toml Cargo.lock` is empty and `sha256sum Cargo.lock` equals the T001 value (T040 check)
- [ ] T041 (MANUAL / ENV-BLOCKED: AUR publish) Maintainer release steps from quickstart section 5: tag `v<pkgver>`, copy `PKGBUILD`, `.SRCINFO`, `passwsync.install` to the AUR repo, run `updpkgsums`, regenerate `.SRCINFO`, build once, publish, commit the pinned checksum back. Out of scope for this feature's gate (FR-027); stays unchecked
  - Status: out of scope here (no tag, no AUR publish).
- [ ] T042 (MANUAL) Final on-host walkthrough M1-M12 and SC-007 (built package to working UI in under 3 minutes following only the messages, including one re-login) and SC-008 (confined service starts with networking off); record outcomes in the PR
  - Status: Not run here (real Arch host walkthrough).

---

## Dependencies and execution order

- Phase 1 -> Phase 2 -> user stories. Phase 2: T004 before T005a; T005a before T005b; T006 anytime after T005b. T010 follows the red state of T021 (see T010). T015a is red before T016.
- US1 recipe (Phase 3) and US2 (Phase 4) are independent after Phase 2 and can proceed in parallel (T007-T014 vs T015-T019). US4 (Phase 5) needs T010 (placeholder install file) and T011 sync. US3 (Phase 6) is independent of US2/US4. Phase 7 needs T009, T016, T017, T022, T026, T028 (all installed files). Phase 8 after Phase 7.
- T012, T018, T023, T029, T033, T039 all edit `packaging/verify.sh`: sequential, never parallel.
- Always: test task, see it fail, then artifact task. A test task and its artifact task never run in parallel. After every PKGBUILD or `.install` edit re-run T011 (`srcinfo`) and T019 (`no-config-writes`).

## Parallel opportunities

- Phase 3: T007 and T008 (different test files) together; T013, T014 after T012.
- Phase 4 test T015 with Phase 6 tests T025, T027 and Phase 5 test T021 (different files) once Phase 2 is done.
- T019 in parallel with T015. T037 and T038 in parallel with T036.

## Implementation strategy

- MVP = Phases 1-4 plus Phase 7 build (US1 + US2): a verifiable package that installs a confined service. US4 (message-only hooks, no data loss) MUST ship before any AUR publish. US3 and US5 complete the set.
- At each checkpoint run the relevant suite and, when available, `bash packaging/verify.sh --skip-build`. Never weaken a directive rule (D1-D12) or a launcher case to make a test pass; change the contract first.
- Manual / environment-blocked tasks: T020, T024, T030, T042 (real Arch host), T006, T034 (network for `--fetch`), T013, T035 (`namcap` not installed), T014 (`shellcheck` optional), T041 (AUR publish).

## Verification map

Every row has at least one automated check, except where marked MANUAL-only. `verify.sh` ids in parentheses.

| Requirement | Tasks | Automated check |
|-------------|-------|-----------------|
| FR-001 one tagged source, no VCS/prebuilt | T007, T009 | recipe_fields.sh (recipe-fields), srcinfo.sh |
| FR-002 SHA-256 pin, no SKIP | T007, T008, T009 | recipe_fields.sh, recipe_integrity.sh (checksum-tamper) |
| FR-003 locked deps, offline build | T007, T008, T033 | recipe_fields.sh, recipe_integrity.sh (lock-mismatch), build |
| FR-004 deterministic, stripped, no debug pkg | T007, T031, T032 | recipe_fields.sh, package_contents.sh, reproducible.sh (binary-paths) |
| FR-005 test suite in check(), skipped tests named | T007, T033 | recipe_fields.sh (skip list equals the `#[ignore]` set), build |
| FR-006 user unit, absolute ExecStart | T015, T016 | unit_directives.sh D1-D2 (unit-directives), unit-verify |
| FR-007, FR-007a memlock, core, drop-in | T015, T016, T017 | unit_directives.sh D3 and drop-in exact content |
| FR-008 no privileges, syscall filter | T015, T016 | unit_directives.sh D4-D5, unit-security |
| FR-009 private tmp, strict system, namespaces | T015, T016 | unit_directives.sh D6, unit-security |
| FR-010 sockets AF_INET + AF_NETLINK, no listen sockets | T015, T016 | unit_directives.sh D8, D11 |
| FR-011 empty home, only passwsync dirs, umask | T015, T015a, T016, T020 | unit_directives.sh D3, D6, D7, D10; confinement-probe P1, P4; MANUAL M3, M5 |
| FR-012 no regression 002-005 | T015a, T018, T020, T042 | confinement-probe P1-P5 (home view, /proc/net/tcp, syscalls, writes, netlink); unit-directives D5-D8; regression map in unit-file.md; MANUAL M3, M7-M9 for loopback UI, suspend, networking and sync |
| FR-013 restart policy, SIGTERM, stop timeout | T015, T016, T020 | unit_directives.sh D9; MANUAL M2 |
| FR-014 journal unchanged | T015, T016 | unit_directives.sh D11 (no Standard* keys) |
| FR-015 exact package contents | T009, T031, T033 | package_contents.sh (package-contents) |
| FR-016 hooks only print | T021, T022, T019 | install_script.sh (empty-PATH stubs), no_config_writes.sh |
| FR-017 post-install message | T021, T022 | install_script.sh phrase checks |
| FR-018 upgrade leaves service, message | T021, T022, T024 | install_script.sh; MANUAL M11 |
| FR-019 removal keeps data, message | T021, T022, T024 | install_script.sh snapshot; MANUAL M12 |
| FR-020 desktop entry valid, no autostart/MIME | T027, T028 | desktop_entry.sh (desktop-validate) |
| FR-021 launcher validation and start-not-enable | T025, T026 | launcher.sh L1-L8 (launcher-tests) |
| FR-022 no address/token leaks, messages | T025, T026, T032 | launcher.sh L3, L9, L12; verify_cli.sh token scan |
| FR-023 no config/wallet/password | T025, T026, T019 | launcher.sh L13, no_config_writes.sh |
| FR-024 offline verification entry point | T005, T012, T018, T023, T029, T033, T039 | verify_cli.sh, `verify.sh` run |
| FR-025 reproducibility (a) dirs (b) same path | T032, T033, T034 | reproducible.sh (repro-dirs, repro-package) |
| FR-026 manual checks documented | T036, T020, T024, T030, T042 | README.md content (manual) |
| FR-027 exclusions, no crates change | T003, T019, T040 | no_config_writes.sh git-diff guard, T040 |
| SC-001 verify.sh passes every check | T034, T035, T040 | `verify.sh` exit 0 (needs `namcap`; exit 2 until then) |
| SC-002 exposure <= 1.5 | T018 | unit-security (`--threshold=15`) |
| SC-003 reproducible 100% | T032, T034 | repro-dirs, repro-package |
| SC-004 install tests 100% | T021-T023 | install_script.sh |
| SC-005 no config writes | T019 | no_config_writes.sh |
| SC-006 launcher: one opener call per valid file | T025, T026 | launcher.sh L1, L2, L8 |
| SC-007 package to UI under 3 min | T030, T042 | MANUAL only |
| SC-008 confined service, networking off | T015a, T020, T042 | confinement-probe and unit-directives D8 (automated part); MANUAL M3, M9 (networking on, pair and sync) |
| Edge: old `~/.cargo/bin` install | T015 | unit_directives.sh D1 |
| Edge: manual instance running (exit 4) | T015, T025 | D9 `RestartPreventExitStatus`; launcher.sh L8 |
| Edge: no user namespaces | T036, T020 | README requirement; MANUAL |
| Edge: first start dirs absent | T015, T020 | D10; MANUAL M3 |
| Edge: package removed while enabled | T021, T024 | install_script.sh post-remove message; MANUAL M12 |
| Edge: no default browser | T025, T030 | launcher.sh L9; MANUAL |

Manual / environment-blocked: T006, T013, T014, T020, T024, T030, T034, T035, T041, T042.
