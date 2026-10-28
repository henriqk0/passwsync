# Research: AUR Packaging of the Local Service

Feature: [spec.md](spec.md) | Plan: [plan.md](plan.md)

Non-interactive planning: each decision is the most secure option, then the simplest. All
`systemd-analyze` figures below were **measured** on the planning host (systemd 262, Arch,
rustc 1.99.1) against a draft of the unit in [contracts/unit-file.md](contracts/unit-file.md).

## R1. Where the packaging files live and what goes to the AUR

- **Decision**: All packaging sources live in `packaging/` in this repository. The AUR git
  repository receives only `PKGBUILD`, `.SRCINFO` and `passwsync.install` (makepkg requires the
  install script next to the recipe). Every file installed by the package (unit, drop-in,
  desktop entry, launcher, README) is taken from `packaging/` **inside the checksummed release
  archive**, so the single pinned source (FR-001/FR-002) authenticates them too.
- **Rationale**: one source entry, one checksum, no files that can drift between the AUR
  repository and the tagged release.
- **Alternatives**: shipping unit/launcher as extra local `source=()` entries in the AUR repo
  (more checksums, files not tied to a tag; rejected); a `packaging/arch/` subtree (no other
  distribution is in scope, FR-027; rejected as speculative).

## R2. Source archive and checksum

- **Decision**: `source=("$pkgname-$pkgver.tar.gz::https://github.com/henriqk0/passwsync/archive/refs/tags/v$pkgver.tar.gz")`
  with one `sha256sums` entry. An archive cannot contain its own checksum, so the
  in-repository recipe carries the previous release's value (before the first release: 64
  zeros, which fails closed on any real download); at release the maintainer runs
  `updpkgsums` in the AUR copy and commits the value back after the tag. The offline
  verification never downloads: it produces a local archive with the same name and layout
  (`passwsync-<ver>/…`) and rewrites the checksum **in a temporary copy** of the recipe, so the
  checksum check itself is always exercised (a tampered archive test proves FR-002).
- **Rationale**: SHA-256 is what the spec requires and what `updpkgsums`/namcap expect;
  makepkg looks for a source file of that name in the start directory before downloading, which
  makes offline builds possible without touching the recipe logic.
- **Alternatives**: `b2sums` (equally strong, less familiar to AUR reviewers); `-git` package
  (forbidden); `SKIP` (forbidden).

## R3. Local release archive for offline verification

- **Decision**: `packaging/tests/lib.sh` builds the archive from the working tree:
  `git ls-files -z --cached --others --exclude-standard` → `tar --null -T - --sort=name
  --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner --transform
  's,^,passwsync-<ver>/,'` → `gzip -n -9`. `SOURCE_DATE_EPOCH` = `git log -1 --format=%ct
  HEAD`.
- **Rationale**: includes not-yet-committed files (this project never commits during
  implementation, so `git archive` would miss `packaging/`), excludes `target/` and ignored
  files, and is itself deterministic.
- **Alternatives**: `git archive` (misses untracked files), `git stash create` (misses
  untracked files).

## R4. Locked, offline dependency handling (FR-003)

- **Decision**: Arch Rust package guidelines: `prepare()` runs `cargo fetch --locked --target
  "$(rustc -vV | sed -n 's/host: //p')"`; `build()`/`check()` use `--frozen` (= `--locked
  --offline`). `RUSTUP_TOOLCHAIN=stable` is exported so the repository's
  `rust-toolchain.toml` never makes rustup download components. The verification uses a
  dedicated `CARGO_HOME` cache (`${XDG_CACHE_HOME:-$HOME/.cache}/passwsync-verify/cargo`)
  filled once by `packaging/verify.sh --fetch` (the only step that may use the network), and
  then runs every build with `CARGO_NET_OFFLINE=true` inside a network-less namespace
  (`unshare --user --map-current-user --net`), so "no network in build" is enforced, not
  assumed.
- **Rationale**: `--frozen` fails if `Cargo.lock` would change (acceptance US1-3) and if any
  crate is missing from the cache; the dedicated `CARGO_HOME` also isolates the build from the
  developer's `~/.cargo/config.toml` (edge case "modified global build configuration").
- **Alternatives**: vendoring (`cargo vendor`) into the archive (large, duplicates crates.io
  checksums already in `Cargo.lock`); trusting `--frozen` alone without a net namespace
  (weaker evidence). If `unshare` cannot create the namespace the build check **fails** (no
  silent fallback); risk noted in plan.

## R5. Deterministic build settings (FR-004)

- **Decision**: `build()` sets, overriding (not appending to) the builder's environment:
  - `RUSTFLAGS="--remap-path-prefix=$srcdir=/build --remap-path-prefix=$CARGO_HOME=/cargo"`
    (`CARGO_HOME` defaulted to `$HOME/.cargo` if unset) — strips build-dir and home paths;
    replacing `RUSTFLAGS` also drops makepkg.conf's `-Cforce-frame-pointers`/debug flags;
  - `CARGO_PROFILE_RELEASE_OPT_LEVEL=3`, `…_DEBUG=false`, `…_STRIP=symbols`,
    `…_CODEGEN_UNITS=1`, `…_LTO=true`, `…_PANIC=unwind`, `…_INCREMENTAL=false`,
    `CARGO_INCREMENTAL=0`, `CARGO_TARGET_DIR=target`; env vars have the highest precedence in
    cargo, above any config file `[profile]`;
  - `cargo build --frozen --release -p passwsyncd --bin passwsyncd`;
  - `options=('!debug' '!lto')` (no debug package; makepkg's C LTO flags are irrelevant and
    disabled to keep the environment fixed); makepkg's default `strip` stays on (idempotent on
    an already stripped binary).
- **Rationale**: codegen-units=1 removes partition-order nondeterminism; fat LTO makes the
  binary smaller, which matters because `mlockall` locks every mapped page (Principle V).
  Cargo ≥ 1.85 no longer mixes `RUSTFLAGS` into `-C metadata`, and path dependencies are hashed
  relative to the workspace root, so different build directories produce identical symbols;
  the double-build check (FR-025a) is the proof, not this argument.
- **Source-date value**: nothing in the binary embeds a time; the date only matters for the
  package metadata, which makepkg reads from `SOURCE_DATE_EPOCH` in its own environment (a
  PKGBUILD cannot set it). The verification and reproducible-build rebuilders export
  `SOURCE_DATE_EPOCH` = the archive timestamp (R3); the README documents this for reviewers.
- **Alternatives**: `[profile.release]` in the workspace `Cargo.toml` (would be overridden by a
  builder's config file; rejected as the authority, not needed in addition);
  `-Z trim-paths` (unstable).

## R6. Tests in `check()` (FR-005)

- **Decision**: `cargo test --frozen --workspace` (dev profile; dependencies at opt-level 3 by
  the existing `[profile.dev.package."*"]`). Two groups are not run, and FR-005 requires each
  to be named in the recipe comment with its reason: (a) the 16 `#[ignore]` tests of the
  workspace (release-mode performance and resource measurements, not correctness), listed as
  `crate/file::name` (`grep -rn '#\[ignore' crates` at the time of writing); (b)
  `startup::real_binary_starts_when_the_memlock_limit_allows`, which skips itself when the hard
  memlock limit is below 256 MiB. `recipe-fields` fails if the comment's list differs from the
  `#[ignore]` set found in the tree. The reproducibility builds use `makepkg --nocheck` (tests do not
  affect the package) to keep verification time bounded; one build with `check()` runs.
- **Alternatives**: `--release` tests (slow fat-LTO compile of every test binary; no benefit).
- **Build B environment (edge case "modified global build configuration")**: the `repro-dirs`
  build B runs with a hostile builder environment (`RUSTFLAGS=-g`, `CFLAGS=-O0 -g`,
  `CARGO_PROFILE_RELEASE_LTO=false`, `CARGO_PROFILE_RELEASE_DEBUG=2`,
  `CARGO_PROFILE_RELEASE_STRIP=none`), and its binary must still be bit-identical to build A.

## R7. Per-user memory-lock limit (FR-007, FR-007a)

- **Decision**: `/usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf` containing
  exactly `[Service]` + `LimitMEMLOCK=256M` (sets soft **and** hard). The user unit also sets
  `LimitMEMLOCK=256M`. Effective after the next login (the user manager is started per login
  session and reads its limits at start).
- **Rationale**: the user manager cannot raise a hard limit above its own (8 MiB on Arch), so
  without the drop-in the service always fails closed (exit 3). No capability (no
  `CAP_IPC_LOCK`) is granted; only this one limit changes.
- **Note**: drop-ins are applied in lexical order; an administrator who wants a higher value
  adds a later-sorting drop-in (documented in README).
- **Alternatives**: `/etc/security/limits.d` (PAM, affects all login processes, not the user
  manager on every setup; rejected); `DefaultLimitMEMLOCK=` in `/etc/systemd/user.conf`
  (system configuration file, forbidden by FR-015; also bounded by the manager's hard limit).

## R8. Sandboxing a *user* unit (FR-008 to FR-011)

- **Decision**: rely on `PrivateUsers=yes` (explicit), which lets the user manager build a
  mount namespace from an unprivileged user namespace; then `ProtectSystem=strict`,
  `ProtectHome=tmpfs`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateIPC=yes`, the
  `Protect*` family, `ProtectProc=invisible`, `KeyringMode=private`, `RestrictNamespaces=yes`,
  `NoNewPrivileges=yes`, empty capability sets, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
  `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native`,
  `UMask=0077`.
- **Measured**: `systemd-analyze --user security --offline=yes` → **1.1** with the final draft
  (system-mode analysis of the same file shows 1.6 because it adds the "runs as root" penalty,
  which does not apply to a user unit; the verification therefore always passes `--user`).
  `--threshold=N` compares against exposure×10: `--threshold=11` fails at 1.2, `--threshold=12`
  passes, so the gate is `--threshold=15`.
- **Remaining exposure (accepted, each justified)**: `PrivateNetwork` (0.5, networking is a
  feature), `AF_INET` (0.3) and `AF_NETLINK` (0.1) (FR-010), `IPAddressDeny` (0.2, not
  enforceable in the user manager; spec clarification), `ProcSubset=` (0.1, see R10),
  `ProtectHome=tmpfs` instead of `yes` (0.1, needed to bind the two passwsync directories),
  `DeviceAllow` `char-rtc:r` (0.1, implied by `ProtectClock=`), `RootDirectory` (0.1).
- **Alternatives**: `ProtectHome=read-only` (whole home readable, rejected by clarification);
  `DynamicUser` (impossible for a per-user unit and would lose the person's files).

## R9. System-call filter (FR-008)

- **Decision**: `SystemCallFilter=@system-service` then `SystemCallFilter=~@privileged
  @resources`; default action (kill with `SIGSYS`; core dump impossible because
  `LimitCORE=0`). No `SystemCallErrorNumber=`.
- **Rationale**: the service needs `mlockall` (`@memlock`, part of `@system-service`, not of
  `@privileged`/`@resources`), `getrlimit`/`setrlimit`: rustix 1.1.5 implements both with
  `prlimit64`, which is in `@default`, so `@resources` (whose only resource-limit call is the
  legacy `setrlimit`) can be removed entirely. Measured: removing `@resources` lowers exposure
  1.2 → 1.1; re-adding `setrlimit` by name keeps 1.2. Killing on a forbidden call is fail-closed
  (an unexpected call is a bug or an attack; restart is bounded by R12).
- **Risk**: a dependency that probes a filtered call would crash the service; covered by the
  manual on-host start check (FR-026) and caught at first start, never silently.
- **Alternatives**: `SystemCallErrorNumber=EPERM` (softer, lets a probe fail gracefully; less
  secure); a hand-written allow-list (brittle across glibc/Rust updates).

## R10. `/proc`, socket families and peer-UID check (FR-010, FR-012)

- **Decision**: `ProtectProc=invisible` but **no** `ProcSubset=pid`, because 002's peer-UID
  check reads `/proc/net/tcp`. `RestrictAddressFamilies=AF_INET AF_NETLINK`: the service binds
  only IPv4 (`127.0.0.1`, and `0.0.0.0` for 003 when networking is on) and enumerates
  interfaces through `if-addrs` → glibc `getifaddrs` → netlink. `AF_UNIX` and `AF_INET6` are
  denied: stderr is connected to the journal by the manager before exec, and the service
  resolves no users/hosts (no NSS, no DNS).
- **PrivateUsers and `/proc/net/tcp`**: the kernel prints socket UIDs translated into the
  reader's user namespace; `PrivateUsers=yes` maps the person's UID to itself and all others to
  `nobody`, so the comparison with `getuid()` keeps accepting the person and rejecting everyone
  else. Covered by the manual on-host check (UI reachable, other user refused).
- **Alternatives**: allowing `AF_UNIX` "just in case" (no consumer; rejected).

## R11. Home directory view and first-run creation (FR-011)

- **Decision**: `ProtectHome=tmpfs` + `BindPaths=%h/.config/passwsync %h/.local/share/passwsync`
  + `ReadWritePaths=%t/passwsync` (**implementation correction**: replaced by a third `BindPaths=`
  entry `%t/passwsync`, because `ProtectHome=tmpfs` also hides `/run/user` and the grant failed
  with 226/NAMESPACE; `PrivatePIDs=yes` added so `ProtectProc=invisible` takes effect, see
  contracts/unit-file.md "Implementation corrections"). Because a bind source must exist, the first
  `ExecStartPre=` runs **unsandboxed** (`+`, still as the person) and: (1) fails with exit 2 and
  a `path:` message if `XDG_CONFIG_HOME`/`XDG_DATA_HOME` point anywhere but the defaults
  (clarification: fail closed, no silent fallback); (2) `exec mkdir -p -m 0700` the three
  directories. `mkdir -p` never changes an existing directory, so a wrongly permissioned
  existing directory is still refused by the service (exit 2).
- **Confinement probe**: a second, sandboxed `ExecStartPre=/usr/bin/findmnt --noheadings
  --output TARGET --target %h --types tmpfs` fails unless the home tree really is the private
  tmpfs, so a kernel/manager that cannot apply the namespace makes the unit fail instead of
  running unconfined (edge case "no unprivileged user namespaces"). `findmnt` is in
  `util-linux` (Arch `base`).
- **Measured correction (systemd 262, 2026-10-28, `systemd-run --user` with the unit's
  `PrivateUsers=yes ProtectHome=tmpfs` and a bind)**: `ProtectHome=tmpfs` mounts the tmpfs on
  `/home`, not on `%h`. The earlier form `--mountpoint %h` exited 1 inside a correct sandbox, so
  the unit would never have started. `--target %h --types tmpfs` exits 0 inside (TARGET `/home`)
  and 1 unconfined (`/` ext4 on the planning host), so it is the form used. Still to be confirmed
  on the Arch host (quickstart M3).
- **Alternatives**: `ConfigurationDirectory=` (follows custom `XDG_CONFIG_HOME`, chmods
  existing directories, and has no equivalent for `~/.local/share`); `BindPaths=-…` (would make
  the service create its directories inside the read-only tmpfs → exit 2 on first run);
  `RuntimeDirectory=` (removes the directory on stop, which would delete a manually started
  instance's lock and launch files; `mkdir` is simpler).

## R12. Restart and stop policy (FR-013)

- **Decision**: `Type=exec`, `Restart=on-failure`, `RestartPreventExitStatus=2 3 4`,
  `RestartSec=5s`, `StartLimitIntervalSec=5min` + `StartLimitBurst=5` (in `[Unit]`),
  `KillSignal=SIGTERM`, `TimeoutStopSec=15s`.
- **Note**: `RestartPreventExitStatus=` applies to the main process; a failing `ExecStartPre=`
  (custom XDG, failed probe) may be retried, but at most 5 times in 5 minutes.
- **Alternatives**: `Restart=always` (restarts after clean stop; rejected).

## R13. Launcher implementation (FR-021 to FR-023)

- **Decision**: a POSIX `sh` script, `/usr/bin/passwsync-open`, using only `systemctl --user`,
  `stat`, `cat`, `sleep`, `xdg-open` and optional `notify-send`, found through `PATH` (tests
  substitute stubs by prepending a directory to `PATH`; no test hooks in the script). Flow: if
  the unit is not active → `systemctl --user start passwsyncd.service` (its failure is not fatal
  by itself: a manually started instance makes the unit exit 4 but still owns a valid launch
  file); poll up to 100 × 0.1 s for a valid launch file; validate with `stat -c` (no symlink
  following: regular file, owner = `id -u`, mode & 077 = 0, size ≤ 128); read with `cat`,
  require the exact pattern and size = length + 1 (exactly one trailing newline); then
  `xdg-open "$url" </dev/null >/dev/null 2>&1`.
- **Token hygiene**: the URL is never echoed, never in `set -x`, never in a message; the
  opener's stdout/stderr (which `xdg-open` and browsers use to echo the URL on error) go to
  `/dev/null` so they cannot reach the journal.
- **Stale file**: after a crash a stale launch file may exist until the restarted service
  rewrites it; opening it shows 002's "link already used" page and a second launch works.
  Accepted (no freshness heuristics; the runtime directory is cleared at logout).
- **Alternatives**: a Rust subcommand in `passwsyncd` (changes service behaviour, FR-027;
  larger to audit); `gio open` (GNOME-only).

## R14. Desktop entry (FR-020)

- **Decision**: `Type=Application`, `Name=passwsync`, `GenericName=Password Manager`,
  `Exec=/usr/bin/passwsync-open`, `Icon=dialog-password` (theme icon; no icon file so the file
  list stays as in FR-015), `Terminal=false`, `StartupNotify=false`, `Categories=Utility;`,
  `Keywords=password;wallet;`. No `MimeType=`, installed only to `/usr/share/applications`
  (never `/etc/xdg/autostart`). Measured: `desktop-file-validate` clean (`Security` category
  would add a hint, so it is omitted).

## R15. Install script (FR-016 to FR-019)

- **Decision**: `passwsync.install` defines `post_install`, `post_upgrade`, `post_remove` that
  use **only the shell builtin `printf`**. No external command, no redirection to files.
  pacman has no hook point that sees the "remove configuration" option inside the script, and
  the package owns no file under a home directory, so `pacman -Rn` cannot touch user data.
- **Test**: the functions are sourced in `bash` with `PATH` set to an empty stub directory
  where every name is a logging stub, `HOME` set to a populated stand-in home, and the working
  directory inside it; the test asserts zero stub calls, an identical snapshot (path, type,
  mode, size, SHA-256) of the home before and after, and the required message phrases.

## R16. Offline verification entry point (FR-024, FR-025)

- **Decision**: `packaging/verify.sh` (bash), run from the repository root, prints one line
  per check (`PASS|FAIL|MISSING|SKIP <id> …`) and exits 0 only if every required check passed;
  1 if any failed; 2 if none failed but a required tool was missing or `--skip-build` was used
  (incomplete ≠ pass). `shellcheck` is optional (SKIP never affects the exit code);
  `makepkg`, `namcap`, `systemd-analyze`, `desktop-file-validate`, `unshare`, `zstd`/`bsdtar`
  are required. See [contracts/verify.md](contracts/verify.md).
- **`systemd-analyze verify`** needs `ExecStart=` to exist: it runs on a temporary copy whose
  `ExecStart=` path is replaced by the binary from the built package (or `/usr/bin/true` with
  `--skip-build`); the directive check separately asserts the real `ExecStart=/usr/bin/passwsyncd`.
  (`--root=` is not supported for `verify`; measured.)
- **Planning-host gaps**: `namcap` and `shellcheck` are not installed here; until the developer
  installs `namcap` (`pacman -S namcap shellcheck`), `verify.sh` exits 2, never 0.

## R17. Daemon changes

- **Decision**: none. Exit codes 2/3/4, the `launch-url` file format and mode 0600, and the
  token-free log are already defined by 002 `contracts/host-runtime.md` and implemented
  (`app.rs`, `paths.rs`, `peer.rs`). FR-027 forbids service behaviour changes; nothing in this
  feature needs one. TDD applies to the shell artifacts through `packaging/tests/`.
