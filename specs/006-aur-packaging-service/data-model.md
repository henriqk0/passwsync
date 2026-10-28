# Data Model: AUR Packaging of the Local Service

This feature adds no runtime data. Its "entities" are files: the packaging sources in the
repository, the artifacts they produce, and the person's data the package must never touch.
Contracts give exact content; this document gives the inventory, relationships and rules.

## 1. Packaging sources (`packaging/` in the repository)

| File | Kind | Shipped to AUR repo | Installed by package | Contract |
|------|------|---------------------|----------------------|----------|
| `PKGBUILD` | bash recipe | yes | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `.SRCINFO` | generated metadata | yes | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `passwsync.install` | bash install hooks | yes | as `.INSTALL` metadata | [pkgbuild.md](contracts/pkgbuild.md) |
| `passwsyncd.service` | systemd user unit | no (from archive) | `/usr/lib/systemd/user/` | [unit-file.md](contracts/unit-file.md) |
| `passwsync-memlock.conf` | `user@.service` drop-in | no (from archive) | `/usr/lib/systemd/system/user@.service.d/` | [unit-file.md](contracts/unit-file.md) |
| `passwsync.desktop` | desktop entry | no (from archive) | `/usr/share/applications/` | [launcher.md](contracts/launcher.md) |
| `passwsync-open` | POSIX sh launcher | no (from archive) | `/usr/bin/` | [launcher.md](contracts/launcher.md) |
| `README.md` | usage, manual checks, lint notes, override recipe | no (from archive) | `/usr/share/doc/passwsync/` | [quickstart.md](quickstart.md) |
| `verify.sh` | bash, verification entry point | no | no | [verify.md](contracts/verify.md) |
| `tests/lib.sh` | helpers: assert, snapshot, stub maker, archive maker | no | no | [verify.md](contracts/verify.md) |
| `tests/unit_directives.sh` | D1-D12 + drop-in check | no | no | [unit-file.md](contracts/unit-file.md) |
| `tests/launcher.sh` | L1-L13 | no | no | [launcher.md](contracts/launcher.md) |
| `tests/install_script.sh` | hook sandbox tests | no | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `tests/package_contents.sh` | file list, modes, `.INSTALL` | no | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `tests/reproducible.sh` | builds A/B/C, hostile-env build B, comparisons | no | no | [verify.md](contracts/verify.md) |
| `tests/lib_selftest.sh` | self-test of `lib.sh` | no | no | [verify.md](contracts/verify.md) |
| `tests/verify_cli.sh` | `verify.sh` usage, exit codes, output, token hygiene | no | no | [verify.md](contracts/verify.md) |
| `tests/recipe_fields.sh` | PKGBUILD fields; `check()` skip list equals the `#[ignore]` set | no | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `tests/recipe_integrity.sh` | checksum-tamper and lock-mismatch | no | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `tests/srcinfo.sh` | `.SRCINFO` equals `makepkg --printsrcinfo` | no | no | [pkgbuild.md](contracts/pkgbuild.md) |
| `tests/confinement_probe.sh` | P1-P5 through `systemd-run --user` | no | no | [unit-file.md](contracts/unit-file.md), [verify.md](contracts/verify.md) |
| `tests/no_config_writes.sh` | SC-005 static guard, mutation self-test | no | no | [verify.md](contracts/verify.md) |
| `tests/desktop_entry.sh` | desktop validation and forbidden keys | no | no | [launcher.md](contracts/launcher.md) |

Repository root `LICENSE` is installed as `/usr/share/licenses/passwsync/LICENSE`.

## 2. Build inputs and outputs

```text
working tree ──(R3 archive maker)──► release archive passwsync-<ver>.tar.gz ──sha256──► PKGBUILD.sha256sums
                                            │
Cargo.lock ──(prepare: cargo fetch --locked)──► CARGO_HOME cache (pre-fetched, offline)
                                            │
                     makepkg (netns, SOURCE_DATE_EPOCH, --frozen) ──► passwsync-<ver>-<rel>-x86_64.pkg.tar.zst
                                                                          ├── usr/bin/passwsyncd (stripped)
                                                                          └── … (FR-015 list)
```

| Artifact | Identity rule | Validation |
|----------|---------------|------------|
| Release archive | name `passwsync-<pkgver>.tar.gz`, top dir `passwsync-<pkgver>/`; timestamp = source-date value | SHA-256 equals the recipe value or the build stops (FR-002) |
| Dependency cache | exactly the crates in `Cargo.lock` | `--frozen` fails on any missing/changed crate (FR-003) |
| Service binary | `usr/bin/passwsyncd` | bit-identical across build directories; contains no build/home path (FR-025a, US5-3) |
| Package file | `passwsync-<pkgver>-<pkgrel>-x86_64.pkg.tar.zst` | identical SHA-256 for same build path, different copies/times (FR-025b); namcap clean |
| Verification report | stdout of `verify.sh` | one status line per check + summary; exit 0/1/2 |

## 3. Installed unit relationships

```text
user@<uid>.service  (system manager; drop-in passwsync-memlock.conf: LimitMEMLOCK=256M)
   └── systemd --user  (hard memlock limit now 256 MiB, after next login)
         └── passwsyncd.service  (LimitMEMLOCK=256M, LimitCORE=0, sandbox)
               ├── ExecStartPre=+ sh: XDG check, mkdir -m 0700 config/data/runtime dirs
               ├── ExecStartPre= findmnt: home is the private tmpfs (sandbox applied)
               └── ExecStart=/usr/bin/passwsyncd  → binds 127.0.0.1:27471, writes launch-url
passwsync.desktop ──Exec──► passwsync-open ──systemctl --user start──► passwsyncd.service
                                          └──reads $XDG_RUNTIME_DIR/passwsync/launch-url──► xdg-open
```

### Service states seen by the person

| State | Cause | Restart? |
|-------|-------|----------|
| inactive | installed, never enabled/started | — |
| active (running) | enabled at login or started by launcher | — |
| failed, status 3 | memlock limit still 8 MiB (no re-login) or protection failure | no |
| failed, status 2 | bad permissions, config error, custom XDG dirs (pre-check) | no (main); pre-check ≤ 5 tries |
| failed, status 4 | another instance or port busy | no |
| failed, start-limit-hit | other abnormal exits 5 times in 5 min | no more |
| failed, `ExecStartPre` findmnt | sandbox not applied | ≤ 5 tries, then start-limit |

## 4. The person's passwsync data (never package-owned)

| Path | Created by | Package/scripts/launcher may |
|------|------------|------------------------------|
| `~/.config/passwsync/` (`config`, `device-id`, `device-key`, `peers`) | person / service | nothing (only the unit's `mkdir -p` of the directory itself at service start) |
| `~/.local/share/passwsync/` (`wallets/`, `sync/`, `received/`) | service | nothing (same `mkdir -p`) |
| `$XDG_RUNTIME_DIR/passwsync/` (`launch-url`, `instance.lock`) | service (`mkdir -p` by unit) | launcher reads `launch-url` only |
| `~/.config/systemd/user/default.target.wants/passwsyncd.service` | person (`systemctl --user enable`) | nothing; removal message gives `disable` |

Validation rules (tested): install/upgrade/remove hooks leave a populated stand-in home
byte-identical including modes (SC-004); the package file list contains nothing under a home
(FR-015); no packaging file writes a configuration file (SC-005).
