# Contract: `PKGBUILD`, `.SRCINFO` and `passwsync.install`

Normative for `packaging/PKGBUILD`, `packaging/.SRCINFO`, `packaging/passwsync.install` and the
tests `packaging/tests/install_script.sh`, `packaging/tests/package_contents.sh`. Rationale:
[research.md](../research.md) R1-R6, R15.

## Metadata

| Field | Value |
|-------|-------|
| `pkgname` | `passwsync` |
| `pkgver` | workspace version of `crates/passwsyncd` (`0.1.0`) |
| `pkgrel` | `1` |
| `pkgdesc` | `Offline peer-to-peer password manager: local service with a browser UI` |
| `arch` | `('x86_64')` |
| `url` | `https://github.com/henriqk0/passwsync` |
| `license` | `('MPL-2.0')` |
| `depends` | `('gcc-libs' 'glibc' 'systemd' 'xdg-utils')` (+ whatever namcap reports as required; nothing else) |
| `optdepends` | `('libnotify: desktop notification when the launcher fails')` |
| `makedepends` | `('cargo')` |
| `options` | `('!debug' '!lto')` |
| `install` | `passwsync.install` |
| `source` | exactly one entry: `"$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz"` |
| `sha256sums` | exactly one 64-hex value; never `SKIP` |

Forbidden: any other `source` entry, `pkgver()` function, `git+`/`-git`, `noextract`,
`backup=()` (the package ships no configuration), `provides`/`conflicts` (nothing to replace).

## Functions

Inside every function `cd "$pkgname-$pkgver"` and `export RUSTUP_TOOLCHAIN=stable`.

| Function | Exactly does |
|----------|--------------|
| `prepare()` | `cargo fetch --locked --target "$(rustc -vV \| sed -n 's/host: //p')"` |
| `build()` | exports `CARGO_TARGET_DIR=target`, `CARGO_INCREMENTAL=0`, `RUSTFLAGS="--remap-path-prefix=$srcdir=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"` (replacing, not appending), `CARGO_PROFILE_RELEASE_OPT_LEVEL=3`, `CARGO_PROFILE_RELEASE_DEBUG=false`, `CARGO_PROFILE_RELEASE_STRIP=symbols`, `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`, `CARGO_PROFILE_RELEASE_LTO=true`, `CARGO_PROFILE_RELEASE_PANIC=unwind`, `CARGO_PROFILE_RELEASE_INCREMENTAL=false`; runs `cargo build --frozen --release -p passwsyncd --bin passwsyncd` |
| `check()` | exports `CARGO_TARGET_DIR=target`; runs `cargo test --frozen --workspace`. A comment names every test that does not run, with its reason (FR-005): each of the 16 `#[ignore]`d tests of the tree, written `crate/file::name` (release-mode performance/resource measurements), and `passwsyncd/startup::real_binary_starts_when_the_memlock_limit_allows` (skips itself below a 256 MiB hard memlock limit). The list must equal the set printed by `grep -rn '#\[ignore' crates` (check `recipe-fields`). No other test is skipped. |
| `package()` | the `install` commands of the file table below, nothing else |

## Package file list (FR-015)

The package MUST contain exactly these regular files (directories implied):

| Path | Mode | From (inside the archive) |
|------|------|------|
| `usr/bin/passwsyncd` | 0755 | `target/release/passwsyncd` |
| `usr/bin/passwsync-open` | 0755 | `packaging/passwsync-open` |
| `usr/lib/systemd/user/passwsyncd.service` | 0644 | `packaging/passwsyncd.service` |
| `usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf` | 0644 | `packaging/passwsync-memlock.conf` |
| `usr/share/applications/passwsync.desktop` | 0644 | `packaging/passwsync.desktop` |
| `usr/share/doc/passwsync/README.md` | 0644 | `packaging/README.md` |
| `usr/share/licenses/passwsync/LICENSE` | 0644 | `LICENSE` |

plus the pacman metadata files (`.PKGINFO`, `.BUILDINFO`, `.MTREE`, `.INSTALL`). Nothing under
`home/`, `root/`, `etc/`, `var/`; no file under `usr/lib/systemd/system/` other than the
drop-in. `package_contents.sh` compares the `bsdtar -tf` listing (non-directories, metadata
excluded) with this table, checks modes, and checks `.INSTALL` is byte-identical to
`packaging/passwsync.install`.

## `.SRCINFO`

Committed; must equal `makepkg --printsrcinfo` output for the committed `PKGBUILD`
(check `srcinfo`).

## Lint expectations

- `bash -n PKGBUILD` and `makepkg --printsrcinfo` succeed.
- `namcap PKGBUILD` and `namcap <package>`: zero `E:` lines. Each `W:` line is either removed
  or listed with its justification in `packaging/README.md` ("Lint notes") — the verify script
  fails on any `W:` line not listed there verbatim (by tag).
- Expected justified warning (to be confirmed when namcap runs): installing `LICENSE` for an
  SPDX license in `licenses` (kept because FR-015 requires the license in the package).

## `passwsync.install`

Defines exactly `post_install()`, `post_upgrade()`, `post_remove()`; each body consists only of
`printf` builtin calls writing to standard output. No other command, no redirection, no
variable other than the positional version arguments, no `pre_*` functions.

Required message content (case-insensitive phrase checks in `install_script.sh`):

| Function | Must contain |
|----------|--------------|
| `post_install` | "networking is off"; the config file path `~/.config/passwsync/config`; `systemctl --user enable --now passwsyncd.service`; `passwsync-open` (or the menu entry "passwsync"); "log out and log back in" (memlock limit); "never enabled or started automatically" |
| `post_upgrade` | `systemctl --user restart passwsyncd.service`; "locks all wallets"; "not restarted automatically" |
| `post_remove` | `~/.config/passwsync`, `~/.local/share/passwsync`; "kept"; "your decision"; `systemctl --user disable --now passwsyncd.service` |

Test harness contract (`install_script.sh`):

1. Create a stand-in home with populated `.config/passwsync/{config,device-id,device-key,peers}`
   and `.local/share/passwsync/{wallets/a.pwsw,sync/…,received/…}` (mixed modes 0600/0700).
2. Snapshot: sorted list of `path type mode size sha256`.
3. For each of `post_install 0.1.0-1`, `post_upgrade 0.1.0-2 0.1.0-1`, `post_remove 0.1.0-1`:
   run `env -i HOME=<home> PATH=<stubdir> bash -c '. <install>; <fn> …'` with cwd = home,
   where `<stubdir>` holds logging stubs named `systemctl rm mv cp mkdir chmod chown sed tee
   install ln find sudo runuser su cat touch truncate dd`.
4. Assert: exit 0, stub log empty, snapshot identical, required phrases present, output does
   not contain `networking = ` / `network =` assignment hints that write config.
5. Static: `grep -vE '^\s*(#|$|printf |post_(install|upgrade|remove)\(\) \{|\})'` on the file
   yields nothing.
