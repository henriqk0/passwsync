# Quickstart: validating AUR packaging of the local service

How to prove the feature works. Exact file content and pass rules are in
[contracts/](contracts/); the inventory is in [data-model.md](data-model.md).

## Prerequisites (one-time developer setup)

```sh
sudo pacman -S --needed base-devel namcap systemd desktop-file-utils libarchive util-linux iproute2
sudo pacman -S --needed shellcheck   # optional; its check is skipped if absent
```

Kernel with unprivileged user namespaces (Arch default). Rust as the Arch `rust` package (or
`rustup` with the stable toolchain); reproducibility is defined for one toolchain version.

## 1. Fill the dependency cache (only step with network)

```sh
packaging/verify.sh --fetch
```

Expected: `cargo fetch --locked` into `~/.cache/passwsync-verify/cargo`; exit 0.

## 2. Fast loop while editing (no package builds)

```sh
packaging/verify.sh --skip-build
```

Expected: `PASS` for `recipe-syntax`, `srcinfo`, `recipe-fields`, `unit-verify`,
`unit-security exposure=1.1`, `unit-directives`, `confinement-probe` (needs a working `systemd-run --user`), `desktop-validate`, `launcher-tests`,
`install-tests`, `no-config-writes` (and `namcap-recipe` once namcap is installed); build
checks `SKIP`; exit **2** (never 0 in this mode).

Individual suites can be run directly while doing Red-Green-Refactor:

```sh
packaging/tests/unit_directives.sh packaging/passwsyncd.service packaging/passwsync-memlock.conf
packaging/tests/launcher.sh packaging/passwsync-open      # ~15 s (L3 waits the full 10 s)
packaging/tests/install_script.sh packaging/passwsync.install
```

## 3. Full offline verification (SC-001)

```sh
packaging/verify.sh
```

Expected: every check `PASS`, including `checksum-tamper`, `lock-mismatch`, `build`,
`namcap-package`, `package-contents`, `binary-paths`, `repro-dirs`, `repro-package`;
`SUMMARY … fail=0 missing=0`; exit **0**. Three release builds run; expect several minutes.

## 4. Manual on-host checks (FR-026; not a gate)

Install the package built by step 3 (path printed by `verify.sh`, or run `makepkg -si` in a
copy of `packaging/` with the local archive):

| # | Action | Expected |
|---|--------|----------|
| M1 | `sudo pacman -U passwsync-*.pkg.tar.zst` | post-install message (networking off, enable command, launcher, re-login); nothing enabled/started (`systemctl --user is-enabled passwsyncd` → `disabled`) |
| M2 | `systemctl --user start passwsyncd` before re-login | fails, `status=3/…`, journal `protection failed: memlock-limit`; `systemctl --user show -p NRestarts passwsyncd` → 0 |
| M3 | log out, log in; `systemctl --user enable --now passwsyncd` | active; `ss -tlnp` shows only `127.0.0.1:27471`; `~/.config/passwsync` and `~/.local/share/passwsync` exist with 0700 |
| M4 | `systemd-analyze --user security passwsyncd` | ≤ 1.5 (live value) |
| M5 | home view: `find /proc/$(systemctl --user show -p MainPID --value passwsyncd)/root$HOME -maxdepth 3` | only the passwsync dirs and their parents |
| M6 | menu → "passwsync" (service stopped first) | browser opens the UI with a fresh session in < 10 s; `journalctl --user -b \| grep -c launch/` → 0 |
| M7 | create/unlock a wallet, copy a credential, suspend/resume | same behaviour as unconfined (002 auto-lock on suspend) |
| M8 | second OS user: `curl http://127.0.0.1:27471/` | refused (peer-UID check under `PrivateUsers=yes`) |
| M9 | set networking on in `~/.config/passwsync/config`, restart | `0.0.0.0:27472/tcp` and `:27473/udp` listen; pair, sync and share with a second device (003-005) |
| M10 | `XDG_DATA_HOME=/tmp/x systemctl --user import-environment XDG_DATA_HOME; systemctl --user restart passwsyncd` | fails with the `path:` message; unset again afterwards |
| M11 | rebuild with `pkgrel=2`, `pacman -U` while running | service still running old binary (PID unchanged); message says restart locks wallets |
| M12 | `sudo pacman -Rns passwsync` | message names the kept dirs and the `disable --now` command; `sha256sum` of every file under the passwsync dirs unchanged |

SC-007: M1→M6 including one re-login takes under 3 minutes following only the messages.

## 5. Releasing (maintainer, out of the verification gate)

Tag `v<pkgver>`; copy `PKGBUILD`, `.SRCINFO`, `passwsync.install` to the AUR repository; there
run `updpkgsums` (downloads the tag archive and pins its SHA-256) and
`makepkg --printsrcinfo > .SRCINFO`; build once; publish (FR-027: manual). Then commit the
pinned checksum back to `packaging/` on the main branch. The archive cannot contain its own
checksum, so the in-repository `PKGBUILD` always carries the previous release's value (an
all-zero placeholder before the first release, which makes any real download fail closed); the
verification rewrites it only in temporary copies (research R2).
