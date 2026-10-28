# passwsync on Arch Linux

The `passwsync` package installs the passwsync local service (`passwsyncd`) as a confined
**systemd user service**, a desktop launcher and a menu entry. It builds from one pinned,
checksummed source archive and changes nothing in your home directory.

Installed files:

| Path | Purpose |
|------|---------|
| `/usr/bin/passwsyncd` | the service (loopback web UI; networking off unless you turn it on) |
| `/usr/bin/passwsync-open` | launcher: starts the service if needed and opens the UI |
| `/usr/lib/systemd/user/passwsyncd.service` | hardened user unit |
| `/usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf` | raises only the user manager's locked-memory limit to 256 MiB |
| `/usr/share/applications/passwsync.desktop` | menu entry "passwsync" |
| `/usr/share/doc/passwsync/README.md` | this file |
| `/usr/share/licenses/passwsync/LICENSE` | MPL-2.0 |

## Using it

1. After installing, **log out and log back in** once. The service locks its memory
   (`mlockall`) and needs a 256 MiB locked-memory limit; the drop-in that grants it applies to
   your user manager only from the next login. Before that the service refuses to start
   (exit 3, journal `protection failed: memlock-limit`) and is not restarted.
2. Start it now and at every login:

   ```sh
   systemctl --user enable --now passwsyncd.service
   ```

3. Open the UI from the menu entry **passwsync** or run `passwsync-open`. The launcher starts
   (never enables) the service when it is not running, waits up to 10 seconds for the one-time
   launch address, checks that the launch file is yours and private, and hands the address only
   to `xdg-open`. It never prints or logs the address.

The package never enables, starts, stops or restarts the service, and never writes a
configuration. **Networking is off by default**; you turn it on only by editing your own
`~/.config/passwsync/config`.

Upgrades do not restart a running service: run `systemctl --user restart passwsyncd.service`
to use the new version (this locks all wallets). Removing the package keeps
`~/.config/passwsync`, `~/.local/share/passwsync` and `$XDG_RUNTIME_DIR/passwsync`; deleting
them is your decision. Stop an enabled service with
`systemctl --user disable --now passwsyncd.service`.

## Requirements and limitations

- **Unprivileged user namespaces** must be enabled (the Arch kernel default). The user manager
  builds the sandbox from one; the unit's sandboxed pre-start probe (`findmnt --target %h
  --types tmpfs`) makes the service fail instead of running unconfined when it cannot.
- **systemd >= 257** (`PrivatePIDs=`). Without its own PID namespace the user manager cannot
  mount a private `/proc`, and `ProtectProc=invisible` would silently have no effect.
- **Custom `XDG_CONFIG_HOME` / `XDG_DATA_HOME` are refused** (exit 2, `path:` message, no
  fallback): the sandbox binds exactly `~/.config/passwsync`, `~/.local/share/passwsync` and
  `$XDG_RUNTIME_DIR/passwsync`. To use other locations, add a unit override
  (`systemctl --user edit passwsyncd.service`) with matching `BindPaths=` and an
  `ExecStartPre=` that replaces the check; you then own that configuration.
- **Higher memlock limit already configured**: drop-ins are applied in lexical order, so an
  administrator who wants a value above 256 MiB adds a later-sorting drop-in, for example
  `/etc/systemd/system/user@.service.d/zz-memlock.conf` with `[Service]` `LimitMEMLOCK=...`.

## Confinement

Offline exposure (`systemd-analyze --user security --offline=yes`): **1.1** (gate: 1.5).
The unit runs with `PrivateUsers=yes`, `PrivatePIDs=yes`, a read-only system
(`ProtectSystem=strict`), an empty private home (`ProtectHome=tmpfs`) into which only the
passwsync directories are bound, private `/tmp`, devices and IPC, `ProtectProc=invisible`,
only `AF_INET` and `AF_NETLINK` sockets, the `@system-service` system calls minus
`@privileged @resources` (a forbidden call kills the service), no capabilities, no core dumps,
`UMask=0077`, and a bounded restart policy that never restarts after exit 2, 3 or 4.
Accepted residual exposure: network access (networking is a feature), no IP allow-list (not
enforceable by the user manager) and the full `/proc` subset (the peer-UID check reads
`/proc/net/tcp`).

## Verifying the package (developers)

```sh
packaging/verify.sh --fetch       # once, the only step that uses the network
packaging/verify.sh --skip-build  # static checks and test suites; never exits 0
packaging/verify.sh               # everything, including three offline release builds
```

Exit 0 means every check passed; 2 means incomplete (a required tool is missing or
`--skip-build`); 1 means a check failed. Builds run with no network (a private network
namespace with only loopback) and a dedicated cargo cache, with `SOURCE_DATE_EPOCH` set to
the last commit time; `repro-dirs` and `repro-package` compare three builds bit for bit.
Required tools: `makepkg`, `namcap`, `systemd-analyze`, `systemd-run`, `desktop-file-validate`,
`bsdtar`, `unshare`, `ss`; `shellcheck` is optional.

## Lint notes

`namcap` warnings that are accepted, by tag, with the reason. `verify.sh` fails on any `W:`
tag not listed in this section.

- Not run here: `namcap` was not installed on the development host (2026-10-28), so
  `namcap-recipe` and `namcap-package` report `MISSING` and `verify.sh` exits 2. Expected,
  to be confirmed when it runs: a warning that `LICENSE` is installed for a license that is
  already in the common licenses (kept because the package must ship its license file).
- `shellcheck` was not installed either; its check reports `SKIP` (optional).

## Manual checks on a real Arch host

Not automatable here (need a fresh login, a second OS user or a second device). Recorded as
"Not run here" until a person runs them; the automated equivalents are the `unit-directives`,
`confinement-probe`, `launcher-tests` and `install-tests` checks.

| # | Action | Expected |
|---|--------|----------|
| M1 | `sudo pacman -U passwsync-*.pkg.tar.zst` | install message; `systemctl --user is-enabled passwsyncd` is `disabled` |
| M2 | start before re-login | fails with status 3, `protection failed: memlock-limit`, `NRestarts=0` |
| M3 | re-login, `systemctl --user enable --now passwsyncd` | active; only `127.0.0.1:27471` listens; both passwsync dirs exist with 0700 |
| M4 | `systemd-analyze --user security passwsyncd` | live exposure <= 1.5 |
| M5 | `find /proc/$(systemctl --user show -p MainPID --value passwsyncd)/root$HOME -maxdepth 3` | only the passwsync dirs and their parents |
| M6 | menu entry with the service stopped | UI opens in under 10 s; `journalctl --user -b \| grep -c launch/` is 0 |
| M7 | unlock a wallet, suspend and resume | wallets auto-lock as without the sandbox |
| M8 | second OS user connects to `127.0.0.1:27471` | refused |
| M9 | networking on, restart | LAN listener and discovery work; pair, sync and share with a second device |
| M10 | custom `XDG_DATA_HOME` in the manager environment | unit fails with the `path:` message |
| M11 | upgrade (`pkgrel=2`) while running | PID unchanged; restart message shown |
| M12 | `sudo pacman -Rns passwsync` | kept-directories message; every passwsync file unchanged |

SC-007: from the built package to a working UI (M1 to M6, one re-login) in under 3 minutes
following only the messages. SC-008: the confined service starts with networking off and
works with networking on (M3, M9).

## Releasing (maintainer)

1. Tag `v<pkgver>`.
2. Copy `PKGBUILD`, `.SRCINFO` and `passwsync.install` to the AUR repository.
3. There run `updpkgsums` (downloads the tag archive and pins its SHA-256) and
   `makepkg --printsrcinfo > .SRCINFO`; build once; publish. AUR publishing is manual.
4. Commit the pinned checksum back to `packaging/`. The archive cannot contain its own
   checksum, so the in-repository recipe carries the previous release's value (all zeros
   before the first release, which fails closed on any download).
