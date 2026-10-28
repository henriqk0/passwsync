# Contract: `passwsync-open` launcher and `passwsync.desktop`

Normative for `packaging/passwsync-open`, `packaging/passwsync.desktop` and
`packaging/tests/launcher.sh`. Rationale: [research.md](../research.md) R13, R14. Launch-file
format: 002 `contracts/host-runtime.md`.

## Command line

```text
passwsync-open        # ensure the service runs, open the launch address in the browser
```

Any argument → usage on stderr, exit 2. No option, no environment override, no prompt.

## Inputs and tools

| Input | Use |
|-------|-----|
| `XDG_RUNTIME_DIR` | required, absolute; launch file = `$XDG_RUNTIME_DIR/passwsync/launch-url` |
| `PATH` | locates `systemctl`, `stat`, `cat`, `sleep`, `id`, `xdg-open`, optional `notify-send` |

Shell: `#!/bin/sh`, POSIX, `set -eu`, never `set -x`.

## Algorithm (order is normative)

1. Arguments empty, else exit 2. `XDG_RUNTIME_DIR` set and absolute, `systemctl` and `xdg-open`
   found, else **error E-ENV**, exit 2.
2. `systemctl --user is-active --quiet passwsyncd.service` false → `systemctl --user start
   passwsyncd.service` (stdout/stderr discarded; result remembered, not fatal). The launcher
   never runs `enable`, `restart`, `stop` or `daemon-reload`.
3. Up to 100 attempts, 0.1 s apart (≈ 10 s): the launch file is **valid** when all hold:
   - `stat -c '%F|%u|%a|%s'` (no dereference) gives type `regular file`, uid = `id -u`,
     mode with no bit in `077`, size between 1 and 128;
   - its content (`cat`) is exactly `URL\n`: the command-substitution value `URL` matches
     `^http://127\.0\.0\.1:[1-9][0-9]{3,4}/launch/[0-9a-f]{64}$`, the port is 1024-65535, and
     size = length(URL) + 1.
   A present but invalid file is re-checked until the deadline (the service may be rewriting
   it), then reported as **E-INVALID**; no file by the deadline → **E-TIMEOUT**.
4. `xdg-open "$URL" </dev/null >/dev/null 2>&1`; non-zero → **E-OPENER**, exit 3.
5. Exit 0. Nothing is printed on success.

## Errors

Every error: one line on stderr `passwsync-open: <message>`, and, if `notify-send` is on `PATH`,
`notify-send --app-name=passwsync passwsync "<message>"` (its failure ignored). Messages are
fixed strings; none contains the URL, the token, the port or the file content.

| Id | Exit | Message (fixed) |
|----|------|-----------------|
| E-USAGE | 2 | `usage: passwsync-open (no arguments)` |
| E-ENV | 2 | `cannot start: XDG_RUNTIME_DIR, systemctl or xdg-open is missing` |
| E-TIMEOUT | 1 | `the service did not provide a launch address within 10 seconds; check: systemctl --user status passwsyncd.service` |
| E-INVALID | 1 | `the launch file is not safe to use (owner, permissions or format); check: systemctl --user status passwsyncd.service` |
| E-OPENER | 3 | `no browser could be opened (xdg-open failed); set a default browser and try again` |

## Guarantees

- Opens at most one URL per run, and only a valid one.
- Never writes, creates, deletes or renames any file; never reads anything but the launch file.
- Never reads or asks for a password; never changes configuration.

## Test matrix (`launcher.sh`, stubs on `PATH`)

Stubs: `systemctl` (records argv; `is-active` answers per scenario; `start` optionally writes
the launch file after a delay), `xdg-open` (records argv to a log; exit per scenario),
`notify-send` (records argv). Each test asserts exit code, opener calls, systemctl calls, and
that neither stdout, stderr, the notify log nor the systemctl log contains the token.

| # | Scenario | Expected |
|---|----------|----------|
| L1 | active, valid file | exit 0; exactly one `xdg-open <URL>`; no `start` |
| L2 | inactive, `start` creates valid file after 1 s | exit 0; `start passwsyncd.service` once, never `enable`; one opener call |
| L3 | inactive, file never appears | exit 1 (E-TIMEOUT) after ≥ 10 s and < 12 s; zero opener calls; message names `systemctl --user status passwsyncd.service` |
| L4 | file is a symlink to a valid file | exit 1 (E-INVALID); zero opener calls |
| L5 | file mode 0640 / 0604 | exit 1; zero opener calls |
| L6 | file owned by another uid (stub `id -u` returns a different uid) | exit 1; zero opener calls |
| L7 | bad content: `https://`, `localhost`, uppercase hex, 63 hex, port 80, port 70000, trailing garbage, two lines, no trailing newline | exit 1 each; zero opener calls |
| L8 | `start` fails but a valid file exists (manual instance) | exit 0; one opener call |
| L9 | opener exits 1 and prints the URL on stderr | exit 3; launcher stderr does not contain the token |
| L10 | `XDG_RUNTIME_DIR` unset; relative; `xdg-open` absent | exit 2; zero opener calls |
| L11 | any argument | exit 2 |
| L12 | `notify-send` absent | errors still on stderr, same exit codes |
| L13 | stand-in home snapshot before/after every test | identical |

## `passwsync.desktop`

```ini
[Desktop Entry]
Type=Application
Name=passwsync
GenericName=Password Manager
Comment=Open the passwsync password manager in your browser
Exec=/usr/bin/passwsync-open
Icon=dialog-password
Terminal=false
StartupNotify=false
Categories=Utility;
Keywords=password;wallet;
```

Checks: `desktop-file-validate` prints nothing and exits 0; no `MimeType=`, no `%u`/`%U`/`%f`
field codes, no `X-GNOME-Autostart*`, `Hidden`, `OnlyShowIn`; installed only to
`/usr/share/applications/`.
