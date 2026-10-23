# passwsync
An open-source P2P straightforward password manager between chosen devices

## Local service (`passwsyncd`)

`passwsyncd` runs on your computer and serves a web UI only to your own browser, at
`http://127.0.0.1:27471`. It works fully offline: there are no accounts, no email and no
login. Each wallet's master password is the only secret, and you need it once per wallet
after each service start.

### Build

```sh
cargo build --release -p passwsyncd
```

### Run

The service locks all of its memory so secrets never reach swap, and it refuses to start
(exit code 3) if it can't. The shell that starts it needs a locked-memory limit of at least
256 MiB:

```sh
ulimit -l 262144          # or add "<user> - memlock 262144" to /etc/security/limits.d/
./target/release/passwsyncd
```

The systemd user unit from the packaging feature sets `LimitMEMLOCK=256M` for you.

Each run writes a single-use launch address to `$XDG_RUNTIME_DIR/passwsync/launch-url`.
Open it to get a browser session (the address stops working once used, and a new one is
written):

```sh
xdg-open "$(cat "$XDG_RUNTIME_DIR/passwsync/launch-url")"
```

To stop the service, send SIGTERM, SIGINT (Ctrl+C) or SIGHUP. It locks every wallet,
deletes the launch file and exits with code 0.

Exit codes: `0` normal stop, `1` other fatal error, `2` configuration or path error,
`3` a protection failed, `4` already running or the port is busy.

### Files

| Path | Content |
|------|---------|
| `~/.local/share/passwsync/wallets/<name>.pwsw` | encrypted wallets (mode 0600) |
| `~/.config/passwsync/config` | optional settings (mode 0600) |
| `~/.config/passwsync/device-id` | device identifier, created on first run |
| `$XDG_RUNTIME_DIR/passwsync/launch-url` | current launch address (deleted on stop) |

### Configuration

All keys are optional. The service reads the file once at start and refuses to start on
an unknown key, a duplicate key, bad syntax or an out-of-range value:

```text
port = 27471                  # 1024..=65535
auto_lock_minutes = 15        # 1..=240 (auto-lock cannot be disabled)
clipboard_clear_seconds = 30  # 5..=300
```
