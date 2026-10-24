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
| `~/.config/passwsync/device-key` | this device's private key (mode 0600, never sent) |
| `~/.config/passwsync/peers` | paired devices (mode 0600) |
| `$XDG_RUNTIME_DIR/passwsync/launch-url` | current launch address (deleted on stop) |

### Configuration

All keys are optional. The service reads the file once at start and refuses to start on
an unknown key, a duplicate key, bad syntax or an out-of-range value:

```text
port = 27471                  # 1024..=65535
auto_lock_minutes = 15        # 1..=240 (auto-lock cannot be disabled)
clipboard_clear_seconds = 30  # 5..=300
```

## Pairing devices on your network

Networking is **off** by default: the service then opens no socket other than the loopback
UI. To pair devices, turn it on in `~/.config/passwsync/config` on each device and restart
the service:

```text
network = on                  # on|off (default off)
peer_port = 27472             # TCP, 1024..=65535, distinct from port and discovery_port
discovery_port = 27473        # UDP, 1024..=65535, distinct
device_name = "Laptop"        # optional, 1..64 characters; default "passwsync device XXXX"
network_interface = "wlan0"   # optional; default: every interface with a private address
```

With networking on, the service listens on TCP 27472 and UDP 27473 (allow both in your
firewall for the local network only). It talks only to IPv4 private and link-local
addresses (10/8, 172.16/12, 192.168/16, 169.254/16), never to the internet, and never
resolves host names. The UI shows the networking state and settings read-only.

To pair:

1. On device A open **Devices**, choose **Show a pairing code**. A shows an 8-digit code
   (valid 5 minutes, single use) and a QR code.
2. On device B pick A from the nearby list, or type A's address (for example
   `192.168.1.5:27472`), enter the code and choose **Join**.
3. A shows B's name and fingerprint. Compare the fingerprints on both screens, then choose
   **Accept** on A.

Paired devices connect over an end-to-end encrypted, mutually authenticated channel (Noise
protocol). The Devices view lists them with their status; **Revoke** removes a device at
once, and only a new pairing brings it back. Wallet contents never cross the network in
this version.
