# Quickstart / Validation Guide: Local Service with Web UI (Feature 002)

Runnable scenarios that prove the feature end-to-end. Routes, files and exit codes are
defined in [contracts/http-api.md](contracts/http-api.md) and
[contracts/host-runtime.md](contracts/host-runtime.md); entities in
[data-model.md](data-model.md).

## Prerequisites

- Linux desktop, Rust toolchain from `rust-toolchain.toml`, a current Firefox or Chromium.
- Locked-memory limit ≥ 256 MiB for the shell that starts the service:
  `ulimit -l` must print `262144`, more, or `unlimited`. To raise it persistently add
  `/etc/security/limits.d/passwsync.conf` with `<user> - memlock 262144` and log in again
  (packaging 006 sets `LimitMEMLOCK=256M` in the systemd user unit instead).
- `XDG_RUNTIME_DIR` set (normal in any desktop session).

## Automated checks

```sh
cargo test --workspace                       # unit + integration (fakes, raw-HTTP tests)
cargo test --workspace --release -- --ignored  # SC-007/SC-008 perf and memory tests
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit
```

Expected: all pass; no new advisories beyond the accepted RUSTSEC-2023-0089.

## Scenario A — protections and start-up (FR-028–FR-031, SC-009)

```sh
cargo build --release -p passwsyncd
(ulimit -l 1024; ./target/release/passwsyncd); echo "exit=$?"
```

Expected: `protection failed: memlock-limit …`, `exit=3`, no launch file created.

```sh
./target/release/passwsyncd &            # in a shell with ulimit -l ≥ 262144
grep VmLck /proc/$!/status               # > 0 kB
grep "Max core file size" /proc/$!/limits  # 0 0
./target/release/passwsyncd; echo "exit=$?"   # second instance → exit=4
```

## Scenario B — create, add, restart, unlock (US1, US2, SC-001, SC-002)

1. `xdg-open "$(cat "$XDG_RUNTIME_DIR/passwsync/launch-url")"` → UI loads at
   `http://127.0.0.1:27471/` (token no longer in the address bar).
2. Create wallet `Personal` with a ≥ 12-char master password typed twice; add credential
   `GitHub` (username, password, URL). Expected: listed; `~/.local/share/passwsync/wallets/
   Personal.pwsw` exists with mode 0600; `grep -c GitHub` on it prints `0`.
3. Reload, then open `http://127.0.0.1:27471/` in a second tab of the same browser: the
   wallet is shown unlocked, no password prompt.
4. Re-opening the *old* launch URL → 403 page (single-use).
5. `kill -TERM %1`; restart; open the new launch address: `Personal` shows locked; wrong
   password → "invalid password or corrupted wallet"; correct password → credentials shown.

## Scenario C — manage, search, copy (US3, US4, SC-005)

Add `GitLab` and `Bank`; search `git` → only GitHub and GitLab. Edit and delete one; restart
and unlock → changes persisted. Copy a password: countdown visible; after 30 s the clipboard
is empty (paste elsewhere) within 2 s of the countdown end; a revealed password hides itself
after 30 s and when leaving the view. Copy again, then press "Lock": clipboard cleared at once.
Every action is reachable with Tab/Enter/Space only, with visible focus. With a copied value
pending clearance, Tab onto a wallet or credential button and wait 10 s: focus stays on it
(the background poll does not rebuild unchanged lists, FR-031b; automated only as a static
check in `crates/passwsyncd/tests/ui_static.rs`).

## Scenario D — auto-lock and suspend (US5, SC-004)

Set `auto_lock_minutes = 1` in `~/.config/passwsync/config`, restart, unlock, leave the tab
open: within 75 s the UI shows the wallet locked and credentials requests return 423.
Unlock again, `systemctl suspend`, resume: wallet is locked before anything is served.
Set `auto_lock_minutes = 0` → service refuses to start (exit 2, message names the key).

## Scenario E — request protection (US6, SC-003)

With a wallet unlocked (`P=27471`, `C=<cookie value from browser devtools>`, `T=<csrf meta>`):

```sh
curl -si -H 'Host: evil.example:27471' http://127.0.0.1:$P/api/state            # 403
curl -si http://127.0.0.1:$P/api/state -H "Cookie: pws_session=$C"              # 403 (no CSRF)
curl -si http://127.0.0.1:$P/api/state -H "X-CSRF-Token: $T"                    # 401 (no session)
curl -si -X POST http://127.0.0.1:$P/api/lock-all -H "Cookie: pws_session=$C" \
     -H "X-CSRF-Token: $T"                                                      # 403 (no Origin)
curl -si -X POST http://127.0.0.1:$P/api/lock-all -H "Cookie: pws_session=$C" \
     -H "X-CSRF-Token: $T" -H 'Origin: http://evil.example'                     # 403
curl -si -X POST http://127.0.0.1:$P/api/wallets -H 'Content-Length: 99999999' # 413
sudo -u nobody curl -si http://127.0.0.1:$P/                                    # connection closed (peer)
ss -ltn | grep $P                                                               # only 127.0.0.1
```

Every response to an allowed page shows the CSP and headers listed in the HTTP contract;
the browser network panel shows no request leaving `127.0.0.1:$P`.

## Scenario F — no secrets in outputs (FR-032, FR-033a, SC-006)

Run Scenarios B–E with a marker password and title (e.g. `MARKER-pw-…`, `MARKER-title`), then
`grep -r MARKER` over captured stderr, `$XDG_RUNTIME_DIR/passwsync`, `~/.config/passwsync`:
zero matches (the launch file contains only the URL). The automated suite performs the same
scan plus an embedded-asset scan for external references.
