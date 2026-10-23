# Contract: `passwsyncd` host runtime (CLI, files, start-up, logging)

Normative for packaging (006) and tests. Rationale: [research.md](../research.md) R3, R4,
R8, R11, R12, R14, R19.

## Command line

```text
passwsyncd            # run the service in the foreground until a termination signal
passwsyncd --help     # usage, exit 0
passwsyncd --version  # version, exit 0
```

Any other argument → usage on stderr, exit 2. No option disables a protection.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | normal stop (SIGTERM/SIGINT/SIGHUP), all wallets locked first |
| 1 | other fatal error |
| 2 | configuration or path error (invalid config, bad permissions, `XDG_RUNTIME_DIR` unset, invalid device-id file) |
| 3 | protection failed (core dumps, non-dumpable, memory lock limit, memory locking) |
| 4 | another instance is running, or the port cannot be bound |

## Files and directories

| Path | Mode | Content | Written by |
|------|------|---------|-----------|
| `$XDG_CONFIG_HOME/passwsync/` (default `~/.config/passwsync/`) | 0700 | — | service (created if missing) |
| `…/passwsync/config` | 0600 (or stricter); optional | settings, see below | the person |
| `…/passwsync/device-id` | 0600 | 32 lowercase hex chars + `\n` | service, first run only |
| `$XDG_DATA_HOME/passwsync/wallets/` (default `~/.local/share/passwsync/wallets/`) | 0700 | — | service |
| `…/wallets/<name>.pwsw` | 0600 | vault-core encrypted wallet (001 file format) | service via `FileStorage` |
| `$XDG_RUNTIME_DIR/passwsync/` | 0700 | — | service |
| `…/passwsync/launch-url` | 0600 | `http://127.0.0.1:<port>/launch/<64 hex>\n`; rewritten after each use; deleted on stop | service |
| `…/passwsync/instance.lock` | 0600 | empty; `flock` exclusive for process lifetime | service |

Existing directories or files with group/other permission bits, or not owned by the user →
exit 2 naming the path. Wallet listing: regular files (not symlinks) named
`<valid name>.pwsw`; everything else ignored.

Wallet name: 1–64 chars of `[A-Za-z0-9 _.-]`, not starting with `.`, not ending with space.

## Configuration file

```text
# passwsync settings (all optional)
port = 27471                  # 1024..=65535
auto_lock_minutes = 15        # 1..=240, cannot be disabled
clipboard_clear_seconds = 30  # 5..=300
```

Grammar: lines are blank, `# comment`, or `key = <decimal integer>` with optional trailing
`# comment`. Unknown key, duplicate key, other syntax, or out-of-range value → exit 2 with
`config: <key or line number>: <problem>`. Read once at start; never written by the service.

## Start-up sequence (order is normative)

1. Parse arguments.
2. Hardening (exit 3 on any failure, naming it): disable core dumps (`RLIMIT_CORE` = 0) →
   set non-dumpable (`PR_SET_DUMPABLE` = 0) → require `RLIMIT_MEMLOCK` ≥ 256 MiB or unlimited
   → `mlockall(MCL_CURRENT | MCL_FUTURE)`.
3. Resolve XDG paths, check/create directories, read config, read/create device id (exit 2).
4. Acquire instance lock (exit 4).
5. Bind `127.0.0.1:<port>` (exit 4).
6. Generate launch token, write launch file, start signal thread, sweeper thread, workers.
7. Log `started 127.0.0.1:<port>` and the launch-file path (never the token).

Required locked-memory limit: **256 MiB** (`LimitMEMLOCK=256M` in the 006 systemd unit;
`ulimit -l 262144` for manual runs).

## Shutdown

On SIGTERM/SIGINT/SIGHUP: stop accepting, lock every wallet (zeroize), delete
`launch-url`, log `stopping`, exit 0. The kernel releases the instance lock.

## Log (stderr) — complete event list

`started <addr>`, `launch file <path>`, `protections applied`,
`protection failed: <core-dumps|non-dumpable|memlock-limit|mlockall> (<error class>)`,
`unlocked <wallet>`, `locked <wallet> (manual|all|idle|suspend|stop)`,
`suspend detected`, `rejected host=<n> origin=<n> csrf=<n> session=<n> size=<n> peer=<n>`
(aggregated, at most once per minute, only when non-zero), `error <class>`, `stopping`.
Nothing else is ever logged: no bodies, tokens, cookies, query strings, credential titles, or
secrets (FR-033a).
