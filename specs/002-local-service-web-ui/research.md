# Research: Local Service with Web UI (Feature 002)

Phase 0 output for [plan.md](plan.md). Each item records the decision, the rationale, and the
alternatives considered. Non-interactive session: where a choice was open, the most secure and
then simplest option consistent with the constitution and `docs/roadmap.md` was taken.

## R1. Crate layout (hexagonal boundary)

- **Decision**: Two new workspace crates.
  - `crates/wallet-service` (library, application layer): wallet registry (locked/unlocked
    slots), browser sessions and launch token, CSRF tokens, idle auto-lock and suspend
    detection, wallet-name validation, request-independent use cases (create, unlock, lock,
    lock all, list, search, get, add, update, delete, read one field). Depends only on
    `vault-core`, `zeroize`, `subtle`, `rand_core`. Defines its own ports
    (`WalletDirectory`, `ElapsedClock`) and in-memory fakes. No HTTP, no filesystem, no OS calls.
  - `crates/passwsyncd` (binary `passwsyncd`, adapters): HTTP/1.1 adapter, JSON mapping,
    embedded UI assets, filesystem `WalletDirectory` (uses `vault-storage-file`), XDG paths and
    config file, launch file, single-instance lock, process hardening (memory locking,
    core dumps), signal handling, logging, peer-UID check, OS clocks.
- **Rationale**: Constitution IV requires the core to be testable with in-memory fakes and
  dependencies pointing inward; a crate boundary enforces this mechanically (same reasoning as
  001's `vault-core` / `vault-storage-file` split). The Android app (007) will reuse
  `wallet-service` without any of the desktop adapters.
- **Alternatives**: One crate with modules (rejected: nothing stops the application layer from
  importing HTTP or OS code; 007 would inherit desktop dependencies). A separate crate per
  adapter (rejected: speculative, no second consumer).

## R2. HTTP server and UI approach

- **Decision (server)**: `std::net::TcpListener` bound to `127.0.0.1:<port>` plus `httparse`
  (request-line and header parsing only). HTTP/1.1, one request per connection
  (`Connection: close`), no keep-alive, no chunked request bodies (`Transfer-Encoding` →
  rejected with 400; bodies require `Content-Length`). One accept thread feeds a bounded queue
  (capacity 16) served by a fixed pool of 4 worker threads (stack 512 KiB each). Per-connection
  read/write timeout 10 s. Limits: request line + headers ≤ 16 KiB, ≤ 48 headers, body ≤ 8 MiB
  (5 vault-core fields × 1 MiB plus JSON escaping headroom), checked from `Content-Length`
  before any body byte is read; the body is read into a `Zeroizing<Vec<u8>>` pre-sized to
  exactly that length (no reallocation copies).
- **Decision (UI)**: Plain HTML + CSS + vanilla JavaScript (ES2020 modules not needed: one
  `app.js`), no framework, no build step, no templating crate. Files live in
  `crates/passwsyncd/ui/` and are embedded with `include_bytes!`. Single page; the page talks
  to a small JSON API (see [contracts/http-api.md](contracts/http-api.md)). The only dynamic
  HTML is `index.html`, into which the server substitutes the session's CSRF token in a
  `<meta>` tag (HTML-attribute-safe: hex only).
- **Rationale**: Low RAM and a tiny audit surface. `httparse` is the parser used by hyper,
  has no dependencies, is fuzzed, and is maintained by the hyper/seanmonstar ecosystem. One
  request per connection removes pipelining, keep-alive state and request smuggling concerns;
  loopback connection setup cost is negligible for a single-person UI. A fixed pool bounds
  threads, stacks and locked memory (R4). Vanilla JS avoids an npm toolchain and third-party
  front-end code entirely (FR-012).
- **Alternatives**: `axum`/`hyper` + `tokio` (rejected: dozens of transitive crates, async
  runtime, larger RSS for a single-user loopback UI). `tiny_http` (rejected: slow maintenance,
  past smuggling advisory RUSTSEC-2020-0031, less control over header/body bounds). A web
  framework/bundler for the UI (rejected: build toolchain and supply chain for no requirement).

## R3. Default port and configuration

- **Decision**: Default port **27471** on `127.0.0.1` only. Configurable via the config file
  (`port`, allowed 1024–65535). If the port is in use the service refuses to start (exit
  code 4); it never falls back to another port or interface.
- **Rationale**: Outside the Linux ephemeral range (32768–60999), so outgoing connections of
  other programs do not randomly occupy it; unprivileged; no widely used service on it. Fixed
  default keeps the launch address predictable for packaging (006).
- **Alternatives**: Port 0 / random per run (rejected: unpredictable for packaging; the
  token already provides per-run unguessability). Common dev ports 8080/3000 (rejected:
  frequent collisions).

## R4. Required memory locking and process hardening (FR-028–FR-031)

- **Decision**: Use `rustix` (safe Rust wrappers over Linux syscalls) for all hardening; no
  `unsafe` and no direct `libc` in our crates, so the workspace-wide `unsafe_code = "forbid"`
  stays intact and no separate unsafe crate is needed. Start-up order, before reading the
  config-dependent wallet directory, spawning workers, or accepting connections:
  1. `setrlimit(RLIMIT_CORE, 0/0)` → "core dumps" protection.
  2. `prctl(PR_SET_DUMPABLE, 0)` (`rustix::process::set_dumpable_behavior`) → "non-dumpable"
     protection (also blocks same-user `ptrace`/`/proc/<pid>/mem` reads by unprivileged
     processes).
  3. Check `RLIMIT_MEMLOCK` (soft) ≥ **256 MiB** or unlimited → "memory lock limit".
  4. `mlockall(MCL_CURRENT | MCL_FUTURE)` → "memory locking".
  Any failure: log `protection failed: <name>` with the error class, exit code 3, nothing else
  is started (FR-031). No flag to skip them. Success is logged as `protections applied`.
- **Locked-memory budget** (why 256 MiB): with `MCL_FUTURE` every later allocation is locked,
  and an allocation beyond the limit fails, which aborts the process (fail closed, wallets
  vanish with it; core dumps are off). The service therefore bounds its peak:
  - Key derivation: one KDF at a time service-wide (a `kdf` mutex), and the service refuses
    to unlock a wallet whose header asks for more than **131 072 KiB (128 MiB)** of Argon2
    memory, reporting the vault-core format error `KdfParamsOutOfRange` without running the
    KDF. All wallets created by our hosts use `KdfConfig::DEFAULT` (64 MiB). This needs one
    additive vault-core function, `peek_kdf_config(&[u8]) -> Result<KdfConfig, VaultError>`
    (see [contracts/vault-core-additions.md](contracts/vault-core-additions.md)).
  - Requests: 4 workers × (8 MiB body + parsed copy) ≈ 64 MiB worst case.
  - Baseline (binary, stacks, allocator, unlocked wallets of typical size) ≈ 20–40 MiB.
  - 128 + 64 + 40 < 256 MiB. Packaging (006) sets `LimitMEMLOCK=256M` (or higher) in the
    systemd user unit; manual runs need `ulimit -l 262144` or an `/etc/security/limits.d`
    entry (documented in quickstart).
- **Rationale**: `rustix` is maintained by the Bytecode Alliance, widely depended upon
  (std-adjacent: used by `tempfile`, `cap-std`, wasmtime), and exposes exactly the calls needed
  (`mm::mlockall`, `process::{setrlimit, getrlimit, set_dumpable_behavior, getuid}`,
  `fs::flock`, `time::clock_gettime`) as safe functions. The explicit limit check turns a
  confusing later abort into a clear start-up refusal.
- **Alternatives**: `nix` (rejected: equivalent but pulls `libc` bindings and a larger API
  surface; rustix uses raw syscalls via `linux-raw-sys`). `memsec`/`region` per-buffer `mlock`
  (rejected: requires tracking every secret allocation including serde/argon2 internals;
  `mlockall` covers all of them). A local crate with `unsafe` libc calls (rejected: unsafe code
  where a vetted safe wrapper exists). Running without locking when the limit is low (rejected:
  spec FR-031 fail closed).

## R5. Restricting the service to the starting user (peer-UID check)

- **Decision**: For each accepted connection, the HTTP adapter looks up the client socket in
  `/proc/net/tcp` (match local `127.0.0.1:<client port>` ↔ remote `127.0.0.1:<service port>`)
  and rejects the connection (closes it, counts reason `peer`) unless the socket's UID equals
  the service's UID (`rustix::process::getuid`). Lookup failure → reject (fail closed).
- **Rationale**: Loopback is reachable by every local OS user. Cookies are not isolated by
  port, and process arguments (e.g. a browser started with the launch URL) are readable by
  other users via `/proc`. Checking the peer UID makes US6 ("other local users cannot use the
  service") hold even if a token or cookie leaks. ~40 lines, no dependency, no unsafe.
- **Alternatives**: Unix-domain socket (rejected: browsers cannot connect to it). TLS client
  certificates (rejected: heavy, and browsers do not support it well on loopback). Relying only
  on the session token (rejected: single layer for a high-value target).

## R6. Session token, launch address, cookie and CSRF design

- **Decision**:
  - Launch token: 32 random bytes from `OsRng` (256 bits), hex-encoded; single-use. Launch
    address `http://127.0.0.1:<port>/launch/<token>`; written to
    `$XDG_RUNTIME_DIR/passwsync/launch-url` (dir 0700, file 0600, atomic temp+rename). On a
    successful exchange the service generates a new token and rewrites the file (FR-004).
  - Exchange (`GET /launch/<token>`, constant-time comparison): creates a browser session with
    a 256-bit session id and an independent 256-bit CSRF token, replies `303 See Other` to `/`
    with `Set-Cookie: pws_session=<hex>; Path=/; HttpOnly; SameSite=Strict` (no `Domain`, no
    `Max-Age` → session cookie). `Referrer-Policy: no-referrer` on every response keeps the
    token out of referrers. A wrong/used token gets a static 403 page, counted as `session`.
  - Sessions live in a small list in `wallet-service`; ids are stored as
    `Zeroizing<[u8; 32]>` and compared in constant time with `subtle` (linear scan over at most
    32 sessions, so no hashing of secrets is needed). Bounded to 32 sessions; the oldest is evicted. All are
    discarded at stop, so earlier-run cookies are rejected (FR-010).
  - CSRF: the CSRF token is embedded in `index.html` as `<meta name="csrf-token">` and sent by
    `app.js` as header `X-CSRF-Token` on **every** `/api/*` request (not only state-changing
    ones); checked in constant time. State-changing methods (`POST`, `PUT`, `DELETE`)
    additionally require `Origin` to equal `http://127.0.0.1:<port>` exactly.
- **Rationale**: Meets FR-002–FR-004, FR-008–FR-010. Requiring the custom header on reads as
  well blocks cross-site reads by construction (a cross-site page cannot set custom headers
  without a CORS preflight, which the service never approves) and makes the API rule uniform.
  `__Host-`/`Secure` cookie prefixes are not used because plain HTTP on loopback cannot
  reliably carry `Secure` cookies across browsers; `HttpOnly` + `SameSite=Strict` + peer-UID
  check + Host check cover the threats.
- **Alternatives**: Token in `localStorage`/`Authorization` header (rejected: FR-004 requires a
  credential inaccessible to page scripts). Double-submit cookie CSRF (rejected: the
  synchronizer token bound to the server-side session is simpler and stronger).

## R7. Request protection pipeline and response headers

- **Decision**: Fixed order per connection/request, each failure ending the request with a
  minimal generic body and a counted reason:
  1. peer UID (R5) → close; 2. size limits while reading (FR-013) → 413/431;
  3. `Host` exactly `127.0.0.1:<port>` (FR-007) → 403; 4. route; 5. session (except
  `/launch/*`, static assets, and `/` which then serves the "open the launch address" page)
  → 401; 6. `X-CSRF-Token` on `/api/*` → 403; 7. `Origin` on state-changing methods → 403;
  8. suspend check (R9) then handler.
  Every response carries:
  `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`,
  `Connection: close`. No CORS headers are ever sent.
- **Rationale**: Host check before routing defeats DNS rebinding (FR-007). `form-action
  'none'`: the UI submits via `fetch`, never native form posts, which is stricter than
  `'self'`. `no-store` on everything (assets are tiny) satisfies FR-033 without per-route logic.
- **Alternatives**: Per-route header sets (rejected: more code, easy to forget one route).

## R8. Where wallet files live and how the service finds them

- **Decision**: Wallet directory `$XDG_DATA_HOME/passwsync/wallets/` (fallback
  `~/.local/share/passwsync/wallets/`), created with mode 0700; each wallet is
  `<name>.pwsw` written through `vault-storage-file::FileStorage` (atomic, 0600). Listing reads
  the directory on each `/api/state` and treats as a wallet every entry that: is a regular
  file (via `symlink_metadata`; symlinks are skipped), ends in `.pwsw`, and whose stem is a
  valid wallet name (R10). Temp files (`.<name>.tmp-*`, hidden) and anything else are ignored.
  A file copied in by the person while the service runs appears on the next listing. Creation
  checks name validity and non-existence under the registry lock before the first save; the
  service is the only writer during a run (spec assumption), and the instance lock (R12)
  prevents a second service.
- **Rationale**: XDG conventions (spec assumption), one file per wallet (FR-014), the file name
  is the display name (key entity "Wallet (file)"). A dedicated extension prevents unrelated
  files from appearing. Scanning on demand avoids inotify and a background watcher.
- **Alternatives**: An index/manifest file (rejected: second source of truth). inotify
  (rejected: complexity, no requirement for push updates).

## R9. Idle auto-lock and suspend detection clocks

- **Decision**: An `ElapsedClock` port returns two durations: monotonic (`CLOCK_MONOTONIC`,
  stops during suspend) and boot time (`CLOCK_BOOTTIME`, includes suspend), both via
  `rustix::time::clock_gettime`. Idle timers use monotonic time since the last deliberate
  action. Suspend detection: the service remembers `boottime − monotonic` at the last check; if
  it grew by more than **5 s**, the computer was suspended → lock all wallets. The check runs
  before every request handler and in the sweeper thread. The sweeper waits on a `Condvar`
  with a 15 s timeout (no busy polling, SC-008) and locks wallets whose idle time ≥ timeout
  (SC-004 bound: ≤ 15 s late). Deliberate actions = every `/api/wallets/{name}/...` operation
  (unlock, search, get, field, add, update, delete); `GET /api/state` (status/list polling) never touches timers (FR-020).
- **Rationale**: `CLOCK_BOOTTIME − CLOCK_MONOTONIC` measures exactly the time spent suspended
  and, unlike the wall clock, is immune to manual clock changes and NTP steps; it is the
  precise form of the spec's "wall clock advanced more than the monotonic clock" (FR-020a).
  Any false positive only locks wallets (safe direction).
- **Alternatives**: `SystemTime` vs `Instant` (rejected: wall-clock jumps cause spurious or
  missed detection). logind `PrepareForSleep` over D-Bus (rejected: D-Bus dependency).

## R10. Wallet-name rules and URL encoding

- **Decision**: Valid name: 1–64 chars from `[A-Za-z0-9 _.-]`, not starting with `.`,
  not ending with a space (to avoid confusable names), case-sensitive (FR-015). Names appear in
  API paths percent-encoded; the adapter decodes `%XX` and rejects anything that does not
  decode to a valid name (so `/`, `..`, NUL are impossible). Path construction always uses
  `dir.join(format!("{name}.pwsw"))` after validation.
- **Rationale**: Safe-set validation eliminates path traversal by construction.

## R11. Configuration file, paths and device identifier

- **Decision**:
  - Config: `$XDG_CONFIG_HOME/passwsync/config` (fallback `~/.config/passwsync/config`),
    a minimal line format `key = integer`, `#` comments, keys `port` (1024–65535, default
    27471), `auto_lock_minutes` (1–240, default 15), `clipboard_clear_seconds` (5–300,
    default 30). Missing file → defaults. Unknown key, duplicate key, non-integer or
    out-of-range value, or a file/dir writable by group/others or not owned by the user →
    refuse to start (exit code 2) with a message naming the key/problem (FR-031a). The parser
    is ~40 lines in `passwsyncd`.
  - Device identifier: `$XDG_CONFIG_HOME/passwsync/device-id`, 32 lowercase hex chars
    (128 bits from `OsRng`) created on first run with mode 0600 (FR-006); validated through
    `DeviceId::new`; an unreadable/invalid file → refuse to start (never silently replaced,
    since change tracking for sync depends on it).
  - Runtime: `$XDG_RUNTIME_DIR/passwsync/` (0700) holding `launch-url` and `instance.lock`.
    If `XDG_RUNTIME_DIR` is unset the service refuses to start (no `/tmp` fallback).
  - Logging: stderr only (journald under systemd); no log file.
- **Rationale**: Three integers do not justify a TOML/serde config dependency; a strict,
  tiny parser that rejects anything unexpected is easier to audit. The format is a TOML
  subset, so a future switch is painless.
- **Alternatives**: `toml` crate (rejected: extra dependencies for three integers);
  environment variables (rejected: spec says only the config file).

## R12. Single instance, signals and shutdown

- **Decision**: Single instance via `rustix::fs::flock(LOCK_EX | LOCK_NB)` on
  `$XDG_RUNTIME_DIR/passwsync/instance.lock`, held for the process lifetime; `EWOULDBLOCK` →
  exit code 4 "already running" (FR-005). Signals: `signal-hook` (`iterator` feature) handles
  `SIGTERM`, `SIGINT`, `SIGHUP` on a dedicated thread: stop accepting, lock all wallets
  (zeroizing), delete the launch file, exit 0 (FR-030).
- **Rationale**: `flock` is released by the kernel on any exit (no stale lock files).
  `signal-hook` is the de-facto safe signal API for Rust (vetted, used by crossterm, tokio's
  ecosystem); registering async-signal-safe handlers ourselves would need `unsafe`.
- **Alternatives**: Port bind as instance lock (rejected: two configs with different ports
  would both run). PID files (rejected: stale-file races). `ctrlc` crate (rejected: less
  general; signal-hook is its underlying primitive anyway).

## R13. JSON mapping and secret hygiene in the adapter

- **Decision**: `serde_json` for API bodies. Request DTOs hold secret fields as
  `Zeroizing<String>` (zeroize `serde` feature); the master password is moved into
  `MasterPassword::new` and nothing keeps a copy (FR-021). Responses containing credential
  data are serialized into a `Zeroizing<Vec<u8>>` pre-sized from the field lengths × 6 + 256
  so serde_json does not reallocate (no unwiped intermediate copies). Error bodies use fixed
  codes and messages from `VaultError`'s fixed `Display` strings; nothing echoes input.
- **Rationale**: serde_json is the most-reviewed JSON implementation in Rust; zeroizing
  buffers plus `mlockall` keep plaintext out of swap and minimize residue.
- **Alternatives**: `application/x-www-form-urlencoded` handwritten (rejected: own parser for
  nested/escaped data is riskier than serde_json).

## R14. Logging

- **Decision**: A tiny `log` module in `passwsyncd` whose only entry point takes a closed
  `enum LogEvent` (Started{addr}, ProtectionsApplied, ProtectionFailed{which}, Unlocked{wallet},
  Locked{wallet, reason}, AutoLocked{wallet}, SuspendDetected, Rejected{counts by reason},
  ErrorClass{class}, Stopping). Rejection counters are aggregated and logged at most once per
  minute by the sweeper. No free-form string logging API exists (FR-033a, FR-032).
- **Rationale**: Making secret logging unrepresentable is simpler and stronger than review.
  No `log`/`tracing` dependency needed.

## R15. Clipboard handling (UI adapter)

- **Decision**: Copy uses `navigator.clipboard.writeText` (available: `http://127.0.0.1` is a
  secure context). After `clipboard_clear_seconds` (value from `/api/state`) or when the UI
  learns the wallet the value came from was locked (manual lock, or `/api/state` polling —
  every 5 s, every 1 s while a copied value is pending — showing it locked, or any 423
  response), `app.js` calls `readText()`; if it equals the copied value or
  reading fails/is denied, it writes `""` (FR-027). A visible countdown is shown while pending;
  the copy notice states that clearing works only while the page stays open. Revealed
  passwords are removed from the DOM after the same timeout, on lock, and on leaving the
  credential view (FR-027a); fetched secrets are kept only in local variables and overwritten
  with `""` when hidden. Password inputs are cleared right after submission.
- **Rationale**: The server cannot reach the desktop clipboard without a display-server
  dependency; the spec assigns clearing to the UI. Comparison avoids wiping something else the
  person copied meanwhile.
- **Alternatives**: Server-side clipboard via `arboard`/X11/Wayland (rejected: large
  dependency tree, display-server coupling, needs desktop session in the service).

## R16. Concurrency model

- **Decision**: `wallet-service::Service` is shared as `Arc<Service>`. Inside: a `Mutex`
  guarding the registry `BTreeMap<WalletName, Arc<WalletSlot>>` (held only briefly); per
  wallet a state `Mutex<Slot>` (held briefly; serializes mutations, FR-017) and an attempt
  `Mutex<()>` (serializes unlock attempts for that wallet); a create `Mutex<()>`
  (serializes wallet creation); a service-wide `Mutex<()>` for key derivation (R4); and a
  `Mutex<Sessions>`. Unlock: take attempt lock → if already unlocked return OK → read bytes
  → peek KDF config (cap, R4) → take KDF lock → `Vault::unlock` → briefly take the state
  lock to store the vault. Neither the registry map nor a state lock is held across a key
  derivation, so the wallet list and other wallets' requests continue meanwhile.
  Mutations (add, update, delete) call new additive vault-core methods
  `add_entry_saved` / `update_entry_saved` / `delete_entry_saved`, which apply the change,
  save through the storage port, and on save failure restore the exact previous record
  (data, timestamps, version vector) before returning the error (FR-023). See
  [contracts/vault-core-additions.md](contracts/vault-core-additions.md).
- **Rationale**: Bounded lock scopes; no async runtime. The existing vault-core API has no
  undo: re-applying an inverse operation would bump version vectors or leave a tombstone, so
  the in-memory state would not truly return to its previous value. Rollback of a single
  record belongs in the domain core, where the entry map is private; it duplicates at most one
  entry's fields briefly (zeroized on drop).
- **Alternatives**: `Vault::clone`/whole snapshot (rejected: duplicates all secret material
  per mutation; violates low-RAM and secret-minimization). Locking the wallet on save failure
  (rejected: forces a re-unlock and does not match FR-023's rollback). Inverse operations in
  the service (rejected: not an exact rollback, see above).

## R17. Testing strategy (TDD)

- **Decision**:
  - `wallet-service`: unit tests with `MemoryWalletDirectory` (fake port over `MemoryStorage`),
    `FakeElapsedClock` (settable monotonic/boot time), `FixedClock`, `KdfConfig::MINIMUM`.
    Covers name validation, create/unlock/lock, generic unlock error, KDF cap, idle lock,
    background vs deliberate activity, suspend lock, sessions (single-use launch, rotation,
    eviction, wrong run), CSRF constant-time check, rollback.
  - `passwsyncd` integration tests (`tests/`): start the server on `127.0.0.1:0` in-process
    with a temp XDG tree, send raw HTTP over `TcpStream` (no HTTP client dependency): Host,
    Origin, CSRF, session, size, `Transfer-Encoding`, header limit, CSP/headers on every
    route, launch single-use, end-to-end create→add→restart→unlock; peer-UID parser unit tests
    on sample `/proc/net/tcp` text; config parser tests; secret-marker scan of captured
    stderr, launch dir and data dir (SC-006); asset scan for `http:`/`https:`/`//` references
    and inline `<script>`/`style=`/`on*=` (SC-006, FR-011).
  - Hardening: the start-up sequence is behind a `Hardening` trait in `passwsyncd`; tests
    inject a fake failing each step and assert refusal + exit code 3 (SC-009); a process test
    spawns the real binary under `sh -c 'ulimit -l 1024; exec …'` and asserts refusal; another
    reads `/proc/<pid>/status` (`VmLck` > 0) and `/proc/<pid>/limits` (core size 0) of a
    running instance.
  - `#[ignore]` release tests: SC-007 (10 000 entries list/search < 300 ms incl. JSON),
    SC-008 (VmRSS < 50 MB with one 1 000-entry wallet unlocked, idle CPU via
    `/proc/<pid>/stat` ticks over 30 s).
  - UI behaviour (keyboard operation, clipboard countdown, SC-001/SC-005) is validated by the
    manual quickstart scenarios; no browser automation dependency.

## R18. Dependency review (new direct dependencies)

Checked 2026-10-23 by resolving the candidate set offline in a scratch project with the
repository `deny.toml`: `cargo deny check` → advisories ok, bans ok, licenses ok, sources ok;
`cargo audit` (1351 advisories) → no vulnerabilities, only the already-accepted
RUSTSEC-2023-0089 (via `postcard`, from 001).

| Crate | Version | Used by | Purpose | License | Notes |
|-------|---------|---------|---------|---------|-------|
| `rustix` | 1.1.x (features `mm`,`process`,`fs`,`time`,`std`) | passwsyncd | mlockall, rlimits, prctl, flock, clocks, getuid | Apache-2.0 WITH LLVM-exception / Apache-2.0 / MIT | Bytecode Alliance; raw syscalls via `linux-raw-sys`; safe API |
| `httparse` | 1.10.x | passwsyncd | HTTP/1.x request head parsing | MIT/Apache-2.0 | zero deps, fuzzed, hyper's parser |
| `serde_json` | 1.0.x | passwsyncd | API bodies | MIT/Apache-2.0 | serde team |
| `signal-hook` | 0.3.x (`iterator`) | passwsyncd | SIGTERM/SIGINT/SIGHUP | MIT/Apache-2.0 | pulls `signal-hook-registry`, `libc` |
| `subtle` | 2.6 | wallet-service | constant-time token compare | BSD-3-Clause | already in tree via aes-gcm |
| `zeroize` (+`serde`) | 1.x | both | wiping DTOs | MIT/Apache-2.0 | already in tree |
| `rand_core` (+`getrandom`) | 0.6 | wallet-service, passwsyncd | tokens, device id | MIT/Apache-2.0 | already in tree |
| `serde` | 1.x | passwsyncd | DTO derive | MIT/Apache-2.0 | already in tree |
| `vault-storage-file` | path | passwsyncd | wallet files | MPL-2.0 | 001 |

New transitive crates: `linux-raw-sys`, `errno`, `bitflags`, `libc`, `signal-hook-registry`,
`itoa`, `memchr`, `zmij`. No networking crates other than `std::net` for the loopback
listener; no async runtime; no outbound connections anywhere (FR-001). The newer
`signal-hook` 0.4 was not selected while 0.3 is the mature line; revisit in 008.

Implementation re-check (T084, 2026-10-23, real workspace): `cargo deny check` → advisories
ok, bans ok, licenses ok, sources ok (only the pre-existing `syn` 2/3 duplicate warning from
001); `cargo audit` → no vulnerabilities, only the accepted RUSTSEC-2023-0089. Crates added to
`Cargo.lock`: `rustix` 1.1.5, `linux-raw-sys`, `errno`, `bitflags`, `httparse`, `serde_json`,
`itoa`, `memchr`, `zmij`, `signal-hook` 0.3.18, `signal-hook-registry` (`libc` was already
present), plus `windows-sys`/`windows-link`, which appear only as Windows-target dependencies
of `errno`/`rustix` and are never compiled on Linux. No `deny.toml` change was needed.

## R19. Exit codes and CLI

- **Decision**: `passwsyncd` runs in the foreground (the systemd user unit from 006
  backgrounds it); flags `--help`, `--version` only. Exit codes: 0 normal stop, 2 config/paths
  error, 3 protection failed, 4 already running or port unavailable, 1 other fatal error. The
  service never prints the token; it logs the launch-file *path*. Opening the browser is left
  to the person/packaging (`xdg-open "$(cat …/launch-url)"`).
- **Rationale**: Minimal surface; spec assumption leaves start-at-login and browser opening to
  packaging.

All Technical Context unknowns are resolved; no NEEDS CLARIFICATION remains.
