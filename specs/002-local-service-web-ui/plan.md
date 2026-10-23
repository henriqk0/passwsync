# Implementation Plan: Local Service with Web UI

**Branch**: `feat/002-local-service-web-ui` | **Date**: 2026-10-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-local-service-web-ui/spec.md`

## Summary

Build the first host application: `passwsyncd`, a per-user Linux daemon that listens only on
`127.0.0.1:27471` and serves an embedded vanilla HTML/CSS/JS UI for vault-core wallets:
create, list, unlock once per run, credential CRUD and search, reveal/copy with browser-side
clipboard clearing, manual lock, idle auto-lock and lock-on-suspend. The application logic
lives in a new I/O-free crate `wallet-service` (registry, sessions, auto-lock, ports); the
binary crate `passwsyncd` holds the adapters: a minimal `std::net` + `httparse` HTTP/1.1
server (one request per connection, fixed 4-worker pool, strict bounds), filesystem wallet
directory over `vault-storage-file`, XDG config/launch files, process hardening via `rustix`
(core dumps off, non-dumpable, `RLIMIT_MEMLOCK` ≥ 256 MiB check, `mlockall`), `signal-hook`
shutdown, a peer-UID check, and a closed-enum logger. Defense layers: loopback bind, peer UID,
exact Host, single-use 256-bit launch token → `HttpOnly; SameSite=Strict` session cookie,
per-session CSRF header on every API call, exact Origin on state changes, strict CSP, no
external assets. Two additive vault-core functions (`peek_kdf_config`, `*_saved` mutations
with exact rollback) support the locked-memory budget and FR-023.

## Technical Context

**Language/Version**: Rust stable, edition 2024, MSRV 1.85 (workspace setting)

**Primary Dependencies**: `vault-core`, `vault-storage-file` (001); new: `rustix` 1.1
(`mm`,`process`,`fs`,`time`), `httparse` 1.10, `serde_json` 1, `signal-hook` 0.3, `subtle` 2.6;
reused: `serde`, `zeroize` (+`serde`), `rand_core` (OsRng). No async runtime, no web framework,
no front-end toolchain (research R2, R18)

**Storage**: One vault-core encrypted file per wallet `<name>.pwsw` in
`$XDG_DATA_HOME/passwsync/wallets/` (0700/0600); config and device id in
`$XDG_CONFIG_HOME/passwsync/`; launch URL and instance lock in `$XDG_RUNTIME_DIR/passwsync/`
(research R8, R11)

**Testing**: `cargo test` — `wallet-service` unit tests with fakes (`MemoryWalletDirectory`,
`FakeElapsedClock`, `FixedClock`, `KdfConfig::MINIMUM`); `passwsyncd` integration tests over
raw `TcpStream`; fake `Hardening` for refusal paths plus real-process `ulimit` test;
`#[ignore]` release perf/memory tests; manual browser scenarios in quickstart (research R17)

**Target Platform**: Linux x86_64 desktop (AUR target), current Firefox/Chromium

**Project Type**: Local web service (daemon binary + application library) with embedded web UI

**Performance Goals**: List/search 10 000 entries rendered < 300 ms (SC-007); auto-lock ≤ 1 min
late (sweeper every 15 s, SC-004); clipboard cleared ≤ 2 s after timeout (SC-005)

**Constraints**: Loopback only, no outbound connections; idle RSS < 50 MB with one 1 000-entry
wallet unlocked, no busy polling (SC-008); all memory locked (`mlockall`), required
`RLIMIT_MEMLOCK` 256 MiB; one KDF at a time, wallet KDF memory cap 128 MiB; body ≤ 8 MiB,
headers ≤ 16 KiB; `unsafe_code` forbidden

**Scale/Scope**: One person per service; ~100 wallets; up to 10 000 credentials per wallet;
~6 screens/views in one page

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | Encrypted at rest; no plaintext to network/storage/logs/swap; vetted libs | PASS — wallets only via vault-core file adapter; loopback only | PASS — `mlockall` + non-dumpable + core dumps off, fail closed (R4); peer-UID, Host, session, CSRF, Origin, CSP layers (R5–R7); closed-enum logger (R14); zeroizing DTOs and pre-sized buffers (R13); passwords sent only by the per-field route |
| I. (P2P E2E) | P2P traffic E2E + mutually authenticated | N/A — no P2P in this feature | N/A |
| II. Simplicity | Simplest equal option; complexity justified | PASS — no framework/runtime/toolchain | PASS — std + `httparse` server, vanilla JS, hand parser for 3-key config; two crates justified below |
| III. TDD | Tests first | PASS — fakes for every port; raw-HTTP tests | PASS — R17 strategy; tasks will order tests first |
| IV. Hexagonal | Core free of infra; ports/adapters; fakes | PASS — new crates depend inward on vault-core | PASS — `wallet-service` has ports `WalletDirectory`, `ElapsedClock`; HTTP, FS, clocks, hardening, signals, clipboard (UI) are adapters; vault-core additions are pure domain |
| V. Resource Efficiency | Deliberate allocation; secrets wiped; measured | PASS | PASS — fixed thread pool, 512 KiB stacks, bounded bodies, one KDF at a time, SC-008 test |
| VI. Decentralization | No central server | PASS — fully local, no accounts | PASS — device id persisted for future sync |
| Workflow | Minimal, vetted, reviewed deps | PASS | PASS — `cargo deny`/`cargo audit` clean on the candidate set (R18) |
| Roadmap globals | Offline, no accounts, master password only secret, FR-025a host obligations | PASS | PASS — FR-028–FR-031 implemented via `rustix`; session token is a local capability, not a login |

No unsafe code is introduced: all syscalls go through `rustix`'s safe API, so no isolated
unsafe crate is needed. Gates pass; deviations are listed in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/002-local-service-web-ui/
├── plan.md              # This file
├── research.md          # Phase 0 output (R1–R19)
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output (validation scenarios)
├── contracts/
│   ├── http-api.md             # routes, protection rules, JSON shapes, headers
│   ├── host-runtime.md         # CLI, exit codes, files, config, start-up, logging
│   └── vault-core-additions.md # peek_kdf_config, *_saved mutations
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks, not created here)
```

### Source Code (repository root)

```text
crates/
├── vault-core/                 # 001; + peek_kdf_config, *_saved, testkit::FailingStorage
├── vault-storage-file/         # 001; unchanged
├── wallet-service/             # NEW application layer (no I/O)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── name.rs             # WalletName validation
│   │   ├── ports.rs            # WalletDirectory, ElapsedClock (+ fakes behind `testkit`)
│   │   ├── registry.rs         # WalletSlot, Service: create/unlock/lock/sweep/suspend
│   │   ├── sessions.rs         # LaunchToken, BrowserSession, CSRF
│   │   └── error.rs            # ServiceError (maps VaultError + service errors)
│   └── tests/                  # use-case tests with fakes
└── passwsyncd/                 # NEW binary + adapters
    ├── src/
    │   ├── main.rs             # start-up sequence, exit codes
    │   ├── hardening.rs        # Hardening trait + rustix implementation
    │   ├── paths.rs            # XDG dirs, permissions, device id, launch file, instance lock
    │   ├── config.rs           # key = integer parser
    │   ├── fs_dir.rs           # FsWalletDirectory over vault-storage-file
    │   ├── clock.rs            # OsElapsedClock (monotonic/boottime)
    │   ├── peer.rs             # /proc/net/tcp peer-UID lookup
    │   ├── http/               # server.rs (accept/pool/limits), request.rs, response.rs,
    │   │                       # guard.rs (peer/host/session/csrf/origin), pages.rs (launch/static), api.rs (routes + DTOs)
    │   ├── assets.rs           # include_bytes! of ui/
    │   ├── signals.rs          # signal-hook shutdown thread
    │   └── log.rs              # closed LogEvent enum, rejection counters
    ├── ui/                     # index.html, app.js, app.css, icon.svg (no external refs)
    └── tests/                  # raw-HTTP integration, hardening, config, scans
```

**Structure Decision**: Extend the Cargo workspace with `crates/wallet-service` (application
core, I/O-free, reusable by the Android app in 007) and `crates/passwsyncd` (all adapters and
the executable). Dependencies point inward: `passwsyncd → wallet-service → vault-core`,
`passwsyncd → vault-storage-file → vault-core`. Workspace `members` gains both crates; the
workspace lints (`unsafe_code = "forbid"`) apply to both.

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Two new crates instead of one | Crate boundary enforces hexagonal inward dependencies; `wallet-service` is reused by 007 without desktop adapters | One crate with modules cannot stop application code from importing HTTP/OS code |
| Own minimal HTTP/1.1 handling (on `httparse`) | Exact control of header/body bounds, one request per connection, tiny dependency set and RSS | `axum`/`hyper`/`tokio` add an async runtime and dozens of crates; `tiny_http` has weaker bounds control and slow maintenance |
| Peer-UID check via `/proc/net/tcp` (spec FR-007a) | US6: other local OS users can reach loopback and read process args; cookies are not port-isolated | Session token alone is a single layer for a high-value target |
| Two additive vault-core APIs (`peek_kdf_config`, `*_saved`) | Locked-memory budget must be checked before Argon2; FR-023 needs exact rollback, which only the core can do on its private entry map | Service-side header parsing duplicates the format; inverse operations bump version vectors/leave tombstones; whole-vault clone duplicates all secrets |
| `signal-hook` dependency | FR-030 lock-before-exit on SIGTERM/SIGINT/SIGHUP without writing `unsafe` signal handlers | Hand-written `sigaction` requires `unsafe` (forbidden) |
