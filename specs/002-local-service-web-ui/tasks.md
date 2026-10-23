# Tasks: Local Service with Web UI

**Input**: Design documents from `/specs/002-local-service-web-ui/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (http-api.md, host-runtime.md, vault-core-additions.md), quickstart.md
**Tests**: MANDATORY (Constitution III, TDD). Every implementation task is preceded by a test task that MUST be run and seen to FAIL (red) before the implementation task starts. Refactor with tests green.
**Organization**: By user story. Within P1, US6 (transport protection) is built first because every other story is served through it.

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repo root. `WS` = `crates/wallet-service`, `PD` = `crates/passwsyncd`, `VC` = `crates/vault-core`.
- Test tasks write the test only (red); the next numbered implementation task makes it green.

---

## Phase 1: Setup

- [X] T001 Add `crates/wallet-service` and `crates/passwsyncd` to workspace `members` and add shared dependency versions (`rustix` 1.1 features `mm,process,fs,time`; `httparse` 1.10; `serde_json` 1; `signal-hook` 0.3; `subtle` 2.6) in `Cargo.toml`
- [X] T002 [P] Create `crates/wallet-service/Cargo.toml` (deps: vault-core, zeroize, rand_core, subtle; `testkit` feature; `[lints] workspace = true`) and empty `crates/wallet-service/src/lib.rs`
- [X] T003 [P] Create `crates/passwsyncd/Cargo.toml` (deps: wallet-service, vault-core, vault-storage-file, rustix, httparse, serde, serde_json, signal-hook, zeroize, rand_core; `[lints] workspace = true`) and stub `crates/passwsyncd/src/main.rs`
- [X] T004 Verify `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` pass on the empty crates and that `unsafe_code = "forbid"` applies to both (`Cargo.toml`, crate manifests)

---

## Phase 2: Foundational (blocks all user stories)

### vault-core additions (contracts/vault-core-additions.md)

- [X] T005 [P] Write failing test `FailingStorage` fake contract in `crates/vault-core/tests/saved_mutations.rs` (fake fails `save` on demand; requires `testkit`)
- [X] T006 Implement `testkit::FailingStorage` (wraps a memory storage, configurable save failure) in `crates/vault-core/src/testkit.rs`
- [X] T007 [P] Write failing tests for `peek_kdf_config` (valid file returns config; bad magic, bad version, unknown kdf_id, out-of-range KDF params, oversize all return the same errors as `unlock`; never needs a password) in `crates/vault-core/tests/peek_kdf.rs`
- [X] T008 Implement `pub fn peek_kdf_config(bytes: &[u8]) -> Result<KdfConfig, VaultError>` reusing the parse steps of `unlock` in `crates/vault-core/src/format.rs` and re-export from `crates/vault-core/src/lib.rs`
- [X] T009 [P] Write failing tests for `add_entry_saved`, `update_entry_saved`, `delete_entry_saved`: success equals unsaved op + save; validation errors change nothing; on `FailingStorage` failure `all_records()` is identical before/after (fields, timestamps, `last_modified_by`, version vector; add leaves no tombstone) in `crates/vault-core/tests/saved_mutations.rs`
- [X] T010 Implement the three `*_saved` methods with exact record restore and zeroized temp copy in `crates/vault-core/src/vault.rs`
- [X] T011 Update 001 contract with the additive items in `specs/001-vault-core/contracts/vault-core-api.md` (required by contracts/vault-core-additions.md)

### wallet-service foundations

- [X] T012 [P] Write failing tests for `WalletName::parse` (1-64 chars `[A-Za-z0-9 _.-]`, no leading `.`, no trailing space, path traversal `../x`, `/`, NUL, empty, 65 chars rejected; byte ordering) in `crates/wallet-service/tests/name.rs`
- [X] T013 Implement `WalletName` in `crates/wallet-service/src/name.rs`
- [X] T014 [P] Write failing tests for `ServiceError` mapping from `VaultError` and service errors to the error codes in contracts/http-api.md (including generic `invalid_password_or_corrupted` message, KDF over cap -> `kdf_params_out_of_range`) in `crates/wallet-service/tests/error.rs`
- [X] T015 Implement `ServiceError` in `crates/wallet-service/src/error.rs`
- [X] T016 [P] Write failing tests for the `testkit` fakes `MemoryWalletDirectory` (list sorted, exists, storage) and `FakeElapsedClock` (settable monotonic/boottime) in `crates/wallet-service/tests/ports.rs`
- [X] T017 Implement ports `WalletDirectory`, `ElapsedClock` and the `testkit` fakes in `crates/wallet-service/src/ports.rs`; wire modules in `crates/wallet-service/src/lib.rs`

### passwsyncd foundations

- [X] T018 [P] Write failing tests for the config parser (defaults; `key = integer` with trailing comment; unknown key, duplicate key, bad syntax, out-of-range `port`/`auto_lock_minutes` (0 and 241)/`clipboard_clear_seconds` each produce `config: <key or line>: <problem>`; config permissions looser than 0600 rejected) in `crates/passwsyncd/tests/config.rs`
- [X] T019 Implement `Settings` and the hand parser in `crates/passwsyncd/src/config.rs`
- [X] T020 [P] Write failing tests for XDG path resolution and permission checks (creates 0700 dirs; existing dir/file with group/other bits or foreign owner -> exit-2 error naming the path; `XDG_RUNTIME_DIR` unset -> error; device-id created once as 32 lowercase hex + `\n` mode 0600, invalid file rejected, reused on second run; wallet listing ignores symlinks and invalid names) in `crates/passwsyncd/tests/paths.rs`
- [X] T021 Implement `paths.rs` (XDG dirs, permission checks, device id via OsRng -> `vault_core::DeviceId`) in `crates/passwsyncd/src/paths.rs`
- [X] T022 [P] Write failing tests for `FsWalletDirectory` (list `<name>.pwsw` regular files only, `exists`, `storage` returns `FileStorage` at `<dir>/<name>.pwsw`, new files 0600) in `crates/passwsyncd/tests/fs_dir.rs`
- [X] T023 Implement `FsWalletDirectory` in `crates/passwsyncd/src/fs_dir.rs`
- [X] T024 [P] Write failing test for `OsElapsedClock` (monotonic non-decreasing; boottime >= monotonic) in `crates/passwsyncd/tests/clock.rs`
- [X] T025 Implement `OsElapsedClock` with `rustix` `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME` in `crates/passwsyncd/src/clock.rs`
- [X] T026 [P] Write failing tests for the closed `LogEvent` enum (every variant renders exactly the contract text; no variant accepts free-form strings; rejection counters aggregate, emit at most once/minute only when non-zero, then reset) in `crates/passwsyncd/tests/log.rs`
- [X] T027 Implement `LogEvent`, stderr writer and `AtomicU64` rejection counters in `crates/passwsyncd/src/log.rs`

**Checkpoint**: vault-core additions, ports, config, paths, directory, clock, logger ready.

---

## Phase 3: User Story 6 - Only the local person's browser can use the service (P1)

**Goal**: Hardened loopback HTTP server with launch-token -> session cookie, Host/Origin/CSRF/session/peer checks, CSP and bounds; host process hardening (FR-001..FR-013 incl. FR-007a, FR-028..FR-031, FR-031a, FR-032, FR-033).
**Independent Test**: Scenario E and A: foreign Host/Origin, missing CSRF/session, oversize requests and failed protections are all refused without data; protections failing means exit 3.

### Tests (red first)

- [X] T028 [P] [US6] Write failing tests for `LaunchToken`/`Sessions` (random 32 bytes; single-use exchange rotates token; wrong token fails in constant time; `authenticate(cookie)`; `check_csrf`; max 32 sessions, oldest evicted; fresh state per `Sessions::new`) in `crates/wallet-service/tests/sessions.rs`
- [X] T029 [P] [US6] Write failing tests for `Hardening` with a fake (each of core-dumps, non-dumpable, memlock-limit, mlockall failure -> start-up aborts with exit 3 naming the protection, and nothing else (no bind, no launch file) happens after the failure; order is normative; wallets never unlocked before protections applied) in `crates/passwsyncd/tests/hardening.rs`
- [X] T030 [P] [US6] Write failing real-process test: run the built binary under `ulimit -l 1024` -> exit 3, stderr `protection failed: memlock-limit`, no launch file (SC-009) in `crates/passwsyncd/tests/hardening_process.rs`
- [X] T031 [P] [US6] Write failing request-parser tests (`httparse`-based: header block > 16 KiB -> 431; > 48 headers; `Transfer-Encoding` -> 400; missing/oversize `Content-Length` > 8 MiB -> 413; 10 s read timeout; one request per connection) in `crates/passwsyncd/tests/http_limits.rs`
- [X] T032 [P] [US6] Write failing guard tests over raw `TcpStream` against a test server: foreign/missing Host -> 403 (checked before routing); no/stale cookie -> 401; missing/invalid CSRF -> 403 (constant time compare); POST/PUT/DELETE with missing or foreign Origin -> 403; unknown method -> 405; rejection bodies are fixed text and never echo input; each reason increments its counter; no wallet data and no state change on any rejection (SC-003) in `crates/passwsyncd/tests/http_guards.rs`
- [X] T033 [P] [US6] Write failing launch/session flow tests (`GET /launch/{token}` valid -> 303 to `/` with `Set-Cookie: pws_session=<64 hex>; Path=/; HttpOnly; SameSite=Strict`, launch file rewritten with new token; reuse of old token -> 403 static page; `GET /` with session returns `index.html` containing `<meta name="csrf-token">`, without session returns static instructions page; sessions invalid after restart) in `crates/passwsyncd/tests/launch.rs`
- [X] T034 [P] [US6] Write failing header tests (every response, including errors and static assets, carries the exact CSP, nosniff, no-referrer, no-store, X-Frame-Options, COOP, CORP, Connection: close; no `Access-Control-*` ever; JSON content type) in `crates/passwsyncd/tests/http_headers.rs`
- [X] T035 [P] [US6] Write failing peer-UID tests (`/proc/net/tcp` parser on fixture text: socket owned by service UID accepted, other UID or unknown -> connection closed, reason `peer`; IPv4 loopback only) in `crates/passwsyncd/tests/peer.rs`
- [X] T036 [P] [US6] Write failing start-up tests (second instance -> exit 4 via `flock`; port busy -> exit 4; invalid args -> usage + exit 2; `--help`/`--version` exit 0; listener bound only to `127.0.0.1`; launch file mode 0600 content `http://127.0.0.1:<port>/launch/<64 hex>\n`, deleted on stop; device-id created on first run and reused, FR-005/FR-006) in `crates/passwsyncd/tests/startup.rs`
- [X] T037 [P] [US6] Write failing shutdown test (SIGTERM/SIGINT/SIGHUP -> all wallets locked, launch file deleted, `stopping` logged, exit 0; FR-030) in `crates/passwsyncd/tests/shutdown.rs`
- [X] T038 [P] [US6] Write failing log-scan and asset-scan tests (marker password/title never appear in stderr, runtime dir, config dir; launch file holds only the URL; embedded assets contain no `http(s)://` to other origins, no `@import`, no external `src`/`href`; SC-006, FR-012, FR-032, FR-033a) in `crates/passwsyncd/tests/scans.rs`

### Implementation

- [X] T039 [US6] Implement `LaunchToken`, `BrowserSession`, `Sessions` in `crates/wallet-service/src/sessions.rs` (makes T028 green)
- [X] T040 [US6] Implement `Hardening` trait plus `rustix` implementation (`RLIMIT_CORE`=0, `PR_SET_DUMPABLE`=0, `RLIMIT_MEMLOCK` >= 256 MiB or unlimited, `mlockall(CURRENT|FUTURE)`) and fake in `crates/passwsyncd/src/hardening.rs` (T029, T030)
- [X] T041 [P] [US6] Implement request parsing and bounds (`httparse`, 10 s timeout, size caps, zeroizing body buffer) in `crates/passwsyncd/src/http/request.rs` (T031)
- [X] T042 [P] [US6] Implement response writer with the mandatory security headers on every response and fixed-text rejection bodies in `crates/passwsyncd/src/http/response.rs` (T034)
- [X] T043 [P] [US6] Implement `/proc/net/tcp` peer-UID lookup in `crates/passwsyncd/src/peer.rs` (T035)
- [X] T044 [US6] Implement guard pipeline (peer -> Host -> route/method -> session -> CSRF -> Origin, rejection counters) in `crates/passwsyncd/src/http/guard.rs` (T032)
- [X] T045 [US6] Implement TCP listener, fixed 4-worker pool with 512 KiB stacks, one request per connection in `crates/passwsyncd/src/http/server.rs`
- [X] T046 [US6] Implement launch/page routes (`/launch/{token}`, `/`, `/static/*`, 403 and instructions pages; atomic rewrite of `launch-url` on each exchange) in `crates/passwsyncd/src/http/pages.rs` (T033); create placeholder embedded `crates/passwsyncd/ui/index.html`, `app.js`, `app.css`, `icon.svg` and `crates/passwsyncd/src/assets.rs` using `include_bytes!`
- [X] T047 [P] [US6] Implement `signal-hook` shutdown thread in `crates/passwsyncd/src/signals.rs` that locks all wallets, deletes the launch file and logs `stopping` before exit 0 (T037)
- [X] T048 [US6] Implement `main.rs` start-up sequence in the normative order (args, hardening, paths/config/device-id, instance lock, bind, launch token + file, threads, log) and exit codes 0-4 in `crates/passwsyncd/src/main.rs` (T030, T036, T038). Note: the sequence lives in `crates/passwsyncd/src/app.rs` (library) so tests can run it in-process with a fake `Hardening` (this machine's hard memlock limit is 8 MiB, so the real binary can only be exercised up to the hardening refusal); `main.rs` calls `app::run` with `Deps::production()`

**Checkpoint**: service starts hardened, serves only to the local user's browser session; no wallet routes yet.

---

## Phase 4: User Story 1 - Create a wallet and add credentials from the browser (P1) MVP

**Goal**: Create a wallet (FR-015), list wallets (FR-016), add a credential (FR-022, FR-023) from the browser; wallet saved encrypted atomically.
**Independent Test**: Quickstart Scenario B steps 1-2: create `Personal`, add `GitHub`; file exists mode 0600 and `grep -c GitHub` is 0.

### Tests (red first)

- [X] T049 [P] [US1] Write failing `Service` tests with fakes: create (validation order name, mismatch, length < 12, exists; nothing written on failure; leaves wallet unlocked; password wiped), `list`, add entry saved to the directory (`KdfConfig::MINIMUM`) in `crates/wallet-service/tests/create_add.rs`
- [X] T050 [P] [US1] Write failing HTTP API tests for `GET /api/state`, `POST /api/wallets` (201, `invalid_name`, `password_mismatch`, `password_too_short`, `wallet_exists`), `POST /api/wallets/{name}/entries` (201 with 32-hex id, `empty_title`, `field_too_large`, `wallet_locked` 423, `wallet_not_found` 404), unknown JSON field -> `bad_request`, and that the file on disk is encrypted with no plaintext marker in `crates/passwsyncd/tests/api_create_add.rs`
- [X] T051 [P] [US1] Write failing UI static test that `index.html` has create-wallet form (name, password, confirm), wallet list and add-credential form with labelled inputs, no inline script/style, in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T052 [US1] Implement `Service`/`WalletSlot` registry (lazy slots, create, list, add via `add_entry_saved`, KDF gate) in `crates/wallet-service/src/registry.rs` (T049)
- [X] T053 [US1] Implement API DTOs (`deny_unknown_fields`, `Zeroizing` fields), JSON error mapping and routes `GET /api/state`, `POST /api/wallets`, `POST /api/wallets/{name}/entries` in `crates/passwsyncd/src/http/api.rs` (T050)
- [X] T054 [US1] Implement UI create-wallet, wallet list and add-credential views in `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/app.css` (T051); keyboard operable with visible focus (FR-031b)

**Checkpoint**: MVP - create a wallet and add a credential end to end.

---

## Phase 5: User Story 2 - Unlock once, use all day (P1)

**Goal**: Unlock with master password once per run; unlocked state shared across tabs and reloads; restarts start locked (FR-017, FR-018, FR-021, FR-023 memory budget).
**Independent Test**: Scenario B steps 3-5.

### Tests (red first)

- [X] T055 [P] [US2] Write failing `Service` tests: unlock correct/wrong password (generic error, stays locked), already unlocked returns without KDF, `peek_kdf_config` cap 131 072 KiB refuses before Argon2, KDF gate serializes concurrent unlocks, per-wallet attempts serialized, restart (new `Service`) starts all locked, format errors map to their classes in `crates/wallet-service/tests/unlock.rs`
- [X] T056 [P] [US2] Write failing HTTP tests for `POST /api/wallets/{name}/unlock` (200, 422 `invalid_password_or_corrupted` exact message, `kdf_params_out_of_range`, 404, 400 `invalid_name`), state shows `unlocked` after reload with a second session/cookie, no password in any response in `crates/passwsyncd/tests/api_unlock.rs`
- [X] T057 [P] [US2] Write failing UI static test for unlock prompt shown only for locked wallets and not shown for unlocked ones in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T058 [US2] Implement unlock with kdf cap, gate, wipe of password in `crates/wallet-service/src/registry.rs` (T055)
- [X] T059 [US2] Add unlock route in `crates/passwsyncd/src/http/api.rs` (T056)
- [X] T060 [US2] Add unlock prompt and 5 s `/api/state` polling (background, no timer reset) in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html` (T057)
- [X] T089 [P] [US2] Write failing tests for wallet files that are corrupted, truncated or of an unsupported version (listed by name, unlock returns the vault-core error class, other wallets unlock normally) and for a wallet file deleted or replaced while unlocked (next save rewrites it atomically, no merge) in `crates/wallet-service/tests/edge_files.rs` and `crates/passwsyncd/tests/fs_dir.rs`
- [X] T090 [US2] Implement tolerant listing and the unlocked-slot-survives-file-removal behaviour in `crates/wallet-service/src/registry.rs` and `crates/passwsyncd/src/fs_dir.rs` (T089). Note: already provided by T052/T023 (listing unions unlocked slots; every save goes through atomic `FileStorage`; listing skips nothing but non-wallet names), so T089's tests needed no new production code

---

## Phase 6: User Story 3 - Manage and find credentials (P2)

**Goal**: View, edit, delete, search credentials; list never carries passwords (FR-022, FR-024, FR-025, FR-033).
**Independent Test**: Scenario C first paragraph; SC-007 perf.

### Tests (red first)

- [X] T061 [P] [US3] Write failing `Service` tests for view entry (no password), update, delete, search (empty query = full list, ordering as vault-core), save failure via `FailingStorage` leaves memory and file unchanged in `crates/wallet-service/tests/manage.rs`
- [X] T062 [P] [US3] Write failing HTTP tests for `POST .../search`, `GET .../entries/{id}` (no password, Unix seconds timestamps), `PUT`, `DELETE` (200 `{}`), 404 `entry_not_found` for bad id, 423 when locked, 500 `storage_error` on failed save, and `Cache-Control: no-store` in `crates/passwsyncd/tests/api_manage.rs`
- [X] T063 [P] [US3] Write failing `#[ignore]` release perf test (10 000 entries list/search < 300 ms server side, SC-007) in `crates/passwsyncd/tests/perf.rs`
- [X] T064 [P] [US3] Write failing UI static test for edit form, delete confirmation, search box in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T065 [US3] Implement view/update/delete/search in `crates/wallet-service/src/registry.rs` (T061)
- [X] T066 [US3] Add search/get/put/delete routes in `crates/passwsyncd/src/http/api.rs` (T062, T063)
- [X] T067 [US3] Add list/search/edit/delete views with confirmation in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.css` (T064)

---

## Phase 7: User Story 4 - Copy a password safely (P2)

**Goal**: Reveal/copy username or password via per-field route; browser clears clipboard after timeout and hides revealed password (FR-026, FR-027, FR-027a, SC-005).
**Independent Test**: Scenario C second paragraph.

### Tests (red first)

- [X] T068 [P] [US4] Write failing `Service` tests for `field(password|username)` returns one value, invalid field name rejected, locked -> `WalletLocked` in `crates/wallet-service/tests/field.rs`
- [X] T069 [P] [US4] Write failing HTTP tests for `POST .../entries/{id}/field` (200 `{value}`, `bad_request`, 423, no-store, password appears only in this route) in `crates/passwsyncd/tests/api_field.rs`
- [X] T070 [P] [US4] Write failing UI static test that `app.js` uses `clipboard_clear_seconds` from `/api/state`, has countdown element, clears clipboard on timeout, on lock, on page hide, and hides revealed passwords after the timeout/on lock/on leaving the view in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T071 [US4] Implement field retrieval in `crates/wallet-service/src/registry.rs` (T068)
- [X] T072 [US4] Add field route with pre-sized zeroizing response buffer in `crates/passwsyncd/src/http/api.rs` (T069)
- [X] T073 [US4] Add reveal/copy buttons, countdown, clipboard clearing, auto-hide in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.css` (T070)

---

## Phase 8: User Story 5 - Lock and auto-lock (P2)

**Goal**: Manual lock/lock-all, idle auto-lock via sweeper, lock on suspend, lock on stop (FR-019, FR-020, FR-020a, FR-030, SC-004).
**Independent Test**: Scenario D.

### Tests (red first)

- [X] T074 [P] [US5] Write failing `Service` tests with `FakeElapsedClock`: lock/lock-all idempotent and zeroize; sweep locks at `monotonic - last_activity >= auto_lock`; deliberate actions reset idle, `state` polling does not; `check_suspend` locks all when `boottime - monotonic` offset grows > 5 s; operations on locked wallet -> `WalletLocked` in `crates/wallet-service/tests/lock.rs`
- [X] T075 [P] [US5] Write failing HTTP tests for `POST .../lock`, `POST /api/lock-all` (`{locked:[...]}`), 423 afterwards, suspend check runs before every handler in `crates/passwsyncd/tests/api_lock.rs`
- [X] T076 [P] [US5] Write failing test that the sweeper thread runs every 15 s, logs `locked <wallet> (idle|suspend)` and the aggregated rejection line, and does not busy-poll in `crates/passwsyncd/tests/sweeper.rs`
- [X] T077 [P] [US5] Write failing `#[ignore]` release memory/idle-CPU test (1 000-entry wallet unlocked, RSS < 50 MB, SC-008) in `crates/passwsyncd/tests/perf.rs`. Note: placed in its own test binary `crates/passwsyncd/tests/perf_memory.rs` so the measured process holds only this scenario (in `perf.rs` the 10 000-entry test inflated RSS)
- [X] T078 [P] [US5] Write failing UI static test for lock buttons, locked-state rendering and clipboard clear on lock in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T079 [US5] Implement lock, lock_all, sweep, check_suspend, activity tracking in `crates/wallet-service/src/registry.rs` (T074)
- [X] T080 [US5] Add lock routes and pre-handler suspend check in `crates/passwsyncd/src/http/api.rs` and `crates/passwsyncd/src/http/server.rs` (T075)
- [X] T081 [US5] Add sweeper thread in `crates/passwsyncd/src/main.rs` (T076, T077). Note: lives in `crates/passwsyncd/src/sweeper.rs`, started by `app.rs` (start-up moved to the library so in-process tests can drive it; `main.rs` only calls `app::run`)
- [X] T082 [US5] Add lock controls and locked rendering in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html` (T078)

---

## Phase 9: Polish & Cross-Cutting

- [X] T083 [P] Write end-to-end log-scan test running create/unlock/add/copy/lock with markers and scanning captured stderr, runtime, config dirs (SC-006, FR-033a) by extending `crates/passwsyncd/tests/scans.rs`, then fix any leak found. Result: no leak found (stderr, runtime dir, config dir and the wallet file are marker-free)
- [X] T084 [P] Run dependency review: `cargo deny check` and `cargo audit`; only RUSTSEC-2023-0089 remains accepted; update `deny.toml` only with a written reason for any new license/advisory entry. Result: deny advisories/bans/licenses/sources ok, audit clean apart from RUSTSEC-2023-0089; no `deny.toml` change (recorded in research.md R18)
- [X] T085 [P] Run `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`; fix findings in the affected files
- [X] T086 [P] Add README section on build, `ulimit -l 262144`, launch-url usage, config keys in `README.md`
- [ ] T087 Validate Quickstart: `cargo test --workspace`, `cargo test --workspace --release -- --ignored`, then Scenarios A-F from `specs/002-local-service-web-ui/quickstart.md` (browser steps manual); record results in the PR description
  - NOT COMPLETE (cannot be finished in this environment). Done: `cargo test --workspace` (282 passed, 0 failed), `cargo test --workspace --release -- --ignored` (all 5 pass: SC-007 10 000 entries < 300 ms, SC-008 RSS < 50 MB and idle CPU <= 5 ticks/30 s, plus 001 perf), Scenario A part 1 (`ulimit -l 1024` -> `protection failed: memlock-limit (limit-too-low)`, exit 3, no launch file), Scenario E and F via the automated in-process tests (`http_guards`, `http_limits`, `scans`). Remaining: Scenario A part 2 and a live Scenario E need the real binary running, which needs `RLIMIT_MEMLOCK` >= 256 MiB, but this machine's hard limit is 8 MiB (raising it needs root); Scenarios B, C, D (and the keyboard/clipboard checks) need a person in a real browser. There is also no PR to record results in, because committing/pushing was out of scope.
- [ ] T088 Verify success criteria SC-001..SC-009 each map to a passing test or recorded manual scenario; confirm no unsafe code and no new network-facing dependency
  - NOT COMPLETE: automated mapping verified, but SC-001 and SC-005 depend on manual Scenarios B/C that are still pending under T087. Mapping: SC-001 -> Scenario B (manual; API path covered by `api_create_add`); SC-002 -> `api_unlock::unlocked_state_is_shared_by_other_sessions_and_reloads`, `wallet-service unlock::a_new_service_starts_with_every_wallet_locked`, `launch::sessions_do_not_survive_a_restart`; SC-003 -> `http_guards`, `http_limits`, `peer`, `startup::listener_is_bound_to_ipv4_loopback_only`; SC-004 -> `wallet-service lock` (sweep/suspend), `sweeper`, `api_lock::suspend_*`; SC-005 -> Scenario C (manual; `ui_static::copy_reveal_countdown_and_clipboard_clearing` checks the code paths); SC-006 -> `scans` (assets, markers end to end); SC-007 -> `perf` (ignored, release); SC-008 -> `perf_memory` (ignored, release), `sweeper::sweeper_thread_sleeps_instead_of_busy_polling_and_stops_promptly`; SC-009 -> `hardening`, `hardening_process`. No `unsafe` anywhere (`#![forbid(unsafe_code)]` in every crate plus the workspace lint); no network-facing dependency added (`httparse` is a parser only; the listener is `std::net` on 127.0.0.1; the only outbound connect is the shutdown wake-up to our own loopback listener).

---

## Dependencies & Execution Order

- Phase 1 -> Phase 2 -> Phase 3 (US6) -> Phase 4 (US1) -> Phase 5 (US2) -> Phases 6, 7, 8 (US3, US4, US5, independent of each other once US2 done; they share `registry.rs`, `api.rs`, `app.js`, so run sequentially or merge carefully) -> Phase 9.
- Inside Phase 2: vault-core (T005-T011) is independent of wallet-service (T012-T017) and passwsyncd foundations (T018-T027); T014/T015 need T008 error variants; T017 needs T006.
- Always: test task (red) before its implementation task; commit nothing red.
- US1 depends on US6 (transport) and Foundational. US2 depends on US1 (a wallet to unlock). US3, US4 depend on US2. US5 depends on US2.

## Parallel Examples

- Phase 2: T005, T007, T009, T012, T016, T018, T020, T022, T024, T026 touch different files.
- US6 tests T028-T038 all different files and may be written together; implementations T041-T043, T047 are parallel.
- After US2: US3, US4, US5 test tasks (T061-T064, T068-T070, T074-T078) parallel across files (UI static test file `ui_static.rs` is shared, so split by test module if run concurrently).

## Implementation Strategy

- MVP = Phases 1-4 (setup, foundations, US6 protections, US1 create + add): the smallest secure, usable slice. Then US2 (daily use), then P2 stories.
- Deliver incrementally; at each checkpoint run `cargo test --workspace` and clippy.

## Phase 10: Convergence

- [X] T091 Write failing tests that an entry update without a password keeps the stored password and that the browser never fetches the password for an edit (red in `crates/wallet-service/tests/manage.rs`, `crates/passwsyncd/tests/api_manage.rs`, `crates/passwsyncd/tests/ui_static.rs`), then make the PUT body accept an explicit `keep_password` flag merged server-side in `crates/wallet-service/src/registry.rs` (`update_entry`) and `crates/passwsyncd/src/http/api.rs`, and drop the `/field` round trip in the edit submit handler of `crates/passwsyncd/ui/app.js` per FR-024 (contradicts)
- [X] T092 Write a failing UI static test that opening another credential (`showEntry`) and saving an edit both hide any revealed password, then call `hideRevealed()` from `showEntry` and after a successful edit save in `crates/passwsyncd/ui/app.js` per FR-027a and US4 AC (partial)
- [X] T093 Write a failing `Service` test that `list`, `create` and operations on another wallet complete while one wallet's key derivation is in progress (blocking storage or KDF gate fake in `crates/wallet-service/tests/unlock.rs`), then stop holding the per-wallet slot mutex and the registry map across the derivation in `crates/wallet-service/src/registry.rs`, keeping one KDF at a time and serialized attempts per wallet per Edge Cases "Several unlock attempts" (partial)
- [X] T094 Write a failing UI static test that the page polls faster while a copied value is pending clearance, then do so in `crates/passwsyncd/ui/app.js` so a server-side auto-lock or suspend lock clears the clipboard within seconds rather than at the 5 s poll boundary per FR-027 "immediately when the wallet is locked" (partial)

## Phase 11: Convergence

- [X] T095 Write a failing UI static test that the background status poll rebuilds the wallet and credential lists only when their data changed, then skip the DOM rebuild when nothing changed in `crates/passwsyncd/ui/app.js` (`renderWallets`, `renderEntries`, `refreshState`) and `crates/passwsyncd/tests/ui_static.rs`, so a keyboard-focused list control keeps focus while a copied value is pending clearance (FR-031b, FR-027 countdown) per FR-031b (partial)
