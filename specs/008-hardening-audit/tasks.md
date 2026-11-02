# Tasks: Hardening Audit

**Input**: Design documents from `/specs/008-hardening-audit/`
**Prerequisites**: plan.md (amendments A1-A3), spec.md (US1-US5, FR-001..FR-038, SC-001..SC-012), research.md (R1-R21), data-model.md, contracts/ (fuzz-harness.md, benchmarks.md, threat-model-structure.md, ci-workflow.md, gate-script.md), quickstart.md (H-1..H-14, CI-0..CI-3, M-1, D-1..D-4)
**Tests**: MANDATORY (Constitution III, TDD). Every implementation task is preceded by a test or checker task that MUST be run and seen to FAIL (red) before the implementation task starts; refactors run with tests green. A test task and its implementation task never run in parallel. For fuzz targets the red test is the `fuzz_<target>.rs` integration test (compile error or failure until `targets/<target>.rs` exists); for Python checkers it is the negative-fixture unit test; for `scripts/gate.sh` it is `scripts/tests/test_gate_selftest.py`. Every defect the audit finds gets a failing regression test BEFORE its fix (FR-017, R21).
**Organization**: Phase 1 setup; Phase 2 builds the std-only fuzz engine and the `vault-core` test entry points (blocks all stories); then US1 (P1, fuzz targets 1-16), US2 (P1, CI gate), US3 (P2, threat model), US4 (P2, benchmarks), US5 (P3, Android coverage: target 17, Android gate, device checks), Polish. Spec numbering is kept for labels.
**Rules for every task**: no new `unsafe` anywhere (the only `unsafe` stays in `crates/passwsync-ffi/src/memprotect.rs`); no third-party dependency (`crates/hardening` has an empty `[dependencies]`; only `hardening` itself may be added to `Cargo.lock`, amendment A1); no change to any valid wallet or wire encoding; no secret, wallet plaintext or leak marker in any output (fuzz seeds are synthetic, R9); product code changes only to reject invalid input or tighten a bound (FR-017); no network access in default-mode commands (`--frozen --offline`); NEVER `git commit` or push (roadmap global rule): this feature produces files only.

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repository root. Test tasks write the test only (red); the next numbered task makes it green.
- **(MANUAL)** = needs a maintainer, a reference laptop [M], a reference phone [D] or a hosted CI runner [CI]. Stays unchecked until a person runs it and records the result in `specs/008-hardening-audit/quickstart.md` ("pending" until then).
- **(ENV-BLOCKED)** = depends on a resource absent from this host: network (image digest, Arch Linux Archive date, `cargo install`), a CI runner, an Arch image, nightly Rust and `libfuzzer-sys` (not cached), Android SDK/NDK/device. Written and unit-tested against stubs/fixtures here; completes only where the resource exists. Never reported as PASS from this environment.
- Verification tags: **[H]** host-verifiable (the gate for this feature), **[CI]** hosted-runner-only, **[M]** reference laptop, **[D]** device-only.
- Measured 2026-10-30: rustc/cargo 1.99.1 (Arch package), `cargo-deny` 0.20.2 and `cargo-audit` 0.22.2 in `~/.cargo/bin` (use that path if absent from PATH), advisory DB in `~/.cargo/advisory-db` (last commit 2026-10-24), Python 3.14.8, `nm` present; absent: `proptest`/`arbitrary`/`libfuzzer-sys`, an Arch image, network.

---

## Phase 1: Setup

- [X] T001 Snapshot the baseline: run `cargo fmt --all --check`, `cargo clippy --frozen --offline --workspace --all-targets -- -D warnings` and `cargo test --frozen --offline --workspace`; record green, the test count, `sha256sum Cargo.lock` and `git status --porcelain` (PR description, no file). Everything later is compared with this baseline (SC-012)
- [X] T002 [P] Record tool availability: `command -v python3 nm xmllint`, `ls ~/.cargo/bin/cargo-deny ~/.cargo/bin/cargo-audit` with `--version`, `git -C ~/.cargo/advisory-db log -1 --format=%cs`, `cargo-deny` DB date, `docker images` (expect no Arch image), `ls ~/.cargo/registry/cache/*/ | grep -E 'proptest|arbitrary|libfuzzer'` (expect none). The absent items drive every ENV-BLOCKED flag (PR description, no file)
- [X] T003 Record amendment A1 (SC-012 = zero third-party lockfile entries; only the path package `hardening` is added), A2 and A3 in `specs/008-hardening-audit/spec.md` under "Plan amendments 2026-10-30" and reword SC-012 and FR-037 accordingly. Done when this task list was generated
- [X] T004 Create the empty directories `crates/hardening/src`, `crates/hardening/tests/targets`, `scripts/tests/fixtures`, `scripts/defects`, `docs`, `.github/workflows`, `fuzz/fuzz_targets`; confirm `git status` shows no change under any existing `crates/*/src`
- [X] T005 Create `crates/hardening/Cargo.toml` (`publish = false`, `[lints] workspace = true`, `[dependencies]` EMPTY, `[dev-dependencies]` = the workspace crates `vault-core`, `vault-storage-file`, `wallet-service`, `device-link`, `device-link-net`, `wallet-sync`, `host-runtime`, `passwsyncd`, `passwsync-ffi` by path with their existing `testkit` features) and an empty `crates/hardening/src/lib.rs` (doc comment only); add `"crates/hardening"` to `members` and `exclude = ["tools/uniffi-bindgen", "fuzz"]` in `Cargo.toml`; `cargo check --frozen --offline -p hardening` passes; `git diff main -- Cargo.lock` shows exactly one new `[[package]]` named `hardening` with no `source` and no `dependencies` (A1, FR-037)

**Checkpoint**: workspace builds with the empty crate; lockfile diff is the single path package.

---

## Phase 2: Foundational - std-only fuzz engine and test entry points (blocks all user stories; FR-001..FR-003, FR-005, FR-007, FR-008, FR-011)

**Goal**: a deterministic, seeded, panic/time/allocation-checked runner exists and is itself tested; `vault-core` exposes the production payload decoder to tests under `testkit` only.

- [X] T006 [P] Write unit tests in `crates/hardening/src/rng.rs` (`#[cfg(test)]`): SplitMix64 matches published reference vectors for seed 0 and a fixed seed; `Rng::for_iteration(seed, target, iter)` is pure and independent of earlier iterations; different targets or iterations give different streams; `DEFAULT_SEED == 0x5057_5359_4E43_0008`. Red: module absent
- [X] T007 Implement `crates/hardening/src/rng.rs` (SplitMix64, `fnv1a64`, `Rng::for_iteration` per research R2) and export `DEFAULT_SEED` and `pub mod rng` from `crates/hardening/src/lib.rs`; wrapping integer ops only. Makes T006 green
- [X] T008 [P] Write unit tests in `crates/hardening/src/mutate.rs`: each of the 9 mutators (BitFlip, BoundaryByte, Insert, Delete, Truncate, Duplicate, Splice, LengthField, VarintBoundary) plus `Rechunk` behaves as data-model §1 states; `LengthField` writes exactly `0, bound-1, bound, bound+1, max(width)` at the declared offset and width/endianness; the truncation sweep visits every length up to `min(len, 256)`; a mutated input never exceeds the target `input_cap`; the same `Rng` gives the same input. Red: module absent
- [X] T009 Implement `crates/hardening/src/mutate.rs` (`Seed`, `Field`, `Width`, `Mutation`, `mutate(seed, rng, cap)`, 1-4 mutations per input, iterations `0..n_seeds` unmutated). Makes T008 green
- [X] T010 [P] Write unit tests in `crates/hardening/src/oracle.rs`: `/proc/self/status` `VmSize`/`VmPeak` parser (fixture text, unreadable file fails closed), `classify` maps panic/time overrun/allocation growth over `bound + 4 MiB`/closed-error-kind violation to the right `Failure.kind`, coverage rule (`accepted >= 1 && rejected >= 1`, else `Coverage`). Red: module absent
- [X] T011 Implement `crates/hardening/src/oracle.rs` (`Verdict`, `Failure`, `FailureKind`, `/proc` readers, `catch_unwind(AssertUnwindSafe)` wrapper with quiet panic hook, `Instant` timing, no `unsafe`). Makes T010 green
- [X] T012 [P] Write unit tests in `crates/hardening/src/report.rs`: `FuzzConfig::from_env` (`PASSWSYNC_FUZZ_SEED` decimal and `0x` hex, `PASSWSYNC_FUZZ_ITERS` can raise but never lower the target minimum, `PASSWSYNC_FUZZ_ONLY`, `PASSWSYNC_FUZZ_TRACE`; a malformed value returns an error that names the variable); exact `FUZZ`, `FUZZ-TIME`, `FUZZ-FAIL` line formats from contracts/fuzz-harness.md; hex printing for binary inputs and `text:"..."` escaping (`\r \n \t \\ \" \xNN`) for HTTP and share text. Red: module absent
- [X] T013 Implement `crates/hardening/src/report.rs` (`FuzzConfig`, `TargetReport`, line formatters). Makes T012 green
- [X] T014 Write unit tests in `crates/hardening/src/runner.rs` with toy targets: a passing target reports counts and `PASS`; a panicking target stops at the FIRST failure and the line names target, seed and iteration; a slow target yields `TimeOverrun`; a target with no accepted (or no rejected) input fails `Coverage`; `PASSWSYNC_FUZZ_ONLY` runs exactly one iteration; two runs with the same seed give identical `FUZZ` lines and counts (SC-002); re-running the reported seed and iteration reproduces the failure (acceptance scenario 4). Red: module absent
- [X] T015 Implement `crates/hardening/src/runner.rs` (`Target` struct per data-model §1, `run(target)`: warm-up run of every seed, `baseline = VmSize`, per-iteration loop, watchdog thread with `AtomicU64` iteration that prints the failure line and `exit(101)` after 5x the time limit, stop at first failure, print report) and `pub mod` lines in `crates/hardening/src/lib.rs`. Makes T014 green; `cargo test -p hardening --lib` all green
- [X] T016 [P] Write `crates/vault-core/tests/testkit_payload.rs` (feature `testkit`): `testkit::encode_payload` then `testkit::decode_payload(version, plaintext)` round-trips for v1 and v2 wallets with 0, 1 and 50 entries, tombstones and histories; a trailing byte, a text field over 1 MiB and a duplicate id are rejected with `InvalidPasswordOrCorrupted`; `testkit::header_bytes` then `testkit::parse_header` round-trips the 63-byte header; `decode_payload` and the production `open_with_key` accept and reject the same plaintexts (run the same bytes through a sealed wallet). Red: entry points absent
- [X] T017 Refactor `crates/vault-core/src/format.rs`: split `open_with_key` into `decrypt` + `decode_plaintext(version, &[u8])` (pure refactor, no behaviour change); add `decode_payload`, `encode_payload`, `parse_header`, `header_bytes` to `crates/vault-core/src/testkit.rs` only (under the existing `#[cfg(feature = "testkit")]`, calling the same production `decode_plaintext`). Run `cargo test -p vault-core --features testkit` (all existing tests green; T016 green)
- [X] T018 Create `crates/hardening/tests/targets/mod.rs` (empty module list; each target task appends one `pub mod <target>;` line and a `#![allow(dead_code)]` for binaries that do not use every module) and document in its header the `pub fn target() -> Target` and `pub fn one_bytes(&[u8])` contract of contracts/fuzz-harness.md. `cargo test -p hardening --no-run` passes

**Checkpoint**: engine tested and green; `cargo test -p hardening --lib` and `cargo test -p vault-core --features testkit` pass; no product behaviour changed.

---

## Phase 3: User Story 1 - Hostile bytes never crash or exhaust the service (P1) - MVP

**Goal**: 16 of the 17 targets (the 17th, `ffi_args`, is US5) execute at least 10,000 deterministic inputs each (64 derived unlocks for `wallet_unlock`) with zero panics, time overruns, allocation-bound or value-bound violations, closed error kinds and round-trip oracles.

**Independent Test**: [H] run H-2 twice with the same seed (identical `FUZZ` lines, all green), then H-5 (injected defects are caught).

Each target pair is: first the `fuzz_<target>.rs` test (`#[test] fn fuzz_<target>() { runner::run(targets::<t>::target()) }`, red because `targets::<t>` does not exist), then `targets/<target>.rs` with `seeds()` from the project's own encoders (synthetic content only, R9), `one()` with the oracles of contracts/fuzz-harness.md, and `one_bytes()` for the optional cargo-fuzz target. Seeds explicitly include at-bound, one-below and one-above-bound cases from the spec Edge Cases.

### Wallet file (targets 1-3)

- [X] T019 [P] [US1] Write `crates/hardening/tests/fuzz_wallet_header.rs` (red). Target 1 oracle: `vault_core::peek_kdf_config`, `peek_format_version` and `testkit::parse_header` only return `MalformedFile`, `UnsupportedVersion`, `UnsupportedKdf` or `KdfParamsOutOfRange`; length under 79 or over 64 MiB is always `MalformedFile`; no key derivation is reachable; header round trip is strict (FR-010, FR-006)
- [X] T020 [US1] Implement `crates/hardening/tests/targets/wallet_header.rs` (seeds: v1/v2 wallets at `KdfConfig::MINIMUM` and default, each KDF parameter at range edges plus/minus one; file lengths 78 and 79 bytes, hand-assembled; add to `targets/mod.rs`). Green T019
- [X] T021 [P] [US1] Write `crates/hardening/tests/fuzz_wallet_payload.rs` (red). Target 2 oracle: `testkit::decode_payload` accepts or returns only `InvalidPasswordOrCorrupted`; accepted payloads have unique ids, text fields at most 1 MiB, versions within state, no trailing bytes; seeds round-trip byte-identically and accepted mutants re-encode to bytes that decode equal (postcard rule P); `VarintBoundary` mutations on (FR-011)
- [X] T022 [US1] Implement `crates/hardening/tests/targets/wallet_payload.rs` (seeds from `testkit::encode_payload`: 0, 1, 50 entries, tombstones, histories, a 1 MiB field and a 1 MiB+1 field (hand-assembled), v1 payloads; allocation bound 64 MiB + 1 MiB per nesting level). Green T021
- [X] T023 [P] [US1] Write `crates/hardening/tests/fuzz_wallet_unlock.rs` (red). Target 3 oracle: `Vault::unlock` with the correct synthetic password returns exactly `InvalidPasswordOrCorrupted` for every input that differs from its seed in salt, nonce, ciphertext or tag and returns no content; inputs rejected by the FR-010 header checks keep that check's error kind and are never derived; KDF-parameter bytes are checked by FR-010 only and never derived; at least 64 derived inputs (bounded by 4,096 attempts, else fail); time limit 10 s (FR-012, research R8)
- [X] T024 [US1] Implement `crates/hardening/tests/targets/wallet_unlock.rs` (seeds: sealed v1/v2 wallets at `KdfConfig::MINIMUM`, test password `"fuzz-only-password"`; `derived` counter in the report). Green T023

### Device link frames and handshakes (targets 4-11)

- [X] T025 [P] [US1] Write `crates/hardening/tests/fuzz_frame.rs` (red). Target 4 oracle: `device_link::wire::{decode_frame, frame_len, encode_frame}`; accepted body length in 1..=1024; consumed = 2 + len; `Ok(None)` only when bytes are fewer than the header or the body is incomplete; strict round trip (FR-013)
- [X] T026 [US1] Implement `crates/hardening/tests/targets/frame.rs` (seeds: bodies of 1, 512, 1023, 1024 and 1025 bytes (1025 hand-assembled) and concatenated frames; allocation bound 4 KiB). Green T025
- [X] T027 [P] [US1] Write `crates/hardening/tests/fuzz_hello.rs` (red). Target 5 oracle: `parse_hello` accepts only v1 and `parse_hello_versioned` only the 4 documented 6-byte values; strict round trip through `hello_versioned`; known magic with unknown version or kind and length plus/minus one rejected (FR-013)
- [X] T028 [US1] Implement `crates/hardening/tests/targets/hello.rs` (seeds: every valid (version, kind) Hello). Green T027
- [X] T029 [P] [US1] Write `crates/hardening/tests/fuzz_channel_payload.rs` (red). Target 6 oracle: `wire::Payload::{decode, decode_v2, decode_v3}` (v1 rejects 0x20/0x21/0x30/0x31, v2 rejects 0x30/0x31), strict round trip; `Channel::seal_any` then peer `Channel::open` of a mutated plaintext ends in a value or `ChannelError`, never a panic (FR-013)
- [X] T030 [US1] Implement `crates/hardening/tests/targets/channel_payload.rs` (seeds: every payload type of v1/v2/v3 via `Payload::encode`; real `testkit` channel pair). Green T029
- [X] T031 [P] [US1] Write `crates/hardening/tests/fuzz_discovery.rs` (red). Target 7 oracle: `discovery::decode_announce` accepts only 39 bytes with the right magic, port at least 1024 and id different from own; strict round trip (FR-013)
- [X] T032 [US1] Implement `crates/hardening/tests/targets/discovery.rs` (seeds: `encode_announce` with ports 1024 and 65535). Green T031
- [X] T033 [P] [US1] Write `crates/hardening/tests/fuzz_pairing_initiator.rs` (red). Target 8 oracle: `PairingInitiator::on_frame` fed a recorded genuine joiner transcript with one message mutated; the attempt ends failed or rejected, the registry gains no pin, no session exists, the code is consumed per 003 rules (state oracle `StateLeak`; FR-013)
- [X] T034 [US1] Implement `crates/hardening/tests/targets/pairing_initiator.rs` (live `testkit` SPAKE2 + Noise run recorded once per process; replay prefix so only the mutated message onward is recomputed if the 300 s budget is at risk, R10). The recorder lives in `targets/handshake.rs` (declared in `targets/mod.rs`, reached as `super::handshake`). Green T033
- [X] T035 [P] [US1] Write `crates/hardening/tests/fuzz_pairing_joiner.rs` (red). Target 9: same oracle through `PairingJoiner::on_frame` (FR-013)
- [X] T036 [US1] Implement `crates/hardening/tests/targets/pairing_joiner.rs` (reuses `targets/handshake.rs` from T034 as `super::handshake`; no duplicate recorder). Green T035
- [X] T037 [P] [US1] Write `crates/hardening/tests/fuzz_channel_responder.rs` (red). Target 10 oracle: `ChannelResponder::on_frame` fed a recorded dialer transcript with one message mutated ends in a protocol `ChannelError`; no `Channel` is returned for a mutated handshake message; the peer store is unchanged (FR-013)
- [X] T038 [US1] Implement `crates/hardening/tests/targets/channel_responder.rs` (testkit paired devices, recorded transcript). Green T037
- [X] T039 [P] [US1] Write `crates/hardening/tests/fuzz_channel_dialer.rs` (red). Target 11: same oracle through `ChannelDialer::on_frame` (FR-013)
- [X] T040 [US1] Implement `crates/hardening/tests/targets/channel_dialer.rs`. Green T039

### Wallet sync, sharing, HTTP (targets 12-16)

- [X] T041 [P] [US1] Write `crates/hardening/tests/fuzz_sync_ctl.rs` (red). Target 12 oracle: `wallet_sync::codec::decode` for every control type; accepted values have at most 512 tags/matches, `CopyStart` size in 79..=64 MiB, input at most 24 KiB; strict round trip (FR-014)
- [X] T042 [US1] Implement `crates/hardening/tests/targets/sync_ctl.rs` (seeds: `encode` of every `Ctl` type including 0 and 512 tags, `CopyStart` at 79 bytes and 64 MiB; one above and one below each bound). Green T041
- [X] T043 [P] [US1] Write `crates/hardening/tests/fuzz_sync_reassembly.rs` (red). Target 13 oracle: `Reassembler::push` over `codec::fragment` output with `Rechunk`, reordering, duplication and dropping the `more = false` fragment; buffer never over 24 KiB; unmutated sequences complete to the original concatenation; oversize resets and errors (FR-014)
- [X] T044 [US1] Implement `crates/hardening/tests/targets/sync_reassembly.rs` (seeds: fragment payloads of 999, 1000 and 1001 bytes; messages of 24 KiB, 24 KiB+1 (hand-assembled) and 1 byte). Green T043
- [X] T045 [P] [US1] Write `crates/hardening/tests/fuzz_sync_copy.rs` (red). Target 14 oracle: sync `Engine` receive side (testkit fakes) fed a recorded copy transfer with one `CopyStart`/`CopyData`/`CopyEnd`/`CopyAbort` mutated; announced sizes outside 79 bytes..64 MiB rejected before any buffering; held transfer buffer at most 1 MiB each and at most 2 transfers (004 FR-029); a mutated copy is adopted only if it authenticates as a wallet (FR-014)
- [X] T046 [US1] Implement `crates/hardening/tests/targets/sync_copy.rs` (two-engine copy of a small and a 1 MiB wallet; allocation bound 2 MiB). Green T045
- [X] T047 [P] [US1] Write `crates/hardening/tests/fuzz_share_msg.rs` (red). Target 15 oracle: `wallet_sync::share::codec::ShareMsg::decode`; unknown type or abort reason, wrong length, trailing bytes and `seconds_left` over 300 rejected; strict round trip (FR-015)
- [X] T048 [US1] Implement `crates/hardening/tests/targets/share_msg.rs` (seeds: every share type, every abort reason, seconds_left 0 and 300). Green T047
- [X] T049 [P] [US1] Write `crates/hardening/tests/fuzz_http_request.rs` (red). Target 16 oracle: `passwsyncd::http::request::read_request` over an in-memory reader delivering arbitrary chunk sizes, then `http::guard::admit` with a testkit `AppState` holding one live session; accepted requests have head at most 16 KiB, at most 48 headers, body at most 8 MiB equal to Content-Length, no `Transfer-Encoding` (independent reference scan of the raw head), exactly one numeric `Content-Length`, no bare LF, UTF-8 target, single Host/Origin/cookie/CSRF; `admit` returning `Api` for a non-GET implies exact Host, exact Origin, valid session and matching CSRF, else `GuardBypass` (FR-016)
- [X] T050 [US1] Implement `crates/hardening/tests/targets/http_request.rs` (seeds: GET/POST/PUT/DELETE API requests, launch, static, index; bodies 0 and 8 KiB; head at 16 KiB-1, 16 KiB and 16 KiB+1 bytes, and 48 and 49 headers; reader returns EOF at the end so it never blocks; allocation bound 8 MiB + 16 KiB). Green T049

### Output hygiene, triage, reproducibility, defect injection

- [X] T051 [P] [US1] Write `crates/hardening/tests/leakage.rs` (red, FR-038, R9): run a scratch target whose seed contains a planted marker string; assert that no `FUZZ`, `FUZZ-TIME` or `FUZZ-FAIL` line, and no panic message, contains the marker; assert the real targets' seed password and filler strings are not any of the leak markers the 001-007 leakage scans search for (read those lists from the existing `crates/*/tests/leakage.rs` text)
- [X] T052 [US1] Make T051 green: ensure `report.rs` prints only labels, counts, hex of seed-derived bytes and `detail` strings built from fixed rules (never from input content); adjust `oracle.rs` panic capture to store only the location and a truncated message. Re-run `cargo test -p hardening --lib --test leakage`
- [X] T053 [US1] Triage run [H]: `cargo test --frozen --offline --release -p hardening --test 'fuzz_*' -- --nocapture`; if Cargo rejects the glob, list the targets in one array (and add the gate's directory cross-check in T071). For every failure assign `F-nnn` (data-model §2); examine the four R20 review items (8 MiB `Content-Length` pre-allocation per connection, serde `Vec` 1 MiB pre-allocation per nesting level, non-minimal postcard varints, `Reassembler` rules) and record each as a finding, a threat-model note or "no issue". Write the list (id, target, seed, iteration, reproducer, kind, severity, owner crate) to the PR description; no finding means T054-T055 are skipped and §9 states `F-000`
- [X] T054 [US1] For each finding `F-nnn` (conditional on T053): write the failing regression test `fn f_nnn_<short_name>()` with the minimal reproducer as a hex or escaped-text literal in `crates/<owner>/tests/regress_008.rs`; run it and see it FAIL; the red run output is recorded in the PR description before the fix (H-13)
- [X] T055 [US1] For each finding with a red test (conditional on T054): the minimal fix in `crates/<owner>/src/` that only rejects invalid input or tightens a bound; the regression test turns green, the original fuzz target passes, every encoder seed still accepted (round-trip oracle green), and the full workspace tests stay green. A finding whose fix would change a valid encoding is NOT fixed: record it as an open finding with severity and owner for the threat model (T090)
- [X] T056 [US1] Reproducibility check [H] (H-2, H-4, SC-002): run the fuzz command twice, `grep '^FUZZ '` both outputs, sort, `diff` (must be identical); every target `inputs >= 10000` (`wallet_unlock` `derived >= 64`), `accepted >= 1`, `rejected >= 1`; run one target with `PASSWSYNC_FUZZ_SEED=0x1234 PASSWSYNC_FUZZ_ONLY=42 PASSWSYNC_FUZZ_TRACE=1` (exactly iteration 42) and `PASSWSYNC_FUZZ_SEED=zz` (fails naming the variable); record the total wall time (must be under 300 s, FR-004)
- [X] T057 [P] [US1] Write the five defect patches `scripts/defects/wallet_header.patch` (remove the wallet header length check), `frame.patch` (remove the frame length range check), `sync_ctl.patch` (remove the `MAX_TAGS` check in sync `decode`), `share_msg.patch` (remove the trailing-bytes check in `ShareMsg::decode`), `http_request.patch` (remove the `Transfer-Encoding` rejection in `read_request`); each applies cleanly with `patch -p1 --dry-run` to the current tree
- [X] T058 [US1] Write `scripts/inject_defects.sh` (R11): copy the tree without `target/` to a `mktemp -d`, apply one patch at a time, run only the matching `fuzz_<target>` with a separate `CARGO_TARGET_DIR`, expect each run to FAIL, print `INJECT <name> DETECTED|MISSED`, exit 0 only if 5 of 5 detected, never touch the working tree; `bash -n` clean
- [X] T059 [US1] Run `scripts/inject_defects.sh` [H] (H-5, SC-003); a MISSED defect means the target oracle is too weak: strengthen `targets/<target>.rs` (test first: add the missed input as a unit case in the target module) and re-run until 5 of 5. Record the result in the PR description (slow, manual [H], not part of the gate)
- [ ] T060 [P] [US1] Create the optional cargo-fuzz directory (FR-009, R12): `fuzz/Cargo.toml` (own `[workspace]`, `libfuzzer-sys` version recorded as UNVERIFIED, `hardening` by path, product crates with `testkit`), `fuzz/README.md` (unbuilt, nightly-only, unverified, must pass `cargo deny` and `cargo audit` before first use, no committed lock), `fuzz/fuzz_targets/<target>.rs` for the 16 targets of this phase (`#![no_main]`, `#[path]` include of `crates/hardening/tests/targets/mod.rs` as `mod targets;`, `fuzz_target!(|data: &[u8]| { let _ = targets::<target>::one_bytes(data); })`). ENV-BLOCKED: never built here. Verify only that `cargo metadata --frozen --offline` and `cargo test --frozen --offline --workspace --no-run` are unaffected and `git diff main -- Cargo.lock` is unchanged from T005 **Status:** ENV-BLOCKED (left unchecked): `fuzz/` written for all 17 targets, never built (no nightly, no libfuzzer-sys); `cargo metadata` and Cargo.lock unaffected.

**Checkpoint**: US1 complete for the 16 targets: all green, deterministic, under 5 minutes, defects detected, findings (if any) fixed test-first.

---

## Phase 4: User Story 2 - Every change is checked by a read-only CI gate (P1)

**Goal**: one offline gate script (11 steps) and one read-only workflow that calls it, both policed by tested checkers.

**Independent Test**: [H] `scripts/gate.sh` exits 0 offline; `python3 scripts/check_workflow.py` passes the real file and rejects every bad copy; breakage in a scratch copy fails the named step. [CI] a real run passes (pending).

### Workflow policy checker and workflow file (W1-W14)

- [X] T061 [P] [US2] Write `scripts/tests/test_check_workflow.py` (`unittest`, red: checker absent): from the real `.github/workflows/ci.yml` generate one mutated copy per negative fixture of contracts/ci-workflow.md (W1 anchor/alias, flow mapping and extra top-level key; W2 `pull_request_target`, `workflow_run`, `issue_comment`, missing schedule; W3 `contents: write`, `id-token: write`, `write-all`; W4 `secrets.`, `github.token`, `GITHUB_TOKEN`, `environment:`; W5 `@v4`, `@main`, short SHA; W6 `archlinux:latest`, `archlinux:base`; W7 `persist-credentials: true`, token in URL, credential helper; W8 `git push`, `git tag`, `gh `, `cargo publish`, `docker push`, `upload-artifact`, `actions/cache`, `curl -X POST`; W9 missing, 0 and 1000 timeout; W10 missing verify call, `continue-on-error: true`, `|| true`; W11 unpinned `cargo install`, `rustup`, `curl | sh`; W12 `mirrors.kernel.org`, `reflector`; W13 refuse-step moved; W14 `self-hosted`) and assert exit 1 with `FAIL Wn`; assert the real file passes with only `PENDING [CI]` lines; the bad copies are written under a temp directory. Also add the SC-010 list as an explicit test (secret reference, write permission, privileged trigger, unpinned action or image, persisted credentials, publish/push/upload step each rejected). Needs a workflow file to mutate: write the unit test against an inline minimal-valid workflow string first, then T063 adds the real-file test case
- [X] T062 [US2] Implement `scripts/check_workflow.py` (Python 3 stdlib only): restricted-YAML reader (block mappings and sequences, plain or quoted scalars, `|` block scalars; anchors, aliases, tags, flow collections, multiple documents rejected, fail closed), rules W1-W14, `PENDING [CI] <pin>` for the all-zero digest and `UNRESOLVED` date, exit 0/1/64, `FAIL Wn: <detail>` lines. Makes T061 green
- [X] T063 [US2] Write `.github/workflows/ci.yml` per contracts/ci-workflow.md: triggers push, pull_request, workflow_dispatch and weekly schedule `17 4 * * 1`; top-level `permissions: contents: read`; NO `uses:` at all; jobs `gate`, `android`, `packaging` in `archlinux@sha256:0000...0000` (sentinel) with pacman on `https://archive.archlinux.org/repos/${ARCH_SNAPSHOT}/$repo/os/$arch` and `ARCH_SNAPSHOT: "UNRESOLVED"`; first step "refuse unresolved pins" in every job; anonymous `git init`/`git fetch --depth=1 ... "$GITHUB_SHA"`/`git checkout`; `cargo install --locked cargo-deny@"$CARGO_DENY_VERSION" cargo-audit@"$CARGO_AUDIT_VERSION"`; `scripts/gate.sh --fetch` then `scripts/gate.sh`; `android/verify.sh`; unprivileged `builder` user then `packaging/verify.sh --fetch` and `packaging/verify.sh`; timeouts 60/60/45; pacman package lists fixed from the tools `android/verify.sh` (cargo, python3, xmllint, cargo-deny, cargo-audit) and `packaging/verify.sh` (006 contracts/verify.md incl. `makepkg`, `namcap`, `systemd-analyze`) check for; no push, tag, release, upload, cache, comment or deploy step. Add the real-file test case to `scripts/tests/test_check_workflow.py`; run `python3 scripts/check_workflow.py` (PASS with two `PENDING [CI]` lines) and `python3 -m unittest scripts.tests.test_check_workflow`. ENV-BLOCKED: package availability in the Arch snapshot cannot be checked here
- [X] T064 [P] [US2] Write the red test for the widened unsafe scan in `crates/passwsync-ffi/tests/unsafe_scope.rs`: a unit-level case that scans a temporary directory tree containing an `unsafe` token under `crates/x/tests/`, `crates/x/benches/` and `fuzz/fuzz_targets/` and expects each to be reported (current scan reads `src` only: red), and an assertion that the real scan roots include `crates/hardening/src`, `crates/hardening/tests` and `fuzz/`
- [X] T065 [US2] Widen `crates/passwsync-ffi/tests/unsafe_scope.rs` to `crates/*/{src,tests,benches}` and `fuzz/` (only `crates/passwsync-ffi/src/memprotect.rs` may contain `unsafe`, and the scan file itself is excluded by an explicit allowance comment-free rule: patterns are built from split strings). Makes T064 green; `cargo test --frozen --offline -p passwsync-ffi --test unsafe_scope` passes over the whole tree (FR-037, SC-012)

### Gate script (11 steps)

- [X] T066 [P] [US2] Create the offline policy fixtures: `scripts/tests/fixtures/advisory.lock` (a lockfile naming one long-standing, non-withdrawn RUSTSEC-advised crate version, chosen by running `cargo audit --no-fetch --file` against the cached DB and confirming it FAILS), `scripts/tests/fixtures/deny-ws/` (two-package path workspace: `Cargo.toml`, a crate named like a `[bans] deny` entry, a crate with a GPL license, a `deny.toml` equal to the repo policy by copy), and, for the threat-model checker later, none yet. No network needed
- [X] T067 [US2] Write `scripts/tests/test_gate_selftest.py` (`unittest`, red: script absent): `scripts/gate.sh --list` prints exactly the 11 step names in order (`toolchain fmt clippy test budgets fuzz release-isolation unsafe-scope audit deny policy`); `PASSWSYNC_GATE_SELFTEST=fail` runs only a synthetic step ending FAIL (the real steps are skipped, so the self-test cannot re-run `policy`), the exit code is 1 with that step named; `=missing` gives exit 2 with no FAIL; unknown argument exits 64; the audit ignore list derived from `deny.toml` (and `tools/uniffi-bindgen/deny.toml`) equals the ids in both files (FR-036); the fuzz target array equals the `crates/hardening/tests/fuzz_*.rs` listing and a missing entry fails the `fuzz` step; the `release-isolation` scan rejects a fixture `nm`/`cargo tree` text containing `testkit::`, `hardening` or a `testkit` feature (hidden option `--selftest <name>` for these pure checks); the deny policy assertion: `deny.toml` has `[advisories] yanked = "deny"`, `unmaintained = "all"`, `unsound = "all"`, and `unknown-registry = "deny"`, `unknown-git = "deny"`; the advisory fixture makes `cargo audit --no-fetch --file scripts/tests/fixtures/advisory.lock` fail and the deny fixture workspace makes `cargo deny --offline check bans licenses` fail (SC-009)
- [X] T068 [US2] Tighten `deny.toml` and `tools/uniffi-bindgen/deny.toml` (R18): `[advisories]` `yanked = "deny"`, `unmaintained = "all"`, `unsound = "all"`, keep `RUSTSEC-2023-0089` and `RUSTSEC-2026-0374` ignores each with a written reason, same list consulted by both tools; keep `[bans] multiple-versions = "warn"`. Run `cargo deny --offline check` for both manifests: any new failure (unmaintained, unsound or yanked notice) is fixed by removal or an explicit ignore with reason AND recorded as a register row for T089 (no dependency change allowed by FR-037, so an ignore is the only route). Makes the policy assertions of T067 green
- [X] T069 [US2] Implement the skeleton of `scripts/gate.sh`: `set -u -o pipefail`, `LC_ALL=C`, run from the repo root, `mktemp -d` log directory removed on exit (path printed on failure), step runner printing one `[gate] <step> <RESULT> <detail>` line, last 40 log lines on FAIL, result line and exit 0/1/2/64, `--list`, `--fetch` (`cargo fetch --locked` for root and `tools/uniffi-bindgen`, refresh both advisory DBs; the ONLY networked mode, run by CI and by a maintainer), `PASSWSYNC_GATE_SELFTEST` (runs only the synthetic step), hidden `--selftest`. Makes the CLI cases of T067 green
- [X] T070 [US2] Gate steps 1-3 in `scripts/gate.sh`: `toolchain` (versions of rustc, cargo, cargo-deny, cargo-audit, python3 and both advisory DB dates; MISSING if a tool or DB is absent; `~/.cargo/bin` prepended to PATH like the verify scripts), `fmt` (`cargo fmt --all --check`), `clippy` (`cargo clippy --frozen --offline --workspace --all-targets --all-features -- -D warnings`)
- [X] T071 [US2] Gate steps 4-6 in `scripts/gate.sh`: `test` (`cargo test --frozen --offline --workspace --all-features --exclude hardening`), `budgets` (`cargo test --frozen --offline --release -p hardening --lib --test budgets --test leakage`; the `budgets` test file exists after T093, until then the step reports MISSING), `fuzz` (`cargo test --frozen --offline --release -p hardening --test 'fuzz_*' -- --nocapture` or the explicit array checked against the directory, one `FUZZ ... result=PASS` line per `fuzz_*.rs` file, wall time under 300 s, prints target and input totals)
- [X] T072 [US2] Gate step 7 `release-isolation` in `scripts/gate.sh` (FR-038, R7): `cargo tree --frozen --offline -e features,normal,build --target all -p passwsyncd` and `-p passwsync-ffi` show no `testkit` feature and no `hardening` package; build `cargo build --frozen --offline --release -p passwsyncd --bin passwsyncd` and `-p passwsync-ffi` exactly as the PKGBUILD and `android/build-rust.sh` do; `nm -C` of the artifacts shows no `testkit::` or `hardening` symbol; the pure scan function is the one T067 tests
- [X] T073 [US2] Gate steps 8-10 in `scripts/gate.sh`: `unsafe-scope` (`cargo test --frozen --offline -p passwsync-ffi --test unsafe_scope`), `audit` (ignore ids parsed from `deny.toml` and, for its own lock, `tools/uniffi-bindgen/deny.toml` with `python3 -c 'import tomllib'`; `cargo audit --no-fetch --deny warnings --ignore <id>...` on both lock files; prints the advisory DB date), `deny` (`cargo deny --offline check` for root and `--manifest-path tools/uniffi-bindgen/Cargo.toml`; prints `duplicates=<n>` from `cargo tree --duplicates --depth 0`, warning only)
- [X] T074 [US2] Gate step 11 `policy` in `scripts/gate.sh`: `python3 scripts/check_workflow.py` (PENDING lines allowed and echoed as `workflow: N pins PENDING [CI]`), `python3 scripts/check_threat_model.py` (MISSING until T082 exists), `python3 -m unittest discover -s scripts/tests`, the advisory and deny fixture checks of T067 (each MUST fail), the `deny.toml` key assertions, and `bash -n` on every `scripts/*.sh`. Makes all of `scripts/tests/test_gate_selftest.py` green
- [X] T075 [US2] Run `scripts/gate.sh` end to end [H] (H-1, H-3, H-6, SC-009): 11 PASS lines and exit 0 once US1 (T053-T055), US3 (T082) and US4 (T093) tasks exist, otherwise the pending steps print MISSING (exit 2) which is the expected incomplete state until then; then in a scratch copy (`cp -a` without `target/`) add a mis-indented line, an unused variable and an `assert!(false)` and confirm exit 1 naming `fmt`, `clippy` and `test`; record durations and the `fuzz` step time (under 300 s) in the PR description
- [ ] T076 [US2] (MANUAL, ENV-BLOCKED) CI-0 placeholder fill-in [CI]: on a trusted networked machine run `docker pull archlinux:base` and `docker inspect --format '{{index .RepoDigests 0}}' archlinux:base`, pick the matching date at `archive.archlinux.org/repos/`, write the digest into the three `image:` lines and the date into `ARCH_SNAPSHOT` of `.github/workflows/ci.yml` (no value is invented in this feature, amendment A2), re-run `python3 scripts/check_workflow.py` and see PASS with NO `PENDING` line, record date and values in `specs/008-hardening-audit/quickstart.md` (CI-0). Stays unchecked: this host has no network and no Arch image **Status:** Left unchecked: no network and no Arch image on this host; sentinels stay fail-closed (2 PENDING [CI] lines).
- [ ] T077 [US2] (MANUAL, ENV-BLOCKED) CI-1 [CI]: after T076 a maintainer pushes the branch (this feature never pushes) and records date, commit and run URL; jobs `gate`, `android`, `packaging` all pass (FR-035, SC-011); verify-script status 2 counts as failure. Pending until run **Status:** Left unchecked: needs a maintainer push and a hosted runner.
- [ ] T078 [US2] (MANUAL, ENV-BLOCKED) CI-2 and CI-3 [CI]: open a pull request from a fork and confirm a read-only token, no secrets, nothing published (US2 scenario 4); run the weekly schedule or a manual dispatch and confirm the same result and that a new advisory fails `audit`. Pending until run **Status:** Left unchecked: needs a hosted runner and a fork PR.

**Checkpoint**: gate and workflow exist and are tested on the host; every [CI] item is recorded as pending, CI-0 fill-in unresolved by design.

---

## Phase 5: User Story 3 - A reviewer can read one threat model of the whole system (P2)

**Goal**: `docs/threat-model.md` passes `scripts/check_threat_model.py` (TM1-TM13), covers 11 boundaries x 6 STRIDE and the 19 required register entries plus advisory ignores.

**Independent Test**: [H] `python3 scripts/check_threat_model.py` prints PASS and every negative unit test rejects its fixture.

- [X] T079 [P] [US3] Write `scripts/threat_model_required.tsv` with the 19 rows RR-01..RR-19 of contracts/threat-model-structure.md (`rr_id`, `source_path`, `anchor_phrase`, optional `pending` flag for RR-11, RR-14, RR-15): read each cited section of specs 002-008 and use the sources and anchors of contracts/threat-model-structure.md verbatim (all anchors were checked by exact-string search on 2026-10-30) so the staleness check works; `grep -F` confirms every anchor occurs in its source file
- [X] T080 [P] [US3] Write `scripts/tests/test_check_threat_model.py` and its fixtures under `scripts/tests/fixtures/threat-model/` (red: checker absent): one valid minimal fixture document plus one mutated copy per rule TM1-TM13 (renamed or reordered heading; missing or extra boundary; boundary without a STRIDE letter; empty cell, bad or duplicate threat id, bad STRIDE value; mitigation without reference, `N/A` without reason; reference to a nonexistent path; `Residual (RR-99)`; register row lacking source, owner, closing condition or with severity outside High/Medium/Low; required RR id missing, wrong source cell, stale anchor; `pending` RR with status `Accepted`; ignored advisory id absent; `Fixed` finding without an existing regression test path or `Open` without owner; missing required asset or actor), each expecting exit 1 and the exact `FAIL TMn`; plus the `F-000` empty-audit row accepted only with id `F-000`
- [X] T081 [US3] Implement `scripts/check_threat_model.py` (Python 3 stdlib: `re`, `tomllib`, `pathlib`): heading skeleton, pipe tables, rules TM1-TM13, advisory ids read from `deny.toml` and `tools/uniffi-bindgen/deny.toml`, required list read from the TSV, `PASS` or one `FAIL TMn: <detail>` per violation, exit 0/1/64. Makes T080 green
- [X] T082 [US3] Run `python3 scripts/check_threat_model.py` against the (still absent) `docs/threat-model.md`: it fails (red for the document tasks below); then create `docs/threat-model.md` with the exact skeleton headings of contracts/threat-model-structure.md, `## 1. Scope and method` (parts of the system, STRIDE, how to update, verification tags [H] [CI] [M] [D]) and `## 2. Severity scale` (High, Medium, Low defined from impact and likelihood)
- [X] T083 [US3] `## 3. Assets` (master password, derived key, decrypted credential, wallet file, device private key, pin, pairing code, invite code, session token, sync record, each with where it lives and its protection), `## 4. Actors` (the 8 required actors, each with capability and in/out of model, attacker model unchanged from 002-007), `## 5. Data flows and trust boundaries` (text diagram plus the table B-01..B-11 with `Crosses`)
- [X] T084 [US3] `### B-01 Wallet at rest`, `### B-02 Process memory and OS`, `### B-03 Loopback HTTP service and browser`: each with all six STRIDE rows (`T-Bnn-n`), mitigation, reference (FR/SC id, existing test path, script path, `RR-nn` or `F-nnn`) and status; referenced paths must exist (TM6). Include the per-connection 8 MiB `Content-Length` note from R20 item 1
- [X] T085 [US3] `### B-04 LAN discovery`, `### B-05 Pairing`, `### B-06 Paired channel`: all six STRIDE rows each, including the stable device identifier visible on the LAN and the unaudited channel library with key copies kept (residual rows pointing to RR ids)
- [X] T086 [US3] `### B-07 Wallet sync`, `### B-08 Sharing`: all six STRIDE rows each, including the undetected restore and unauthenticated sync record, duplicate-detection gap, invitation invalidation by another paired device and non-withdrawable delivered copies
- [X] T087 [US3] `### B-09 Android app and platform`, `### B-10 Packaging and service manager`, `### B-11 Build, dependency and CI supply chain` (runner VM image not pinnable, duplicate crate version count, sentinel pins pending, anonymous-checkout fallback, fork contributors, scheduled runs): all six STRIDE rows each; `N/A` rows carry a one-line reason
- [X] T088 [US3] `## 7. Out-of-model inputs`: the same-user local files (configuration, peers file, sync record, received-wallet metadata, launch file) with the rationale from the spec Clarifications (same OS user is outside the attacker model of 002-005; not fuzzed in this feature)
- [X] T089 [US3] `## 8. Residual-risk register`: rows RR-01..RR-19 (risk, source path that exists, rationale, severity High/Medium/Low, owner, closing condition, status), RR-11, RR-14 and RR-15 as `Pending approval` (the 007 Constitution I exception and its siblings: this feature never grants approval, FR-027), plus one row (id RR-20 onward) for every ignore or notice added by T068; every ignored advisory id of both `deny.toml` files appears (FR-036)
- [X] T090 [US3] `## 9. Audit findings` from T053-T055 and T059: one row per finding (`Fixed` with `crates/<owner>/tests/regress_008.rs::f_nnn_*`, or `Open` with owner and severity) or the single `F-000` row if none; benchmark and review findings of T098 and T053 included (FR-028)
- [X] T091 [US3] `## 10. Change log` (dated entry for this version) and run `python3 scripts/check_threat_model.py` (PASS) and `python3 -m unittest scripts.tests.test_check_threat_model` (green); rerun after any later edit (SC-008)

**Checkpoint**: threat model complete and structurally verified; pending-approval items still pending.

---

## Phase 6: User Story 4 - Resource promises are measured, not assumed (P2)

**Goal**: deterministic budgets gate; measured budgets are reported by `scripts/bench.sh` with a verdict and never gate (FR-020).

**Independent Test**: [H] `scripts/bench.sh` completes and writes `target/bench/report.txt` with B-01..B-20 values; the deterministic budget tests pass in the gate. [M] reference laptop run pending.

- [X] T092 [P] [US4] Write `crates/hardening/tests/budgets.rs` (red: constants or accessors missing): B-09 idle service has no periodic wake-ups beyond the documented timers over simulated idle time (the file prints the B-09 BUDGET line and may call an existing sweeper test helper, no duplicate assertion); B-13 second-run equality of idle sync traffic (5 peers, 10 wallets, one simulated hour, under 1 KiB per peer, identical across two runs); B-18 transfer buffer at most 1 MiB; B-19 at most 2 concurrent transfers; B-20 every public bound constant equals the spec value (frame 1024, fragment 1000, control message 24 KiB, tags 512, HTTP head 16 KiB, 48 headers, body 8 MiB, wallet 79 B and 64 MiB, text field 1 MiB, service KDF cap 131,072 KiB); each test prints its `BUDGET` line before asserting
- [X] T093 [US4] Make T092 green with the smallest change: expose the missing public constants or read-only accessors in the owning crates (no behaviour change, no new encoding), then mutation-check each deterministic assertion once (change a constant in a scratch copy, see the test FAIL, restore). Confirm the `budgets` gate step of T071 now finds `--test budgets`
- [X] T094 [P] [US4] Write `scripts/tests/test_bench_report.py` (`unittest`, red: script absent): stub test outputs feed `scripts/bench.sh` through a `PASSWSYNC_BENCH_STUB_DIR` hook; asserts `BUDGET` lines are parsed strictly (`id`, `value`, `unit`, `limit`, `cmp`, `source`, `class`, `verdict`; malformed lines rejected), a failing assertion does not lose its line, a missing budget becomes `NO-DATA` and exit 2, a complete set exits 0 whatever the verdicts, the machine block (CPU model, logical cores, MemTotal, kernel, `rustc -V`, profile `release`, `reference=no|laptop`, date UTC) is present, the footer `informational: timing verdicts are binding only on reference hardware` appears when `reference=no`, usage error exits 64, and output contains no credential-like text
- [X] T095 [US4] Add the measured benchmarks in `crates/vault-core/tests/perf.rs` (`#[ignore]`, release): new `unlock_default_median_and_worst` (median and worst of 9, B-01/B-02), `time_per_guess` (wrong password, B-03), `unlock_at_service_cap` (131,072 KiB, B-04, info only); add print-only `BUDGET` lines to the existing list, search and peak-memory tests (B-05..B-07); lines contain numbers only, never wallet data; temp directories only
- [X] T096 [US4] Add print-only `BUDGET` lines (no assertion or logic change) to the existing `#[ignore]`d measurement tests `crates/passwsyncd/tests/perf_memory.rs` (B-08), `crates/passwsyncd/tests/resources_network.rs` (B-10, B-11), `crates/passwsyncd/tests/resources_sync.rs` (B-14, B-15), `crates/passwsyncd/tests/sync_perf.rs` (B-16, B-17) and to the deterministic `device-link-net/tests/resources.rs::wakes_are_counted` (B-12) and `resources_sync.rs::idle_sync_costs_less_than_1_kib_per_peer_per_hour` (B-13; not `#[ignore]`d, bench.sh runs it without `--ignored`, see T097); run `cargo test --frozen --offline -p passwsyncd` and confirm test and ignored counts equal the T001 baseline
- [X] T097 [US4] Implement `scripts/bench.sh` (R13): for each listed measurement test run `cargo test --frozen --offline --release ... -- --ignored --nocapture --test-threads=1`, and run the three deterministic BUDGET files (`hardening --test budgets`, `device-link-net --test resources`, `passwsyncd --test resources_sync`) the same way without `--ignored`, capture stdout, extract `BUDGET` lines, write the machine block and one row per budget to `target/bench/report.txt`, print the report, exit 0/1/2/64 as in contracts/benchmarks.md, never invoked by the gate or CI (the gate and workflow do not mention it; W10 unaffected). Makes T094 green
- [X] T098 [US4] Run `scripts/bench.sh` [H] (H-14, SC-005): exit 0, `reference=no`, a value and verdict for every B-01..B-20 and no `NO-DATA`; every deterministic budget PASS; `grep` the report for credential-like text (none); record unexpected OVER verdicts as findings for T090 (measured verdicts never fail the gate)
- [ ] T099 [US4] (MANUAL) M-1 [M]: on the reference laptop run `PASSWSYNC_REFERENCE_DEVICE=laptop scripts/bench.sh`; B-01/B-02 under 2 s, B-03 at least 0.3 s, every measured budget PASS (SC-006); record in `specs/008-hardening-audit/quickstart.md`. Stays pending until run **Status:** Left unchecked: no reference laptop.

**Checkpoint**: deterministic budgets gate; benchmark report produced on the host; reference verdict pending.

---

## Phase 7: User Story 5 - Android-specific inputs and budgets are covered where possible (P3)

**Goal**: the boundary crate's input-taking functions are in the fuzz gate; the Android verify script passes on the host; device items are pending.

**Independent Test**: [H] `android/verify.sh` ends with all steps PASS (ktlint may be SKIPPED) and `fuzz_ffi_args` is green. [D] device checks pending.

- [X] T100 [P] [US5] Write `crates/hardening/tests/fuzz_ffi_args.rs` (red). Target 17 oracle: `passwsyncd::qr::parse_share_text`, `passwsync_ffi` `join_pairing(peer_id, code)` and `redeem_invitation(sender_id, code)` on a testkit core with networking off; malformed ids and codes return only `CoreError` kinds; no state change; share text over its maximum length rejected; strict round trip for share text (FR-013 family, SC-001)
- [X] T101 [US5] Implement `crates/hardening/tests/targets/ffi_args.rs` (valid share text, peer ids and codes as seeds; allocation bound 1 MiB; `one_bytes` for cargo-fuzz). Green T100; confirm the gate `fuzz` step now sees 17 target files and 17 PASS lines
- [ ] T102 [P] [US5] Add `fuzz/fuzz_targets/ffi_args.rs` in the same form as T060. ENV-BLOCKED: not built here **Status:** ENV-BLOCKED (left unchecked): `fuzz/fuzz_targets/ffi_args.rs` written, not built.
- [X] T103 [US5] Run `android/verify.sh` [H] (US5 scenario 1, H-9, SC-012): exit 0 with every step PASS except `ktlint` SKIPPED as 007 allows; confirm `crates/passwsync-ffi/tests/unsafe_scope.rs` (widened in T065) and `android/policy` checks still pass; no edit to `android/` is made by this feature, so any failure is a regression to investigate first in T065
- [X] T104 [US5] Write the device and reference-hardware checklist rows D-1..D-4 and M-1 into `specs/008-hardening-audit/quickstart.md` (already present: verify the table has expected values, source budget ids B-21..B-23 and a "Result" column reading `pending`); no row may read PASS
- [ ] T105 [US5] (MANUAL) D-1 [D]: on the reference phone unlock with the default KDF five times, each under 3 s (007 SC-005, B-21); record. Pending **Status:** Left unchecked: no reference phone.
- [ ] T106 [US5] (MANUAL) D-2 [D]: with a 1,000-credential wallet unlocked read `dumpsys meminfo`, under 128 MiB (007 SC-011, B-22); record. Pending **Status:** Left unchecked: no reference phone.
- [ ] T107 [US5] (MANUAL) D-3 and D-4 [D]: 24 h idle with two paired devices, `dumpsys jobscheduler` against the 007 SC-008 wake-up limit and battery stats against 007 SC-009 (under 1 percent per day) (B-23); record. Pending **Status:** Left unchecked: no reference phone.

**Checkpoint**: 17 of 17 targets green; Android gate green on the host; device items pending.

---

## Phase 8: Polish, gates and final verification

- [X] T108 Re-run `python3 scripts/check_threat_model.py` and `python3 scripts/check_workflow.py` after the last doc or workflow edit; update `docs/threat-model.md` §9 and §10 with any late finding (T098, T103) and re-run
- [X] T109 Update `specs/008-hardening-audit/quickstart.md` result column with the recorded host results (H-1..H-14 outcomes, dates) and keep every [CI], [M], [D] row `pending` with the exact reason (no network, no runner, no reference hardware); CI-0 shows the unresolved sentinels
- [X] T110 Final `scripts/gate.sh` [H]: 11 steps PASS, exit 0, no MISSING (all of T074 inputs now exist); record the printed `[gate]` lines and the `fuzz` step time (SC-001, SC-002, SC-009)
- [X] T111 Constraint checks [H] (H-12, FR-037, SC-012): `git diff main -- Cargo.lock` shows only the `hardening` path package, `cargo tree --frozen --offline -p hardening --edges normal` lists no dependency, no `unsafe` outside `memprotect.rs` (T065 scan), `rg -n 'std::net|TcpStream|UdpSocket' crates/hardening/src` empty, `git diff main --stat -- crates/*/src` shows only the allowed refactors (T017 and findings fixes); `cargo test --frozen --offline --workspace` count equals the T001 baseline plus the new tests
- [ ] T112 Run `packaging/verify.sh` [H] (H-10): exit 0 where its tools exist, otherwise exit 2 recorded as pending as in 006; confirm no packaging file changed **Status:** Left unchecked (2026-11-02): `packaging/verify.sh` exit 1. `no-config-writes` asserts no diff in crates/ against main (006 FR-027, scope of the 006 branch; any feature changing crates fails it); the build steps and `lock-mismatch` fail offline because the packaging dependency cache predates 007's uniffi crates (needs `packaging/verify.sh --fetch`, network); namcap MISSING. `packaging/PKGBUILD` changed: its check() comment now lists the 4 new #[ignore]d tests (recipe-fields FR-005 rule requires it).
- [X] T113 Review H-13 (SC-004): for each `F-nnn` marked Fixed, confirm from the recorded red output (T054) that the regression test was observed failing before the fix; each `Open` row has owner and severity
- [X] T114 Confirm nothing was committed or pushed: `git log main..HEAD` unchanged by this feature, `git status` lists the new files only, `.github/workflows/ci.yml` present but unpushed (spec Assumptions)
- [X] T115 Walk `quickstart.md` top to bottom once more on the host and confirm each [H] row matches its expected output; list all remaining pending items (T076, T077, T078, T099, T105, T106, T107 and the unbuilt `fuzz/` directory) in the PR description

---

## Dependencies and execution order

- Phase 1 -> Phase 2 (engine tasks T006-T015 strictly test-then-implement; T016-T017 independent of T006-T015 and can run in parallel with them) -> T018 -> Phase 3.
- Phase 3 (US1) targets are mutually independent: each pair (test then implementation) can run in parallel with other pairs; `targets/mod.rs` and `fuzz/` edits are sequential appends. T036 depends on T034 (shared transcript recorder). T053 needs all of T019-T050 and T051-T052; T054-T055 are conditional on T053; T056 needs T053-T055; T057-T059 need T020-T050; T060 needs the targets' `one_bytes`.
- Phase 4 (US2) T061-T063 and T064-T065 are independent; T066 -> T067 -> T068 -> T069 -> T070 -> T071 -> T072 -> T073 -> T074 sequentially (same file `scripts/gate.sh`, never parallel). T071's `budgets` step and T074's threat-model call report MISSING until T093 and T082; T075 is only fully green after US3 and US4. T076-T078 are manual and gated by network and a runner.
- Phase 5 (US3) is independent of Phases 3-4 except T090 (needs findings from T053-T059) and T089 (needs the ignore changes of T068); T079 and T080 in parallel, T081 after T080, document tasks T082-T091 sequential (one file).
- Phase 6 (US4) is independent of US1-US3 except T071 (gate `budgets` step) and T090 (benchmark findings); T092 and T094 in parallel; T095 and T096 touch different files; T097 after T094.
- Phase 7 (US5) needs Phase 2 and `targets/mod.rs`; T103 needs T065.
- Phase 8 needs everything.
- Story order: US1 -> US2 -> US3 -> US4 -> US5 (US3 and US4 may start right after Phase 2).
- Always: test task, see it fail, then implementation; after each `scripts/gate.sh` edit re-run `python3 -m unittest scripts.tests.test_gate_selftest`.

## Parallel opportunities

- Phase 1: T002 in parallel with T001.
- Phase 2: T006, T008, T010, T012 test-writing in parallel (different files); their implementations follow; T016-T017 in parallel with all of them.
- Phase 3: the red `fuzz_*.rs` files T019/T021/T023/T025/T027/T029/T031/T033/T035/T037/T039/T041/T043/T045/T047/T049 are different files and can be written together; target implementations are different files too (only `targets/mod.rs` is shared and appended sequentially). T051, T057 and T060 in parallel.
- Phase 4: T061 and T064 in parallel; T066 in parallel with T061-T065.
- Phase 5: T079 and T080 in parallel.
- Phase 6: T092 and T094 in parallel; T095 and T096 in parallel.
- Phase 7: T100 and T102 in parallel.

## Implementation strategy

- MVP = Phase 1 + Phase 2 + Phase 3 (US1): the engine and 16 fuzz targets, host-verified with H-2 and H-5. Add US2 for the gate that keeps it true, then US3 and US4 for assurance documents and measurements, then US5.
- Product code is never edited except T017 (pure split + testkit entry points), T068 (policy files), T093 (read-only constants/accessors), T096 (print-only lines) and the minimal fixes of T055; fixes only reject invalid input or tighten bounds, otherwise they become open findings (FR-017).
- Items that cannot be completed here are written and tested against fixtures, then recorded as pending: CI-0 fill-in (T076), real CI runs (T077-T078), reference laptop (T099), reference phone (T105-T107), the cargo-fuzz build (T060, T102).
- At each checkpoint run `scripts/gate.sh`; before Phase 4 completes its `MISSING` steps (exit 2) are expected and are never reported as PASS.

## Verification map (FR and SC to tasks)

Tags: [H] host, [CI] runner, [M] reference laptop, [D] device. Rows with a MANUAL or ENV-BLOCKED task are marked.

| Requirement | Tasks | Checks / flags |
|-------------|-------|----------------|
| FR-001 | T006-T015, T065, T072, T111 | engine unit tests; unsafe scan; release isolation; no dependencies |
| FR-002 | T008, T009 | mutate.rs tests (all 9 mutators) |
| FR-003 | T006, T007, T012, T013, T056 | seed/env tests; H-2, H-4 |
| FR-004 | T053, T056, T071, T075, T110 | fuzz step under 300 s, 10,000 inputs per target |
| FR-005 | T010, T011, T014, T015 | panic, time, allocation, error-kind oracles |
| FR-006 | T019-T050, T100, T101 | strict (S) and FR-006 (P) round-trip oracles; amendment A3 |
| FR-007 | T012-T015, T052, T056 | FUZZ-FAIL line, reproduction |
| FR-008 | T010, T011, T014, T015 | coverage rule |
| FR-009 | T060, T102 | ENV-BLOCKED: `fuzz/` written, never built; lock unchanged (T111) |
| FR-010 | T019, T020 | wallet_header |
| FR-011 | T016, T017, T021, T022 | testkit entry + wallet_payload |
| FR-012 | T023, T024 | wallet_unlock (64 derived) |
| FR-013 | T025-T040, T100, T101 | frame, hello, channel payload, discovery, 4 handshake targets, ffi args |
| FR-014 | T041-T046 | sync_ctl, sync_reassembly, sync_copy |
| FR-015 | T047, T048 | share_msg |
| FR-016 | T049, T050 | http_request + guard |
| FR-017 | T053-T055, T058-T059, T090, T113 | red regression tests, open findings |
| FR-018 | T095, T096, T097, T098 | bench.sh, perf tests |
| FR-019 | T092-T098 | one B-nn row per budget with source |
| FR-020 | T071, T092, T093, T097 | deterministic gates; measured never gates; bench not in CI (W10 rules, T063) |
| FR-021 | T094, T097, T098 | machine block, temp dirs, no secrets |
| FR-022 | T099, T104-T107, T109 | MANUAL [M][D]: checklist written, results pending |
| FR-023 | T082, T083 | assets, actors, data flows |
| FR-024 | T083-T087 | boundaries B-01..B-11 |
| FR-025 | T084-T087, T080, T081 | six STRIDE per boundary; TM3-TM5 |
| FR-026 | T079, T089 | register RR-01..RR-19 |
| FR-027 | T089, T080, T081 | pending-approval rows (TM10) |
| FR-028 | T090, T108 | findings table |
| FR-029 | T080, T081, T091 | TM1-TM13 negative tests |
| FR-030 | T067, T069-T075, T110 | 11 gate steps |
| FR-031 | T061-T063 | W2, W10; MANUAL [CI] run T077 |
| FR-032 | T061-T063 | W2-W4, W7, W8 |
| FR-033 | T061-T063 | W5, W6, W9, W11, W12; sentinels PENDING (A2); MANUAL ENV-BLOCKED T076 |
| FR-034 | T061, T062, T074 | W1-W14 in gate `policy` |
| FR-035 | T063, T077 | [CI] MANUAL ENV-BLOCKED: Arch container and Android runner run pending |
| FR-036 | T067, T068, T073, T089 | one ignore list; register rows; DB date printed |
| FR-037 | T005, T064, T065, T072, T111 | lockfile diff (A1), unsafe scan, no network, no encoding change |
| FR-038 | T051, T052, T072 | leakage test; release-isolation step |
| SC-001 | T053, T056, T100, T101, T110 | 17 targets, 10,000 inputs (64 unlocks), zero violations |
| SC-002 | T014, T056 | identical reports; under 5 minutes |
| SC-003 | T057, T058, T059 | defect injection 5 of 5 [H] manual |
| SC-004 | T054, T055, T090, T113 | red-first regression tests or open entries |
| SC-005 | T092, T094, T097, T098 | value and verdict for B-01..B-20 |
| SC-006 | T099 | MANUAL [M] pending |
| SC-007 | T105, T106, T107 | MANUAL [D] pending |
| SC-008 | T080-T091 | structure check PASS |
| SC-009 | T066-T075 | gate exits 0; named failures; fixtures |
| SC-010 | T061, T062, T063 | workflow-policy negatives |
| SC-011 | T077, T078 | MANUAL ENV-BLOCKED [CI] pending |
| SC-012 | T003, T005, T065, T103, T111, T112 | A1 recorded in spec; unsafe and lockfile; verify scripts still pass |

### Flag summary

- MANUAL / ENV-BLOCKED [CI]: T076 (CI-0 placeholder fill-in: image digest and `ARCH_SNAPSHOT`, unresolved by design, amendment A2), T077 (CI-1), T078 (CI-2, CI-3); parts of T063 (package availability) and FR-035.
- MANUAL [M]: T099. MANUAL [D]: T105, T106, T107 (and their documentation T104).
- ENV-BLOCKED (never built here): optional `fuzz/` directory (T060, T102).
- Host tasks that depend on tools present here: T068, T073, T075 (cargo-deny, cargo-audit, advisory DB), T103 (`android/verify.sh`), T112 (`packaging/verify.sh`, may end with status 2 as in 006).
