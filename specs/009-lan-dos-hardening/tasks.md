# Tasks: LAN Denial-of-Service Hardening

**Input**: Design documents from `/specs/009-lan-dos-hardening/`
**Prerequisites**: plan.md, spec.md (US1-US4, FR-001..FR-023, SC-001..SC-009), research.md (R1-R11), data-model.md, contracts/peer-behaviour.md, quickstart.md, evidence/poc_lan.rs.txt
**Tests**: MANDATORY (Constitution III, FR-022). Every fix has a failing test task BEFORE its code task. The test task ends with the test run and seen RED (compile error counts for a new API); the code task ends with it GREEN. A test task and its code task never run in parallel. A task marked **(GUARD)** pins behaviour that is already correct today: it is green before and after, and the task says how to prove it can fail.
**Organization**: Phase 1 setup, Phase 2 shared test support, then US1 version fallback (R1, R2, R9, R10), US2 pairing (R3, R4, R5, R11), US3 announcements (R6, R7, R8), US4 documentation check and flip, Polish gates. All tasks are strictly sequential: do them in numeric order, no `[P]`.
**Rules for every task**:
- Documentation and code only inside the files named. `crates/passwsyncd/tests/**` is NEVER edited (`android/verify.sh` requires it identical to main). Other tests under `crates/passwsyncd/` stay as they are.
- `Timing` gains NO field (`crates/passwsyncd/tests/common/server.rs` builds it as a struct literal). Derive new intervals from existing fields: hint spacing = `step_timeout / 2`, minimum redial = `dial_backoff_min`, address expiry = `nearby_expiry`. The 6 h upgrade interval is a constant.
- No wire change, no cryptography change, no new dependency, no new `unsafe`, no new timer (everything runs on the existing 30 s discovery tick).
- No code, key, password or wallet data in any log, notice or test output (FR-023).
- Tests for out-of-scope findings (poc4 pairing oracle, poc5 unauthenticated slot exhaustion) are NOT ported and their fixes are NOT made.
- NEVER `git commit` or push in this task list.

## Format: `- [ ] T### [Story?] Description with file path`

Paths are relative to the repository root. Verification: all tasks are **[H]** (host, offline, loopback) except the last one, which is **(MANUAL)** [M][D].

---

## Phase 1: Setup

- [ ] T001 Baseline: run `cargo fmt --all --check`, `cargo clippy --frozen --offline --workspace --all-targets -- -D warnings`, `cargo test --frozen --offline --workspace`; record green, test count, `sha256sum Cargo.lock`, `git status --porcelain` (PR description, no file)
- [ ] T002 Record the frozen surface: `git diff --quiet main -- crates/passwsyncd/tests && echo unchanged` must print `unchanged`; `grep -n "Timing {" -A12 crates/passwsyncd/tests/common/server.rs` and note the field list that `Timing` must keep exactly; note `crates/passwsyncd/tests/api_pairing.rs:332` (6th code gives 429) and `crates/passwsyncd/tests/share_old_peer.rs`
- [ ] T003 Find every user of the behaviour being changed. Run `grep -rnE "max_version|LEGACY_RETRY|is_legacy|PeerLegacy|PeerNoShare|TooManyCodes|too_many_codes|at most 5|dial_now|on_announce|keep_existing|dialing|CODES_PER_WINDOW" crates android docs --include='*.rs' --include='*.kt' --include='*.js' --include='*.md'` (exclude `target/`). Known so far, NOT guaranteed complete: `crates/device-link/src/{code,error,link}.rs`, `crates/device-link/tests/{error,link,code}.rs`, `crates/device-link-net/src/{lib,dialer,conn,discovery}.rs`, `crates/device-link-net/tests/{channel_v2_loopback,channel_v3_loopback}.rs`, `crates/host-runtime/src/{net_runtime,share_runtime}.rs` and `crates/host-runtime/tests`, `crates/passwsync-ffi/src/{sync,network}.rs`, `crates/passwsyncd/src/http/{api_network,api_share,api_sync}.rs`, `crates/wallet-sync/tests/codec.rs`. Write the full list in the PR description. Every file found outside `crates/passwsyncd/tests` that pins old behaviour gets its own rewrite task or is fixed in T017/T052; anything under `crates/passwsyncd/tests` that pins old behaviour is a design conflict: stop and report it instead of editing

**Checkpoint**: baseline green, frozen surface known, full user list known.

---

## Phase 2: Foundational - regression test support (blocks all stories)

- [ ] T004 Create `crates/device-link-net/tests/lan_attacks.rs` with `mod support;` and helpers ported from `specs/009-lan-dos-hardening/evidence/poc_lan.rs.txt`: `partitioned`, `udp`, `announce`, `tarpit` (`hold` true or false), `connect_for_real`. Keep the evidence file unchanged and uncompiled. Do not port `poc4` or `poc5`. Each test in this file prints one measurement line with no secret
- [ ] T005 In `crates/device-link-net/tests/lan_attacks.rs` add the control test (no attacker: version v3, one sync channel) from the evidence `control` test. Run `cargo test --frozen --offline -p device-link-net --test lan_attacks -- --test-threads=1`: green on unfixed code (this is the baseline all later red tests are compared with)

**Checkpoint**: the attack harness compiles and the control passes.

---

## Phase 3: User Story 1 - An attacker cannot lock sync off for 24 hours (P1) - R1, R2, R9, R10

**Goal**: nothing about a peer's version outlives its channel; a reduced channel gets back to v3; "unsupported" follows the authenticated channel.
**Independent test**: after an early-close attack ends, real announcements give a v3 sync channel in 10 of 10 runs with no restart and no wait.

### Tests first (red)

- [ ] T006 [US1] In `crates/device-link-net/tests/lan_attacks.rs` add `downgrade_attack_does_not_outlive_the_attacker` adapted from `poc1`: announce each paired id with an address that closes at once (`tarpit(false)`), let both devices dial it, stop the attacker, play real announcements; assert v3 and one sync channel, no restart, no waiting for any timer. Loop 10 runs with fresh nodes, all must pass (SC-001). Do not assert any `max_version` value (the API goes away). Run: RED
- [ ] T007 [US1] In the same file add `attack_never_shows_peer_unsupported` (SC-003, FR-004): during and after the early-close attack of T006, `Node::is_legacy(peer)` is false, no `PeerLegacy` or `PeerNoShare` event is emitted, and `peer_share` never answers `unsupported` (it answers `unknown` or `supported`). Run: RED
- [ ] T008 [US1] In the same file add `one_dial_is_bounded_by_one_step_timeout` (R9): a hold-open tarpit that closes just before each timeout; assert the whole dial (all fallback versions) ends within about one `step_timeout` plus slack, not three. Run: RED
- [ ] T009 [US1] **(GUARD)** In the same file add `older_peers_still_get_the_highest_common_version` (SC-002, FR-003): pairs of nodes where one side is a v1-only, v2-only or v3 peer (use `tests/support/old_peer.rs` as the existing channel tests do), on either dial direction; assert the highest common version. Run: GREEN now; it must stay green. Prove it bites: temporarily make the dial start at v1, see it fail, revert
- [ ] T010 [US1] Rewrite `crates/device-link-net/tests/channel_v3_loopback.rs`: remove every assertion about the 24 h memory, `Node::max_version` and `LEGACY_RETRY`; replace with the new rule (each dial starts at v3, a v2 peer is reached by fallback inside the dial, and a second dial starts at v3 again). Run: RED where it asserted fallback memory. Check the file by reading, not by assuming only these items
- [ ] T011 [US1] Rewrite `crates/device-link-net/tests/channel_v2_loopback.rs` the same way (24 h memory, `max_version`). Run: RED
- [ ] T012 [US1] In `crates/device-link/tests/link.rs` (or the version-duplicate test file you find with `grep -rn keep_existing crates/device-link/tests`) add unit tests for a new wrapper that compares versions before `keep_existing` (`crates/device-link/src/link.rs:83`): higher version wins on both sides' computation; equal versions fall through to `keep_existing` unchanged. Run: RED (compile error)
- [ ] T013 [US1] In `crates/device-link/tests/link.rs` add upgrade-probe tests with the fake clock: a channel below v3 schedules `next_upgrade` at +6 h; before that the tick asks for nothing; at +6 h the tick asks for one probe dial to `last_addr` that starts at v3 and stops at the current channel's version; a v3 channel schedules nothing; a dropped channel clears it (R10, FR-006). Run: RED

### Code (green)

- [ ] T014 [US1] In `crates/device-link-net/src/dialer.rs` make `dial_negotiated` start at v3 on every dial and fall back inside that dial only; keep nothing on failure (R1). Remove the read of the version memory. Run T006: GREEN or only blocked by T015
- [ ] T015 [US1] In `crates/device-link-net/src/lib.rs` remove `State.max_version`, `LEGACY_RETRY` and `Node::max_version`. Fix compile errors in `crates/device-link-net` only. Run T006, T010, T011: GREEN
- [ ] T016 [US1] In `crates/host-runtime/src/net_runtime.rs` and `crates/host-runtime/src/share_runtime.rs` drop the `max_version` wrapper and `peer_share` uses (data-model "Removed"); then fix every other user found in T003 (`crates/passwsync-ffi/src/{sync,network}.rs`, `crates/passwsyncd/src/http/{api_share,api_sync}.rs`, `crates/host-runtime/tests/**`, any other hit). `crates/passwsyncd/tests` is NOT edited. `cargo test --frozen --offline --workspace --no-run` compiles
- [ ] T017 [US1] Re-run the T003 grep for `max_version|LEGACY_RETRY`: no hit may remain in `crates android` outside `target/`; rewrite any remaining test or doc comment that mentions the memory (do not assume the list in T003 was complete)
- [ ] T018 [US1] In `crates/device-link-net/src/lib.rs` and `crates/device-link-net/src/conn.rs` make `Node::is_legacy(peer)` mean "a channel is up with this peer at v1", emit `PeerLegacy` and `PeerNoShare` only when an authenticated channel registers below the version, and make `peer_share` read channel version, then `seen`, then `unknown` (R2). Run T007: GREEN
- [ ] T019 [US1] In `crates/device-link-net/src/dialer.rs` give all waits before Noise message 2 in one dial one shared `step_timeout` deadline across fallback versions (R9). Run T008: GREEN
- [ ] T020 [US1] In `crates/device-link/src/link.rs` add the version-first duplicate wrapper and call it from `register` in `crates/device-link-net/src/conn.rs` (replace the direct `keep_existing` call). Run T012: GREEN
- [ ] T021 [US1] In `crates/device-link/src/link.rs` add `next_upgrade` and its tick output; in `crates/device-link-net/src/dialer.rs` and `crates/device-link-net/src/discovery.rs` run the probe dial from the existing 30 s tick (constant `UPGRADE_INTERVAL = 6 h`, no new timer, no `Timing` field); a higher authenticated channel replaces the lower one. Run T013: GREEN
- [ ] T022 [US1] Verify T009 and the rest of `cargo test --frozen --offline -p device-link -p device-link-net` are green, `cargo clippy` clean for both crates, then refactor (no behaviour change, tests green). Run `cargo test --frozen --offline -p passwsyncd --test share_old_peer` and confirm it passes UNCHANGED (its peer closes v3, authenticates at v2, and the `share peer unsupported` log follows the channel)

**Checkpoint**: US1 independent test passes 10 of 10; old peers interoperate; share_old_peer passes unchanged.

---

## Phase 4: User Story 2 - An attacker cannot burn the pairing code (P1) - R3, R4, R5, R11

**Goal**: only a complete key message uses up the code; Hellos hold nothing; five burned codes do not lock pairing out.
**Independent test**: 20 Hello-only contacts then the correct code pairs 10 of 10; one well-formed key message then abort refuses the code; the sixth untried code is refused as today.

### Tests first (red)

- [ ] T023 [US2] In `crates/device-link/tests/code.rs` add `CodeRateLimiter` tests (R5, FR-011): 5 untried then refuse; 5 tried (`mark_tried` after each) then a sixth granted; the 21st in 600 s refused; 5 untried codes then a sixth refused; `mark_tried` marks the newest entry and is idempotent; entries older than 600 s drop out. Run: RED (compile error on `mark_tried`)
- [ ] T024 [US2] In `crates/device-link/tests/` (the file that tests `PairingInitiator`; find it with `grep -rln PairingInitiator crates/device-link/tests`) add tests for the read accessor of its `consumed` flag: false after a malformed key message, true after a well-formed one (R4). Run: RED (compile error)
- [ ] T025 [US2] In `crates/device-link-net/tests/lan_attacks.rs` add `hello_only_contacts_do_not_burn_the_code` adapted from `poc2`: show a code, run at least 20 contacts that open and send a pairing Hello only (and some that send nothing, and some that send half a key message), then pair with the correct code. Loop 10 runs; all must pair (SC-004). Assert no `PairingSlot` is held by the idle contacts and `pairing.state` stays `waiting` (FR-008, FR-012). Do NOT port the old assertion "correct code refused 5 of 5". Run: RED
- [ ] T026 [US2] In the same file add `malformed_key_message_keeps_the_code_valid`: a Hello followed by a malformed key message is refused, `machine` returns to `None`, the slot is released and the correct code still pairs. Run: RED
- [ ] T027 [US2] **(GUARD, security, R3)** In the same file add `a_well_formed_key_message_uses_up_the_code_even_if_the_contact_aborts`: send a Hello and a well-formed key message (a random 33-byte `SPAKE_B`-shaped value that parses), read the answer, drop the connection at once; assert (a) the next attempt with the CORRECT code is refused, (b) a second well-formed key message on the same code is not answered, (c) two well-formed key messages sent at the same time get at most one answer (US2.3), (d) `pairing.state` is `failed` with a reason from the existing set. This is what prevents unlimited online guessing. Run: GREEN now (the consume point is unchanged); it must stay green. Prove it bites: temporarily move `code.consume` in `on_spake_b` to after the next message, see (a) or (b) fail, revert and record this in the PR description
- [ ] T028 [US2] In `crates/device-link-net/tests/lan_attacks.rs` add `contacts_before_the_key_message_do_not_block_the_real_exchange` (FR-012, US2.6): 16 idle Hello-only contacts open, the real device starts its exchange and completes it. Run: RED
- [ ] T029 [US2] In `crates/passwsyncd/src/http/api_network.rs` add a `#[cfg(test)]` unit test (inside src, NOT in `crates/passwsyncd/tests`) asserting the 429 body still has code `too_many_codes` and status 429, and the message text no longer contains "at most 5" and contains no code or key material. Run: RED

### Code (green)

- [ ] T030 [US2] In `crates/device-link/src/code.rs` implement the two tiers (`CODES_PER_WINDOW = 5` untried, `TOTAL_CODES_PER_WINDOW = 20`, `CODE_WINDOW = 600 s`, `created: list of (created_at, tried)`, `try_create`, `mark_tried`) per data-model. Run T023: GREEN
- [ ] T031 [US2] In `crates/device-link/src/pairing.rs` add the read accessor for `consumed` and nothing else (the machine, its fuzz targets and tests stay valid). Run T024: GREEN
- [ ] T032 [US2] In `crates/device-link-net/src/conn.rs` restructure `serve_pairing`: validate the Hello and read the next frame within the step timeout holding no lock, no `machine` and no `PairingSlot`; only then check for an active code, acquire the slot, create the `PairingInitiator` and feed the frame; if the accessor says the code was not used up (malformed frame), set `session.machine` back to `None` and release the slot (R4). Keep `code.consume` in `on_spake_b` exactly where it is (R3). Run T025, T026, T028: GREEN, and T027 still GREEN
- [ ] T033 [US2] In `crates/device-link-net/src/lib.rs` update `InitSession`: `exchanging` starts at the key message; call `mark_tried` on the limiter when an exchange uses up the current code (data-model state table). Run T025-T028: GREEN
- [ ] T034 [US2] In `crates/passwsyncd/src/http/api_network.rs` change only the `too_many_codes` message text (status and error code unchanged). Run T029: GREEN
- [ ] T035 [US2] Run `cargo test --frozen --offline -p passwsyncd --test api_pairing` and confirm the 6th-code 429 test (`crates/passwsyncd/tests/api_pairing.rs:332`) passes UNCHANGED; run `git diff --quiet main -- crates/passwsyncd/tests && echo unchanged` and confirm `unchanged`. If the 6th-code test fails, the limiter change is wrong: fix the limiter, never the test

### Initiator notice (R11)

- [ ] T036 [US2] CONFIRM (read only, no edit): how the Android pairing screen shows initiator-side failure reasons. Read `android/app/src/main/**/screens/Pairing.kt` and its string resources (`grep -rn "wrong_code_or_tampered\|reason" android/app/src/main`) and `crates/passwsyncd/ui/app.js` (`FAIL_REASONS`). Record in the PR description: (a) which file maps `wrong_code_or_tampered`, `timeout`, `protocol` to text on the showing side, (b) whether Android has a mapping or needs a new string. The research found no mapping in `Pairing.kt`
- [ ] T037 [US2] Based on T036, change the notice text: in `crates/passwsyncd/ui/app.js` set the showing-side text for `wrong_code_or_tampered`, `timeout` and `protocol` to "Another device tried to pair. Show a new code." (joining-side text unchanged); in `android/app/src/main/` add or change the same text (a new string resource plus the mapping if none exists). The text contains no code, guess or key material. Do not change the `reason` values or any API shape. If T036 shows Android never displays initiator reasons, add the minimal mapping and say so in the PR description
- [ ] T038 [US2] Run `cargo test --frozen --offline -p device-link -p device-link-net -p passwsyncd` and `android/verify.sh` (if it needs the Android SDK and the host lacks it, record ENV-BLOCKED and run its non-SDK checks); refactor with tests green

**Checkpoint**: US2 independent test passes; the guard from T027 is green; frozen tests unchanged.

---

## Phase 5: User Story 3 - A discovery flood cannot starve reconnection (P1) - R6, R7, R8

**Goal**: a flood cannot take the only dial slot, bounded work per datagram, a real or moved device still connects.
**Independent test**: with 1000+ datagrams/s naming a paired id with an attacker address, two disconnected paired nodes connect in 10 of 10 runs within the SC-005 budget, and dial attempts stay under the per-minute bound.

### Tests first (red)

- [ ] T039 [US3] In `crates/device-link/tests/discovery.rs` add hint-table tests (R7, data-model): at most 4 addresses per peer; keyed by source IP, newest datagram updates the port; a full table evicts the oldest `last_heard`; entries expire at `nearby_expiry`; selection picks the least recently tried; an address is not retried before `dial_backoff_min`; clear on authenticated channel; a hint never changes `last_addr` or the pin; 100000 datagrams from random sources keep the table at 4 entries (constant work, R8, SC-007). Run: RED (compile error)
- [ ] T040 [US3] In `crates/device-link/tests/link.rs` add two-path tests with the fake clock (R6): `known` and `hint` have separate `dialing` entries and backoffs; a failure on one never delays the other; an announcement does not reset or shorten the `known` backoff and wakes `known` no sooner than `dial_backoff_min` after its last attempt; only one hint dial at a time; hint dials spaced at least `step_timeout / 2`; a simulated 5 minute flood of 1000 announcements/s produces at most 12 hint dials per minute per peer and at most 2 dial threads in flight (SC-007). Run: RED
- [ ] T041 [US3] In `crates/device-link/tests/link.rs` add FR-018 tests: malformed, own-id, unknown-id, out-of-subnet and public-source datagrams, and duplicate or reordered ones, change no dial state and no table. Run: RED where a case is not yet ignored
- [ ] T042 [US3] In `crates/device-link/tests/link.rs` rewrite `an_announcement_resets_the_backoff` (line 61) to the bounded form: an announcement wakes the `known` path only once `dial_backoff_min` has passed since its last attempt, and does not shorten the doubling backoff beyond that. Check the other tests in that file for the same old assumption. Run: RED
- [ ] T043 [US3] In `crates/device-link-net/tests/lan_attacks.rs` add `announce_flood_does_not_starve_the_real_dial` adapted from `poc3`: flood from ONE source with a hold-open tarpit, the devices moved (use `partitioned`), real announcements every 300 ms; assert both channels come up within the fast-profile equivalent of the SC-005 budget (one `step_timeout` plus `step_timeout / 2` spacing plus slack) while the flood continues. Replace the old assertion "never up" and drop the comment about the tarpit closing triggering a downgrade (no longer true). Loop 10 runs. Run: RED
- [ ] T044 [US3] In the same file add the variant where the devices have NOT moved (pins hold the true `last_addr`, devices merely disconnected) and the flood comes from many forged source IPs (bind several `127.0.0.x` sockets if the datagram source rules accept them; if they do not, keep the many-source case in T039/T040 and say so in the test doc comment): they connect through the `known` path within the budget (SC-005, US3.5). Run: RED
- [ ] T045 [US3] **(GUARD)** In the same file add `returning_device_reconnects_no_slower_without_an_attack` (SC-006, US3.4): no flood, one real announcement; measure the time to channel against the existing reconnect scenario and assert it is within the same bound the current tests use. Run: GREEN now; must stay green
- [ ] T046 [US3] In the same file add `#[ignore]` test `five_minute_flood_keeps_dials_and_memory_bounded` (SC-007): 1000 datagrams/s for 5 minutes (fast profile scaled if the profile requires), assert dial attempts per minute under the T040 bound and process thread count and table sizes flat. Run it with `-- --ignored` once after T053 and record the result (not part of default `cargo test`)

### Code (green)

- [ ] T047 [US3] In `crates/device-link/src/discovery.rs` implement the per-peer hint table (`MAX_HINTS_PER_PEER = 4`, fields `addr`, `last_heard`, `last_tried`), no new field in `Timing`. Run T039: GREEN
- [ ] T048 [US3] In `crates/device-link/src/link.rs` split dial state into `known_backoff`, `known_next`, `known_last_attempt`, `hint_next` per `PeerRuntime`, implement `on_announce` per R6 (feeds the table, may wake `known` only after `dial_backoff_min`, never resets backoff), hint spacing `step_timeout / 2`, one hint dial at a time. Run T040, T041, T042: GREEN
- [ ] T049 [US3] In `crates/device-link-net/src/discovery.rs` make `on_datagram` do constant work (validate, feed the table, return) and make the tick drive both paths; in `crates/device-link-net/src/lib.rs` split `State.dialing` into `dialing_known` and `dialing_hint`, keep `Node::dial_now` on the `known` entry; in `crates/device-link-net/src/dialer.rs` add the hint dial path (least recently tried address, at most 3 connections sharing one `step_timeout`, clear the table when a channel authenticates; a hint never writes `last_addr`). No datagram rate limit (R8). Run T043, T044: GREEN
- [ ] T050 [US3] Run T045 (still GREEN) and the whole of `cargo test --frozen --offline -p device-link -p device-link-net`; then run T043 and T044 in a loop of 10 runs each and confirm 10 of 10 (SC-005)
- [ ] T051 [US3] Run T046 with `-- --ignored` and record the dial count per minute and memory observations in the PR description
- [ ] T052 [US3] Re-run the T003 grep for `dial_now|on_announce|dialing` and fix every remaining test or call site that assumed the single `dialing` set or the old reset-on-announce behaviour, including `crates/host-runtime/tests/**`; `crates/passwsyncd/tests` is NOT edited. Run `cargo test --frozen --offline --workspace`. Refactor with tests green
- [ ] T053 [US3] Confirm `Timing` is unchanged: `git diff main -- crates | grep -n "struct Timing" -A15` shows no added field, and `crates/passwsyncd/tests/common/server.rs` still compiles (`cargo test --frozen --offline -p passwsyncd --no-run`)

**Checkpoint**: all three stories green; the PoC findings 1-3 are covered by regression tests.

---

## Phase 6: User Story 4 - Maintainers see the residual risk and the out-of-scope list (P3)

**Goal**: documents match the code. Runs after the code of US1-US3 has landed.

- [ ] T054 [US4] Check, by reading, that the spec Out of Scope list (weak master password policy, unauthenticated slot exhaustion, pairing oracle, TCP subnet checks and virtual interfaces, local port impersonation) matches the deferred rows in `docs/threat-model.md`, and that `crates/device-link-net/tests/lan_attacks.rs` contains no test for poc4 or poc5. Residual risks to find stated in the threat model: a present attacker can still burn a code; an on-path attacker can force a lower version until the 6 h probe; an attacker can delay connection while present. Fix gaps in wording only
- [ ] T055 [US4] Flip documentation from pending to done now that the code landed: `grep -rni "pending 009" specs docs` and in each place (specs 003, 004, 005 amendment notes found by that grep, for example `specs/003-device-identity-pairing/{spec,research,data-model}.md`, `specs/004-wallet-sync-protocol/{research,data-model}.md`, `specs/005-wallet-sharing/{research,contracts/share-protocol}.md`, and any in `contracts/`) replace "(pending 009 implementation)" by "(implemented in 009)" and keep the rest of the note; in `docs/threat-model.md` change the finding statuses for the 009 findings (T-B05-5, T-B04-1, T-B04-5, the downgrade row in B-06, residual-risk rows) from Open to Fixed (or Residual where the text says residual) and add a change-log entry dated today naming 009. Only change a status whose test exists and passes (name the test in the row). Run `python3 scripts/check_threat_model.py`
- [ ] T056 [US4] Re-run `grep -rni "pending 009" specs docs`: no hit remains; update `specs/009-lan-dos-hardening/quickstart.md` only if a command or expected value changed during implementation

---

## Phase 7: Polish - gates

- [ ] T057 `cargo fmt --all --check` and `cargo clippy --frozen --offline --workspace --all-targets -- -D warnings` are clean
- [ ] T058 `cargo test --frozen --offline --workspace` is green and the test count is not below the T001 baseline except for tests deliberately rewritten in T010, T011, T042
- [ ] T059 Quickstart validation: `cargo test --frozen --offline -p device-link -p device-link-net` and check every row of the "Validate the fix" table in `specs/009-lan-dos-hardening/quickstart.md` against a passing test (SC-001..SC-007)
- [ ] T060 `scripts/gate.sh` passes (includes the fuzz targets and budgets); `python3 scripts/check_threat_model.py` passes
- [ ] T061 `android/verify.sh` passes (or reports ENV-BLOCKED where the Android SDK is missing, never PASS from this host); `git diff --quiet main -- crates/passwsyncd/tests && echo unchanged` prints `unchanged`
- [ ] T062 Confirm the frozen tests: `cargo test --frozen --offline -p passwsyncd --test api_pairing` (6th code 429) and `cargo test --frozen --offline -p passwsyncd --test share_old_peer` pass with no edit under `crates/passwsyncd/tests`
- [ ] T063 Leak and policy check (SC-009, FR-023): run the lan_attacks tests with `--nocapture` and search the output, the new log lines and the new notice text for a pairing code, key or wallet data (none allowed); `git diff main -- Cargo.lock` is empty; `git diff main -- crates | grep -c "unsafe"` shows no new `unsafe`; `git status --porcelain` shows only the files named in this list (nothing committed)
- [ ] T064 (MANUAL) [M][D] Real network checks the host cannot do: forged-source UDP across a physical LAN and Android background behaviour during a flood. Leave unchecked until a maintainer records the result in `specs/009-lan-dos-hardening/quickstart.md`

---

## Traceability

| Requirement | Tasks |
|-------------|-------|
| FR-001, FR-002, FR-005 | T006, T010, T011, T014, T015 |
| FR-003, SC-002 | T009, T022 |
| FR-004, SC-003 | T007, T018 |
| FR-006 | T013, T021 |
| FR-007 | T022 |
| FR-008, FR-012 | T025, T028, T032 |
| FR-009, FR-013 | T027, T032 |
| FR-010 | T036, T037 |
| FR-011 | T023, T030, T033, T035 |
| FR-014, FR-015 | T040, T042, T048 |
| FR-016, SC-007 | T039, T040, T046, T047-T049 |
| FR-017, SC-005, SC-006 | T043-T045, T050 |
| FR-018 | T041 |
| FR-019..FR-021 | T002, T034, T053, T061-T063 |
| FR-022 | every test task precedes its code task |
| FR-023, SC-009 | T063 |
| US4 | T054-T056 |

## Dependencies

Phase 1 then Phase 2, then US1, US2, US3 in order (they touch the same files `lib.rs`, `conn.rs`, `link.rs`, so no parallel work), then US4 (needs the code), then Polish. T015 compiles `device-link-net` only; T016 restores the rest of the workspace.

## Implementation strategy

MVP is US1 (T001-T022). Each story ends at a checkpoint where the workspace is green and the frozen `passwsyncd` tests pass unchanged.
