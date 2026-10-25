# Tasks: Wallet Sync Protocol

**Input**: Design documents from `/specs/004-wallet-sync-protocol/`
**Prerequisites**: plan.md, spec.md, research.md (R1-R17), data-model.md, contracts/ (file-format-v2.md, sync-protocol.md, vault-core-sync-api.md, http-api-sync.md, host-runtime-sync.md), quickstart.md
**Tests**: MANDATORY (Constitution III, TDD). Every implementation task is preceded by a test task that MUST be run and seen to FAIL (red) before the implementation task starts. Refactor with tests green.
**Analysis round 1 (2026-10-24)**: no existing task ID changed; T139-T142 were added in their phases, each placed before the implementation task it is made green by (T139-T140 in Phase 3, T141 in Phase 5, T142 in Phase 6).
**Organization**: By user story. Priority order: US1 edits propagate (P1), US2 concurrent edits kept (P1), US3 locked wallets (P1), US4 rollback detection (P2), US5 status and sync now (P2), US6 many devices and partitions (P3). The merge algorithm, v2 format and wire codecs are shared and live in Phase 2.
**Security rules for every task**: no plaintext metadata in wallet files or on the wire (R2); the master password is never sent and never stored; sync never resets the 002 idle timer; `unsafe_code` stays forbidden; no secret, title, wallet id or state vector in logs.

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repo root. `VC` = `crates/vault-core`, `WS` = `crates/wallet-sync`, `WSV` = `crates/wallet-service`, `DL` = `crates/device-link`, `DN` = `crates/device-link-net`, `PD` = `crates/passwsyncd`.
- Test tasks write the test only (red); the next numbered implementation task makes it green.
- **(MANUAL)** = needs a human, a browser, two hosts or network namespaces (root), tcpdump or pidstat; cannot be automated here.

---

## Phase 1: Setup

- [X] T001 Add `crates/wallet-sync` to workspace `members` and add `hmac` 0.12 and `sha2` 0.10 as shared dependencies (versions already in `Cargo.lock`; no new crate in the tree) in `Cargo.toml`
- [X] T002 [P] Create `crates/wallet-sync/Cargo.toml` (deps: vault-core, hmac, sha2, zeroize, rand_core; `testkit` feature; `[lints] workspace = true`; NO dependency on device-link, wallet-service, std networking or async) and empty `crates/wallet-sync/src/lib.rs`
- [X] T003 Add `sha2` to `crates/vault-core/Cargo.toml` (for `content_hash` only; vault-core MUST NOT depend on `wallet-sync`, which depends on vault-core, Principle IV) and `wallet-sync` to `crates/passwsyncd/Cargo.toml`; verify `cargo build --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` pass
- [X] T004 [P] Early dependency gate: run `cargo deny check` and `cargo audit`; only the already-accepted advisory (RUSTSEC-2023-0089) may remain; confirm `cargo tree -p wallet-sync` adds no crate outside the 003 tree (R17). Fix `Cargo.toml` features if anything new appears
- [X] T005 [P] Snapshot the baseline: run `cargo test --workspace` and record that 001-003 tests are green before any change (output noted in the PR description, no file)

---

## Phase 2: Foundational (blocks all user stories)

### vault-core: StateVector and Version types (data-model.md)

- [X] T006 [P] Write failing tests for `StateVector` (`get`, `bump` checked +1 with overflow error, `join` component-wise max, `dominates` with missing = 0, `compare` -> Equal/Newer/Older/Concurrent, canonical postcard encoding sorted by device id, reject unsorted/duplicate/zero counters/> 256 devices on decode) in `crates/vault-core/tests/state_vector.rs`
- [X] T007 Implement `StateVector` in `crates/vault-core/src/state.rs`; export from `crates/vault-core/src/lib.rs`
- [X] T008 [P] Write failing tests for `Version`, `content_hash` (SHA-256 of the postcard `Version`, known-answer vector) and the v2 `Entry { id, created_at, current, conflicts }` invariants (`is_conflicted`, <= 15 conflicts, no duplicate hash, no dominated version, canonical FR-014 order with current first, where a live version precedes a tombstone among concurrent versions, 001 accessors read `current`) in `crates/vault-core/tests/entry_v2.rs`
- [X] T009 Implement `Version`, `Entry` v2, `content_hash` and accessors in `crates/vault-core/src/entry.rs` and `crates/vault-core/src/version.rs` (001 tests keep passing)

### vault-core: file format v2 and v1 migration (contracts/file-format-v2.md)

- [X] T010 [P] Write failing tests for the v2 payload round trip (`wallet_id`, `created_at`, `state`, `password_epoch`, entries with conflicts) and parse order (`format_version` 2 accepted, 3 -> `UnsupportedVersion(3)`, header identical to v1 with only the version byte changed, size 79..=64 MiB) in `crates/vault-core/tests/format_v2.rs`
- [X] T011 [P] Write failing tests for v2 decode rejection, each case -> `InvalidPasswordOrCorrupted`: state > 256 devices, unsorted/duplicate/zero counters, > 15 conflicts, two versions with equal content hash, a version dominated by a sibling, non-canonical order, any version component greater than `state`; plus a fuzz-style loop over truncated/bit-flipped files (never panics) in `crates/vault-core/tests/format_v2_reject.rs`
- [X] T012 [P] Write failing tests for v1 reading: each v1 entry becomes `current` with no conflicts, `password_epoch = []`, `state[d] = sum of entries' version[d]` (exact), `format_version_loaded() == 1`, the next `save` writes version 2, a v1 file is byte-identical until saved, and a v2 file is never downgraded in `crates/vault-core/tests/migrate_v1.rs`
- [X] T013 [P] Write failing tests for no plaintext metadata (R2/SC-005): scan a v2 file for the wallet id, device ids, device-name strings and counters in clear; header equals the v1 layout byte for byte except the version; `Debug` of `Vault`/`OpenedCopy` shows no secret in `crates/vault-core/tests/leakage.rs` (extend)
- [X] T014 Implement v2 encode/decode, canonical-order checks and v1 -> v2 read conversion in `crates/vault-core/src/format.rs`; `Vault::state`, `format_version_loaded` in `crates/vault-core/src/vault.rs`
- [X] T015 Make every local mutation (`add`, `edit`, `delete`, `change_password`) bump the device's counter in `state` and in the touched version; first write by a device adds it to the vector; reject at 256 devices (`TooManyDevices`); extend failing tests first in `crates/vault-core/tests/manage_entries.rs` and `crates/vault-core/tests/saved_mutations.rs`, then implement in `crates/vault-core/src/vault.rs`
- [X] T016 [P] Write failing tests for `VaultStorage::store_versioned` (default impl delegates to `store`; `Vault::save` calls it with `SaveMeta { wallet_id, state }`; existing 001 adapters compile unchanged) in `crates/vault-core/tests/storage_memory.rs`
- [X] T017 Add `SaveMeta` and the default `store_versioned` method in `crates/vault-core/src/storage.rs`; call it from `Vault::save` in `crates/vault-core/src/vault.rs`; keep `crates/vault-storage-file` unchanged and its tests green

### vault-core: OpenedCopy and merge (contracts/vault-core-sync-api.md, R5, R6)

- [X] T018 [P] Write failing tests for `open_copy_own_key` (no KDF run, authentication failure -> generic `InvalidPasswordOrCorrupted`), `open_copy_with_password` (runs Argon2id once, password wiped), `needs_password` (header differs), `OpenedCopy` has no `Clone`/`Serialize`, `Debug` shows only wallet id and state, key material zeroized on drop in `crates/vault-core/tests/open_copy.rs`
- [X] T019 Implement `OpenedCopy`, `open_copy_own_key`, `open_copy_with_password`, `needs_password` in `crates/vault-core/src/copy.rs` and `crates/vault-core/src/vault.rs`
- [X] T020 [P] Write failing example tests for `merge` per entry: Equal -> unchanged, Newer/Older -> keep dominating version, Concurrent -> both kept with deterministic `current` (FR-014 order: live before tombstone, then modified_at (newest first), then device id, then content hash), edit vs delete concurrent keeps both with the live version as `current` (US2 scenario 2), tombstone vs older live keeps tombstone, new entries added, equal vector with different content kept as conflict plus `merge_change`, superseding version clears conflicts (FR-017), `WalletMismatch`, `TooManyConflicts` (> 15, nothing changes), `JumpTooLarge` (2^32 bound), `TooManyDevices`; `MergeReport` fields correct; on error the vault is untouched in `crates/vault-core/tests/merge.rs`
- [X] T021 Implement `merge` and `MergeReport`/`MergeError` in `crates/vault-core/src/merge.rs` (starts only when T020 and T022 are red); the merge is a pure function over entries plus a state join, bump the local counter only when `merge_change` applies (R5)
- [X] T022 [P] (written with T020, before T021 is implemented; red until T021/T023) Write failing property-style tests (seeded deterministic generator, >= 1000 cases per property, no new dependency: simple xorshift in the test) over random wallets built from random edits/deletes on 2-5 devices: convergence (all merge orders give identical entries, tombstones, conflicts), idempotence (`merge(a, a) == a`, merging an already-merged copy changes nothing), commutativity (`a+b == b+a`), associativity, no entry ever moves backwards (every resulting version dominates-or-equals each input's version of that entry, or is kept in conflicts), no silent overwrite (every input version not dominated by another input version is still present in the result), state vector = join, tombstones never dropped in `crates/vault-core/tests/merge_properties.rs`
- [X] T023 Fix any property failure found by T022 in `crates/vault-core/src/merge.rs` until all properties pass at 1000+ cases (no test weakening)
- [X] T024 [P] Write failing tests for the password-change epoch (FR-022): newer epoch adopted (`password_adopted`, copy key becomes the vault key, saved with the new salt/nonce), older ignored, concurrent epochs -> `PasswordConflict` and nothing changes, `merge_choosing_password(keep)` joins epochs and increments for me; wrong-password copy with a differing header -> `needs_password` in `crates/vault-core/tests/merge_password.rs`
- [X] T025 Implement password epoch handling, `merge_choosing_password`, `PasswordChoice` in `crates/vault-core/src/merge.rs`
- [X] T026 [P] Write failing tests for save-or-rollback on `merge` (storage failure -> vault exactly as before, 002 rule) and zeroization of the copy after merge in `crates/vault-core/tests/saved_mutations.rs`
- [X] T027 Implement a saved-merge helper (`merge` then `save`, rollback on failure) used by wallet-service in `crates/vault-core/src/vault.rs`
- [X] T028 [P] Write a failing allocation/size check for 10 000 entries merge (one entry differs): merge time and peak memory logged and bounded (`#[ignore]` benchmark, Constitution V) in `crates/vault-core/tests/perf.rs`; implement tuning only if the bound fails, in `crates/vault-core/src/merge.rs`

### device-link: channel v2 negotiation and sync frames (contracts/sync-protocol.md)

- [X] T029 [P] Write failing tests for Hello v2 (`PWSC || 0x02 || 0x01`), Noise prologue `passwsync-channel-v2 || Hello`, pairing Hello unchanged, responder answering v1 with a v1 channel (sync frames = protocol error) and v2 with a sync-enabled channel, `session_hash()` equal on both ends and different per session in `crates/device-link/tests/channel_v2.rs`
- [X] T030 [P] Write failing tests for `SyncCtl` (0x20, `more` 0/1, fragment 1..=1000) and `CopyData` (0x21, bytes 1..=1000) wire codecs: empty, 1001 bytes, bad `more`, unknown type on v1 and on v2, both valid only when `sync_enabled()`, wrong-state use (before handshake complete), replayed ciphertext and reordered frames rejected by the channel nonce in `crates/device-link/tests/wire_sync.rs` and `crates/device-link/tests/channel_attacks.rs` (extend)
- [X] T031 Implement `HelloVersion`, v2 prologue, `Payload::SyncCtl`/`CopyData`, `Channel::session_hash`, `sync_enabled`, `seal_sync` in `crates/device-link/src/wire.rs` and `crates/device-link/src/channel.rs` (003 tests unchanged and green)
- [X] T032 [P] Write failing loopback tests for dialer fallback (v2 dial closed before Noise msg2 -> peer marked `legacy`, redial v1 at once, retry v2 after 24 h or restart on a fake clock), `SyncFrameSink` callbacks (`channel_up` with session and dialer role, `frame`, `channel_down`), `Node::send_sync` holds the channel mutex across seal and write and refreshes the keepalive clock, frames to a v1 channel refused in `crates/device-link-net/tests/channel_v2_loopback.rs`
- [X] T033 Implement dialer v2 -> v1 fallback, `SyncFrameSink`, `Node::send_sync` in `crates/device-link-net/src/lib.rs` (and the channel/dialer modules it uses)

### wallet-sync: codecs, tags, ports (sans-IO)

- [X] T034 [P] Write failing tests for the control-message codec (all ctypes 0x01-0x0A with exact byte layouts, `sv` encoding, ranges: `n` <= 512, idx range, `CopyStart.size` 79..=67 108 864; reject trailing bytes, unknown ctype, truncation, oversize, unsorted `sv`) and fragmentation/reassembly (<= 24 KiB else protocol error, 1000-byte fragments, `more` handling, interleaved CopyData rejected) in `crates/wallet-sync/tests/codec.rs`
- [X] T035 Implement control-message types, encode/decode and the fragmenter/reassembler in `crates/wallet-sync/src/codec.rs`
- [X] T036 [P] Write failing tests for tags and digests (HMAC-SHA-256 keyed by wallet id, known-answer vectors for `tag` and `state_digest`, role/round/session separation: different session, round or role gives different tag; output truncated to 16 bytes; comparison through `hmac`'s constant-time `verify_slice` (no extra crate); wallet id never appears in any message) in `crates/wallet-sync/tests/tags.rs`
- [X] T037 Implement tag and digest functions in `crates/wallet-sync/src/tags.rs`
- [X] T038 [P] Write failing tests for port fakes: `MemorySyncStore` (record read/write with failure injection per step, pending files, partial files), `FakeMonoClock`/`FakeWallClock`, `FakeWalletReader` (offerable file bytes + digest), `FakeMerger` (accepts/rejects copies) in `crates/wallet-sync/tests/ports.rs`
- [X] T039 Implement ports (`SyncStore`, `WalletSource`, `Merger`, clocks, `Rng`) and `testkit` fakes in `crates/wallet-sync/src/ports.rs` and `crates/wallet-sync/src/error.rs`; wire modules in `crates/wallet-sync/src/lib.rs`

### sync record (host-runtime-sync.md)

- [X] T040 [P] Write failing tests for the record text codec: exact header and line grammar, `sv` text form, checksum line over all preceding bytes, reject unknown line, bad hex, unsorted vector, > 256 devices, > 32 peers, > 1 MiB, checksum mismatch -> `Corrupted`, round trip of all fields (prepared, flags, peers, pending, warnings) in `crates/wallet-sync/tests/record.rs`
- [X] T041 Implement `SyncRecord`, `PeerSyncState`, `PendingCopy`, `SyncWarning` (closed set) and the strict encode/decode in `crates/wallet-sync/src/record.rs`

### passwsyncd: config, files, log

- [X] T042 [P] Write failing tests for config key `sync_interval_minutes` (default 60, range 15..=1440, bad/duplicate -> `config: <key>: <problem>` exit 2; all 002/003 config tests unchanged) in `crates/passwsyncd/tests/config.rs`
- [X] T043 Implement `sync_interval_minutes` in `crates/passwsyncd/src/config.rs`
- [X] T044 [P] Write failing tests for the sync directory store: `sync/` 0700, `<wallet-id>/` 0700, `record`/`pending-<peer>`/`incoming-<peer>.part` 0600, atomic write (temp + fsync + rename + dir fsync), symlink/foreign owner/wrong mode refused without overwriting, `*.part` deleted at start, orphan pending removed, fault injection at each write step in `crates/passwsyncd/tests/sync_store.rs`
- [X] T045 Implement the `SyncStore` adapter in `crates/passwsyncd/src/sync_store.rs` (uses `fs_dir.rs` helpers)
- [X] T046 [P] Write failing tests for the added closed `LogEvent` variants (each renders exactly its host-runtime-sync.md text; none accepts free-form strings; never emits wallet id, state vector, titles, other devices' wallet names, or keys) in `crates/passwsyncd/tests/log.rs`
- [X] T047 Implement the added `LogEvent` variants in `crates/passwsyncd/src/log.rs`

**Checkpoint**: format v2, merge with properties, channel v2, codecs, record and stores ready.

---

## Phase 3: User Story 1 - Edits on one device appear on the other (P1)

**Goal**: unlocked paired devices converge on add/edit/delete within 60 s, with no plaintext on the wire.
**Independent test**: two in-process or loopback devices, same wallet unlocked on both, edits on A appear on B with identical fields/vectors/tombstones; traffic contains no known plaintext (SC-001, SC-005).

### Round engine

- [X] T048 [P] [US1] Write failing tests for the round state machine (`Idle -> Tagging -> Summarizing -> Transferring -> Closing -> Idle`): tags/matches/summary exchange, `in_sync` wallets exchange only summaries (FR-029b), simultaneous `Tags` (dialer wins), `Busy` answer, one round per peer, wallets that the other side lacks are never created or named (FR-002, FR-010), `Done` handshake in `crates/wallet-sync/tests/rounds.rs`
- [X] T049 [P] [US1] Write failing tests for the want rule (all six conditions of sync-protocol.md; slot-limited retry is not a failure; refused peer's Summary still serves our side) in `crates/wallet-sync/tests/decide.rs`
- [X] T139 [P] [US1] Write failing scope tests for FR-039 and FR-006c (negative scope, written before the codec is final): the control-message ctype set is exactly 0x01-0x0A with no create, share or invite message; no message, summary or record field carries a device name, setting, pairing data or a wallet name; a round never contacts an address that is not a pinned peer; no relay, URL or internet configuration key exists for sync; no per-wallet sync switch exists in the config or API; sync never creates or deletes a wallet file (FR-002) in `crates/wallet-sync/tests/scope.rs` and `crates/passwsyncd/tests/scope_sync.rs`; green through T035, T050 and T066
- [X] T140 [P] [US1] Write failing tests for the rotating summary window (FR-005, FR-029): with 600 syncable wallets a round summarizes at most 512, the window rotates so every wallet both devices hold is summarized within `ceil(n / 512)` rounds, and a wallet outside the window is neither named nor created on the peer in `crates/wallet-sync/tests/rounds.rs` (extend); implemented in T050
- [X] T050 is also where T139 and T140 are made green.
- [X] T050 [US1] Implement the round engine in `crates/wallet-sync/src/round.rs` and the want decision in `crates/wallet-sync/src/decide.rs`
- [X] T051 [P] [US1] Write failing tests for the transfer: `CopyStart`/`CopyData*`/`CopyEnd` streamed to `incoming-<peer>.part` (<= 1 MiB buffer, <= 2 transfers service-wide), size mismatch, overrun beyond `size`, `CopyData` outside a transfer, `CopyAbort` reasons, `Refuse` reasons, sender re-hashes while streaming and aborts with `changed` if the file differs from the record digest, only the device's own stored file is offered (FR-006a), part deleted on any failure, `.part` -> `pending-<peer>` atomic rename only after exact size in `crates/wallet-sync/tests/transfer.rs`
- [X] T052 [US1] Implement transfer handling (send and receive, slots, hashing) in `crates/wallet-sync/src/round.rs` and `crates/wallet-sync/src/transfer.rs`
- [X] T053 [P] [US1] Write failing negative-path tests at the protocol level: malformed messages of every ctype, oversized control message (> 24 KiB) and oversized frame, wrong-state messages (`Matches` before `Tags`, `Want` before `Summary`, `Done` early, `CopyEnd` without start), wrong round number, idx out of range, `Want` for an unsummarized wallet, replayed old-round messages, unknown ctype; each closes the round with a protocol error, never panics, leaks no state, and deletes partial files in `crates/wallet-sync/tests/protocol_attacks.rs`
- [X] T054 [US1] Fix gaps found by T053 in `crates/wallet-sync/src/round.rs` and `crates/wallet-sync/src/codec.rs`

### Accepting and merging (unlocked path)

- [X] T055 [P] [US1] Write failing tests for `Service::merge_copy` (unlocked wallet only; `Err(Locked)` when locked; `check` closure verifies authenticated wallet id equals requested, claimed state equals authenticated state, jump bound; mismatch rejected with warning; merge saved atomically via 002 save-or-rollback; does NOT reset the auto-lock idle timer, FR-006b; password buffer never involved) in `crates/wallet-service/tests/merge_copy.rs`
- [X] T056 [US1] Implement `Service::merge_copy`, `sync_facts`, `CopyFacts`, `CopyVerdict` in `crates/wallet-service/src/lib.rs` and `crates/wallet-service/src/sessions.rs`
- [X] T057 [P] [US1] Write failing tests for FR-026 (a local edit made between preparing and applying a merge is not lost: the merge applies to the live vault, not a stale snapshot) in `crates/wallet-service/tests/merge_copy.rs`; implement in `crates/wallet-service/src/lib.rs`
- [X] T058 [P] [US1] Write failing tests for merge serialization with the KDF lock (merges and unlock KDF never run concurrently; peak memory stays within the 002 budget; one merge at a time) in `crates/wallet-service/tests/merge_copy.rs`; implement in `crates/wallet-service/src/lib.rs`

### Daemon integration (basic path)

- [X] T059 [P] [US1] Write failing tests for the `sync-merge` and runtime wiring using in-process fake nodes: networking off -> no sync thread, no sync socket, no sync file activity (FR-001/networking invariant); networking on -> threads started after 003 step 5b; shutdown aborts rounds, deletes partial files and stops sync threads before the network in `crates/passwsyncd/tests/sync_runtime.rs`
- [X] T060 [US1] Implement `SyncRuntime` (feeds `SyncFrameSink` into `wallet-sync`, runs `sync-merge`, adapts `WalletSource`/`Merger` to wallet-service, only peers that are pinned and not revoked, FR-001) in `crates/passwsyncd/src/sync_runtime.rs`; start/stop from `crates/passwsyncd/src/net_runtime.rs` and `crates/passwsyncd/src/app.rs`
- [X] T061 [P] [US1] Write failing tests for the v1 -> v2 upgrade at unlock only when networking is on and >= 1 peer is paired (R3); log `wallet upgraded to format 2`; with networking off or no peer the v1 file stays byte-identical in `crates/passwsyncd/tests/upgrade_v2.rs`
- [X] T062 [US1] Implement the conditional upgrade in `crates/passwsyncd/src/app.rs` and `crates/wallet-service/src/lib.rs` (unlock path)
- [X] T063 [P] [US1] Write failing loopback tests: two real `Node`s on 127.0.0.1 (testkit policy), same wallet on both, edit on A -> B converges (identical entries, vectors, tombstones); delete propagates; add propagates; a capture proxy shows zero occurrences of any known title/username/password/URL/note/wallet name/wallet id/device name after the Hello (SC-005) in `crates/passwsyncd/tests/sync_two_devices.rs`
- [X] T064 [US1] Make T063 green; fix integration gaps in `crates/passwsyncd/src/sync_runtime.rs`
- [X] T065 [P] [US1] Write failing tests that revoking a peer (003) stops sync at once, deletes its pending copies and its peer lines in every record, and that sync with an unpinned or changed-key peer is refused (FR-001, Story 6 scenario 3) in `crates/passwsyncd/tests/sync_revoke.rs`
- [X] T066 [US1] Implement revoke handling in `crates/passwsyncd/src/sync_runtime.rs` and `crates/passwsyncd/src/net_runtime.rs`
- [X] T067 [P] [US1] Write a failing `#[ignore]` performance test: 10 000-credential wallet differing by one credential syncs < 10 s on loopback (SC-008) in `crates/passwsyncd/tests/sync_perf.rs`; fix bottlenecks in `crates/wallet-sync/src/transfer.rs` if it fails
- [ ] T068 [US1] (MANUAL) Two hosts or network namespaces (root): run quickstart scenarios 1 and 2 (edit visible <= 60 s; `strings` on wallet file shows no wallet id or device ids; `tcpdump` shows only Noise ciphertext after the 6-byte Hello) — **Not run here:** needs two hosts or root network namespaces and tcpdump; in-process equivalent is T063 (two real instances over loopback, capture proxy shows no plaintext, wallet file scan in T013).

**Checkpoint**: US1 works end to end for unlocked devices.

---

## Phase 4: User Story 2 - Concurrent edits are never lost (P1)

**Goal**: concurrent edits and edit/delete pairs keep every version, identically on every device, until the person resolves them.
**Independent test**: edit the same credential on A and B while disconnected, reconnect, both hold the same conflict with both versions and the same current version; resolving on one clears it on the other (SC-003).

- [X] T069 [P] [US2] Write failing tests for `Vault::resolve` / `Resolution::{Keep(index), KeepBoth}`: `Keep(i)` yields one version with a new vector dominating all inputs, `KeepBoth` creates `live_versions - 1` new entries (returned ids), tombstone-vs-live resolution, `not_conflicted` error, index out of range, resolution is itself a mergeable change (the resolved entry dominates the old versions on the peer, FR-017), and `resolve_saved` rolls back on storage failure in `crates/vault-core/tests/resolve.rs`
- [X] T070 [US2] Implement `resolve`, `resolve_saved`, `Resolution`, `Vault::conflicted`, `versions` in `crates/vault-core/src/merge.rs` and `crates/vault-core/src/vault.rs`
- [X] T071 [P] [US2] Write failing tests that list/search include conflicted entries with a `conflicted` flag and that 001/002 field access uses `current` in `crates/vault-core/tests/manage_entries.rs`; implement in `crates/vault-core/src/vault.rs`
- [X] T072 [P] [US2] Write failing two-device tests (in-process): concurrent edit/edit -> same conflict set and same `current` on both; edit/delete -> both versions kept; resolve "keep one" on A clears on B; "keep both" creates the extra entry on both; a third concurrent version added while resolving is kept (no lost update); > 15 versions -> `TooManyConflicts`, wallet sync `disabled(too_many_conflicts)` without data loss in `crates/wallet-sync/tests/conflicts_sync.rs`
- [X] T073 [US2] Fix gaps found by T072 in `crates/wallet-sync/src/round.rs` and `crates/wallet-service/src/lib.rs`
- [X] T074 [P] [US2] Write failing tests for `Service::resolve_conflict` (unlocked only, `Err(Locked)` otherwise, saves atomically, resolution counts as a deliberate action per 002 idle rules) in `crates/wallet-service/tests/resolve_conflict.rs`
- [X] T075 [US2] Implement `Service::resolve_conflict` in `crates/wallet-service/src/lib.rs`
- [X] T076 [P] [US2] Write failing HTTP tests for `GET /api/wallets/{name}/conflicts`, `GET .../conflicts/{id}` (deliberate, `423` when locked, `device` shows the device name or "unknown device"), `POST .../conflicts/{id}/field` (002 reveal/copy rules), `POST .../conflicts/{id}/resolve` (`keep: n` or `"both"`, `409 not_conflicted`, `500 storage_error` rolled back), and `conflicted` flag in list/search; raw-HTTP checks that every route keeps the 002/003 protections (session cookie, `X-CSRF-Token`, exact `Origin` on non-GET, exact Host, loopback peer UID, size limits, CSP headers, 404 for unknown paths) in `crates/passwsyncd/tests/api_conflicts.rs`
- [X] T077 [US2] Implement the conflict routes in `crates/passwsyncd/src/http/api_sync.rs`; register in `crates/passwsyncd/src/http/mod.rs` and the dispatcher in `crates/passwsyncd/src/http/api.rs`
- [X] T078 [P] [US2] Write failing UI asset tests (conflict list, conflict view with all versions side by side, resolve and keep-both actions are keyboard-operable, no inline script, passwords masked until reveal) in `crates/passwsyncd/tests/ui_assets.rs`
- [X] T079 [US2] Implement the conflict list/view/resolve UI in `crates/passwsyncd/ui/index.html` and `crates/passwsyncd/ui/app.js` (served via `crates/passwsyncd/src/assets.rs`)
- [ ] T080 [US2] (MANUAL) Browser: quickstart scenario 3 (conflict on both devices, resolve with keep both, cleared on the other); verify keyboard-only operation — **Not run here:** needs a real browser and two instances; automated equivalents: T072 (two-device conflicts, resolve, keep both), T076 (routes), T078 (UI assets, keyboard buttons).

---

## Phase 5: User Story 3 - Sync works while a wallet is locked (P1)

**Goal**: a locked device stores received ciphertext only, never needs the password to store it, and merges on unlock.
**Independent test**: lock B, edit on A; B has `pending-<A>`, its wallet file digest unchanged, state `changes_waiting`; unlock B merges within 10 s and removes pending.

- [X] T081 [P] [US3] Write failing tests for locked reception: copy stored as `pending-<peer>` ciphertext only (no key, no decrypt attempt, no password asked), at most one pending per peer per wallet (newer replaces older), wallet file and record `digest` unchanged, pending deleted if dominated by local state or peer revoked, total pending bounded (FR-029a), owner-only 0600 files, no copy created for a wallet the device does not hold, and a locked device holding `pending-<A>` never offers or sends that pending copy to C (FR-006a, US3 scenario 4; only its own stored file is offered) in `crates/wallet-sync/tests/pending.rs`
- [X] T141 [P] [US3] Write failing tests for storage-full on reception (spec edge case): with the store failing with "no space" when writing `pending-<peer>` or `incoming-<peer>.part`, no pending copy is kept, the partial file is removed, the wallet file and record are unchanged, the wallet status is `sync_error`, and the next attempt waits for the backoff (FR-028) in `crates/wallet-sync/tests/pending.rs` (extend); made green in T082
- [X] T082 [US3] Implement pending-copy handling in `crates/wallet-sync/src/round.rs` and `crates/wallet-sync/src/record.rs` (also makes T141 green)
- [X] T083 [P] [US3] Write failing tests for the `PendingCopies` port and `Service::unlock` merging pending copies: one at a time, copies under the wallet's own key merge via `open_copy_own_key`, a copy needing another password (differing header) is left `cannot_open` / password-conflict, unlock succeeds even if a copy is invalid (copy rejected with warning, wallet still opens), single save at the end, password wiped after, unlock signature unchanged, merged pending removed, outcome reported through `outcome()` in `crates/wallet-service/tests/unlock_pending.rs`
- [X] T084 [US3] Implement `PendingCopies`, `PendingRef`, `PendingOutcome`, and the unlock merge in `crates/wallet-service/src/ports.rs` and `crates/wallet-service/src/lib.rs`; adapter in `crates/passwsyncd/src/sync_runtime.rs`
- [X] T085 [P] [US3] Write failing tests for `open_pending_with_password` (wrong password -> `422 invalid_password_or_corrupted`, copy stays pending; right password merges; password wiped) and the password-conflict path (`merge_choosing_password` with `keep: local|copy`, wrong password rejected) in `crates/wallet-service/tests/pending_password.rs`
- [X] T086 [US3] Implement `open_pending_with_password` and the choose-password flow in `crates/wallet-service/src/lib.rs`
- [X] T087 [P] [US3] Write failing tests for owner-only sync records and files: modes 0600/0700 enforced, a record with wrong mode or foreign owner is treated as corrupted (sync disabled for that wallet, never silently reset), a record never contains secrets, plaintext, names of other devices' wallets or the master password; scan record and pending files for known plaintext markers in `crates/passwsyncd/tests/sync_store.rs` (extend)
- [X] T088 [US3] Implement the permission and corruption handling in `crates/passwsyncd/src/sync_store.rs`
- [X] T089 [P] [US3] Write failing HTTP tests for `POST /api/wallets/{name}/sync/pending/{peer}/open`, `.../choose-password`, `.../discard` (protections as T076; `422` handling; the password never logged, never echoed, never in any state response) in `crates/passwsyncd/tests/api_pending.rs`
- [X] T090 [US3] Implement the pending routes in `crates/passwsyncd/src/http/api_sync.rs`; UI prompts (changes waiting, cannot open, password conflict, discard) in `crates/passwsyncd/ui/index.html` and `crates/passwsyncd/ui/app.js`
- [X] T091 [P] [US3] Write failing end-to-end test: lock B, edit on A, wait for pending, assert wallet file bytes unchanged, unlock B merges <= 10 s on a fake clock, pending gone; while B is locked no credential content is served (`423`) in `crates/passwsyncd/tests/sync_locked.rs`
- [X] T092 [US3] Make T091 green; fix gaps in `crates/passwsyncd/src/sync_runtime.rs`
- [ ] T093 [US3] (MANUAL) Browser: quickstart scenario 4 (locked receiver) and verify the idle timer is not reset by sync activity — **Not run here:** needs a real browser; automated equivalents: T091 (locked receiver end to end), T055 merging_never_resets_the_idle_timer (FR-006b).

---

## Phase 6: User Story 4 - Old states are detected, never silently accepted (P2)

**Goal**: restored old files, older peers and replayed traffic never roll data back silently; crashes never corrupt a wallet.
**Independent test**: restore an old wallet file or serve an older copy; the device flags it, does not offer or accept it, and never moves an entry backwards (SC-004, SC-007).

### High-water marks and rollback

- [X] T094 [P] [US4] Write failing tests for marks: `mark = join(mark, state)` on each committed save; `peer_mark[p]` = newest authenticated state from `p`; a peer `Summary` with `state < peer_mark` -> "older state offered" warning and no `Want`; own file digest differing from record at start -> `possible_rollback` (reason `digest`, cleared only by an unlock that authenticates the file); own authenticated state not dominating `mark` -> `possible_rollback` and the wallet is not offered while flagged; flag persists until a merge brings state above the mark; jump bound `2^32` -> `invalid_copy` in `crates/wallet-sync/tests/marks.rs`
- [X] T095 [US4] Implement marks, flags and the check logic in `crates/wallet-sync/src/decide.rs` and `crates/wallet-sync/src/record.rs`
- [X] T096 [P] [US4] Write failing replay tests: an old complete round transcript replayed on a new channel fails (fresh Noise session, session-bound tags), a replayed old `pending` file offered again is rejected by the peer mark, a stale tag from a previous session never matches, and copy-after-rollback of the whole record plus wallet is detected by peer marks on other devices ("older state offered" on them) in `crates/wallet-sync/tests/replay.rs`
- [X] T097 [US4] Fix gaps found by T096 in `crates/wallet-sync/src/tags.rs` and `crates/wallet-sync/src/decide.rs`
- [X] T098 [P] [US4] Write failing tests for the authenticated checks at merge time (wrong wallet id, claimed `sv` differing from the authenticated one, `state` below the peer mark, jump too large, tampered ciphertext, truncated copy, copy authenticated under a different key): each is rejected with an `invalid_copy` warning naming only the peer, the wallet and data untouched, and the copy deleted in `crates/wallet-service/tests/merge_copy.rs`
- [X] T099 [US4] Implement the rejection paths in `crates/wallet-service/src/lib.rs` and warning creation in `crates/wallet-sync/src/record.rs`
- [X] T100 [P] [US4] Write failing tests for self-rollback recovery: after a restore of the whole installation, a peer offers a state with counters of this device above the local ones; the merge succeeds, bumps past them (`self_rollback_recovered`), and counter reuse never silently drops a version (equal vector with different content kept as conflict plus `merge_change`) in `crates/vault-core/tests/merge_recovery.rs`
- [X] T101 [US4] Implement `self_rollback_recovered` handling in `crates/vault-core/src/merge.rs`

### Two-phase save journal and crash safety

- [X] T102 [P] [US4] Write failing sans-IO journal tests with fault injection at every step: `prepared` written (record update with new digest/state/peer-mark updates/consumed pending) -> wallet file written (atomic) -> `committed` (prepared cleared, digest and marks advanced) -> pending deleted. Crash after each step then recovery: before the wallet write -> prepared discarded, old wallet intact; after the wallet write but before commit -> recovery sees digest match with prepared and commits; wallet digest matches neither -> `possible_rollback` (reason `digest`) until unlock; recovery is idempotent (run twice); the wallet is always openable with either the old or the new state, never partial, and no edit is lost (SC-007) in `crates/wallet-sync/tests/crash_points.rs`
- [X] T103 [US4] Implement the journal and recovery in `crates/wallet-sync/src/journal.rs`
- [X] T104 [P] [US4] Write failing tests for the journaling storage decorator (`store_versioned` writes `prepared`, then the inner store, then commit; inner failure leaves old wallet and a discarded prepare; record write failure aborts the save before touching the wallet file; works with the real file adapter) and for crash injection during transfer (killed mid-`.part`, mid-`pending` rename), merge (killed before/after save) and local save in `crates/passwsyncd/tests/crash_injection.rs`
- [X] T105 [US4] Implement the journaling decorator in `crates/passwsyncd/src/sync_runtime.rs` (or `crates/passwsyncd/src/journaling_storage.rs`) and wire all wallet saves through it, including 002 local edits and `change_password`
- [X] T106 [P] [US4] Write failing start-up tests (step 5c): recover journals, delete `*.part`, drop orphan pending files and lines, verify each wallet digest, corrupted record -> wallet sync disabled with a clear message and the service still starts (exit codes unchanged), duplicate wallet id in two files -> `duplicate_wallet_id` and both disabled in `crates/passwsyncd/tests/startup_sync.rs`
- [X] T142 [P] [US4] Write failing recovery-without-lockout tests (FR-025, FR-036, SC-007): with a corrupted or deleted sync record, the wallet still unlocks with the correct password and its contents are intact, the record is rebuilt from the authenticated file only by an explicit `reset` (T108), and no sync state ever blocks unlock; a wallet flagged `possible_rollback` still unlocks, edits and saves locally; a wrong-password unlock never changes the record; a copy that cannot be opened never blocks unlock; after a crash at each journal step (T102) the next unlock succeeds with either the old or the merged state in `crates/passwsyncd/tests/recovery_unlock.rs`; made green by T107 and T062
- [X] T107 [US4] Implement start-up step 5c in `crates/passwsyncd/src/app.rs` (also makes T142 green)

### Warnings, recovery actions

- [X] T108 [P] [US4] Write failing HTTP tests for warnings and recovery: `GET /api/sync` lists warnings with stable ids; `POST /api/sync/warnings/dismiss` removes the warning only and never changes marks or data (FR-036); `POST .../sync/accept-older` and `.../sync/reset` require `confirm: true`, an unlocked wallet (`423` otherwise), are logged (`sync accepted older state`, `sync state reset`), accept-older resets this wallet's mark and peer marks, reset rebuilds the record from the authenticated file and clears `disabled(corrupted_record)`; protections as T076 in `crates/passwsyncd/tests/api_rollback.rs`
- [X] T109 [US4] Implement the warning and recovery routes in `crates/passwsyncd/src/http/api_sync.rs`; warnings and confirm dialogs in `crates/passwsyncd/ui/index.html` and `crates/passwsyncd/ui/app.js`
- [ ] T110 [US4] (MANUAL) Two instances: quickstart scenarios 5 and 6 (restore old wallet file, older peer offered, corrupt the record, reset sync state); confirm warnings stay visible until dismissed — **Not run here:** needs two separately started instances driven by hand; automated equivalents: T106 (restored file, corrupted record at start-up), T096 (older peer, restored installation), T108 (warnings, accept older, reset).

---

## Phase 7: User Story 5 - Status, sync now and resource-bounded scheduling (P2)

**Goal**: the person sees each wallet's sync state and can sync on demand; background activity is event-driven, backed off and cheap.
**Independent test**: wallet list shows state and last sync; "Sync now" runs one coalesced round; idle 5 peers x 10 wallets stays under budget (SC-006).

- [X] T111 [P] [US5] Write failing scheduler tests on fake clocks (sans-IO): rounds start only on exactly the five triggers of FR-027: (a) peer channel up, (b) a shared wallet changed and saved locally after the 5-second quiet period (coalesced), (c) a wallet unlocked with pending copies, (d) "Sync now" (starts within 2 s and bypasses backoff once; repeated presses do not start a second round), (e) the safety interval (`sync_interval_minutes`) since the last round with that peer; the backoff uses random jitter; no other periodic activity; no timers when networking is off; exponential backoff 30 s, 60 s, ... capped at 1 h and reset on success; `Busy` handled as a backoff; at most 1 round per peer and 2 transfers service-wide; coalescing of repeated triggers; legacy peers (`legacy_until` 24 h) never scheduled for sync; jittered safety interval does not synchronize across peers in `crates/wallet-sync/tests/sched.rs`
- [X] T112 [US5] Implement the scheduler in `crates/wallet-sync/src/sched.rs`
- [X] T113 [P] [US5] Write failing tests for the round timeout (30 s without progress -> failed, partial files deleted, backoff applied) and failure classes (`failed`, `busy`, `timeout`, `protocol`) feeding `last_outcome` and the log line `sync round end ... sent= received=` in `crates/wallet-sync/tests/rounds.rs` (extend)
- [X] T114 [US5] Implement timeout and outcome classes in `crates/wallet-sync/src/round.rs`
- [X] T115 [P] [US5] Write failing tests for the derived wallet state (priority: `sync_off`, `disabled(reason)`, `possible_rollback`, `conflicts(n)`, `changes_waiting`, `syncing`, `sync_error`, `not_synced(no_peer|unlock_once|format_v1)`, `in_sync`) and per-peer `position` (`in_sync|behind|ahead|diverged|unknown|offline|older_state_offered|error`) in `crates/wallet-sync/tests/status.rs`
- [X] T116 [US5] Implement status derivation in `crates/wallet-sync/src/status.rs`
- [X] T117 [P] [US5] Write failing HTTP tests for `GET /api/state` (per-wallet `sync` object), `GET /api/sync`, `GET /api/wallets/{name}/sync` (background routes: do not reset idle timers; no credential content for locked wallets; local names only; only peers that matched the wallet are listed), `POST /api/sync/now` (`202`, `409 networking_off`, coalesced while running, wallet name validated, unknown wallet 404), all with the 002/003 protections in `crates/passwsyncd/tests/api_sync_status.rs`
- [X] T118 [US5] Implement the status and sync-now routes in `crates/passwsyncd/src/http/api_sync.rs`; extend `/api/state` in `crates/passwsyncd/src/http/api.rs`
- [X] T119 [P] [US5] Write failing UI asset tests (wallet list shows sync state and last-synced time; per-wallet details view lists peers and positions; the paired-devices view (003) shows the time and outcome of the last sync round per device (FR-033); global and per-wallet "Sync now"; peer "sync unsupported by peer"; all keyboard-operable; polling reuses the existing network poll without extra requests when the tab is hidden) in `crates/passwsyncd/tests/ui_assets.rs`
- [X] T120 [US5] Implement the status, details and sync-now UI in `crates/passwsyncd/ui/index.html` and `crates/passwsyncd/ui/app.js`
- [X] T121 [P] [US5] Write failing `#[ignore]` resource tests (SC-006): 5 connected peers x 10 wallets all in sync, idle for the window: < 1 KiB/peer/hour of sync traffic, < 1 % CPU, < 8 MiB RSS above the 003 baseline, no timer wakeups while networking is off, buffers <= 1 MiB per transfer and <= 2 transfers (measured peak), 10 000-wallet-entry merge memory bounded in `crates/passwsyncd/tests/resources_sync.rs`
- [X] T122 [US5] Tune the scheduler and buffers until T121 passes, in `crates/wallet-sync/src/sched.rs` and `crates/passwsyncd/src/sync_runtime.rs`
- [X] T123 [P] [US5] Write failing flood tests (hostile peer: endless `Tags`, malformed frames, endless `Want`, huge `CopyStart`, slow-loris transfer, > 32 peers, 513 tags): bounded memory and CPU, round closed, other peers unaffected, drop counters logged at most once per minute in `crates/passwsyncd/tests/flood_sync.rs`
- [X] T124 [US5] Fix gaps found by T123 in `crates/wallet-sync/src/round.rs` and `crates/passwsyncd/src/sync_runtime.rs`
- [ ] T125 [US5] (MANUAL) Quickstart scenarios 7 and 8 (press "Sync now" twice -> one round in the log; kill A's network -> retries back off 30 s, 60 s, up to 1 h; run B on the 003 build -> `sync peer legacy`, channel stays up, no sync traffic); measure idle CPU/RAM with pidstat — **Not run here:** needs pressing buttons in a browser, a real network cut, a 003 build and pidstat; automated equivalents: T117 (sync now, coalesced), T111 (backoff 30 s doubling to 1 h), T032 (legacy peer fallback), T121 (idle cost).

---

## Phase 8: User Story 6 - Many devices and partitions converge (P3)

**Goal**: 3 or more devices with partitions and any merge order converge to identical entries, tombstones and conflicts.
**Independent test**: randomized 5-device simulator reaches identical state on all devices (SC-002).

- [X] T126 [P] [US6] Write a failing in-process multi-device simulator harness with 5 devices (real `vault-core` wallets, real `wallet-sync` engines, in-memory channels, fake clocks, a partition matrix, message loss and reordering, locked/unlocked toggling) in `crates/wallet-sync/tests/support/sim.rs`; implement the harness (test support code only) in the same file
- [X] T127 [P] [US6] Write failing simulation tests: A-B and B-C connected, never A-C, B unlocked -> A and C edit different credentials and converge through B; same through an unlocked intermediary only; a locked intermediary stores pending copies and never offers them (FR-006a); after it is unlocked it merges them and then offers only its own merged file; a revoked device receives nothing and its pending copies are dropped in `crates/wallet-sync/tests/multi_device.rs`
- [X] T128 [P] [US6] Write failing randomized simulation tests (seeded, >= 200 scenarios, seed printed on failure): random edits/deletes/resolutions, random partitions healing, random merge order, random crashes at journal points, random lock/unlock; after final connectivity all 5 devices hold identical entries, tombstones and conflict sets; no entry ever moves backwards on any device at any step; every non-dominated version ever created is present somewhere or was resolved by a recorded resolution; marks never decrease in `crates/wallet-sync/tests/partition_sim.rs`
- [X] T129 [US6] Fix every defect found by T127 and T128 in `crates/wallet-sync/src/` and `crates/vault-core/src/merge.rs` (no weakening of assertions; add a regression test per defect first)
- [X] T130 [P] [US6] Write a failing loopback test with 3 real `Node` instances (3 passwsyncd runtimes in-process): chain topology A-B-C converges, a restart of B mid-round recovers, revoking B stops propagation in `crates/passwsyncd/tests/sync_three_devices.rs`
- [X] T131 [US6] Make T130 green; fix gaps in `crates/passwsyncd/src/sync_runtime.rs`

---

## Phase 9: Polish and cross-cutting

- [X] T132 [P] Dependency review: `cargo deny check` and `cargo audit` pass with no new advisories or licenses; `cargo tree -d` shows no new duplicate crates; `hmac`/`sha2` pinned to versions already in `Cargo.lock`; record the outcome in the PR description (`Cargo.toml`, `Cargo.lock`, `deny.toml` only if an exception is needed and justified)
- [X] T133 [P] Static security checks: `grep` tests asserting no `unsafe`, no `println!`/`dbg!`/`eprintln!` of secrets or wallet data in `crates/wallet-sync` and the new `crates/passwsyncd/src` modules, and that no `Debug`/`Display` impl exposes wallet ids, state vectors, passwords or keys in `crates/wallet-sync/tests/scans.rs` and `crates/passwsyncd/tests/scans.rs` (extend)
- [X] T134 [P] Log-content scan: run the full sync test suite capturing the log; assert only closed `LogEvent` texts appear and no credential data, titles, keys, passwords, wallet ids, state vectors, or other devices' wallet names in `crates/passwsyncd/tests/log.rs`
- [X] T135 [P] Update the 001/002 contract documents named in vault-core-sync-api.md (`specs/001-vault-core/contracts/vault-core-api.md`, `specs/002-local-service-web-ui/contracts/vault-core-additions.md`) with the additive items; update `docs/roadmap.md` status for feature 004
- [X] T136 Regression of 001-003: run `cargo test --workspace`, `cargo test --workspace -- --ignored`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`; every 001-003 test passes unmodified (any test edited for 004 is listed in the PR with the reason); wallet files written by 001/002 builds still open and a v2 file produces the documented `UnsupportedVersion` on a 001 build
- [X] T137 Traceability: add the verification map below to the end of this file (update the table with real test file names after implementation) and confirm every FR and SC has at least one automated test or an explicit MANUAL task; fail the task if any row is empty
- [ ] T138 Final quickstart validation: run every command under "Automated checks" in `specs/004-wallet-sync-protocol/quickstart.md` and record pass/fail; (MANUAL) execute the 8 manual scenarios on two hosts or namespaces and record results; confirm "no crash, no data lost, all warnings visible until dismissed" — **Not run here:** automated part done (all quickstart commands pass: per-crate tests, --ignored resource/perf tests, clippy -D warnings); the 8 manual scenarios need two hosts or network namespaces and a browser.

---

## Dependencies and execution order

- Phase 1 -> Phase 2 -> user stories. Within Phase 2: vault-core (T006-T028) is independent of device-link (T029-T033); wallet-sync codecs (T034-T041) need T007 only for `StateVector`; passwsyncd items (T042-T047) need T041 for the record.
- US1 depends on all of Phase 2. US2 depends on US1 (it exercises the round path) and T021. US3 depends on US1 and T019. US4 depends on US1 and US3 (pending and record); journal tasks T102-T107 can start after T041 and T045. US5 depends on US1 (scheduler may start after T041). US6 depends on US1-US4.
- Always: test task, see it fail, then implementation task. A test task and an implementation task never run in parallel.

## Parallel opportunities

- Phase 2: T006, T008, T010-T013, T016, T018 (vault-core tests, different files) run together; DL tests T029/T030, WS tests T034/T036/T038/T040, PD tests T042/T044/T046 run in parallel with them.
- US1: T048, T049, T051, T053, T055, T059, T061, T065 test files are independent.
- US4 journal work (T102-T107) in parallel with marks (T094-T101) after Phase 2.
- US5 scheduler (T111-T112) in parallel with the HTTP and UI work (T117-T120).

## Implementation strategy

- MVP = Phases 1-3 (US1): two unlocked devices converge. Then US2 (never lose data) and US3 (locked) complete the P1 set; US4 before any release (rollback safety); US5, US6 and Polish last.
- At each checkpoint run `cargo test --workspace` and clippy. Do not weaken any merge property to make a test pass.
- Manual/hardware tasks: T068, T080, T093, T110, T125, T138.

## Verification map (completed by T137)

Test paths: `VC/tests`, `WS/tests`, `WSV/tests`, `DL/tests`, `DN/tests`, `PD/tests` (see the
path abbreviations above). Every row has at least one automated test; MANUAL tasks add the
two-host checks.

| Requirement | Tasks | Automated tests |
|-------------|-------|-----------------|
| FR-001 paired peers only | T060, T065, T066 | PD sync_revoke.rs, PD sync_runtime.rs, WS scope.rs (only_connected_peers_are_ever_addressed) |
| FR-002 never create a wallet | T048, T081 | WS rounds.rs (wallets_the_other_side_lacks...), WS scope.rs, WS pending.rs |
| FR-003 only encrypted files | T051, T063, T013 | WS transfer.rs, PD sync_two_devices.rs, VC leakage.rs |
| FR-004 additive versioned protocol | T029-T033, T125 | DL channel_v2.rs, DL wire_sync.rs, DL channel_attacks.rs, DN channel_v2_loopback.rs |
| FR-005 bounded sizes, rotating window | T030, T034, T051, T053, T123, T140 | WS codec.rs, WS transfer.rs, WS protocol_attacks.rs, WS rounds.rs (window), PD flood_sync.rs |
| FR-006, 006a, 006b, 006c | T055, T051, T058, T093, T048, T081, T139 | WSV merge_copy.rs, WS transfer.rs (own file only), WS pending.rs, WS scope.rs, PD scope_sync.rs |
| FR-007 no password to store | T081, T083 | WS pending.rs, WSV unlock_pending.rs, PD sync_locked.rs |
| FR-008 authenticate copies | T018, T098, T099 | VC open_copy.rs, WSV merge_copy.rs, WS pending.rs (invalid copy) |
| FR-009, FR-010 summaries and blinded tags | T036, T037, T048, T063 | WS tags.rs, WS rounds.rs, WS replay.rs, PD sync_two_devices.rs |
| FR-011, FR-012 state vector, no plaintext metadata | T006, T013, T014, T068 | VC state_vector.rs, VC leakage.rs, VC format_v2.rs, WS marks.rs |
| FR-013, FR-014, FR-015 merge and determinism | T020-T023 | VC merge.rs, VC merge_properties.rs, VC entry_v2.rs |
| FR-016, FR-017 resolution | T069-T080 | VC resolve.rs, WSV resolve_conflict.rs, WS conflicts_sync.rs, PD api_conflicts.rs, PD ui_assets.rs |
| FR-018 tombstones kept | T020, T022, T128 | VC merge_properties.rs, WS partition_sim.rs |
| FR-019 replay | T030, T096, T097 | DL channel_attacks.rs, WS replay.rs, WS protocol_attacks.rs |
| FR-020 never backwards | T022, T094, T128 | VC merge_properties.rs, WS marks.rs, WS partition_sim.rs |
| FR-021, FR-021a marks | T094, T095, T108 | WS marks.rs, WS decide.rs, WS replay.rs, PD api_rollback.rs, PD startup_sync.rs |
| FR-022 password epoch | T024, T025, T085, T086 | VC merge_password.rs, WSV pending_password.rs, PD api_pending.rs |
| FR-023, FR-024, FR-025 atomic save, ciphertext only, owner-only records | T026, T027, T044, T087, T102-T105 | VC saved_mutations.rs, PD sync_store.rs, WS crash_points.rs, PD crash_injection.rs |
| FR-026 local edits not lost | T057 | WSV merge_copy.rs |
| FR-027, FR-028, FR-029, FR-029a, FR-029b scheduling and bounds | T111-T114, T121, T081 | WS sched.rs, WS rounds.rs (timeout), WS transfer.rs (two transfers), WS pending.rs, PD resources_sync.rs |
| FR-030, FR-031 format v2 and bounds | T010-T017, T020, T072 | VC format_v2.rs, VC format_v2_reject.rs, VC migrate_v1.rs, PD upgrade_v2.rs, WS conflicts_sync.rs |
| FR-032-FR-037 UI and HTTP | T076-T079, T089, T090, T108-T109, T115-T120 | PD api_conflicts.rs, PD api_pending.rs, PD api_rollback.rs, PD api_sync_status.rs, PD ui_assets.rs, WS status.rs |
| FR-038 log | T046, T047, T134 | PD log.rs |
| FR-039 no sharing (explicit negative tests) | T139, T048 (no create path), T060 | WS scope.rs, PD scope_sync.rs |
| Edge: storage full on reception | T141, T082 | WS pending.rs (storage_full_keeps_nothing_and_fails_the_round) |
| Recovery without lockout (FR-025, FR-036, SC-007) | T106, T142, T107, T102 | PD recovery_unlock.rs, PD startup_sync.rs, WS crash_points.rs |
| SC-001 timing | T063, T067, T068 | PD sync_two_devices.rs, PD sync_locked.rs, PD sync_perf.rs (ignored) |
| SC-002 multi-device | T126-T128, T130 | WS multi_device.rs, WS partition_sim.rs, PD sync_three_devices.rs |
| SC-003 conflicts kept | T072, T020 | WS conflicts_sync.rs, VC merge.rs |
| SC-004 rollback | T094-T100, T110 | WS marks.rs, WS replay.rs, VC merge_recovery.rs |
| SC-005 no plaintext in traffic | T013, T063, T068 | VC leakage.rs, PD sync_two_devices.rs |
| SC-006 idle cost | T121, T125 | PD resources_sync.rs |
| SC-007 crash safety | T102-T106, T142 | WS crash_points.rs, PD crash_injection.rs, PD startup_sync.rs, PD recovery_unlock.rs |
| SC-008 10 000-credential sync | T028, T067 | VC perf.rs (ignored), PD sync_perf.rs (ignored) |
