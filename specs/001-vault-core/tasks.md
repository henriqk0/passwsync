---

description: "Task list for feature 001 vault-core"
---

# Tasks: Vault Core

**Input**: Design documents from `/specs/001-vault-core/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/vault-core-api.md, contracts/file-format.md, quickstart.md

**Tests**: REQUIRED. The constitution (Principle III, NON-NEGOTIABLE) mandates TDD: every test
task MUST be written and observed failing (`cargo test` red) before its paired implementation
task starts. Unit tests live in a `#[cfg(test)] mod tests` inside the module file they test;
integration tests live in `crates/*/tests/`.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US5)
- Paths are relative to the repository root and follow the plan.md structure (`crates/vault-core`, `crates/vault-storage-file`)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace initialization and tooling

- [X] T001 Create workspace `Cargo.toml` (members `crates/vault-core`, `crates/vault-storage-file`; `resolver = "3"`; `[workspace.package] edition = "2024"`, `rust-version = "1.85"`; `[workspace.lints.rust] unsafe_code = "forbid"`; `[workspace.lints.clippy] all = "warn"`) and `rust-toolchain.toml` (channel `stable`, components `rustfmt`, `clippy`)
- [X] T002 Review every dependency listed in research.md R15 (`cargo audit` / RustSec advisories, maintenance status, license) and record the result and pinned versions in a "Dependency review" note appended to specs/001-vault-core/research.md (constitution workflow gate: deps reviewed before being added)
- [X] T003 [P] Create `crates/vault-core/Cargo.toml` (deps: `argon2` 0.5, `aes-gcm` 0.10, `zeroize` 1 with `derive`, `rand_core` with `getrandom`, `serde` 1 with `derive`, `postcard` 1 with `alloc`, `unicode-normalization` 0.1, `thiserror` 2; feature `testkit = []`; `[lints] workspace = true`) and an empty `crates/vault-core/src/lib.rs` with `#![forbid(unsafe_code)]`
- [X] T004 [P] Create `crates/vault-storage-file/Cargo.toml` (dep `vault-core` path; dev-dep `vault-core` with `features = ["testkit"]`; `[lints] workspace = true`) and an empty `crates/vault-storage-file/src/lib.rs` with `#![forbid(unsafe_code)]`
- [X] T005 Add Rust entries (`/target`, `**/*.rs.bk`) to `.gitignore` (current file only has Go patterns) and confirm `cargo build --workspace` succeeds on the empty crates

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared value types and ports used by every user story

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T006 [P] Write failing unit tests in `crates/vault-core/src/error.rs`: every `VaultError` and `StorageError` variant has a fixed `Display` string; `StorageError::NotFound` is distinguishable from `Io`; `VaultError::Storage` wraps `StorageError` (variants per contracts/vault-core-api.md "Errors")
- [X] T007 Implement `VaultError` and `StorageError` with `thiserror` in `crates/vault-core/src/error.rs` (no variant carries secret or plaintext data) so T006 passes
- [X] T008 [P] Write failing unit tests in `crates/vault-core/src/ids.rs`: `WalletId`/`EntryId` random generation yields distinct values over 1,000 draws; lowercase-hex `Display` and `EntryId::from_str` round-trip; `DeviceId::new` rejects empty and >64-byte strings with `InvalidDeviceId` and accepts 1–64 bytes
- [X] T009 Implement `WalletId`, `EntryId` (16 bytes from `rand_core::OsRng`, failure → `VaultError::Rng`), and `DeviceId` in `crates/vault-core/src/ids.rs` so T008 passes
- [X] T010 [P] Write failing unit tests in `crates/vault-core/src/clock.rs`: `FixedClock::new(t).now() == t`, `set`, `advance`; `SystemClock::now()` is within 5 s of `SystemTime::now()`
- [X] T011 Implement `Clock` trait, `SystemClock`, `FixedClock` (AtomicI64) in `crates/vault-core/src/clock.rs` so T010 passes
- [X] T012 [P] Write failing unit tests in `crates/vault-core/src/secret.rs`: `MasterPassword::new` applies NFC (composed "é" U+00E9 and decomposed "e"+U+0301 produce equal normalized bytes); `char_count` counts Unicode scalar values after NFC; `Debug` of `MasterPassword` and `VaultKey` prints `[REDACTED]`; compile-time assertion that both types implement `ZeroizeOnDrop`
- [X] T013 Implement `MasterPassword` (Zeroizing NFC string, no Clone/Display/Serialize) and `VaultKey` (32-byte zeroize-on-drop) in `crates/vault-core/src/secret.rs` so T012 passes
- [X] T014 [P] Write failing unit tests in `crates/vault-core/src/version.rs`: `VersionVector::new(&d)` == `{d: 1}`; `increment(&d)` adds exactly 1 to `d` only; `get` of absent device == 0; `iter` yields devices in sorted order; serde round-trip through postcard preserves contents
- [X] T015 Implement `VersionVector` (BTreeMap<DeviceId, u64>; `new`, `increment`, `get`, `iter`; serde as sorted `Vec<(String, u64)>` per contracts/file-format.md) in `crates/vault-core/src/version.rs` so T014 passes (comparison comes in US5)
- [X] T016 [P] Write failing unit tests in `crates/vault-core/src/storage.rs`: `MemoryStorage::load` before any store → `StorageError::NotFound`; store then load returns identical bytes; second store replaces the first
- [X] T017 Implement `VaultStorage` trait and `MemoryStorage` in `crates/vault-core/src/storage.rs` so T016 passes
- [X] T018 Declare modules and public re-exports (error, ids, clock, secret, version, storage) in `crates/vault-core/src/lib.rs`; `cargo test -p vault-core` green

**Checkpoint**: Foundation ready — user story implementation can now begin

---

## Phase 3: User Story 1 - Create a wallet and store credentials securely (Priority: P1) 🎯 MVP

**Goal**: Create a wallet with a master password, add credentials, save, and unlock them back unchanged.

**Independent Test**: `cargo test -p vault-core --test roundtrip` — create, add, save to `MemoryStorage`, drop, open with the same password, compare every field and metadata value (quickstart V1–V3).

### Tests for User Story 1 ⚠️ (write first, must fail)

- [X] T019 [P] [US1] Write failing unit tests in `crates/vault-core/src/entry.rs`: `EntryFields` with empty or whitespace-only title → `EmptyTitle`; any field > 1 MiB → `FieldTooLarge`; `Entry::new_live(fields, device, now)` sets `id`, `created_at == modified_at == now`, `last_modified_by == device`, `version == {device: 1}`; `Debug` of `EntryFields`/`Entry` redacts `password` and `notes`; compile-time assertion that `EntryFields` implements `ZeroizeOnDrop`
- [X] T020 [P] [US1] Write failing unit tests in `crates/vault-core/src/kdf.rs`: `KdfConfig::DEFAULT == {65536, 12, 1}`, `MINIMUM == {19456, 2, 1}`; `validate` accepts the documented bounds inclusive and rejects one below/above each bound with `KdfParamsOutOfRange`; derivation with `MINIMUM` and a fixed salt is deterministic and differs for a different salt or password
- [X] T021 [P] [US1] Write failing unit tests in `crates/vault-core/src/format.rs`: header encodes to exactly 63 bytes with magic `PWSV`, version 1, kdf_id 1 and fields at the offsets in contracts/file-format.md; header parse round-trips; `seal` then `open` with the same key returns the same payload; two `seal` calls on the same payload produce different nonces and ciphertexts; decrypt with a wrong key → `InvalidPasswordOrCorrupted`
- [X] T022 [P] [US1] Write failing integration tests in `crates/vault-core/tests/roundtrip.rs` (all using `KdfConfig::MINIMUM`, `FixedClock`, `MemoryStorage`): create → add 3 entries → save → `Vault::open` returns identical fields, ids, timestamps, versions, wallet id and created_at (SC-001); wrong password → `InvalidPasswordOrCorrupted`; 11-character password → `PasswordTooShort`, 12-character accepted; NFC-equivalent password unlocks; `add_entry` with empty title → `EmptyTitle`; `Vault::create` with `KdfConfig` outside bounds → `KdfParamsOutOfRange`; `change_master_password` with an 11-character password → `PasswordTooShort` and the old password still works; `change_master_password` with a valid password then save → old password fails, new password unlocks, KDF salt in header changed; `open` on empty storage → `Storage(NotFound)`; `lock` consumes the vault; shared-wallet case (FR-005b): bytes sealed by a vault created with device "A" unlock via `Vault::unlock` with device "B" and the same password, yielding identical entries; three consecutive `save` calls after one unlock succeed without any password argument (FR-005a)

### Implementation for User Story 1

- [X] T023 [P] [US1] Implement `EntryFields` (ZeroizeOnDrop, redacting Debug, `validate`), `Entry` (private fields, accessors per contract), `EntryState::Live`, and `Entry::new_live` in `crates/vault-core/src/entry.rs` so T019 passes
- [X] T024 [P] [US1] Implement `KdfConfig` (DEFAULT, MINIMUM, bounds `validate`) and `derive_key(&MasterPassword, &KdfConfig, &[u8; 32]) -> Result<VaultKey, VaultError>` using `argon2` Argon2id v0x13 with 32-byte output written into a zeroizing buffer in `crates/vault-core/src/kdf.rs` so T020 passes
- [X] T025 [US1] Implement header encode/parse (parse order steps 1–4 of contracts/file-format.md, before any KDF), postcard payload encode into a `Zeroizing<Vec<u8>>` buffer, AES-256-GCM `seal` (random nonce, header as AAD) and `open` (decrypt into zeroizing buffer, decode payload; any failure → `InvalidPasswordOrCorrupted`) in `crates/vault-core/src/format.rs` so T021 passes (depends on T023, T024)
- [X] T026 [US1] Write failing unit test in `crates/vault-core/src/vault.rs` (`#[cfg(test)]`, crate-private key access): after `create` and after `unlock`, the 32 derived key bytes and the UTF-8 master password bytes do not occur anywhere in the output of `seal` (FR-005a); `VaultKey` and `Vault` do not implement `Serialize` (compile-time negative check via trait-absence helper or doc-test `compile_fail`)
- [X] T027 [US1] Implement `Vault` in `crates/vault-core/src/vault.rs` (key memory-only, never serialized; password dropped right after derivation): `create` (password ≥12 chars check, KDF bounds check, new salt, derive key, drop password), `unlock`, `open`, `seal`, `save`, `lock`, `Drop` (zeroizes key and entries), redacting `Debug`, `wallet_id`, `created_at`, `kdf_config`, `add_entry`, `get`, `change_master_password` (≥12 chars, new salt, same KdfConfig, wipe old key) so T022 and T026 pass (depends on T025)
- [X] T028 [US1] Export `entry`, `kdf` (KdfConfig only), `vault` items in `crates/vault-core/src/lib.rs`; `cargo test -p vault-core` green

**Checkpoint**: MVP — a wallet can be created, filled, saved, and unlocked.

---

## Phase 4: User Story 2 - Manage credentials: edit, delete, list, search (Priority: P2)

**Goal**: Edit, delete (tombstone), list, and search credentials in an unlocked wallet.

**Independent Test**: `cargo test -p vault-core --test manage_entries` (quickstart V4).

### Tests for User Story 2 ⚠️ (write first, must fail)

- [X] T029 [P] [US2] Write failing integration tests in `crates/vault-core/tests/manage_entries.rs`: `update_entry` replaces fields, advances `modified_at` (FixedClock advanced), increments the device counter by 1, keeps `id`/`created_at`; `delete_entry` removes the entry from `get`/`list`/`search`, keeps it in `all_records` with `deleted_at` set, `fields() == None`, counter incremented; update/delete of unknown id or tombstone → `EntryNotFound` and no change; `list` sorted case-insensitively by title then id (GitHub, gitlab, Bank → Bank, GitHub, gitlab); duplicate titles both listed; `search("git")` returns GitHub and gitlab only; search matches username, URL, notes; search never matches a string present only in `password`; Unicode case-insensitive match ("ÉCOLE" finds "école"); empty query equals `list`; tombstones and edits survive save/open round trip

### Implementation for User Story 2

- [X] T030 [US2] Add `Entry::replace_fields` (whole-value replacement) and `Entry::into_tombstone`/`mark_deleted` (drops and zeroizes fields, sets `EntryState::Deleted { deleted_at }`) with metadata updates in `crates/vault-core/src/entry.rs`
- [X] T031 [US2] Implement `update_entry`, `delete_entry`, `list`, `search` (Unicode lowercase of query and fields into `Zeroizing<String>` temporaries; title/username/url/notes only), and `all_records` in `crates/vault-core/src/vault.rs` so T029 passes (depends on T030)

**Checkpoint**: US1 and US2 both pass independently.

---

## Phase 5: User Story 3 - Tamper and corruption detection (Priority: P2)

**Goal**: Any modified, truncated, padded, or unsupported wallet is rejected with no partial data.

**Independent Test**: `cargo test -p vault-core --test tamper` (quickstart V5–V6).

### Tests for User Story 3 ⚠️ (write first, must fail where behavior is missing)

- [X] T032 [P] [US3] Write integration tests in `crates/vault-core/tests/tamper.rs` (wallet sealed with `KdfConfig::MINIMUM` and 2 entries): flipping each single byte of the file in turn never yields `Ok` (SC-002); truncation to every length from 0 to len-1 never yields `Ok`; appending 1 byte → error; bytes 0–3 changed → `MalformedFile`; version set to 2 → `UnsupportedVersion(2)`; kdf_id set to 2 → `UnsupportedKdf`; memory field set to 4 GiB/iterations 0/parallelism 17 → `KdfParamsOutOfRange` returned in < 50 ms (proves no KDF ran); input > 64 MiB → `MalformedFile`; correct password but flipped ciphertext byte → `InvalidPasswordOrCorrupted`
- [X] T033 [P] [US3] Write failing unit tests in `crates/vault-core/src/format.rs` for authenticated-but-invalid payloads (sealed directly with a crafted payload through a private test helper): duplicate entry ids, unsorted or duplicate version-vector keys, zero counter, empty title on a live entry, trailing bytes after the payload → each `InvalidPasswordOrCorrupted`

### Implementation for User Story 3

- [X] T034 [US3] Add payload validation (checks from T033) and the 79-byte minimum / 64 MiB maximum length checks to `open` in `crates/vault-core/src/format.rs`; fix any T032 failures there so T032 and T033 pass

**Checkpoint**: Tamper resistance verified independently of US2.

---

## Phase 6: User Story 4 - Pluggable storage (Priority: P3)

**Goal**: Identical behavior for in-memory and file storage; crash-safe file saves.

**Independent Test**: `cargo test -p vault-core --features testkit --test storage_memory` and `cargo test -p vault-storage-file` (quickstart V7–V8).

### Tests for User Story 4 ⚠️ (write first, must fail)

- [X] T035 [US4] Implement the shared contract suite `testkit::storage_contract<S: VaultStorage>(make: impl Fn() -> S)` in `crates/vault-core/src/testkit.rs` (gated by `#[cfg(feature = "testkit")]`, exported from `lib.rs`): load-before-store → `NotFound`; store/load identical; second store replaces; empty and 1 MiB payloads round-trip
- [X] T036 [P] [US4] Write `crates/vault-core/tests/storage_memory.rs` running `storage_contract(MemoryStorage::new)` (`required-features = ["testkit"]` in `crates/vault-core/Cargo.toml`)
- [X] T037 [P] [US4] Write failing `crates/vault-storage-file/tests/contract.rs` running `storage_contract` against `FileStorage` in a unique directory under `std::env::temp_dir()` (random-suffixed, removed at end)
- [X] T038 [P] [US4] Write failing unit tests in `crates/vault-storage-file/src/lib.rs` (`#[cfg(test)]`): temp file written but commit (rename) skipped leaves the old file byte-identical and unlockable (SC-008); a failing rename (target path is a directory) returns `Io` and removes the temp file; created file mode is `0600` on Unix (`#[cfg(unix)]`); missing file → `NotFound`; missing parent directory → `Io`
- [X] T039 [P] [US4] Write failing `crates/vault-storage-file/tests/vault_file_roundtrip.rs`: `Vault::create` → add entry → `save(&mut FileStorage)` → `Vault::open` returns identical entry; file starts with bytes `50 57 53 56 01 00 01`; a known plaintext marker in password/notes is not present in the file bytes

### Implementation for User Story 4

- [X] T040 [US4] Implement `FileStorage` in `crates/vault-storage-file/src/lib.rs`: `new(path)`, `load` (read whole file, map `NotFound`), `store` split into private `write_temp` (`.<name>.tmp-<random hex>` in the same directory, `OpenOptions` with mode 0600 on Unix, `write_all`, `sync_all`) and `commit` (`rename`, then fsync parent dir on Unix; on any error remove temp) so T037–T039 pass

**Checkpoint**: Both storage adapters pass the same contract suite.

---

## Phase 7: User Story 5 - Sync-ready metadata (Priority: P3)

**Goal**: Stable identities and version vectors that let a future sync feature classify copies as equal/newer/older/concurrent.

**Independent Test**: `cargo test -p vault-core --test sync_metadata` (quickstart V9).

### Tests for User Story 5 ⚠️ (write first, must fail)

- [X] T041 [P] [US5] Write failing unit tests in `crates/vault-core/src/version.rs` for `compare`: identical → `Equal`; strictly dominating → `Newer`/`Older`; missing device treated as 0; `{A:2,B:1}` vs `{A:1,B:2}` → `Concurrent`; `compare` is antisymmetric (a.compare(b) is the inverse of b.compare(a)) over a table of cases
- [X] T042 [P] [US5] Write failing integration tests in `crates/vault-core/tests/sync_metadata.rs`: create on device A, edit twice, delete → id unchanged, version `{A:4}`, `last_modified_by == A`, `modified_at` updated each step, tombstone survives save/open; seal once, unlock the same bytes as device A and as device B, edit the same entry on each → versions compare `Concurrent`; edit only on B → B's copy `Newer`; wallet id and entry ids identical across both copies

### Implementation for User Story 5

- [X] T043 [US5] Implement `VersionOrdering` and `VersionVector::compare` in `crates/vault-core/src/version.rs` and export them from `crates/vault-core/src/lib.rs` so T041 and T042 pass

**Checkpoint**: All user stories independently functional.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Leakage, performance, memory, portability, and quickstart validation

- [X] T044 [P] Write `crates/vault-core/tests/leakage.rs` (SC-006, FR-025): with unique marker strings in title/username/password/url/notes and the master password, assert no marker appears in sealed bytes, in `format!("{:?}")` of `Vault`, `Entry`, `EntryFields`, `MasterPassword`, or in `Display`/`Debug` of every `VaultError` produced by the US1/US3 failure paths
- [X] T045 [P] Write `#[ignore]` release-mode tests in `crates/vault-core/tests/perf.rs`: unlock with `KdfConfig::DEFAULT` < 2 s and ≥ 0.3 s on the reference laptop (SC-003, laptop half); `list` and `search` over 10,000 generated entries < 100 ms (SC-004); a counting `#[global_allocator]` (std `System` wrapper, safe code only) asserts peak heap while unlocked with 10,000 typical entries (excluding the KDF call) < 64 MB (SC-005)
- [X] T046 [P] Add `crates/vault-storage-file/examples/smoke.rs` per quickstart.md (creates a wallet in a temp dir, adds one entry, saves, reopens, prints only the title)
- [X] T047 [P] Write rustdoc for all public items in `crates/vault-core/src/lib.rs` and module files, including a "Security notes" section on zeroization limits and the host obligation to lock memory against swap and disable core dumps (FR-025a, research R7)
- [ ] T048 Verify portability: `cargo check -p vault-core -p vault-storage-file --target aarch64-linux-android` succeeds; record the reference laptop and Android phone models and a manual Android unlock timing with `KdfConfig::DEFAULT` (SC-003 Android half, < 4 s) in a "Reference devices" section of specs/001-vault-core/quickstart.md
- [X] T049 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, and `cargo test --workspace --release -- --ignored`; fix any findings
- [X] T050 Execute quickstart.md validation scenarios V1–V14 and confirm each expected outcome; review against constitution review gates (no plaintext outside protected memory; core has no filesystem imports — `grep -rn "std::fs" crates/vault-core/src` returns nothing; offline — `grep -rn "std::net" crates/` returns nothing and `cargo tree --workspace` lists no networking crates (FR-032); no account/email/login/identity types exist (FR-033); complexity justified)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 first; T002 before T003/T004 (deps reviewed before added); T003 and T004 in parallel; T005 after both
- **Foundational (Phase 2)**: depends on Setup; blocks all user stories
- **US1 (Phase 3)**: depends on Foundational
- **US2 (Phase 4)**, **US3 (Phase 5)**: depend on US1 (they extend `Vault`/`format` and need sealed wallets) — independent of each other
- **US4 (Phase 6)**: depends on Foundational for T035–T038/T040; T039 also needs US1
- **US5 (Phase 7)**: T041/T043 depend only on Foundational; T042 needs US1 and US2 (edit/delete)
- **Polish (Phase 8)**: depends on all stories

### Within Each User Story

- Test tasks first; confirm they fail (red) before starting the paired implementation (Principle III)
- entry/kdf before format; format before vault
- Story checkpoint green before moving on

### Story Completion Order

```text
Setup → Foundational → US1 ─┬─▶ US2 ─┐
                            ├─▶ US3 ─┼─▶ US5 (T042) ─▶ Polish
                            └─▶ US4 ─┘
             Foundational ──▶ US4 (T035–T038, T040), US5 (T041, T043) may start early
```

### Parallel Opportunities

- Phase 1: T003, T004 (T005 after both)
- Phase 2: all test tasks T006, T008, T010, T012, T014, T016 in parallel; then implementations in parallel (different files)
- US1: T019, T020, T021, T022 in parallel; T023 and T024 in parallel
- US3: T032 and T033 in parallel
- US4: T036–T039 in parallel after T035
- US5: T041 and T042 in parallel
- Polish: T044–T047 in parallel

---

## Parallel Example: User Story 1

```bash
# Tests first (all different files):
Task: "Unit tests for EntryFields/Entry in crates/vault-core/src/entry.rs"        # T019
Task: "Unit tests for KdfConfig/derive_key in crates/vault-core/src/kdf.rs"       # T020
Task: "Unit tests for header/seal/open in crates/vault-core/src/format.rs"        # T021
Task: "Integration tests in crates/vault-core/tests/roundtrip.rs"                 # T022

# Then independent implementations:
Task: "Implement Entry in crates/vault-core/src/entry.rs"                         # T023
Task: "Implement KDF in crates/vault-core/src/kdf.rs"                             # T024
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 (Setup) and Phase 2 (Foundational)
2. Complete Phase 3 (US1)
3. **STOP and VALIDATE**: `cargo test -p vault-core --test roundtrip`, quickstart V1–V3

### Incremental Delivery

1. Setup + Foundational → foundation ready
2. US1 → MVP (create/add/save/unlock)
3. US3 → tamper resistance (security priority, recommended right after US1)
4. US2 → full credential management
5. US4 → real file storage
6. US5 → sync-ready comparison
7. Polish → leakage, performance, memory, portability gates

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- Tests in the same module file as the code are written first in a separate task; the paired implementation task is never [P] with its test task
- Never log, print, or include secrets in assertions' failure messages (use `assert!(!bytes.windows(..).any(..))` style checks without echoing the marker)
- Do not commit; committing is outside this feature's workflow scope unless the maintainer asks

---

## Phase 9: Convergence

**Purpose**: Remaining gaps found by `/speckit-converge` against spec.md, plan.md, and the constitution. T048 (Android check and phone timing, SC-003) is still open from Phase 8 and is not repeated here.

- [X] T051 Make `format::seal` (and so `Vault::seal`/`save`) fail instead of producing a file larger than the 64 MiB read limit, with a failing test first (e.g., entries totalling over 64 MiB); today such a wallet saves fine but can never be unlocked, per FR-022 and contracts/file-format.md length rule (partial)
- [X] T052 Run `cargo audit` and `cargo deny check` (install them if missing), fix or justify every finding, and replace the "advisory scan NOT yet done" note in the Dependency review section of specs/001-vault-core/research.md with the results, per T002 and the constitution's "dependencies security-reviewed" workflow gate (partial)
- [X] T053 Write a failing test, then change `MasterPassword::new` in `crates/vault-core/src/secret.rs` so no unzeroized copy of the password can be left behind when NFC normalization outgrows the pre-sized buffer (e.g., skip the copy when `is_nfc`, otherwise size the buffer for worst-case expansion), per FR-024 (partial)
- [X] T054 Wrap the serialization buffer in `format::seal` so it is zeroized on the error path too (today it is wrapped only after `to_extend` succeeds), per FR-024 (partial)
- [X] T055 Make the SC-005 memory test in `crates/vault-core/tests/perf.rs` assert peak usage (e.g., `VmHWM` delta) rather than only retained RSS, and note the method in specs/001-vault-core/quickstart.md, per SC-005 (partial)
- [X] T056 Add failing-then-passing tests in `crates/vault-storage-file/src/lib.rs` for interruption at the remaining save steps (temp file cannot be created in a read-only directory; stale temp file from a crashed save does not block the next one — adapted: removing the target directory mid-save destroys the old wallet by definition, so it is not a meaningful interruption point) asserting the previous wallet stays byte-identical and unlockable, per SC-008 (partial)
