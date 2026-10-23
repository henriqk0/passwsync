# Implementation Plan: Vault Core

**Branch**: `main` (no feature branch created; feature tracked via `.specify/feature.json` → `specs/001-vault-core`) | **Date**: 2026-10-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-vault-core/spec.md`

## Summary

Build the pure-domain wallet core of the P2P password manager as a Rust library: create a
wallet protected by a master password (≥12 chars, NFC), add/edit/delete/list/search
credentials, and save/unlock through a storage port. Wallets are serialized with postcard,
encrypted with AES-256-GCM under an Argon2id-derived key, and written in a versioned binary
format whose 63-byte header (magic, version, KDF params, salt, nonce) is authenticated as AAD.
All secrets are zeroized. Each entry carries a version vector so the later sync feature can
detect concurrent edits; deletes leave tombstones. Delivered as two crates: `vault-core`
(domain, crypto, format, port, in-memory fake) and `vault-storage-file` (atomic file adapter).

Operating model: fully offline, no accounts/email/login/identity. The wallet's master
password is the only secret; it is wiped right after key derivation, and the derived key
lives in memory only while unlocked (lock, drop/exit, or host auto-lock wipes it) and is
never persisted. A wallet copied from another device opens with the same master password
alone.

## Technical Context

**Language/Version**: Rust stable, edition 2024, MSRV 1.85

**Primary Dependencies**: `argon2` 0.5, `aes-gcm` 0.10, `zeroize` 1 (derive), `rand_core` (OsRng via `getrandom`), `serde` 1 + `postcard` 1, `unicode-normalization` 0.1, `thiserror` 2 (see research R15)

**Storage**: Opaque encrypted bytes through the `VaultStorage` port; in-memory fake and a single-file adapter (atomic temp + fsync + rename, mode 0600)

**Testing**: `cargo test` (unit, integration, shared storage contract suite via `testkit` feature, exhaustive byte-mutation tests); `#[ignore]` release-mode perf/memory tests

**Target Platform**: Linux x86_64 (primary, future AUR service); Android aarch64 (future background app) — core must cross-compile

**Project Type**: Library (Cargo workspace, 2 crates)

**Performance Goals**: Unlock with default KDF < 2 s laptop / < 4 s mid-range Android; list/search over 10,000 entries < 100 ms

**Constraints**: Peak heap < 64 MB for 10,000 entries plus ≤ 64 MiB transient KDF memory; no plaintext outside process memory; master password/derived key never persisted; fully offline (no networking), no UI/service, no accounts/identity; file ≤ 64 MiB

**Scale/Scope**: Up to ~10,000 credentials per wallet; single writer per wallet file

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status (pre-research) | Status (post-design) |
|-----------|------|----------------------|----------------------|
| I. Security-First | AES-256-GCM + Argon2id at rest; vetted libs only; no plaintext to storage/logs; no custom crypto | PASS — RustCrypto crates only; header as AAD; generic auth error; redacted Debug; only ciphertext reaches the port | PASS — see file-format contract and R4/R7. Note: process-level memory locking / core-dump disabling deferred to host features (process owner), documented in R7 |
| I. (Zero-knowledge) | Secrets never reach network/unencrypted storage | PASS — offline crates; only master password is secret, never stored; key memory-only, no `Serialize` | PASS — enforced by leakage tests (T044) and no-network check (T050) |
| I. (P2P E2E) | P2P traffic E2E encrypted & mutually authenticated | N/A — no networking in this feature | N/A |
| II. Simplicity | Simplest option; complexity justified | PASS — linear search, no index; postcard instead of custom codec; no uuid/chrono/tempfile deps | PASS — two crates justified below |
| III. TDD | Tests written first and failing | PASS — tasks ordered test-first per story; contract suite shared by adapters | PASS |
| IV. Hexagonal | Core free of infra; ports + adapters; in-memory fakes | PASS — `VaultStorage` and `Clock` ports; `MemoryStorage`, `FixedClock` fakes; file adapter in separate crate | PASS — crate boundary enforces inward deps |
| V. Resource Efficiency | Deliberate allocation; secrets wiped; measurements | PASS — borrowed list/search results; bounded KDF/field/file sizes; memory test (SC-005) | PASS |
| VI. Decentralization | No central server; deterministic conflict handling without data loss | PASS (foundation) — 128-bit random ids, version vectors, tombstones; merge itself deferred to sync feature | PASS |
| Workflow gates | Minimal, vetted deps; reviews check plaintext & isolation | PASS — dependency table in R15 | PASS |

No unjustified violations. Swap/core-dump protection is assigned by spec FR-025a to the
executable that owns the process (service feature / Android app) as a required acceptance item
there; this feature documents the obligation in rustdoc (task T047) and minimizes plaintext
lifetime via zeroization.

## Project Structure

### Documentation (this feature)

```text
specs/001-vault-core/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── vault-core-api.md   # library API + storage port contract
│   └── file-format.md      # encrypted file format v1
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks)
```

### Source Code (repository root)

```text
Cargo.toml                      # workspace: members = crates/*
rust-toolchain.toml             # stable, components rustfmt + clippy
crates/
├── vault-core/
│   ├── Cargo.toml              # features: testkit
│   ├── src/
│   │   ├── lib.rs              # public re-exports only
│   │   ├── error.rs            # VaultError, StorageError
│   │   ├── ids.rs              # WalletId, EntryId, DeviceId, random id generation
│   │   ├── clock.rs            # Clock port, SystemClock, FixedClock
│   │   ├── secret.rs           # MasterPassword (NFC, zeroizing), VaultKey
│   │   ├── version.rs          # VersionVector, VersionOrdering
│   │   ├── entry.rs            # EntryFields, Entry, tombstones, validation
│   │   ├── kdf.rs              # KdfConfig, bounds, Argon2id derivation
│   │   ├── format.rs           # header encode/parse, payload codec, seal/open (AEAD)
│   │   ├── vault.rs            # Vault: create/unlock/save/lock/CRUD/list/search
│   │   ├── storage.rs          # VaultStorage port, MemoryStorage
│   │   └── testkit.rs          # storage contract suite (cfg feature = "testkit")
│   └── tests/
│       ├── roundtrip.rs        # US1
│       ├── manage_entries.rs   # US2
│       ├── tamper.rs           # US3
│       ├── storage_memory.rs   # US4 (contract suite on MemoryStorage)
│       ├── sync_metadata.rs    # US5
│       ├── leakage.rs          # SC-006
│       └── perf.rs             # SC-003/004/005 (#[ignore]), counting allocator
└── vault-storage-file/
    ├── Cargo.toml              # depends on vault-core (dev: features = ["testkit"])
    ├── src/lib.rs              # FileStorage
    ├── examples/smoke.rs       # manual smoke check (quickstart)
    └── tests/
        ├── contract.rs         # shared contract suite on FileStorage
        └── atomicity.rs        # interrupted write, temp cleanup, 0600, NotFound
```

**Structure Decision**: Cargo workspace with two library crates under `crates/`. The core crate
owns every domain rule and the storage/clock ports; the file adapter is the only crate allowed
to touch the filesystem. Future features (service, Android bindings, sync) add new crates that
depend on `vault-core` without modifying its boundaries.

## Complexity Tracking

| Violation / added complexity | Why Needed | Simpler Alternative Rejected Because |
|------------------------------|------------|-------------------------------------|
| Second crate (`vault-storage-file`) | Principle IV: compile-time guarantee that the core never imports filesystem code | Single crate with an adapter module relies on reviewer discipline only |
| Version vector instead of a revision counter | Principle VI: concurrent edits must be detectable to avoid silent overwrite | A single counter cannot distinguish concurrent edits from sequential ones |
| `Clock` port | Principle III: deterministic timestamp tests | Calling `SystemTime` directly makes timestamp assertions flaky |
