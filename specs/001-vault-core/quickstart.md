# Quickstart / Validation Guide: Vault Core (001)

How to prove feature 001 works once implemented. API shapes:
[contracts/vault-core-api.md](contracts/vault-core-api.md). File layout:
[contracts/file-format.md](contracts/file-format.md).

## Prerequisites

- Rust stable ≥ 1.85 (`rustup toolchain install stable`), `cargo`.
- Linux (primary). Android cross-compilation checks are optional:
  `rustup target add aarch64-linux-android` and the Android NDK.

## Build and test

```sh
cargo build --workspace
cargo test --workspace                       # unit + integration + storage contract suites
cargo test --workspace --release -- --ignored  # performance / memory checks (SC-003..SC-005)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Optional: `cargo build -p vault-core --target aarch64-linux-android` must succeed (portability).

## Validation scenarios

| # | Scenario | How | Expected |
|---|----------|-----|----------|
| V1 | Create → add → save → unlock round trip (US1, SC-001) | `vault-core` integration test using `MemoryStorage` | All fields and metadata identical after unlock |
| V2 | Wrong password (US1) | Unlock with a different password | `InvalidPasswordOrCorrupted`; no data returned |
| V3 | Short master password (FR-002) | Create with an 11-character password | `PasswordTooShort` |
| V4 | Edit / delete / list / search (US2) | Integration test on a vault with GitHub/GitLab/Bank | Search "git" → 2 results; deleted entry absent from list/search; tombstone in `all_records` |
| V5 | Tamper detection (US3, SC-002) | Flip each byte of a saved wallet in turn; also truncate and append | Every attempt fails (generic or format error), none succeed |
| V6 | Unsupported version / hostile KDF params (US3) | Patch version field to 2; patch memory to 4 GiB | `UnsupportedVersion(2)`; `KdfParamsOutOfRange`, returned without running the KDF |
| V7 | Storage parity (US4, SC-007) | `testkit::storage_contract` against `MemoryStorage` and `FileStorage` | Both pass |
| V8 | Atomic save (US4, SC-008) | File-adapter test simulating failure before rename | Previous file still unlocks |
| V9 | Version vectors (US5) | Edit same entry on copies with devices A and B; compare | `Concurrent`; single-side edit → `Newer` |
| V10 | No plaintext leakage (SC-006) | Search stored bytes and `format!("{:?}")` of vault/entries/errors for marker strings | Markers never found |
| V11 | Performance (SC-003/004) | Ignored release tests: unlock with `KdfConfig::DEFAULT`; search over 10,000 entries | Unlock < 2 s (laptop); search < 100 ms |
| V12 | Memory (SC-005) | Ignored test with counting allocator, 10,000 entries | Peak heap (excluding KDF) < 64 MB |
| V13 | Shared wallet on another device (FR-005b) | Seal on device A; unlock the same bytes with device B and the same password | Unlocks with identical entries; no other input needed |
| V14 | Offline / no secret persisted (FR-005a, FR-032) | Search sealed bytes for password and derived key; `cargo tree` and source grep for network crates/`std::net` | Neither found |

## Manual smoke check (optional)

A tiny example program (`crates/vault-storage-file/examples/smoke.rs`) creates a wallet at a
temp path, adds one entry, saves, reopens, and prints the entry title only. Run with
`cargo run -p vault-storage-file --example smoke`; inspect the file with `xxd` and confirm the
first bytes are `PWSV 0100 01` and no plaintext is visible.

## Reference devices (T048)

| Device | Role | Measured (default KDF: 64 MiB, 12 passes, 1 lane) |
|--------|------|-----------------------------------------------------|
| AMD Ryzen 5 PRO 4650U laptop (Linux, release build) | Reference laptop | Unlock ≈ 0.4 s (SC-003 window 0.3–2 s: pass) |
| Android phone (2021+ mid-range SoC) | Reference phone | **Not yet measured**: needs a real device (SC-003 target < 4 s) |

Not done in this environment: `cargo check --target aarch64-linux-android` (the installed Rust
toolchain is distro-packaged and has only the `x86_64-unknown-linux-gnu` target; no rustup).
Run it, and the phone unlock timing, when the Android feature sets up the NDK toolchain.

## Validation record (T050)

Run on 2026-10-23: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features
-- -D warnings`, `cargo test --workspace --all-features` (92 tests) and
`cargo test --workspace --release -- --ignored` (3 tests) all pass.

| # | Covered by |
|---|------------|
| V1–V3 | `tests/roundtrip.rs` |
| V4 | `tests/manage_entries.rs` |
| V5–V6 | `tests/tamper.rs` |
| V7–V8 | `tests/storage_memory.rs`, `vault-storage-file` contract and unit tests |
| V9 | `tests/sync_metadata.rs`, `version.rs` unit tests |
| V10 | `tests/leakage.rs` |
| V11–V12 | `tests/perf.rs` (ignored, release); memory measured as peak growth of `VmHWM` (counter reset after the transient KDF) because a counting global allocator needs `unsafe`, which the workspace forbids |
| V13 | `tests/roundtrip.rs::wallet_from_another_device_opens_with_the_password_alone` |
| V14 | `vault.rs` unit test; `grep std::fs` in the core, `grep std::net` in all crates, and a `cargo tree` scan for networking crates all return nothing; no account/email/login types exist |
