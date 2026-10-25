# Implementation Plan: Wallet Sync Protocol

**Branch**: `feat/004-wallet-sync-protocol` | **Date**: 2026-10-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-wallet-sync-protocol/spec.md`

## Summary

Make the same wallet on several paired devices converge without a server and without ever
sending the master password or any plaintext. Wallet format v2 (vault-core) adds, **inside
the encrypted payload only**, a wallet state vector, per-entry concurrent versions and a
password-change epoch; v1 files stay readable and are rewritten as v2. A new sans-IO crate
`wallet-sync` runs rounds over a v2 of the 003 channel (same framing, Hello version 2, two new
payload types): session-blinded wallet tags and state digests, full vectors only for wallets
that differ, pull-based whole-file transfer of ciphertext in 1000-byte chunks to disk. Unlocked
devices merge immediately with a deterministic lattice join of entry versions; locked devices
stage pending ciphertext and merge on unlock. Rollback protection uses a per-wallet sync record
(owner-only, digest-bound to the wallet file) with a high-water mark and per-peer marks, a
two-phase save journal for crash safety, and peers as distributed witnesses. Event-driven
scheduling with exponential backoff keeps idle cost < 1 KiB/peer/hour.

## Technical Context

**Language/Version**: Rust stable, edition 2024, MSRV 1.85 (workspace)

**Primary Dependencies**: existing `vault-core`, `wallet-service`, `device-link`,
`device-link-net`, `snow`, `postcard`/`serde`, `zeroize`, `rand_core`; new direct deps `hmac`
0.12 and `sha2` 0.10, both already in `Cargo.lock` (no new crate in the tree; research R17)

**Storage**: wallet files unchanged location, format v2 (contracts/file-format-v2.md); sync
records and pending copies under `$XDG_DATA_HOME/passwsync/sync/` (0700/0600, atomic writes;
contracts/host-runtime-sync.md)

**Testing**: `cargo test`; property tests for merge; sans-IO round/journal/scheduler tests with
in-memory ports; 5-device partition simulator; loopback transfer tests; raw-HTTP tests;
storage fault injection at every journal step; `#[ignore]` resource tests (research R16)

**Target Platform**: Linux desktop service (002/003); domain crates reusable by Android (007)

**Project Type**: library crates (domain + adapters) integrated into the local web service

**Performance Goals**: change visible on unlocked peer ≤ 60 s (95 %), ≤ 10 s after unlock;
10 000-credential wallet differing by one entry synced < 10 s on LAN (SC-001, SC-008)

**Constraints**: networking off ⇒ no sync activity; frames ≤ 1024 B, control messages ≤ 24 KiB,
copies ≤ 64 MiB, ≤ 1 MiB buffers per transfer, ≤ 2 transfers, 1 round per peer; idle
< 1 KiB/peer/hour, < 1 % CPU, < 8 MiB RAM over the 003 baseline; no plaintext metadata at
rest; `unsafe_code` forbidden

**Scale/Scope**: ≤ 32 peers, ≤ 256 devices per wallet, ≤ 512 wallets per round (rotating),
≤ 16 versions per entry

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | Encrypted at rest, zero plaintext on network, E2E + mutual auth, vetted crypto | PASS | PASS — only vault-core ciphertext crosses the 003 Noise channel; tags/digests are HMAC-SHA-256 (RustCrypto) keyed by the never-transmitted wallet id and bound to the Noise handshake hash; **no new plaintext metadata in wallet files** (R2); copies authenticated before use; rollback/replay handled with marks + digest + peers (R10, R11) |
| II. Simplicity | Simplest equal option | PASS | PASS — whole-file transfer, reuse of 003 framing and threads, text record files, no database/async; extra pieces justified below |
| III. TDD | Tests first, fakes | PASS | PASS — every rule testable in memory; property and crash-point tests planned (R16) |
| IV. Hexagonal | Core free of infra | PASS | PASS — `wallet-sync` sans-IO with ports; merge in `vault-core`; files/sockets/HTTP in adapters; network crates do not know wallets |
| V. Resource Efficiency | Bounded, measured | PASS | PASS — bounds above; streamed transfers; merges serialized with KDF (peak within 002 budget); measured by SC-006/SC-008 tests |
| VI. Decentralization | P2P, partitions, no silent overwrite | PASS | PASS — lattice merge (commutative/associative/idempotent), concurrent versions kept until resolved, tombstones kept forever |
| Workflow | Minimal, reviewed deps | PASS | PASS — no new crate in the tree; `cargo deny`/`cargo audit` unchanged gates |
| Roadmap globals | Offline except sync, no accounts, master password only secret, never sent | PASS | PASS — sync only with networking on and paired peers; password used only at local unlock or to open a pending copy, then wiped |

Gates pass. Deviations in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/004-wallet-sync-protocol/
├── plan.md
├── research.md            # R1–R17 (R2 header-metadata decision, R10–R11 rollback/DoS)
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── file-format-v2.md
│   ├── sync-protocol.md
│   ├── vault-core-sync-api.md
│   ├── http-api-sync.md
│   └── host-runtime-sync.md
├── checklists/requirements.md
└── tasks.md               # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
crates/
├── vault-core/            # format.rs (v1+v2), state.rs (StateVector), merge.rs (merge,
│                          # resolve, password epoch), copy.rs (OpenedCopy), storage.rs (+store_versioned)
├── wallet-sync/           # NEW sans-IO: codec.rs, tags.rs, round.rs, decide.rs, record.rs,
│   ├── src/               # journal.rs, sched.rs, ports.rs (+testkit fakes), error.rs
│   └── tests/             # rounds, marks, crash points, 5-device simulator
├── wallet-service/        # unlock merges pending; merge_copy, resolve_conflict, PendingCopies port
├── device-link/           # wire.rs (Hello v2, 0x20/0x21), channel.rs (session_hash, sync_enabled)
├── device-link-net/       # dialer v2→v1 fallback, SyncFrameSink, Node::send_sync
├── passwsyncd/            # sync_store.rs, sync_runtime.rs, journaling storage decorator,
│                          # http/api_sync.rs, config.rs (+sync_interval_minutes), log.rs, ui/
└── vault-storage-file/    # unchanged
```

**Structure Decision**: add `crates/wallet-sync` to workspace members (workspace lints,
`unsafe_code = "forbid"`). Dependencies point inward: `wallet-sync → vault-core`;
`wallet-service → vault-core`; `passwsyncd → {wallet-sync, wallet-service, device-link-net,
device-link, vault-core}`. `device-link*` do not depend on wallet crates.

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Spec amendment: wallet id and state vector NOT in a plaintext header (FR-012/FR-030 changed); locked devices use a digest-bound sync record | A plaintext state vector leaks device count, edit activity and cross-wallet device linkage from any backup or shared folder; the digest check detects every external file change, which is stronger than an unauthenticated header comparison (R2) | Plaintext authenticated header: leaks and gives only unauthenticated values while locked. Cost accepted: a hand-copied file syncs only after its first unlock on that device |
| New crate `wallet-sync` | Hexagonal isolation and reuse by 007 | Logic in `passwsyncd` cannot be tested without I/O or reused |
| Channel protocol v2 (Hello version 2, v1 fallback) | 003 v1 peers close on unknown messages; Hello is the only ignorable negotiation point; version bound into the Noise prologue (R7) | Capability field in `ChannelHello` breaks v1 peers; separate port duplicates handshake and pins |
| Control-message fragmentation inside 1024-byte frames | Keeps the reviewed 003 frame bound while summaries can reach ~19 KiB (256 devices) | Raising the frame limit changes a reviewed DoS bound |
| Additive `VaultStorage::store_versioned` default method | Two-phase journal needs the state vector of the bytes being saved, which is encrypted (R12) | Recomputing in the adapter is impossible without the key; changing `store`'s signature breaks 001 adapters |
| Equal-vector-different-content kept as conflict + "merge change" (beyond FR-013 wording) | Lossless handling of counter reuse after an undetected whole-installation restore (R5, R10) | Treating equal vectors as identical silently drops one version |
| Concurrent password changes keep the copy pending until the person chooses (FR-022 realized as a pending-copy conflict) | Merging needs one key; a deterministic winner could lock the person out | Automatic winner by tie-breaker risks a password the person does not know |
| No MAC on the sync record | Same-user writers are out of scope; a wallet-key MAC is unverifiable across password changes; a local key sits beside the record. Fail-safe semantics + peer marks cover tampering (R10, R11) | MAC adds key management without protecting against the only attacker who can write the file |
| `v1 → v2` upgrade at unlock when networking is on and a peer is paired | Otherwise a never-edited v1 wallet never syncs; networking+pairing is the opt-in (R3) | Upgrade on every unlock breaks downgrade for people who never sync |

## Post-design notes

- Open questions: none. All spec-level choices left open are resolved in research.md; the
  spec was amended (FR-010, FR-012, FR-013, FR-021, FR-030 and the last clarification) to
  match R2/R5/R9/R10, with a dated "Plan amendment" note.
- Residual risk (documented, R10): edits made on a device after an undetected restore of its
  whole installation and before it resyncs may be dominated by pre-restore edits elsewhere;
  peers flag the device ("older state offered"). Full elimination needs trusted monotonic
  hardware storage (revisit in 007/008).
