# Implementation Plan: Wallet Sharing

**Branch**: `feat/005-wallet-sharing` | **Date**: 2026-10-25 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/005-wallet-sharing/spec.md`

## Summary

Put an existing wallet on another already-paired device through a short-lived, single-use
invitation bound to one wallet and one recipient, with consent on both devices, without ever
sending the master password. The sender (wallet unlocked and 004-eligible) creates an invitation
with an 8-digit code (existing 003 `PairingCode` + rate limiter) and a QR. The recipient redeems
over the existing 003 channel, upgraded to **channel protocol v3** (Hello version 3, v3→v2→v1
fallback, two new payload types), by sending a session-bound HMAC-SHA-256 proof of the code (the
code itself never crosses the network). The sender verifies it in constant time, the person
accepts, and the stored encrypted wallet file is streamed with the 004 whole-file sender, size
bound and shared transfer limit. The recipient stores it as an owner-only, ciphertext-only
"received wallet" (≤ 8, deleted after 24 h); opening it with a local name and the master password
(new `wallet-service::adopt_received`) stores the exact bytes as a wallet, creates its 004 sync
record (with the sender's peer mark) and from then on 004 keeps it in sync. Logic lives in a new
sans-IO `share` module of `wallet-sync`; no new crate and no new dependency.

## Technical Context

**Language/Version**: Rust stable, edition 2024, MSRV 1.85 (workspace)

**Primary Dependencies**: existing `wallet-sync` (`hmac`, `sha2`, `zeroize`, `rand_core`),
`wallet-service`, `device-link` (`PairingCode`, `CodeRateLimiter`, `normalize_code`, Noise via
`snow`), `device-link-net`, `qrcodegen`, `serde_json`; **no new crate in `Cargo.lock`** (R15)

**Storage**: received wallets under `$XDG_DATA_HOME/passwsync/received/` (0700; `.pwsw`/`.meta`
0600, atomic writes, ciphertext only); opened wallets in the 002 `wallets/` directory with a 004
sync record; invitations and codes in memory only (contracts/host-runtime-share.md)

**Testing**: `cargo test`; sans-IO share engine tests with fake clocks and in-memory stores;
proof known-answer and binding tests; v3 negotiation and fallback tests; loopback two/three
service tests; raw-HTTP route/guard tests; traffic marker scan; storage fault injection;
`#[ignore]` performance and idle tests (R14)

**Target Platform**: Linux desktop service (002–004); domain module reusable by Android (007)

**Project Type**: library crates (domain + adapters) integrated into the local web service

**Performance Goals**: share + open < 2 min of person time (SC-001); 10 000-credential wallet
transferred < 10 s on LAN (SC-006); after open, changes converge within the 004 bound (SC-005)

**Constraints**: networking on and 003 pins required; frames ≤ 1024 B; copies 79 B..64 MiB;
≤ 2 transfers service-wide shared with 004; ≤ 1 MiB buffers per transfer; 5-minute invitation,
5 invitations / 10 min, ≤ 8 received wallets, 24 h retention; zero traffic and no background
activity without an invitation/redemption (SC-007); no plaintext name/code/credential on the wire
or at rest; `unsafe_code` forbidden

**Scale/Scope**: one invitation and one redemption per device at a time; ≤ 32 paired devices

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | Encrypted at rest, zero plaintext on network, E2E + mutual auth, vetted crypto | PASS — spec forbids sending the password and requires the 003 channel | PASS — only the vault-core ciphertext and non-secret share messages travel inside the 003 Noise channel; the code is never sent (HMAC-SHA-256 proof bound to session, both ids and `rid`, verified in constant time, R5); invitation bound to one recipient, one wallet, one attempt, 5 min (R6); received files ciphertext-only, 0600, deleted after 24 h (R9); password used once in `wallet-service` and wiped (R10); no custom primitives |
| II. Simplicity | Simplest equal option | PASS | PASS — reuses 003 codes/QR/channel, 004 transfer/limits/sync record; one module, no new crate, thread or dependency; fixed limits, no new config |
| III. TDD | Tests first, fakes | PASS | PASS — every rule testable in memory; marker scan and fault injection planned (R14) |
| IV. Hexagonal | Core free of infra | PASS | PASS — `wallet-sync::share` is sans-IO with ports (`ReceivedStore`, `WalletSource`, `SyncStore`, clocks, RNG, `TransferSlots`); files, sockets and HTTP in adapters; network crates stay wallet-agnostic; no dependency cycle (R1) |
| V. Resource Efficiency | Bounded, measured | PASS | PASS — 004 transfer bounds reused and shared; no new thread or wake (sweeper tick, R12); SC-006/SC-007 tests |
| VI. Decentralization | P2P, no server | PASS | PASS — LAN-only via 003; after open, 004 handles partitions and conflicts |
| Workflow | Minimal, reviewed deps | PASS | PASS — no new crate; `cargo deny`/`cargo audit` unchanged |
| Roadmap globals | Offline except sync, no accounts, master password only secret, never sent | PASS | PASS — sharing only with networking on and paired devices; code is ephemeral and never protects a wallet; no account, relay or pairing created |

Gates pass. Deviations in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/005-wallet-sharing/
├── plan.md
├── research.md              # R1–R15
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── share-protocol.md    # channel v3, share messages, proof, exchange, timeouts
│   ├── http-api-share.md    # /api/share, actions, UI
│   ├── host-runtime-share.md# received/ files, start-up, sweeper, log events
│   └── core-api-share.md    # additive Rust API (wallet-sync, wallet-service, device-link*)
├── checklists/requirements.md
└── tasks.md                 # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
crates/
├── wallet-sync/             # share/{mod,codec,proof,invite,redeem,received}.rs (NEW module),
│   │                        # slots.rs (TransferSlots, also used by round.rs), ports (+ReceivedStore), testkit fakes
│   └── tests/               # share_codec, share_proof, share_invite, share_redeem, share_received, share_slots
├── wallet-service/          # adopt.rs (adopt_received), ports.rs (+LockObserver), registry.rs (observer calls)
├── device-link/             # wire.rs (HelloVersion::V3, 0x30/0x31), channel.rs (share_enabled)
├── device-link-net/         # dialer.rs (per-peer max version, v3→v2→v1), lib.rs (ensure_channel,
│                            # channel_version, PeerNoShare, send_sync for share payloads)
├── passwsyncd/              # share_store.rs (FsReceivedStore), share_runtime.rs, http/api_share.rs,
│   │                        # paths.rs (+received/), app.rs (start-up 5e, observer, shutdown),
│   │                        # sweeper hook, sync_runtime.rs (dispatch 0x30/0x31, TransferSlots), log.rs, qr.rs (share URI)
│   └── ui/                  # app.js/app.css/index.html: Share dialog, invitation panel, Receive form, Received list
├── vault-core/              # unchanged
└── vault-storage-file/      # unchanged
```

**Structure Decision**: no new workspace member. Sharing is a module of `wallet-sync` because it
reuses that crate's peer ids, clocks, 004 transfer sender and limits. Dependencies keep pointing
inward and stay acyclic: `wallet-sync → vault-core`; `wallet-service → vault-core`;
`device-link-net → device-link`; `passwsyncd → all`. `wallet-sync` does not depend on
`device-link` (codes enter as digits, sessions and ids as `[u8; 32]`).

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Channel protocol v3 (Hello version 3, three-step fallback) | 004 v2 peers close on unknown payloads/ctypes; the Hello is the only negotiation point they reject before crypto; version bound into the Noise prologue (R3, FR-024) | Share ctypes inside v2 `SyncCtl` break sync with 004 peers; capability field breaks v1/v2; separate port duplicates handshake and pins |
| Redemption proof (HMAC of the code) instead of sending the code inside the channel | SC-002 (no code in clear) holds even for channel plaintext; a wrongly selected paired device never learns the code; binding to session/ids/rid gives FR-025 replay protection for free (R5) | Sending the code is simpler by one HMAC call but exposes it to the chosen peer; SPAKE2 adds round trips with no gain over an authenticated channel |
| Code-less tombstone after an invitation ends | FR-009a/US3 require the recipient to see "cancelled by sender"/"expired"/"used" even if it redeems after the end (R6) | Proactive push impossible (recipient has no state before redeeming); a generic "invalid" fails the spec's "reason shown on both devices" |
| Shared `TransferSlots` replacing the 004 Engine's private counter | FR-017: share transfers count in the same service-wide limit (R8) | A separate share limit exceeds the reviewed 004 resource bound |
| `LockObserver` port in `wallet-service` | FR-009a must cover every lock cause, including future ones (R7) | Hooking each `passwsyncd` lock call site is easy to miss; polling is forbidden |
| Received-wallet expiry on the existing sweeper tick (≤ 15 s late) | FR-022a "existing 15-second timer, no per-wallet polling" satisfied without a new thread/wake; hard limits are enforced synchronously at each step (R12) | Dedicated timer thread adds a wake source; the 004 scheduler does not run with networking off |
| Duplicate detection limited to wallets with a 004 sync record | Wallet ids of never-unlocked wallets are encrypted (R10); residual case ends as 004 `disabled(duplicate_wallet_id)` without data loss | Trying keys of locked wallets is impossible without their passwords |

## Post-design notes

- Open questions: none; every spec-level open choice is resolved in research.md. The spec is
  amended only where a documented technical limit must be stated: FR-020 and US5.3 now name the
  residual duplicate case (wallet never unlocked since 004; R10), and FR-022a names the existing
  15-second service timer. Key Entities lists the full invitation state set.
- Residual risks (documented): a paired device can invalidate an invitation addressed to another
  device by redeeming it (spec-mandated single attempt; paired devices are trusted to be the
  person's own); an already delivered copy cannot be withdrawn (spec FR-029; revoke + password
  change, US4.4); `snow` key copies without zeroize (003 residual, unchanged).
