# Tasks: Wallet Sharing

**Input**: Design documents from `/specs/005-wallet-sharing/`
**Prerequisites**: plan.md, spec.md, research.md (R1-R15), data-model.md, contracts/ (share-protocol.md, core-api-share.md, http-api-share.md, host-runtime-share.md), quickstart.md
**Tests**: MANDATORY (Constitution III, TDD). Every implementation task is preceded by a test task that MUST be run and seen to FAIL (red) before the implementation task starts. Refactor with tests green. A test task and its implementation task never run in parallel.
**Organization**: By user story. Priority order: US1 share a wallet with a paired device (P1), US2 shared wallet stays in sync (P1), US3 invitations scoped, single-use, expiring (P1), US4 consent and cancellation on both sides (P2), US5 received wallet cannot be opened (P3). Channel v3, share codec, proof, transfer slots, ports and the received-file store are shared and live in Phase 2.
**Security rules for every task**: the master password is never sent, stored or logged; the invite code is never sent (only the HMAC proof), never stored, never logged; no wallet name, wallet id, code, proof, `rid`, received id, key or content in logs or on the wire (FR-016, FR-028); received files are ciphertext only, owner-only; sharing never resets the 002 idle timer except `POST /api/wallets/{name}/share`; no new crate in `Cargo.lock` (R15); `unsafe_code` stays forbidden; vault-core and vault-storage-file are unchanged.

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repo root. `VC` = `crates/vault-core`, `WS` = `crates/wallet-sync`, `WSV` = `crates/wallet-service`, `DL` = `crates/device-link`, `DN` = `crates/device-link-net`, `PD` = `crates/passwsyncd`.
- Test tasks write the test only (red); the next numbered implementation task makes it green.
- **(MANUAL)** = needs a human, a browser, two hosts or network namespaces (root), or tcpdump; it cannot be automated in this environment. Such tasks stay unchecked until a person runs them and record "Not run here" with the automated equivalents, as in 004.

---

## Phase 1: Setup

- [X] T001 Snapshot the baseline: run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`; record that 001-004 are green before any change (noted in the PR description, no file)
- [X] T002 [P] Early dependency gate: run `cargo deny check` and `cargo audit`; only the already-accepted advisory (RUSTSEC-2023-0089) may remain; record the `Cargo.lock` crate set to prove it is unchanged at the end (R15)
- [X] T003 [P] Confirm without editing manifests that `crates/wallet-sync/Cargo.toml` already has `hmac`, `sha2`, `zeroize`, `rand_core` and that `crates/passwsyncd/Cargo.toml` already has `device-link` and `qrcodegen`; `wallet-sync` MUST NOT gain a dependency on `device-link`, `wallet-service` or networking (Principle IV). Only if something is missing, fix `crates/wallet-sync/Cargo.toml` / `crates/passwsyncd/Cargo.toml` with already-locked versions
- [X] T004 Create the empty module tree `crates/wallet-sync/src/share/{mod,codec,proof,invite,redeem,received}.rs` and `crates/wallet-sync/src/slots.rs`, declared from `crates/wallet-sync/src/lib.rs` (`pub mod share; pub mod slots;`); verify `cargo build --workspace` passes

---

## Phase 2: Foundational (blocks all user stories)

### device-link: channel v3 (contracts/share-protocol.md "Negotiation", core-api-share.md, R3)

- [X] T005 [P] Write failing tests for `HelloVersion::V3` and the share payloads: `PWSC || 3 || 1` encodes and parses via `parse_hello_versioned`, the 003 `parse_hello` stays v1-only, pairing Hello unchanged, `Payload::ShareMsg` (0x30) and `Payload::ShareData` (0x31) round-trip with body 1..=1000 bytes and reject 0 / 1001 bytes / unknown types in `crates/device-link/tests/wire_share.rs`
- [X] T006 [P] Write failing tests for channel v3 in `crates/device-link/tests/channel_v3.rs`: prologue `passwsync-channel-v3 || Hello`, a Hello/prologue version mismatch fails the handshake, `Channel::share_enabled()` true only for V3, share payloads on a V1 or V2 channel are `Error::Protocol` (close), a V2 channel behaves exactly as in 004, a V3 channel carries sync (0x20/0x21) and share payloads, framing and step timeouts unchanged
- [X] T007 Implement `HelloVersion::V3`, `parse_hello_versioned` v3 and the 0x30/0x31 payload codec in `crates/device-link/src/wire.rs`; export from `crates/device-link/src/lib.rs`
- [X] T008 Implement the v3 prologue, version-gated payload validation and `Channel::share_enabled` in `crates/device-link/src/channel.rs` (makes T005 and T006 green; existing `channel_v2.rs`, `wire_sync.rs`, `channel_attacks.rs` stay green unmodified)

### device-link-net: negotiation, fallback, ensure_channel (R3, R11)

- [X] T009 [P] Write failing loopback tests in `crates/device-link-net/tests/channel_v3_loopback.rs`: dialer starts at V3; a responder that closes before Noise msg2 lowers the per-peer maximum v3 -> v2 -> v1 and redials at once; lowered maximum raised again after 24 h (fake clock) or restart; `NetEvent::PeerNoShare` emitted on v3->v2 fallback while `PeerLegacy` keeps meaning "no sync"; `SyncFrameSink::channel_version` called before `channel_up`; responder accepts v1/v2/v3 Hellos; share frames delivered through `SyncFrameSink::frame`
- [X] T010 [P] Write failing tests in `crates/device-link-net/tests/ensure_channel.rs`: existing channel returned when present; dial of `hint` under the 003 address policy; `NotPaired`, `IdMismatch` (channel identity differs from `expected`), `Unreachable`, `NetworkOff`, `SelfDevice`; with `expected = None` the responder static must be a pinned key; `send_sync` accepts `ShareMsg`/`ShareData` only on V3 channels (`SendError::NotShareEnabled` otherwise); blocking bounded by the 003 step timeouts
- [X] T011 Implement per-peer maximum version with retry-up, `channel_version` hook, `PeerNoShare` and the share-aware `send_sync` in `crates/device-link-net/src/dialer.rs` and `crates/device-link-net/src/lib.rs`
- [X] T012 Implement `Node::ensure_channel` and `EnsureError` in `crates/device-link-net/src/lib.rs` (makes T009 and T010 green; existing `channel_v2_loopback.rs` stays green unmodified)

### wallet-sync: slots, codec, proof, ports (contracts/share-protocol.md, core-api-share.md, R4, R5, R8)

- [X] T013 [P] Write failing tests for `TransferSlots` in `crates/wallet-sync/tests/share_slots.rs`: `try_take` up to the maximum (2), `SlotGuard` releases on drop and on abort paths, the 004 `Engine` (via `EngineDeps.slots`, default `TransferSlots::new(2)`) and the share engine draw from the same counter so 2 sync transfers leave none for a share (FR-017); behaviour of 004 transfer limits identical to before
- [X] T014 Implement `TransferSlots`/`SlotGuard` in `crates/wallet-sync/src/slots.rs` and replace the 004 Engine's private counter with `EngineDeps.slots` in `crates/wallet-sync/src/round.rs` (existing `transfer.rs`, `rounds.rs` stay green unmodified)
- [X] T015 [P] Write failing tests for the share codec in `crates/wallet-sync/tests/share_codec.rs`: round trip of `Redeem`, `Pending`, `Offer`, `End`, `Stored`, `Abort` (all 10 reasons), exact lengths, `Pending.seconds_left` 1..=300, `Offer.size` 79..=67 108 864, unknown `stype`, unknown abort reason, wrong length, trailing bytes, empty body, body > 1000 bytes -> `ProtocolError`; `Debug` of every type omits proofs and `rid`
- [X] T016 Implement `ShareMsg`, `AbortReason`, `encode`/`decode` in `crates/wallet-sync/src/share/codec.rs`
- [X] T017 [P] Write failing tests for `redeem_proof` in `crates/wallet-sync/tests/share_proof.rs`: known-answer HMAC-SHA-256 vectors for key = 8 ASCII digits and message `"passwsync-share-redeem-v1" || session || sender_id || recipient_id || rid`; changing the code, session, sender id, recipient id or `rid` changes the proof; verification is constant time (`Mac::verify_slice`); the code never appears in the output; `Zeroizing` code wiped after use
- [X] T018 Implement `redeem_proof` and the constant-time verifier in `crates/wallet-sync/src/share/proof.rs`
- [X] T019 [P] Write failing tests for the `ReceivedStore` port and its in-memory fake in `crates/wallet-sync/tests/share_received_store.rs`: `begin` returns a 004 `IncomingCopy` writer, `finish` makes the entry visible only when complete, an aborted/dropped writer leaves nothing, `list`/`read`/`delete`, ciphertext-only content, injectable faults (no space, I/O error) at every step
- [X] T020 Implement `ReceivedStore`, `ReceivedMeta`, `StoreError`, `ShareDeps`, the 1 MiB-bounded buffers and the testkit fake (`InMemoryReceivedStore` with fault injection) in `crates/wallet-sync/src/share/received.rs`, `crates/wallet-sync/src/ports.rs` and `crates/wallet-sync/src/testkit.rs`

### passwsyncd: received/ store and log events (contracts/host-runtime-share.md, R9)

- [X] T021 [P] Write failing tests for `FsReceivedStore` and paths in `crates/passwsyncd/tests/share_store.rs`: `received/` created 0700 under `$XDG_DATA_HOME/passwsync/`, `.part`/`.pwsw`/`.meta` 0600, write order (append -> fsync -> rename -> directory fsync -> atomic meta), meta text format `passwsync-received-v1` with sender, received, size and sha-256 `check`, no wallet name/id/code/password written, a permissive or foreign-owned directory yields `received_unusable` and is never rewritten, `list` skips and reports unparsable entries, fault injection at every step leaves no usable partial file
- [X] T022 Implement `FsReceivedStore` in `crates/passwsyncd/src/share_store.rs` and the `received/` path and permission checks in `crates/passwsyncd/src/paths.rs`; declare modules in `crates/passwsyncd/src/lib.rs`
- [X] T023 [P] Write failing tests for the closed sharing log events in `crates/passwsyncd/tests/share_log.rs`: each event text from host-runtime-share.md "Log events" exists and identifies peers only by fingerprint; no code, proof, `rid`, wallet name, wallet id, received id, key, password or contents can be formatted into any event
- [X] T024 Implement the sharing `LogEvent` variants in `crates/passwsyncd/src/log.rs`

**Checkpoint**: v3 channel, share codec/proof, shared transfer slots and the received-file store exist and are tested; no user-visible behaviour yet.

---

## Phase 3: User Story 1 - Share a wallet with another paired device (P1)

**Goal**: an unlocked wallet on A reaches paired device B as an encrypted received wallet through a code/QR invitation with consent on both devices; B opens it with the master password and sees the same credentials; the password never travels.
**Independent test**: with two paired service instances share a wallet from A to B, accept on A, open on B with the master password, compare credentials; captured traffic holds no password, name, credential or code (SC-001, SC-002).

### Sharing engine: sender and recipient happy paths (R4, R6)

- [X] T025 [P] [US1] Write failing tests for invitation creation in `crates/wallet-sync/tests/share_invite.rs`: `create` with an unlocked eligible wallet yields state `Active`, `expires = created + 300 s`, one recipient, 8-digit code held only inside the invitation; eligibility through `SyncStore::load` (record valid, not flagged, file digest equal) with refusals `format_v1`, `possible_rollback`, `disabled`, `no_record`, `changed`; `view()` exposes the code only while `Active` and never a proof; `Debug` omits code
- [X] T026 [P] [US1] Write failing tests for the sender exchange in `crates/wallet-sync/tests/share_sender.rs`: valid `Redeem` from the recipient -> `Pending{rid, seconds_left}` within 10 s, code wiped, state `AwaitingAcceptance`; `accept` re-checks not expired, wallet still eligible, free slot, then `Offer{rid, size}` (the start of the transfer); the stored file streamed as `ShareData` chunks <= 1000 bytes totalling exactly `size`, `End`, digest re-check against the sync record, `Stored` -> `Completed`; only the stored encrypted file and non-secret messages are produced (no name, wallet id, state); snapshot taken at the start of the transfer; progress reported; chunking bounded by 1 MiB buffers
- [X] T027 [P] [US1] Write failing tests for the recipient exchange in `crates/wallet-sync/tests/share_redeem.rs`: `redeem` on an ensured channel sends `Redeem{rid, proof}` with a random `rid` and the proof bound to session and both ids, code wiped immediately; `Pending` extends the wait to `seconds_left + 10 s`; `Offer` range-checked; chunks streamed into `ReceivedStore::begin`; `End` with exactly `size` bytes -> finish -> `Stored`; received id and `received_at` recorded; at most one exchange per channel; answer timeout 10 s and channel wait 300 s with a fake clock
- [X] T028 [US1] Implement invitation creation, eligibility, view and the sender exchange in `crates/wallet-sync/src/share/invite.rs` and `crates/wallet-sync/src/share/mod.rs` (`ShareEngine::{new, create, accept, channel_up, channel_down, on_msg, poll_outgoing, view}`), makes T025 and T026 green
- [X] T029 [US1] Implement the recipient exchange (`redeem`, `sender_channel`, `on_data`, received-file finish, timeouts, `take_events`) in `crates/wallet-sync/src/share/redeem.rs` and `crates/wallet-sync/src/share/received.rs`, makes T027 green

### wallet-service: opening a received wallet (R10)

- [X] T030 [P] [US1] Write failing tests for `Service::adopt_received` in `crates/wallet-service/tests/adopt.rs`: correct password stores the received bytes verbatim (file digest equals the received digest) under the new local name, calls `PendingCopies::unlocked` once with the authenticated state, registers the wallet unlocked, wipes the password; name validated (`invalid_name`), existing name refused (`wallet_exists`) under the create lock, KDF cap and KDF gate honoured, `decide(&UnlockFacts)` called with authenticated facts only; on any error nothing is written
- [X] T031 [US1] Implement `adopt_received`, `AdoptVerdict` and `ServiceError::AlreadyPresent` in `crates/wallet-service/src/adopt.rs`, `crates/wallet-service/src/lib.rs` and `crates/wallet-service/src/error.rs` (makes T030 green; 002/004 service tests stay green unmodified)

### passwsyncd: runtime, HTTP, UI (contracts/http-api-share.md, host-runtime-share.md, R11, R13)

- [X] T032 [P] [US1] Write failing tests for the invitation code and QR in `crates/passwsyncd/tests/share_qr.rs`: the code comes from `device_link::PairingCode` (8 digits, CSPRNG, shown in groups of 4), `qr_text` is exactly `passwsync://share?v=1&code=<8 digits>&id=<64hex>&addr=<ip:port>`, the QR path is generated locally without external resources, the share URI parses back (code, device id, address) and rejects malformed or oversized input
- [X] T033 [US1] Implement the share URI builder/parser in `crates/passwsyncd/src/qr.rs`
- [X] T034 [P] [US1] Write failing raw-HTTP tests for the sender routes in `crates/passwsyncd/tests/api_share.rs`: `GET /api/share` JSON shape (available, peers with `share` support, invitation with `code`/`qr`/`qr_text`/`expires_in` only while `active`, `progress`, `reason`), `POST /api/wallets/{name}/share` success and every error row (`networking_off`, `wallet_not_found`, `wallet_locked` 423, `not_eligible` with reason, `device_not_found`, `peer_unsupported`, `busy`, `too_many_invitations` 429), `POST /api/share/accept` (`nothing_pending`, `share_mismatch`, `expired`, `wallet_locked`, `busy`), idle timer reset only by the share route
- [X] T035 [P] [US1] Write failing raw-HTTP tests for the recipient routes in `crates/passwsyncd/tests/api_receive.rs`: `POST /api/receive` validation (`invalid_code` unless 8 digits after removing spaces/dashes, `invalid_address` under the 003 policy, `invalid_device_id`, `missing_sender`, `device_not_found`, `self`, `networking_off`, `busy`, `received_limit`) and `202` with progress in `GET /api/share` `receive`; `device_id` + `address` mismatch yields `receive.reason = id_mismatch` and nothing sent (FR-012); `POST /api/received/{received_id}/open` success `{name, unlocked}` and the wallet in `GET /api/state` with its `sync` object; `404 received_not_found` for a bad id
- [X] T036 [P] [US1] Write failing tests that every new route (`/api/share*`, `/api/receive*`, `/api/received/*`, `/api/wallets/{name}/share`) goes through the 002 guard pipeline (loopback, peer UID, exact `Host`, session cookie, `X-CSRF-Token`, exact `Origin` on POST, size limits, fixed rejection bodies, error body shape) and that no response ever contains a code after redemption, a proof, a wallet id or credential data (FR-027) in `crates/passwsyncd/tests/share_guards.rs`
- [X] T037 [US1] Implement `ShareRuntime` (owns the `ShareEngine`, invitation `CodeRateLimiter`, notices, a short-lived worker for `ensure_channel`), the `FsReceivedStore`/`WalletSource`/`SyncStore` wiring, 0x30/0x31 dispatch and shared `TransferSlots` in `crates/passwsyncd/src/share_runtime.rs`, `crates/passwsyncd/src/sync_runtime.rs`, `crates/passwsyncd/src/net_runtime.rs` and `crates/passwsyncd/src/app.rs` (start-up step 5e creates `received/`)
- [X] T038 [US1] Implement `GET /api/share`, `POST /api/wallets/{name}/share`, `/api/share/accept`, `/api/receive`, `/api/received/{received_id}/open` in `crates/passwsyncd/src/http/api_share.rs` and register them in `crates/passwsyncd/src/http/mod.rs` and `crates/passwsyncd/src/http/api.rs` (makes T034, T035, T036 green)
- [X] T039 [P] [US1] Write failing UI asset tests in `crates/passwsyncd/tests/share_ui_assets.rs`: Share dialog, invitation panel (code in groups, countdown, Cancel), acceptance prompt ("Send wallet '<name>' to <device> (<fingerprint>)?" with Accept/Reject), Devices view "Receive a wallet" form, Received wallets list with Open; QR built as `<svg>` with DOM APIs (no `innerHTML`), no external assets, no new asset files, CSP unchanged, all controls keyboard operable, Share/Receive disabled with the reason when `available: false`
- [X] T040 [US1] Implement the Share dialog, invitation panel, acceptance prompt, Receive form and Received list (Open) with polling (5 s, 1 s while non-terminal) in `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/app.css`
- [X] T041 [P] [US1] Write failing two-service loopback test in `crates/passwsyncd/tests/share_two_devices.rs` (support in `crates/passwsyncd/tests/common/share.rs`): A creates an invitation, B redeems by paired list and by manual address, A accepts, B lists a received wallet from A, B opens it with a local name and the master password, credentials identical, the invitation is unusable afterwards, the received files are gone after opening
- [X] T042 [US1] Make T041 green; fix gaps in `crates/passwsyncd/src/share_runtime.rs`
- [X] T043 [US1] Write the traffic scan (SC-002) in `crates/passwsyncd/tests/share_leakage.rs` (not parallel: it runs only after T042 is green, so it reads the finished flows): record the bytes of a full share session at the socket and the channel plaintext; assert zero occurrences of the master password, wallet name, credential titles/fields, the invite code digits and the proof inputs; after the 6-byte Hello only Noise ciphertext; `received/*.meta`, `received/*.pwsw` and the log contain no code, wallet name or password (any hit fails the task)
- [X] T044 [P] [US1] Write failing test for an older peer (FR-024) in `crates/passwsyncd/tests/share_old_peer.rs`: a peer limited to channel v2 (004 build) makes `peers[].share = unsupported`, `POST /api/wallets/{name}/share` returns `409 peer_unsupported`, the UI text "this device does not support sharing" is present, and 004 sync with that peer keeps working
- [X] T045 [US1] Make T044 green; fix gaps in `crates/passwsyncd/src/share_runtime.rs` and `crates/passwsyncd/src/net_runtime.rs` (`PeerNoShare` handling)
- [ ] T046 [US1] (MANUAL) Browser on two hosts or namespaces: quickstart scenarios 1 and 2 (share, manual address, QR id mismatch) and time "Share" to open under 2 minutes (SC-001) — needs a real browser and two network endpoints; automated equivalents: T041, T035, T039 — **Not run here (2026-10-25):** needs a real browser and two network endpoints; automated equivalents T041, T035, T039 pass.

**Checkpoint**: US1 delivers the MVP - a wallet can be shared and opened on a paired device.

---

## Phase 4: User Story 2 - The shared wallet stays in sync (P1)

**Goal**: after the wallet is opened once on B, edits on either device converge through 004 with no further sharing step; an unopened received wallet takes no part in sync.
**Independent test**: after US1 add a credential on A and edit another on B; both converge within the 004 bound; a conflict made while partitioned shows on both devices (SC-005).

- [X] T047 [P] [US2] Write failing tests in `crates/passwsyncd/tests/share_then_sync.rs` (the test lives where the real `SyncStore` and the opening hook are, as T048; wallet-sync fakes are not used here): the 004 record created by opening has `digest` equal to the received file, `state` from the authenticated unlock and `peer_mark[sender]` = that state; the first 004 round between sender and recipient finds both equal and transfers nothing; a later edit on A transfers normally; a sender state below `peer_mark` is still flagged as in 004
- [X] T048 [US2] Implement setting `peer_mark[sender]` on the new record after `adopt_received` in `crates/passwsyncd/src/share_runtime.rs` and `crates/passwsyncd/src/sync_store.rs`
- [X] T049 [P] [US2] Write failing tests in `crates/passwsyncd/tests/share_sync.rs`: while a received wallet is unopened on B, edits on A create nothing under B's `sync/`, B serves and requests nothing for it, and it is absent from B's wallet list and sync status; after opening, B syncs including A's later changes within 60 s on a fake clock (SC-005); edits on B reach A
- [X] T050 [P] [US2] Write failing three-device test in `crates/passwsyncd/tests/share_three_devices.rs`: share A->B, then B->C; any device edits and all three converge; a conflict created while one device is partitioned is shown on both sides after reconnection (004 behaviour unchanged)
- [X] T051 [US2] Make T049 and T050 green; fix gaps in `crates/passwsyncd/src/sync_runtime.rs` and `crates/passwsyncd/src/share_runtime.rs`
- [ ] T052 [US2] (MANUAL) Quickstart scenario 4 on two hosts: edit on A visible on B within 60 s, edit on B on A, nothing under B's `sync/` before opening — needs two hosts or namespaces; automated equivalents: T047, T049, T050 — **Not run here (2026-10-25):** needs two hosts or root for namespaces; automated equivalents T047, T049, T050 pass.

---

## Phase 5: User Story 3 - Invitations are scoped, single-use and expire (P1)

**Goal**: a code works only for its wallet, only on its recipient device, only once and only before expiry; a wrong code ends the invitation; every refusal sends nothing and is visible on both devices and in the log.
**Independent test**: redeem from another paired device, with a wrong code, after expiry, a second time, after cancellation and after a restart; every attempt fails and nothing is sent (SC-003).

- [X] T053 [P] [US3] Write failing tests in `crates/wallet-sync/tests/share_invalidate.rs` for every FR-010 invalidation: success, expiry (at `Active`, at `AwaitingAcceptance`), cancel, reject, wallet lock before the transfer, one wrong proof (single attempt, invitation `Refused(wrong_code)`), `Redeem` from a non-recipient even with the correct code (`Refused(not_recipient)`, `Abort(invalid)`), recipient revoked, replaced by a new invitation; in each case no `Offer` or `ShareData` is ever produced; the verification uses constant-time compare; after any end a `Redeem` from the recipient is answered from the tombstone (`cancelled | expired | invalid(used)`), the tombstone holds no code or wallet name and is dropped at `until` or on a new invitation
- [X] T054 [P] [US3] Write failing tests in `crates/wallet-sync/tests/share_limits.rs`: at most one active invitation (a new one cancels the previous as `replaced`), at most 5 creations per 10 minutes on a fake clock (`TooMany`), creation while `Transferring` -> `busy`, no free transfer slot at accept -> `Abort(busy)` and invitation failed, code never retained after the first `Redeem`
- [X] T055 [P] [US3] Write failing tests in `crates/wallet-sync/tests/share_expiry.rs`: validity exactly 300 s on the sender's clock only (receiver clock irrelevant); every step before `Offer` checks `now < expires`; a transfer whose `Offer` was sent before expiry finishes within the 004 timeouts (30 s no progress, 15 min total); a transfer not started by expiry never starts; `Pending.seconds_left` correct; accept after expiry -> `Abort(expired)`
- [X] T056 [US3] Implement all invalidations, tombstones, single attempt, rate limiting and expiry in `crates/wallet-sync/src/share/invite.rs` (makes T053, T054, T055 green)
- [X] T057 [P] [US3] Write failing tests in `crates/wallet-sync/tests/share_attacks.rs`: a proof recorded in another session, with another `rid` or for another sender/recipient pair is refused; messages for the last finished `rid` are ignored, any other `rid` mismatch is a protocol error; `ShareData` outside a transfer, more bytes than `size`, `End` with fewer bytes, unknown `stype`, a second exchange on the same channel, `Redeem` flood -> protocol error or `busy`, partial file deleted; share messages from a peer whose channel is not share-enabled are dropped
- [X] T058 [US3] Implement the replay binding and protocol-error handling in `crates/wallet-sync/src/share/mod.rs` and `crates/wallet-sync/src/share/redeem.rs` (makes T057 green)
- [X] T059 [P] [US3] Write failing tests for `LockObserver` in `crates/wallet-service/tests/lock_observer.rs`: `locked(&name)` is called once after the slot is locked and zeroized, outside service locks, for manual lock, lock all, idle timeout, suspend and stop; not called for a failed unlock; only one observer is kept
- [X] T060 [US3] Implement `LockObserver` and `Service::set_lock_observer` in `crates/wallet-service/src/ports.rs`, `crates/wallet-service/src/registry.rs` and `crates/wallet-service/src/lib.rs` (makes T059 green)
- [X] T061 [P] [US3] Write failing service-level tests in `crates/passwsyncd/tests/share_scope.rs`: third paired device C with the correct code is refused and the invitation is invalidated, A shows "refused (not recipient)"; wrong code on B invalidates; expiry after 300 s (fake clock) and B is told `expired`; reuse of a completed code is refused ("already used"); lock of the wallet on A while B waits cancels the invitation and B shows "cancelled by sender" (FR-009a); a lock after `Offer` lets the transfer finish from its snapshot; revoking B cancels the invitation; an unpaired or revoked device never gets past the 003 handshake; a restart of A during an invitation makes B's redeem `invalid`; every refusal produces exactly the log events of host-runtime-share.md and sends no wallet bytes
- [X] T062 [US3] Wire the `LockObserver` registration, revoke hook (cancels the invitation, aborts exchanges), start-up/shutdown invalidation and refusal log events in `crates/passwsyncd/src/share_runtime.rs`, `crates/passwsyncd/src/app.rs` and `crates/passwsyncd/src/log.rs` (makes T061 green)
- [ ] T063 [US3] (MANUAL) Quickstart scenario 5 on three hosts or namespaces: wrong device, wrong code, 5-minute expiry, reuse, restart of A, revoke then redeem — needs three endpoints, real waiting and root for namespaces; automated equivalents: T053, T055, T061 — **Not run here (2026-10-25):** needs three endpoints and root for namespaces; automated equivalents T053, T055, T061 pass.

---

## Phase 6: User Story 4 - Consent and cancellation on both sides (P2)

**Goal**: either person can stop a share at any point before it completes, leaving no wallet and no data on the receiving device; received wallets do not accumulate.
**Independent test**: cancel before and during redemption, reject on A, cancel the wait on B, discard a received wallet; no wallet is created on B and nothing is left (SC-004).

- [X] T064 [P] [US4] Write failing tests in `crates/wallet-sync/tests/share_cancel.rs`: `cancel` in `Active`, `AwaitingAcceptance` and `Transferring` takes effect at once and aborts the exchange (`Abort(cancelled)`), `reject` -> `Abort(rejected)` and invitation invalidated, no decision before expiry -> `Abort(expired)`, recipient `cancel_redemption` / `Abort(recipient_cancelled)` at each stage, partial `.part` removed in every abort and on channel loss, a completed invitation reports `AlreadyDelivered` with no state change, a redeemed invitation lost with its channel is `Failed(channel_lost)` and single-use
- [X] T065 [P] [US4] Write failing tests in `crates/wallet-sync/tests/share_received.rs`: at most 8 received wallets (`Abort(received_limit)` and `received_limit` error), discard deletes the ciphertext and leaves no wallet, expiry at `received_at + 86 400` and deletion when `received_at` is more than 300 s in the future (fake wall clock) with a `received_expired` notice, `peer_revoked` deletes that sender's received wallets and emits `received_deleted_revoked`, notices bounded to 16 oldest dropped, dismissal removes only the notice
- [X] T066 [US4] Implement cancel/reject/abort paths, received-wallet limit, expiry and revocation handling in `crates/wallet-sync/src/share/invite.rs`, `crates/wallet-sync/src/share/redeem.rs` and `crates/wallet-sync/src/share/received.rs` (makes T064 and T065 green)
- [X] T067 [P] [US4] Write failing tests in `crates/passwsyncd/tests/share_retention.rs` (fake wall clock): start-up step 5e deletes every `*.part`, `.pwsw` without `.meta` and `.meta` without `.pwsw`, pairs with unparsable or checksum-failing meta, size mismatch, unpinned sender, older than 24 h or more than 5 minutes in the future, and the newest extras above 8, each class logged once with a count and shown as a `received_cleaned` notice; the existing 15 s sweeper tick deletes received wallets past 24 h with a notice and log and ends expired invitations and timed-out redemptions, with no new thread or periodic wake; revoking a sender in 003 deletes its received wallets (FR-023); nothing here stops the service
- [X] T068 [US4] Implement start-up step 5e, the sweeper hook, revoke deletion and shutdown (abort exchange best effort, delete `.part`, wipe invitation code, release slots) in `crates/passwsyncd/src/app.rs`, `crates/passwsyncd/src/sweeper.rs`, `crates/passwsyncd/src/share_runtime.rs` and `crates/passwsyncd/src/share_store.rs` (makes T067 green)
- [X] T069 [P] [US4] Write failing fault-injection tests in `crates/passwsyncd/tests/share_faults.rs`: storage full or I/O error at each step of the receive leaves no `.pwsw`, `.meta` or `.part` and no wallet (error shown on both sides), kill of B mid-transfer leaves nothing after restart, kill between `.pwsw` rename and meta write is cleaned at start-up, kill of A mid-transfer fails B with `channel_lost`, oversize `Offer` aborts as `too_large` as soon as exceeded (SC-004)
- [X] T070 [US4] Make T069 green; fix gaps in `crates/passwsyncd/src/share_store.rs` and `crates/passwsyncd/src/share_runtime.rs`
- [X] T071 [P] [US4] Write failing raw-HTTP tests in `crates/passwsyncd/tests/api_share_actions.rs`: `POST /api/share/cancel` (`{state: cancelled}`, `{already_delivered: true}` after completion, `{}` when nothing), `POST /api/share/reject` (`nothing_pending`), `POST /api/receive/cancel` (sends `Abort(recipient_cancelled)` when an exchange runs), `POST /api/received/{received_id}/discard`, `POST /api/share/notices/dismiss`; none of these resets idle timers
- [X] T072 [US4] Implement the cancel, reject, receive-cancel, discard and notices routes in `crates/passwsyncd/src/http/api_share.rs` and their `ShareRuntime` methods in `crates/passwsyncd/src/share_runtime.rs` (makes T071 green)
- [X] T073 [P] [US4] Extend `crates/passwsyncd/tests/share_ui_assets.rs` with failing assertions: Cancel on the invitation panel, Reject on the prompt, Cancel while waiting on B, Discard with a confirmation dialog, time left before automatic deletion, notices with Dismiss, and the after-completion explanation "the encrypted copy already reached <device>; to stop access, revoke the device and change the master password" (US4.4)
- [X] T074 [US4] Implement those controls and texts in `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/app.css`
- [ ] T075 [US4] (MANUAL) Quickstart scenarios 6 and 8 on two hosts: cancel before/during/after, Reject, cancel the wait, Discard, lock on A while B waits, 24 h expiry with a shifted clock, kill B mid-transfer — needs a browser, two endpoints and clock changes; automated equivalents: T064, T067, T069, T071 — **Not run here (2026-10-25):** needs a browser, two endpoints and clock changes; automated equivalents T064, T067, T069, T071 pass.

---

## Phase 7: User Story 5 - Received wallet cannot be opened (P3)

**Goal**: a wrong password, a corrupted or invalid file, or a wallet already held creates nothing on B; the person can retry or discard.
**Independent test**: deliver a valid file with a wrong password; a corrupted file; a wallet B already holds; verify the outcomes of US5.

- [X] T076 [P] [US5] Write failing tests in `crates/wallet-service/tests/adopt_failures.rs`: wrong password -> generic `invalid_password_or_corrupted`, nothing written, password wiped, 002 unlock rate limits and serialized attempts apply per received wallet; a file failing authentication with the correct password and a malformed file are indistinguishable from a wrong password; a v1 file -> `UnsupportedVersion`; KDF parameters out of range and oversized wallet refused; `decide` returning `AlreadyPresent(local_name)` -> `ServiceError::AlreadyPresent` and no second wallet; storage error -> nothing created
- [X] T077 [US5] Make T076 green; fix gaps in `crates/wallet-service/src/adopt.rs`
- [X] T078 [P] [US5] Write failing raw-HTTP tests in `crates/passwsyncd/tests/api_received_open.rs`: `422 invalid_password_or_corrupted` (entry stays listed, retry allowed, discard allowed), `422 unsupported_version` / `malformed_file` / `kdf_params_out_of_range` / `wallet_too_large` (entry stays), `400 invalid_name`, `409 wallet_exists`, `500 storage_error` (nothing created, entry stays), `409 already_present` with `existing` local name and received files deleted plus an `already_present` notice and log event, password never echoed or logged
- [X] T079 [US5] Implement the duplicate detection (`decide` using wallet ids from 004 sync records), error mapping, `already_present` notice and deletion in `crates/passwsyncd/src/http/api_share.rs`, `crates/passwsyncd/src/share_runtime.rs` and `crates/passwsyncd/src/sync_store.rs` (makes T078 green; residual duplicate case of never-unlocked wallets ends as 004 `disabled(duplicate_wallet_id)`, documented in R10)
- [X] T080 [P] [US5] Write failing end-to-end test in `crates/passwsyncd/tests/share_two_devices.rs`: sharing a wallet B already holds (with a sync record) opens as "already present", creates no second wallet and syncs automatically; corrupting the received `.pwsw` yields the generic error and Discard works; the residual case (B holds the wallet but never unlocked it since 004, FR-020) creates the second copy and 004 shows `disabled (duplicate_wallet_id)` on first unlock with no data loss; a file made under a master password that A later changed (004 password-change marker) opens with the password valid when it was sent
- [X] T081 [US5] Make T080 green; fix gaps in `crates/passwsyncd/src/share_runtime.rs`
- [ ] T082 [US5] (MANUAL) Quickstart scenario 7 in a browser: wrong password, corrupted `.pwsw`, already-present wallet — needs a browser; automated equivalents: T076, T078, T080 — **Not run here (2026-10-25):** needs a browser; automated equivalents T076, T078, T080 pass.

---

## Phase 8: Polish and cross-cutting

- [X] T083 [P] Write `#[ignore]` performance test in `crates/passwsyncd/tests/share_perf.rs`: a 10 000-credential wallet transfers in under 10 s over loopback with additional memory within the 004 per-transfer bound (SC-006); run with `cargo test --workspace -- --ignored`
- [X] T084 [P] Write `#[ignore]` idle-cost test in `crates/passwsyncd/tests/resources_share.rs`: with no invitation or redemption the feature adds zero network traffic, no thread and no periodic wake beyond 003/004 and the existing sweeper (SC-007); two sync transfers in progress make a share `busy` and vice versa
- [X] T085 [P] Write failing flood tests in `crates/passwsyncd/tests/flood_share.rs`: repeated `Redeem`, oversized or malformed share frames and endless `ShareData` from a paired peer are bounded in memory and time, never crash the service, never starve 004 sync
- [X] T086 Make T083, T084 and T085 green; fix gaps in `crates/wallet-sync/src/share/` and `crates/passwsyncd/src/share_runtime.rs`
- [X] T087 [P] Static security checks: extend `crates/wallet-sync/tests/scans.rs` and `crates/passwsyncd/tests/scans.rs` to assert no `unsafe`, no `println!`/`dbg!`/`eprintln!` of secrets, no `Debug`/`Display` of codes, proofs, `rid`, received ids, wallet ids or passwords in the share modules and new `passwsyncd` modules
- [X] T088 Log-content scan: run the full sharing test suite capturing the log; assert only closed `LogEvent` texts appear and no code, proof, `rid`, wallet name, wallet id, received id, key, password or content (FR-028); extends `crates/passwsyncd/tests/share_log.rs` after T024 (same file as T023, so not parallel with it)
- [X] T089 [P] Update the contract documents the change touches, additively: `specs/003-device-identity-pairing/contracts/peer-protocol.md` (Hello v3), `specs/004-wallet-sync-protocol/contracts/sync-protocol.md` and `specs/004-wallet-sync-protocol/contracts/vault-core-sync-api.md` (TransferSlots, share payload types), and `docs/roadmap.md` status for feature 005
- [X] T090 [P] Dependency review: `cargo deny check` and `cargo audit` pass with no new advisories or licenses; `Cargo.lock` crate set identical to the T002 snapshot; `cargo tree -d` shows no new duplicate crates (R15)
- [X] T091 Regression of 001-004: run `cargo test --workspace`, `cargo test --workspace -- --ignored`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`; every 001-004 test passes unmodified (any test edited is listed in the PR with the reason); networking off still adds nothing and 003/004 behaviour is unchanged with the share paths unused
- [X] T092 Traceability: update the verification map at the end of this file with the real test file names and confirm every FR and SC has at least one automated test or an explicit MANUAL task; fail the task if any row is empty
- [ ] T093 Final quickstart validation: run every command under "Automated checks" in `specs/005-wallet-sharing/quickstart.md` and record pass/fail; (MANUAL) execute manual scenarios 1-10 (scenario 9: not-eligible wallet, 6 invitations in 10 minutes -> `429`, 8 received wallets -> `received_limit`; scenario 10: older 004 peer, plus the tcpdump leak check of scenario 3) on two or three hosts or network namespaces and record results — **environment-blocked here:** needs a real browser, root for namespaces and tcpdump; automated equivalents: T043, T044, T034, T035, T083 — **Automated part run 2026-10-25: all PASS** (`cargo test -p wallet-sync`, `-p wallet-service`, `-p device-link -p device-link-net`, `-p passwsyncd`, `cargo test --workspace -- --ignored`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`). **Manual scenarios 1-10 not run here:** no browser, no root for namespaces, no tcpdump in this environment.

---

## Dependencies and execution order

- Phase 1 -> Phase 2 -> user stories. Within Phase 2: device-link (T005-T008) comes before device-link-net (T009-T012); wallet-sync items (T013-T020) are independent of both and run in parallel with them; passwsyncd items (T021-T024) need T020 for the store trait.
- US1 depends on all of Phase 2. US2 depends on US1 (T031, T037). US3 depends on US1 (engine and runtime); T059-T060 can start right after Phase 2. US4 depends on US1 and US3 (invalidation, tombstones, observer). US5 depends on US1 (T031, T038) and the sync record from US2 for duplicate detection.
- Always: test task, see it fail, then implementation task. A test task and an implementation task never run in parallel.

## Parallel opportunities

- Phase 2: T005, T006, T013, T015, T017, T019, T021, T023 are different files and run together; T009, T010 after T008.
- US1: T025, T026, T027, T030, T032, T034, T035, T036, T039 are independent test files.
- US3: T053, T054, T055, T057, T059 in parallel; US4: T064, T065, T067, T069, T071, T073 in parallel.
- US5 (T076, T078) in parallel with US4 once US1 is done.

## Implementation strategy

- MVP = Phases 1-3 (US1): a wallet is shared, accepted on A and opened with the master password on B. Then US2 (sync afterwards) and US3 (scope, single-use, expiry) complete the P1 set; US3 MUST ship before any release because the invitation is the security boundary. US4 and US5 next; Polish last.
- At each checkpoint run `cargo test --workspace` and clippy. Never weaken a scope, expiry or consent rule to make a test pass.
- Manual/environment-blocked tasks: T046, T052, T063, T075, T082, T093.

## Verification map (completed by T092)

Test paths: `VC/tests`, `WS/tests`, `WSV/tests`, `DL/tests`, `DN/tests`, `PD/tests` (see the path abbreviations above). Every row has at least one automated test; MANUAL tasks add the two-host checks.

| Requirement | Tasks | Automated tests |
|-------------|-------|-----------------|
| FR-001 paired peers, networking on, channel only | T034, T061, T010 | PD api_share.rs, PD share_scope.rs, DN ensure_channel.rs |
| FR-002 unlocked and eligible wallet | T025, T034 | WS share_invite.rs, PD api_share.rs |
| FR-003 no account, relay, pairing | T010, T061 | DN ensure_channel.rs (NotPaired), PD share_scope.rs (unpaired never past handshake) |
| FR-004 one wallet, one recipient, once | T025, T053 | WS share_invite.rs, WS share_invalidate.rs |
| FR-005 code, 5 minutes, start before expiry | T055, T032, T025 | WS share_expiry.rs, PD share_qr.rs |
| FR-006 code and QR without external resources | T032, T039 | PD share_qr.rs, PD share_ui_assets.rs |
| FR-007 one active, 5 per 10 min | T054, T034 | WS share_limits.rs, PD api_share.rs (429) |
| FR-008 memory only, never logged | T025, T061, T043, T088 | WS share_invite.rs, PD share_scope.rs (restart), PD share_leakage.rs, PD share_log.rs |
| FR-009, FR-009a cancel, cancel on lock | T064, T059, T061 | WS share_cancel.rs, WSV lock_observer.rs, PD share_scope.rs |
| FR-010 invalidations | T053, T061 | WS share_invalidate.rs, PD share_scope.rs |
| FR-011 sender choice, manual address, code | T035, T041, T010 | PD api_receive.rs, PD share_two_devices.rs, DN ensure_channel.rs |
| FR-012 QR id must match channel identity | T035, T010 | PD api_receive.rs (id_mismatch), DN ensure_channel.rs (IdMismatch) |
| FR-013 proof over channel, constant time, recipient bound | T017, T053, T057 | WS share_proof.rs, WS share_invalidate.rs, WS share_attacks.rs |
| FR-014 acceptance on sender | T026, T064, T039 | WS share_sender.rs, WS share_cancel.rs, PD share_ui_assets.rs |
| FR-015 recipient consent, cancel wait, not a wallet until opened | T027, T064, T049 | WS share_redeem.rs, WS share_cancel.rs, PD share_sync.rs |
| FR-016 only ciphertext and non-secret messages | T026, T015, T043 | WS share_sender.rs, WS share_codec.rs, PD share_leakage.rs |
| FR-017 004 transfer rules and shared limit | T013, T026, T085, T084 | WS share_slots.rs, WS share_sender.rs, PD flood_share.rs, PD resources_share.rs |
| FR-018 ciphertext atomic owner-only, <= 8 | T021, T065, T069 | PD share_store.rs, WS share_received.rs, PD share_faults.rs |
| FR-019 open with name and password, 002 rules | T030, T076, T035, T078 | WSV adopt.rs, WSV adopt_failures.rs, PD api_receive.rs, PD api_received_open.rs |
| FR-020 already present (residual case in T080) | T076, T078, T080 | WSV adopt_failures.rs, PD api_received_open.rs, PD share_two_devices.rs |
| FR-021 synced by 004 after open, not before | T047, T049, T050 | PD share_then_sync.rs, PD share_sync.rs, PD share_three_devices.rs |
| FR-022 discard | T065, T071 | WS share_received.rs, PD api_share_actions.rs |
| FR-022a 24 h deletion, no polling | T065, T067, T084 | WS share_received.rs, PD share_retention.rs, PD resources_share.rs |
| FR-023 revoked sender's received wallets deleted | T065, T067 | WS share_received.rs, PD share_retention.rs |
| FR-024 additive negotiated protocol, older peers | T005, T006, T009, T044 | DL wire_share.rs, DL channel_v3.rs, DN channel_v3_loopback.rs, PD share_old_peer.rs |
| FR-025 bounded, session-bound messages | T015, T017, T057, T085 | WS share_codec.rs, WS share_proof.rs, WS share_attacks.rs, PD flood_share.rs |
| FR-026 UI | T039, T073 | PD share_ui_assets.rs |
| FR-027 002 protections | T036, T034, T071 | PD share_guards.rs, PD api_share.rs, PD api_share_actions.rs |
| FR-028 log | T023, T088, T087 | PD share_log.rs, PD scans.rs, WS scans.rs |
| FR-029 exclusions (negative tests) | T010, T061, T049 | DN ensure_channel.rs (unpaired refused), PD share_scope.rs, PD share_sync.rs |
| Edge: storage full / restart mid transfer | T069, T067 | PD share_faults.rs, PD share_retention.rs |
| Edge: networking off, offline recipient | T034, T035, T010 | PD api_share.rs, PD api_receive.rs, DN ensure_channel.rs |
| Edge: lock/restart/revoke during invitation | T061, T059 | PD share_scope.rs, WSV lock_observer.rs |
| Edge: file changed after acceptance | T026, T055 | WS share_sender.rs, WS share_expiry.rs |
| SC-001 under 2 minutes | T046, T041 | PD share_two_devices.rs (+ MANUAL timing) |
| SC-002 no secret in traffic | T043, T017 | PD share_leakage.rs, WS share_proof.rs |
| SC-003 all bad redemptions send nothing | T053, T061 | WS share_invalidate.rs, PD share_scope.rs |
| SC-004 no partial data on abort | T064, T069, T065 | WS share_cancel.rs, PD share_faults.rs, WS share_received.rs |
| SC-005 sync within 60 s after open | T047, T049 | PD share_then_sync.rs, PD share_sync.rs |
| SC-006 10 000 credentials under 10 s | T083 | PD share_perf.rs (ignored) |
| SC-007 no idle cost | T084, T067 | PD resources_share.rs (ignored), PD share_retention.rs |

Verified by T092: every test file named above exists (checked mechanically) and every FR, SC
and edge row has at least one automated test. Additional automated coverage written during
implementation: DL `wire_share.rs`, `channel_v3.rs`; DN `channel_v3_loopback.rs`,
`ensure_channel.rs` (incl. the address-plus-id probe for FR-012); WS `share_slots.rs`,
`share_received_store.rs`, `share_redeem.rs`; WSV `adopt.rs`, `adopt_failures.rs`,
`lock_observer.rs`; PD `share_store.rs`, `share_qr.rs`, `share_guards.rs`,
`share_old_peer.rs`, `share_leakage.rs`, `share_faults.rs`, `api_share_actions.rs`,
`api_received_open.rs`, `flood_share.rs`, `share_perf.rs` (ignored), `resources_share.rs`
(ignored). Manual two-host checks: T046, T052, T063, T075, T082, T093.
