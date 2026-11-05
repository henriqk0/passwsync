# Research: Wallet Sharing (005)

Phase 0 decisions for [spec.md](spec.md). Format per decision: Decision / Rationale /
Alternatives. Non-interactive session: every open choice takes the most secure, then simplest
option consistent with the constitution and the roadmap global rules. No spec decision is
changed by this plan.

## R1. Crate layout (hexagonal boundary, no new crate, no cycle)

- **Decision**:
  - `crates/wallet-sync` (domain, extended): new module `share` (sans-IO): share message codec
    (R4), redemption proof (R5), sender invitation state machine and recipient redemption state
    machine (R6), received-wallet rules (R9) and the `ReceivedStore` port. It reuses the crate's
    `PeerId`, `MonoClock`/`WallClock`, the 004 whole-file sender (`transfer::Serving`, re-hashing
    against the sync-record digest) and the 004 size bounds (`MIN_COPY`, `MAX_COPY`,
    `MAX_FRAGMENT`). The service-wide transfer limit becomes a small shared `TransferSlots`
    handle used by both the 004 `Engine` and the share engine (R8).
  - `crates/wallet-service` (extended, additive): `Service::adopt_received` (turn an
    authenticated received file into a held, unlocked wallet, R10) and a `LockObserver` port
    notified on every lock cause (R7).
  - `crates/device-link` (extended, additive): channel protocol v3 (Hello version byte 3,
    prologue `passwsync-channel-v3`) and two opaque payload types `ShareMsg` (0x30) and
    `ShareData` (0x31) valid only on v3 channels (R3).
  - `crates/device-link-net` (extended, additive): v3 → v2 → v1 dial fallback, delivery of share
    frames to the existing `SyncFrameSink`, `Node::send_sync` accepting share payloads on v3
    channels, and `Node::ensure_channel` for the recipient's "dial this paired device / this
    address now" (R11).
  - `crates/passwsyncd` (adapters): `share_store.rs` (file `ReceivedStore`), `share_runtime.rs`
    (glue between `wallet-sync::share`, `wallet-service`, `device-link-net`, the 004 sync
    runtime and the sweeper), `http/api_share.rs`, UI, log events. Invite codes are generated
    with the existing `device_link::PairingCode` and limited with `CodeRateLimiter` (R5).
- **Dependency graph after 005** (unchanged edges, no cycle):
  `passwsyncd → {wallet-sync, wallet-service, device-link-net, device-link, vault-core,
  vault-storage-file}`; `wallet-sync → vault-core`; `wallet-service → vault-core`;
  `device-link-net → device-link`. `wallet-sync` still does not depend on `device-link` (the
  session hash and device ids are plain `[u8; 32]`; the code arrives as digits).
- **Rationale**: Principle IV (protocol and invitation logic testable with in-memory fakes);
  Principle II (sharing is "the first sync of a wallet": same peer ids, clocks, transfer and
  limits, so a separate crate would duplicate or re-export them); reuse required by FR-017.
- **Alternatives**: new crate `wallet-share` (needs `pub` access to 004 transfer internals and
  limits, i.e. widening `wallet-sync`'s API for one consumer, or duplication); logic inside
  `passwsyncd` (not testable without I/O, not reusable by 007); generating codes inside
  `wallet-sync` (duplicates the reviewed 003 `PairingCode`).

## R2. What is transferred

- **Decision**: exactly the bytes of the sending device's stored wallet file (format v2, as
  saved by vault-core), streamed as the 004 sender does, plus the non-secret share messages of
  [contracts/share-protocol.md](contracts/share-protocol.md). No wallet name (the recipient
  names it), no wallet id, no state vector, no sync record, no pending copies. Eligibility on
  the sender (FR-002): wallet unlocked, sync record present and valid, file digest equal to the
  record digest, format version 2, not `possible_rollback`, not `disabled`. The receiver accepts
  only files that authenticate as format version 2.
- **Rationale**: FR-016; the file is already the 004 transfer unit and contains everything
  needed (inside the encryption); the record digest check guarantees that what is sent is the
  current authenticated state (clarification Q2).
- **Alternatives**: re-encrypting a fresh export (needs new code paths and the key outside
  vault-core); sending the record or marks (local metadata, no value to the recipient, leaks
  device ids).

## R3. Negotiation: channel protocol v3

- **Decision**: Channel Hello v3 = `PWSC || 0x03 || 0x01`, Noise prologue
  `passwsync-channel-v3 || Hello`; handshake, framing, keepalive and duplicate rule unchanged.
  v3 = v2 (004 sync, unchanged) + payload types 0x30 `ShareMsg` and 0x31 `ShareData`. A v3
  responder accepts Hello v1, v2 and v3. A v3 dialer dials v3; if the connection closes before
  Noise message 2, the peer's maximum version is lowered to v2 in memory and it is redialed at
  once (which may itself fall back to v1 exactly as in 004). A lowered peer is retried at its
  higher version after 24 h or a restart (the 004 `legacy` map generalized to a per-peer
  maximum version). Share payloads on a v1/v2 channel are a protocol error (close), as 004 does
  for sync payloads on v1. The UI shows "this device does not support sharing" for a peer whose
  current channel is below v3 (FR-024).
- **Rationale**: a 004 (v2) peer closes the channel on any unknown payload or control type, so
  adding share messages to v2 would break sync with older peers. The plaintext Hello is the only
  negotiation point an older peer rejects before any crypto, and the version is bound into the
  Noise prologue, so an active attacker can only downgrade to "no sharing", never alter traffic.
  Same reasoning as 004 R7; no new mechanism.
  **Amended by 009 (pending 009 implementation)**: that reasoning is wrong for the same reason, and the per-peer maximum
  version is removed; 009 research R1.
- **Alternatives**: share control types inside 004 `SyncCtl` (v2 peers close on unknown ctype);
  capability bit in `ChannelHello` (v1/v2 close on trailing bytes); separate TCP port (second
  handshake and pin logic, extra socket).

## R4. Share messages and flow

- **Decision**: [contracts/share-protocol.md](contracts/share-protocol.md). One `ShareMsg`
  frame per message (largest is 37 bytes, no fragmentation needed), `ShareData` chunks of at
  most 1000 bytes (004 chunk size). Messages: `Redeem`, `Pending`, `Offer`, `End`, `Stored`,
  `Abort`. Flow: recipient → `Redeem{rid, proof}`; sender verifies → `Pending{rid,
  seconds_left}`; person accepts on the sender → `Offer{rid, size}` + `ShareData`* + `End{rid}`;
  recipient stores atomically → `Stored{rid}`. Any side may send `Abort{rid, reason}` at any
  point; a share exchange is bound to one channel connection (session) and one `rid`; channel
  loss aborts it. At most one share exchange per channel and one active invitation per device.
  The recipient never pushes and the sender never sends without a redemption, a positive person
  decision and a free transfer slot.
- **Rationale**: FR-013 to FR-018, FR-025; mirrors 003 pairing (`PairPending` → accept →
  commit) and reuses the 004 transfer shape (`CopyStart`/`CopyData`/`CopyEnd`), so reviewers see
  known patterns.
- **Alternatives**: reuse 004 `CopyData` (0x21) for the transfer (it is defined as belonging to
  the current sync transfer; mixing two transfers on one type complicates demultiplexing and
  the 004 checks); a recipient "accept offer" step (entering the code already is the recipient's
  consent, clarification Q4).

## R5. Invite code and redemption proof

- **Decision**:
  - Code: 8 decimal digits from the OS CSPRNG via the existing `device_link::PairingCode`
    (uniform rejection sampling, `Zeroizing`, 5-minute validity, displayed `1234 5678`), rate
    limited by the existing `CodeRateLimiter` (5 per 10 minutes, FR-007) in a separate limiter
    instance for invitations. Normalized input with the existing `normalize_code`. Held only in
    service memory (FR-008).
  - The code never crosses the network, not even inside the channel. The recipient sends
    `proof = HMAC-SHA-256(key = code ASCII digits, "passwsync-share-redeem-v1" || session ||
    sender_id || recipient_id || rid)` (32 bytes), where `session` is the 003/004 Noise handshake
    hash of the channel carrying the message and the ids are the two 32-byte device ids as
    authenticated by that channel. The sender recomputes it from its active invitation and
    compares with `Mac::verify_slice` (constant time, from the `hmac` crate already used by
    `wallet-sync`).
  - One attempt: the first `Redeem` that reaches an active invitation consumes it whatever the
    outcome. A `Redeem` from a paired device that is not the invitation's recipient invalidates
    the invitation too (clarification Q1, FR-010).
- **Rationale**: FR-005, FR-013, SC-002 ("zero occurrences of the invite code in clear"
  holds even for channel plaintext); binding to the session, both ids and `rid` makes a proof
  useless on any other channel, in any other exchange and towards any other device (FR-025).
  The channel already proves both device identities, so the code only proves the person's
  intent and selects the invitation (spec assumption); a PAKE would add nothing because the
  only party that can see the proof is the authenticated peer, and a single allowed attempt
  makes offline guessing of a captured proof pointless (the invitation is already consumed).
- **Alternatives**: sending the code inside the channel (meets FR-013 but needlessly exposes the
  code to a wrongly chosen paired device); SPAKE2 per redemption (extra round trips and state
  for no gain over an authenticated channel); longer codes (8 digits with one attempt gives a
  1 in 10^8 chance, and the recipient binding makes a guessed code useless elsewhere).

## R6. Invitation and redemption state machines

- **Decision** ([data-model.md](data-model.md)):
  - Sender `Invitation`: `Active → AwaitingAcceptance → Transferring → Completed`; terminal
    failures `Cancelled(by_person | wallet_locked | recipient_revoked | replaced)`,
    `Expired`, `Rejected`, `Refused(wrong_code | not_recipient)`, `Failed(reason)`.
    "Transfer started" = the `Offer` frame has been handed to the channel. Expiry (5 minutes from
    creation, sender's monotonic clock) is checked synchronously at every step: no `Pending`,
    accept or `Offer` after expiry. A transfer started before expiry finishes within the 004
    bounds (30 s without progress, 15 minutes total). After a terminal state the invitation is
    kept only as a code-less tombstone (recipient, reason) until its original expiry so that a
    late `Redeem` from the recipient gets the precise reason ("cancelled by sender", "expired",
    "already used"); everyone else gets `invalid`.
  - Recipient `Redemption`: `Connecting → AwaitingSender → Receiving → Stored`; terminal
    `Failed(reason)`, `Cancelled`. Waiting bounds: connecting ≤ 300 s, `Pending` reply ≤ 10 s
    after `Redeem`, decision ≤ `seconds_left` + 10 s, transfer 004 bounds, `Stored` sent after
    the atomic store.
  - One active invitation per device (a new one replaces the previous unless it is
    `Transferring`, then `409 busy`); one redemption per device at a time.
- **Rationale**: FR-004 to FR-015, US3, US4; every path is a finite state machine testable with
  fake clocks; the tombstone satisfies FR-009a ("recipient told 'invitation cancelled by
  sender'") without keeping the code.
- **Alternatives**: proactively pushing "cancelled" to the recipient (the recipient has no state
  before it redeems; it learns it at redemption or immediately if already waiting).

## R7. Cancelling on lock, revocation, restart

- **Decision**: `wallet-service` gains an additive `LockObserver` port (`fn locked(&self,
  name: &WalletName)`) called after any lock (manual, all, idle, suspend, stop, and the 004
  paths). The share runtime cancels the invitation for that wallet if its transfer has not
  started (`Abort(cancelled)` to a waiting recipient). Defence in depth: the sender also re-checks
  "wallet unlocked and eligible" at accept and right before `Offer`. Revoking a device (003)
  cancels an invitation for it, aborts an exchange with it and deletes its received wallets
  (FR-023). Restart: invitations live only in memory; partial received files are deleted at
  start.
- **Rationale**: clarification Q2 / FR-009a with no path that misses a lock cause (the observer
  sits where the lock happens, not in each HTTP or sweeper call site).
- **Alternatives**: hooking each `LogEvent::Locked` call site in `passwsyncd` (easy to miss a
  future lock path); polling the lock state (forbidden).

## R8. Transfer reuse and limits

- **Decision**: Sender: `transfer::Serving` (004) streams the stored file in 1000-byte chunks
  and re-hashes it against the sync-record digest; the record and the file handle are taken
  under the journaling decorator's per-wallet save serialization so they describe the same bytes
  (a later save renames a new file and does not affect the open handle: the snapshot of FR-009a).
  A digest mismatch aborts with `Abort(sender_error)`. Receiver: streams to
  `received/<id>.part` through the `ReceivedStore` writer, enforces `size` from `Offer`
  (79..=64 MiB) before storing any byte and aborts as soon as a chunk would exceed it, `fsync` +
  rename on `End` with exactly `size` bytes. Limits shared with 004: ≤ 2 transfers service-wide
  (sync and share together, via a `TransferSlots` counter injected into both engines), ≤ 1 MiB
  buffers per transfer, frames ≤ 1024 bytes. A sender without a free slot at accept answers
  `Abort(busy)` and the invitation fails (the person may create a new one).
- **Rationale**: FR-017, SC-006 (10 000 credentials ≈ 2–3 MiB, far under 10 s on a LAN, as
  measured by 004 for whole-file copies).
- **Alternatives**: a separate share slot (exceeds the reviewed 004 resource bound); waiting for
  a slot (adds queueing state to a 5-minute flow; failing fast is simpler).

## R9. Received wallets at rest

- **Decision**: `$XDG_DATA_HOME/passwsync/received/` (0700) holding, per received wallet with a
  random 128-bit id: `<id>.pwsw` (0600, ciphertext exactly as received), `<id>.meta` (0600, text:
  sender device id, receipt Unix time, size, checksum line) and transiently `<id>.part`. Order:
  part → fsync → rename to `.pwsw` → fsync dir → atomic meta write → `Stored`. Start-up: delete
  `*.part`, files without their pair, corrupted meta (both files), expired entries (24 h), entries
  whose sender is no longer pinned; each deletion is logged and shown as a notice. At most 8
  received wallets (checked before `Redeem` and again at `Offer`). No wallet name, id or state is
  stored (the file cannot be authenticated without the password). Not visible to 004 sync (not
  under `wallets/` or `sync/`), so it never takes part in sync (FR-021).
  Expiry: wall-clock receipt time + 24 h; an entry whose receipt time lies more than 5 minutes in
  the future (clock moved back) is also deleted (fail-safe: deletion only costs a new share).
  Checked at start-up and on the existing 15-second sweeper tick (R12).
- **Rationale**: FR-018, FR-022, FR-022a, FR-023, SC-004; same atomic-write and owner-only rules
  as 002–004.
- **Alternatives**: storing received files under `sync/` as pending copies (pending copies need a
  wallet id and a record; the recipient has neither before the password); one index file for all
  received wallets (one corruption loses all).

## R10. Opening a received wallet

- **Decision**: `Service::adopt_received(name, bytes, password, decide)` in `wallet-service`,
  under the create lock and the KDF gate (002 rules: name validation, `wallet_exists`, KDF memory
  cap, one derivation at a time, generic `invalid_password_or_corrupted`, attempts on one received
  wallet serialized): decrypt with `Vault::unlock`; require format version 2; call `decide` with
  the authenticated `UnlockFacts` so the host can detect "already present" (wallet id equal to a
  wallet known from a sync record, FR-020); then store the received bytes verbatim as the new
  wallet file, call the existing `PendingCopies::unlocked` hook (creates the 004 sync record from
  the authenticated state), and register the wallet as unlocked. The host then sets
  `peer_mark[sender] = state` (authenticated) in the new record and deletes the received files.
  On "already present" the received files are deleted and the person is told the local name of
  the existing wallet. Wrong password: the received wallet stays (US5.1). Format or
  authentication failure with a correct password is indistinguishable (generic error), so the
  entry stays and can be retried or discarded (US5.2).
- **Rationale**: FR-019, FR-020, FR-021; storing the exact received bytes keeps the file's digest
  equal to what the sender's record describes, so the very first 004 round finds both in sync.
  The password is used once, inside `wallet-service`, and wiped (zeroizing) as in 002.
- **Residual risk (documented)**: a wallet held on the recipient but never unlocked since 004 has
  no sync record, so its id is unknown and a duplicate cannot be detected at open; 004 then marks
  the pair `disabled(duplicate_wallet_id)` on the next unlock, with no data loss.
- **Alternatives**: re-saving the vault under a fresh nonce instead of storing the received bytes
  (first sync would transfer the file back for nothing); trying the password against every held
  wallet to detect duplicates (needs keys of locked wallets: impossible).

## R11. Recipient connection (paired list, manual address, QR)

- **Decision**: `POST /api/receive` carries the code plus a sender `device_id` (chosen from the
  paired list or read from a QR), an `address` (manual or from the QR), or both. The runtime calls
  `Node::ensure_channel(expected: Option<DeviceId>, hint: Option<SocketAddrV4>)`: reuse an
  existing v3 channel to that peer, otherwise dial (address policy of 003: IPv4 private or
  link-local literal only). With an `expected` id the 003 rule "responder static ≠ pin of the
  dialed peer → close" applies (FR-012: QR id must match the channel identity). With only an
  address the responder's static must be a pinned, non-revoked key; the resulting peer is the
  sender. Unpaired or revoked devices never get past the 003 handshake (US3.5). The QR text is
  `passwsync://share?v=1&code=<8 digits>&id=<64 hex>&addr=<a.b.c.d:port>` rendered with the
  existing server-side `qrcodegen` path (FR-006).
- **Rationale**: FR-001, FR-011, FR-012; no new trust path: sharing never pairs (FR-003).
- **Alternatives**: requiring the paired list only (FR-011 requires manual address); trusting a
  manual address without pin check (forbidden).

## R12. Timers and background cost

- **Decision**: No new thread and no new periodic wake. Share frames are processed on the
  network threads → the 004 sync runtime's dispatch (the `SyncFrameSink` already used for 004),
  which forwards share payloads to the share engine under its own mutex; transfers reuse the 004
  `sync-send` worker pattern. Hard deadlines (invitation expiry, waiting bounds) are enforced
  synchronously at each step by comparing monotonic deadlines. State clean-up and notifications
  (expired invitation, recipient waiting timeout, received-wallet 24 h deletion) run on the
  existing 15-second sweeper tick (`extra` hook) and at start-up. With no invitation, no
  redemption and no received wallet the feature does nothing (SC-007).
- **Rationale**: FR-022a (the existing 15-second service timer, no per-wallet polling and no new timer;
  no additional wake-ups), Principle V, SC-007.
- **Alternatives**: a dedicated `share-timer` thread (one more thread and wake source for state
  that changes at most every few minutes); the 004 `sync-sched` thread (runs only with networking
  on, but received wallets must expire in a run with networking off too).

## R13. HTTP API, UI, logging

- **Decision**: [contracts/http-api-share.md](contracts/http-api-share.md),
  [contracts/host-runtime-share.md](contracts/host-runtime-share.md). One background route
  `GET /api/share` (invitation, redemption, received list, notices, peer share support), polled
  every 5 s and every 1 s while an invitation or redemption is active; deliberate POST routes for
  create, cancel, accept, reject, receive, receive-cancel, open, discard, dismiss notices. All
  behind the unchanged 002 guard pipeline (loopback, peer UID, Host, session, CSRF, Origin, size
  limits, CSP). UI: "Share" button per unlocked wallet, invitation panel (code, QR `<svg>` built
  from the path, countdown, cancel, accept/reject with name and fingerprint), "Receive a wallet"
  form, received list with Open (name + password) and Discard, progress and outcomes; all in the
  existing single page, keyboard operable, no new asset files. Log: closed set of events
  identifying peers by fingerprint; never codes, proofs, wallet names, ids, keys or passwords
  (FR-028).
- **Rationale**: FR-026 to FR-028; same conventions as 003/004.

## R14. Testing strategy (TDD)

- **Decision**: `wallet-sync::share`: codec round-trips and rejection of every malformed message;
  proof known-answer vectors and binding tests (other session, other ids, other rid fail);
  sender/recipient state machines with fake clocks and in-memory `ReceivedStore`/`WalletSource`
  (every invalidation of FR-010, expiry at each step, lock before and after `Offer`, one attempt,
  tombstone reasons, slot exhaustion, oversize and short transfers). `device-link(-net)`: v3/v2/v1
  negotiation and fallback chain, share payloads refused below v3, `ensure_channel` pin rules.
  `wallet-service`: `adopt_received` success, wrong password (stays), v1 file refused,
  `already_present`, name taken, lock observer for every lock cause. `passwsyncd`: raw-HTTP tests
  for every route and guard; two- and three-service loopback tests (share, then sync converges;
  C redeems; restart mid-invitation; revoke); plaintext/code marker scan of channel plaintext and
  ciphertext (SC-002); fault injection of storage during receive (SC-004); start-up clean-up and
  24 h expiry with a fake wall clock; `#[ignore]` performance test for 10 000 credentials
  (SC-006) and idle-cost test (SC-007).
- **Rationale**: Principle III; mirrors 003/004.

## R15. Dependencies

- **Decision**: none added. `wallet-sync` already depends on `hmac`/`sha2`/`zeroize`/`rand_core`;
  `passwsyncd` already has `device-link` (codes, rate limiter) and `qrcodegen`. No new crate in
  `Cargo.lock`; `cargo deny`/`cargo audit` gates unchanged; `unsafe_code = "forbid"` everywhere.
- **Rationale**: constitution workflow gate (minimal, vetted dependencies); no hand-rolled crypto
  (HMAC-SHA-256 and Noise from existing vetted crates).
