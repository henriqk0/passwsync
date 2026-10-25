# Data Model: Wallet Sharing (005)

Rationale for every rule: [research.md](research.md). Wire and file layouts:
[contracts/](contracts/). Times: `mono` = monotonic (never persisted), `unix` = wall clock
seconds (display and the 24 h received-wallet bound only).

## wallet-sync::share (domain, sans-IO)

### InviteCode (input, owned by the host)

8 ASCII digits in `Zeroizing<String>`, produced by `device_link::PairingCode` in `passwsyncd`
and handed to the engine at invitation creation. Never stored on disk, logged, serialized or
sent; dropped (wiped) as soon as it is consumed by the first `Redeem` or the invitation is
cancelled, expires or is replaced.

### Invitation (sender, in memory, at most one per device)

| Field | Type | Rule |
|-------|------|------|
| wallet | `WalletName` + `WalletId` | the unlocked, eligible wallet (FR-002); id from `sync_facts` |
| recipient | `PeerId` | a pinned, non-revoked device chosen by the person (FR-004) |
| code | `Option<InviteCode>` | `Some` only while `Active` |
| created | mono | |
| expires | mono | `created + 300 s` (FR-005) |
| exchange | `Option<ExchangeRef>` | `{ conn: u64, session: [u8; 32], rid: u32 }` once redeemed |
| sent | u64 | bytes sent (progress) |
| state | see below | |

States and transitions:

```text
Active ──valid Redeem from recipient──▶ AwaitingAcceptance ──person Accept + slot + still
  │                                         │                 unlocked & eligible──▶ Transferring
  │                                         │                                          │
  │                                         ├─Reject──────────▶ Rejected               ├─Stored──▶ Completed
  │                                         ├─expiry──────────▶ Expired                ├─Abort / timeout /
  │                                         ├─recipient Abort─▶ Failed(recipient_cancelled)   channel loss /
  │                                         └─channel loss────▶ Failed(channel_lost)          digest change ─▶ Failed(reason)
  ├─wrong proof──────────▶ Refused(wrong_code)
  ├─Redeem from other peer▶ Refused(not_recipient)
  ├─expiry───────────────▶ Expired
  ├─person Cancel────────▶ Cancelled(by_person)        (also from AwaitingAcceptance;
  ├─wallet locked────────▶ Cancelled(wallet_locked)     from Transferring only by_person:
  ├─recipient revoked────▶ Cancelled(recipient_revoked) aborts the transfer, FR-009)
  └─new invitation───────▶ Cancelled(replaced)
```

Rules:
- Every step checks `now < expires` except steps inside `Transferring` (FR-005).
- A terminal invitation becomes a **Tombstone** `{recipient, reason, until = expires}` (no code,
  no wallet name) used only to answer a later `Redeem` from the recipient with the precise
  reason; it is dropped at `until` or when a new invitation is created.
- `Completed` + person "Cancel" → no state change; the API reports `already_delivered` (US4.4).
- Creation is limited to 5 per 10 minutes (shared `CodeRateLimiter` instance for invitations,
  FR-007); a new invitation while `Transferring` → refused (`busy`).

### Redemption (recipient, in memory, at most one per device)

| Field | Type | Rule |
|-------|------|------|
| sender | `Option<PeerId>` | from the paired list / QR; else learnt from the channel |
| hint | `Option<SocketAddrV4>` | manual address / QR address (003 address policy) |
| code | `InviteCode` | wiped as soon as the proof is computed |
| exchange | `Option<ExchangeRef>` | `rid` = random u32 chosen here |
| offer | `Option<{ size: u32, received: u64, writer }>` | after `Offer` |
| deadline | mono | current waiting bound (R6) |
| state | `Connecting → AwaitingSender → Receiving → Stored`; terminal `Failed(reason)`, `Cancelled` | |

Failure reasons shown to the person (closed set): `invalid` (wrong code, not for this device,
no invitation, already used), `cancelled_by_sender`, `expired`, `rejected`, `busy`,
`too_large`, `storage`, `sender_error`, `unreachable`, `unsupported` (peer channel < v3),
`received_limit`, `channel_lost`, `timeout`, `id_mismatch` (QR id ≠ channel identity).

### ReceivedWallet (recipient, persisted)

| Field | Type | Rule |
|-------|------|------|
| id | `[u8; 16]` | random, file name stem (hex32); not secret, never sent |
| sender | `PeerId` | must be pinned; deleted at revocation (FR-023) |
| received_at | unix | expiry = `received_at + 86 400`; also deleted if `received_at > now + 300` |
| size | u64 | 79..=64 MiB, equals the ciphertext file size |
| attempts lock | in memory | serializes open attempts (002 rule) |

Bounds: ≤ 8 entries (FR-018). Ciphertext only; no name, wallet id or state.
Lifecycle: `(receiving .part) → Stored → { Opened (moved into wallets/, files deleted) |
AlreadyPresent (files deleted) | Discarded | Expired | SenderRevoked }`; a wrong password or
an unauthenticated file leaves it `Stored`.

### ShareNotice (in memory, bounded 16, oldest dropped)

Closed set: `received_expired{sender}`, `received_deleted_revoked{sender}`,
`received_cleaned{count}` (start-up removal of partial or inconsistent files),
`already_present{local_name}`. Invitation outcomes are not notices: they are shown as the
`invitation` state and reason in `GET /api/share`, which keeps a terminal result for 60 s.
Dismissal removes a notice only.

### Share message (wire, see contracts/share-protocol.md)

`Redeem{rid, proof[32]}`, `Pending{rid, seconds_left}`, `Offer{rid, size}`, `End{rid}`,
`Stored{rid}`, `Abort{rid, reason}`, plus `ShareData{bytes}` chunks.

### TransferSlots (shared with the 004 Engine)

Counter `≤ max_transfers` (2) taken by a sync serve/receive or a share send/receive; released
on completion or abort. Replaces the 004 Engine's private `transfers` counter (same limit).

### Ports (added)

- `ReceivedStore`: `list() -> Vec<ReceivedMeta>`, `begin(id, sender, received_at) ->
  Box<dyn IncomingCopy>` (reuses the 004 `IncomingCopy` writer trait; `finish` writes ciphertext
  then meta atomically), `read(id) -> Vec<u8>`, `delete(id)`. Start-up clean-up is performed by
  the host (host-runtime-share.md, step 5e) through `list` and `delete`.
- Reused: `WalletSource` (sender's stored file + digest), `SyncStore::load` (record digest,
  flags, format eligibility), `MonoClock`, `WallClock`, injected RNG (`rid`, received ids).

## wallet-service (additive)

- `LockObserver` port: `fn locked(&self, name: &WalletName)`; called after any lock.
- `Service::adopt_received(name, bytes, password, decide) -> Result<WalletName, ServiceError>`
  with `decide: &dyn Fn(&UnlockFacts) -> AdoptVerdict`, `AdoptVerdict = Proceed |
  AlreadyPresent(WalletName)`. New error variants: `AlreadyPresent(WalletName)`,
  `UnsupportedVersion` (existing 002 class reused for a v1 received file).

## device-link (additive)

- `HelloVersion::V3`; prologue `passwsync-channel-v3`.
- `Payload::ShareMsg { body: Vec<u8> }` (0x30, 1..=1000 bytes) and `Payload::ShareData { bytes }`
  (0x31, 1..=1000 bytes); valid only when `Channel::share_enabled()` (v3).

## device-link-net (additive)

- Per-peer maximum version `{V3, V2, V1}` with retry-up after 24 h (generalizes the 004 `legacy`
  map; `NetEvent::PeerLegacy` keeps meaning "no sync", new `NetEvent::PeerNoShare`).
- `SyncFrameSink::channel_version(peer, conn, version)` (default no-op) before `channel_up`;
  share payloads delivered through `SyncFrameSink::frame`.
- `Node::ensure_channel(expected: Option<DeviceId>, hint: Option<SocketAddrV4>) ->
  Result<(DeviceId, u64), EnsureError>`.

## passwsyncd (adapters)

- `FsReceivedStore` over `received/` (contracts/host-runtime-share.md).
- `ShareRuntime`: owns the share engine, invitation limiter, notices; registered as
  `LockObserver`; hooked into revoke, sweeper tick, start-up and shutdown.

## Relationships

`Invitation 1 — 1 wallet (unlocked)`, `Invitation 1 — 1 PeerPin (recipient)`,
`Invitation 0..1 — 1 ExchangeRef (channel session)`, `ReceivedWallet n — 1 PeerPin (sender)`,
`ReceivedWallet → (opened) 1 wallet file + 1 SyncRecord (004) with peer_mark[sender]`.
