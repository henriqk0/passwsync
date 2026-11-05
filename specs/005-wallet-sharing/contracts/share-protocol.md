# Contract: Wallet sharing over the peer channel (channel protocol v3)

Extends [003 peer-protocol.md](../../003-device-identity-pairing/contracts/peer-protocol.md)
and [004 sync-protocol.md](../../004-wallet-sync-protocol/contracts/sync-protocol.md).
Rationale: [research.md](../research.md) R3–R8. Integers big-endian (as 003).

## Negotiation

- Channel Hello v3: `PWSC || 0x03 || 0x01`; Noise prologue `passwsync-channel-v3 || Hello`.
  Handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), framing (`len:u16`, body 1..=1024), step
  timeouts, keepalive, pin check and duplicate rule unchanged.
- Responder: Hello v1 → 003 channel; v2 → 004 sync channel; v3 → sync + share channel.
  Pairing Hello stays `PWSC || 0x01 || 0x02`.
- Dialer: dials its current maximum for the peer (initially v3). Closed before Noise msg2 →
  lower the maximum by one (v3 → v2 → v1, the v2 → v1 step being the 004 rule) and redial at
  once. A lowered maximum is raised again after 24 h or a restart. UI: peer below v3 → "this
  device does not support sharing"; below v2 → also the 004 "sync unsupported by peer".
  **Amended by 009 (pending 009 implementation)**: each dial starts at v3, the fallback stays inside that dial and nothing is
  remembered; a channel below v3 is retried every 6 h. See
  `specs/009-lan-dos-hardening/contracts/peer-behaviour.md`.
- Valid transport types: v1 = 003 set; v2 = v1 + 0x20, 0x21; v3 = v2 + 0x30, 0x31. Anything
  else → protocol error (close), as in 003.

## New payload types (inside Noise)

| Type | Name | Fields |
|------|------|--------|
| 0x30 | ShareMsg | `stype:u8 || fields` — one complete message per frame (≤ 1000 bytes) |
| 0x31 | ShareData | `bytes` (1..=1000), belongs to the sender's current share transfer on this channel |

Unknown `stype`, wrong length, trailing bytes → protocol error (close).

`rid:u32` identifies one share exchange; chosen at random by the recipient; at most one share
exchange per channel connection at a time.

| stype | Name | Dir | Fields |
|-------|------|-----|--------|
| 0x01 | Redeem | R→S | `rid, proof[32]` |
| 0x02 | Pending | S→R | `rid, seconds_left:u16 (1..=300)` |
| 0x03 | Offer | S→R | `rid, size:u32 (79..=67 108 864)` |
| 0x04 | End | S→R | `rid` |
| 0x05 | Stored | R→S | `rid` |
| 0x06 | Abort | both | `rid, reason:u8` |

### Reason mapping (wire → shown on each side)

The wire `Abort` code is the only value sent. Each side maps what it sends or receives to the
closed UI reasons of [http-api-share.md](http-api-share.md) (`invitation.reason` on S,
`receive.reason` on R) as follows; no other reason strings exist.

| Wire `Abort` | On R (`receive.reason`) | On S (invitation state / `reason`) |
|--------------|-------------------------|------------------------------------|
| 1 invalid | `invalid` | `refused` / `wrong_code` or `not_recipient` (the invitation's own reason); no-invitation or used → no state change |
| 2 rejected | `rejected` | `rejected` / `by_person` |
| 3 cancelled | `cancelled_by_sender` | `cancelled` / `by_person`, `wallet_locked`, `recipient_revoked` or `replaced` (the reason S recorded) |
| 4 expired | `expired` | `expired` |
| 5 busy | `busy` | `failed` / `busy` |
| 6 storage | `storage` | `failed` / `storage` |
| 7 too_large | `too_large` | `failed` / `too_large` |
| 8 sender_error | `sender_error` | `failed` / `sender_error` |
| 9 recipient_cancelled | state `cancelled`, reason null (local) | `failed` / `recipient_cancelled` |
| 10 received_limit | `received_limit` | `failed` / `received_limit` |

Local-only R reasons (never on the wire): `unreachable`, `unsupported`, `id_mismatch`,
`channel_lost`, `timeout`. S-only: `channel_lost`, `timeout` (`Failed`).

S = sender (holds the invitation), R = recipient (redeems). `Abort` reasons:

| Code | Name | Sent by | Meaning |
|------|------|---------|---------|
| 1 | invalid | S | no invitation for this device, wrong code, or already used |
| 2 | rejected | S | the person pressed Reject |
| 3 | cancelled | S | cancelled by sender (person, wallet locked, recipient revoked, replaced) |
| 4 | expired | S | invitation expired before acceptance / transfer start |
| 5 | busy | S or R | no free transfer slot, or another exchange runs |
| 6 | storage | R | could not store (disk full, I/O) |
| 7 | too_large | R | `size` or received bytes above the bound |
| 8 | sender_error | S | the stored file changed or could not be read during the transfer |
| 9 | recipient_cancelled | R | the person cancelled the wait or the transfer |
| 10 | received_limit | R | 8 received wallets already wait for opening |

## Redemption proof (R5)

```text
session = Noise handshake hash of this channel (32 bytes, as 004)
proof   = HMAC-SHA-256(key = code as 8 ASCII digits,
                       "passwsync-share-redeem-v1" || session || sender_id[32] || recipient_id[32] || rid)
```

Ids are the device ids authenticated by the channel (sender = channel peer as seen by R; R's own
id). The sender recomputes with its own id and the channel peer's id and compares in constant
time (`Mac::verify_slice`). The code itself never appears in any frame.

## Exchange

1. R → `Redeem{rid, proof}`. S decides, in this order:
   - no active invitation: tombstone for this peer → `Abort(reason of tombstone: cancelled |
     expired | invalid(used))`; otherwise `Abort(invalid)`;
   - peer ≠ invitation recipient → invitation `Refused(not_recipient)`, `Abort(invalid)`;
   - proof mismatch → invitation `Refused(wrong_code)`, `Abort(invalid)`;
   - expired → `Abort(expired)`;
   - otherwise invitation `AwaitingAcceptance`, code wiped, → `Pending{rid, seconds_left}`.
   S answers within 10 s.
2. S shows the acceptance prompt. Reject → `Abort(rejected)`. No decision before expiry →
   `Abort(expired)`. Accept → S re-checks: not expired, wallet unlocked and eligible, free
   transfer slot (else `Abort(cancelled | expired | busy)`); then → `Offer{rid, size}`. Sending
   `Offer` is the start of the transfer (FR-005, FR-009a).
3. S → `ShareData`* (exactly `size` bytes in chunks ≤ 1000) → `End{rid}`. S re-hashes the file
   against its sync-record digest; mismatch or read error → `Abort(sender_error)`.
   R streams to `received/<id>.part`; `Offer.size` out of range or above the free count →
   `Abort(too_large | received_limit)`; more bytes than `size`, `ShareData` outside a transfer,
   or `End` with fewer bytes → protocol error (close, partial file deleted).
4. R on `End`: fsync, rename, meta write (contracts/host-runtime-share.md) → `Stored{rid}`;
   failure → `Abort(storage)`. S on `Stored` → invitation `Completed`.

Either side may send `Abort` at any time before `Stored`; receiving it ends the exchange on both
sides (partial file deleted). Messages for the last finished `rid` on this channel are ignored;
any other `rid` mismatch → protocol error (close). Channel loss ends the exchange; an invitation
that was redeemed is then `Failed(channel_lost)` (single use).

## Timeouts (R6)

| Wait | Bound | On expiry |
|------|-------|-----------|
| R: channel to S available | 300 s | R `Failed(unreachable)` |
| R: answer to `Redeem` | 10 s | R `Failed(timeout)`, sends `Abort(recipient_cancelled)` |
| R: `Offer`/`Abort` after `Pending` | `seconds_left` + 10 s | as above |
| Either: no progress during transfer | 30 s (004) | `Abort` + exchange failed |
| Transfer total | 15 min (004 `max_round`) | as above |
| S: `Stored` after `End` | 30 s | invitation `Failed(timeout)` |

## Limits

Frames ≤ 1024 bytes; copies 79..=64 MiB; ≤ 2 transfers service-wide shared with 004 sync;
≤ 1 MiB buffers per transfer; one share exchange per channel; one invitation and one
redemption per device; 5 invitations per 10 minutes.

## Privacy

No message carries a wallet name, wallet id, state vector, entry count, the code or the master
password. The only wallet-related value besides ciphertext is `Offer.size`.
