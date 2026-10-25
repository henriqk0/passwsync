# Contract: Wallet sync over the peer channel (channel protocol v2)

Extends [003 peer-protocol.md](../../003-device-identity-pairing/contracts/peer-protocol.md).
Rationale: [research.md](../research.md) R7–R11. Integers big-endian (as 003).

## Negotiation

- Channel Hello v2: `PWSC || 0x02 || 0x01`; Noise prologue `passwsync-channel-v2 || Hello`.
  Handshake, framing (`len:u16`, body 1..=1024), timeouts, keepalive, duplicate rule unchanged.
- Responder: Hello v1 → 003 channel (no sync); Hello v2 → sync-enabled channel. Pairing Hello
  stays `PWSC || 0x01 || 0x02`.
- Dialer: dials v2; if closed before Noise msg2 → peer `legacy`, redial v1 at once; retry v2
  after 24 h or restart. UI peer status: "sync unsupported by peer".
- On a v2 channel the valid transport types are the 003 set plus 0x20 and 0x21. On v1 they
  are a protocol error (close), as in 003.

## New payload types (inside Noise)

| Type | Name | Fields |
|------|------|--------|
| 0x20 | SyncCtl | `more:u8 (0/1) || fragment` (fragment 1..=1000 bytes) |
| 0x21 | CopyData | `bytes` (1..=1000), belongs to the sender's current transfer |

Control messages are concatenated from consecutive SyncCtl fragments until `more = 0`;
reassembled size ≤ 24 KiB, else protocol error (close). A control message is
`ctype:u8 || fields`; trailing bytes → protocol error.

Notation: `sv` = `n:u16 (0..=256) || n × (len:u8 (1..=64) || device-id bytes || counter:u64)`,
sorted by device id, counters ≥ 1. `round:u32`, `idx:u16` (index into the round's `Tags`).

| ctype | Name | Dir | Fields |
|-------|------|-----|--------|
| 0x01 | Tags | I→R | `round, n:u16 (0..=512), n × (tag[16] || state_digest[16])` |
| 0x02 | Matches | R→I | `round, n:u16, n × (idx || in_sync:u8)` |
| 0x03 | Summary | both | `round, idx, flags:u8 (bit0 no_offer), sv` |
| 0x04 | Want | both | `round, idx` |
| 0x05 | Refuse | both | `round, idx, reason:u8` (1 busy, 2 not_offerable, 3 changed, 4 storage) |
| 0x06 | CopyStart | both | `round, idx, size:u32 (79..=67 108 864)` |
| 0x07 | CopyEnd | both | `round, idx` |
| 0x08 | CopyAbort | both | `round, idx, reason:u8` (1 read_error, 2 changed, 3 too_large, 4 storage, 5 cancelled) |
| 0x09 | Done | both | `round` |
| 0x0A | Busy | R→I | `round` (a round is already running; retry after backoff 30 s) |

I = round initiator, R = responder. Unknown ctype, wrong round, idx out of range, `Want` for a
wallet the peer did not summarize, `CopyData` outside a transfer or beyond `size` → close.

## Tags and digests (R9)

`session` = Noise handshake hash (32 bytes). `role` = 0 if I is the channel dialer, else 1.
`wid` = wallet id (16 bytes) used as HMAC-SHA-256 key.

```text
tag          = HMAC(wid, "passwsync-sync-tag-v1"   || session || round || role)[0..16]
state_digest = HMAC(wid, "passwsync-sync-state-v1" || session || round || role || sv)[0..16]
```

Syncable wallet = has a valid record, not `disabled`. I sends one entry per syncable wallet
(window of 512, rotating). R matches against all its syncable wallets; `in_sync = 1` iff its own
`state_digest` (computed with I's role) equals the received one. No message names a wallet
id, wallet name, entry count or size other than `CopyStart.size`.

## Round

1. I → `Tags`. (If both sides send `Tags` simultaneously, the dialer's round proceeds; the
   other side discards its own and answers.)
2. R → `Matches`; for each match with `in_sync = 0`: `Summary`.
3. I → `Summary` for each such idx.
4. Each side, per differing wallet, applies the want rule; at most one outstanding `Want` per
   direction. Server side answers a `Want` with `CopyStart` + `CopyData`* + `CopyEnd`, or
   `Refuse`. The sender re-hashes the file while streaming; a mismatch with the record digest →
   `CopyAbort(changed)`.
5. Each side → `Done` when it has no `Want` to send and none outstanding to serve. Round ends
   when both `Done` were exchanged; outcome recorded per peer.

No progress for 30 s → round failed. Channel close → round failed; partial copies deleted.

## Want rule (receiver, per wallet, peer p)

Send `Want` iff all hold:
- peer `Summary` has no `no_offer`;
- `peer_state ≥ peer_mark[p]` (else record "older state offered", no Want);
- some component `peer_state[d] > local_state[d]` (peer has a change we lack);
- no component exceeds `max(local_state[d], peer_mark[p][d]) + 2^32` (else invalid);
- no stored pending copy (from any peer) or local state already dominates `peer_state`;
- a transfer slot is free (else retry next round, not a failure).

A refused peer's `Summary` still drives our side of step 4 (we serve its `Want`).

## Accepting a copy

Received bytes stream to `incoming-<peer>.part`; on `CopyEnd` with exactly `size` bytes the
file becomes `pending-<peer>` (replacing an older one). Unlocked → merged immediately; locked
→ kept pending. At merge time: authenticated `wallet_id` must equal the requested wallet,
authenticated `state` must equal the claimed `sv` and be `≥ peer_mark[p]`, and pass the jump
bound; otherwise the copy is rejected and a warning naming the peer is recorded. After the
merged result is saved, `peer_mark[p] = authenticated state`.

## Limits

Frames ≤ 1024 bytes; control messages ≤ 24 KiB; copies ≤ 64 MiB; 1 round per peer;
≤ 2 transfers service-wide; ≤ 1 MiB buffers per transfer.
