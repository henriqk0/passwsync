# Contract: `passwsyncd` host runtime changes for wallet sharing

Extends [002 host-runtime.md](../../002-local-service-web-ui/contracts/host-runtime.md),
[003 host-runtime-network.md](../../003-device-identity-pairing/contracts/host-runtime-network.md)
and [004 host-runtime-sync.md](../../004-wallet-sync-protocol/contracts/host-runtime-sync.md).
Rationale: [research.md](../research.md) R7–R12.

## Sockets

Unchanged from 003/004. Sharing uses only the existing peer channel (v3). No new socket, port,
DNS or internet destination. With networking off, sharing is unavailable.

## Files (added)

| Path | Mode | Content | Written by |
|------|------|---------|------------|
| `$XDG_DATA_HOME/passwsync/received/` | 0700 | — | service (created at start if missing) |
| `…/received/<id hex32>.part` | 0600 | partial ciphertext; deleted at start and on abort | service |
| `…/received/<id hex32>.pwsw` | 0600 | received encrypted wallet file, byte for byte | service (rename from `.part`) |
| `…/received/<id hex32>.meta` | 0600 | meta (below), atomic write | service |

Same ownership/permission checks as the other data directories: a permissive or foreign-owned
`received/` disables sharing with status `received_unusable` (shown in `GET /api/share`
`unavailable_reason`) and never stops the service; it is never rewritten.

Meta format (text, ≤ 1 KiB):

```text
passwsync-received-v1
sender <device-id hex64>
received <unix seconds>
size <bytes>
check <sha256 hex64 of all preceding bytes>
```

No wallet name, wallet id, state, code or password is ever written. Invitations and codes are
never written anywhere (memory only).

Write order on receipt: append chunks to `.part` → `fsync` → rename to `.pwsw` → `fsync`
directory → atomic meta write (temp, `fsync`, rename, directory `fsync`) → `Stored` sent.

Opening moves nothing: the ciphertext bytes are written as `wallets/<name>.pwsw` through the
normal 002 storage (atomic, create-only under the create lock), the 004 sync record is created
from the authenticated state with `peer_mark[sender]`, then both received files are deleted.

## Start-up (appended after 004 step 5c)

5e. Create `received/` if missing; delete every `*.part`; delete `.pwsw` without `.meta` and
`.meta` without `.pwsw`; delete pairs whose meta is unparsable or fails its checksum, whose
size differs from the file, whose sender is not pinned, whose receipt is older than 24 h or more
than 5 minutes in the future; if more than 8 remain, delete the newest extras. Each deletion
class is logged once with a count and shown as a notice. Exit codes unchanged; nothing here
stops the service.

## Running

- Share frames arrive through the 004 `SyncFrameSink` dispatch and are handled by the share
  engine under its own mutex; transfers run on the 004 `sync-send` worker pattern with the shared
  transfer limit (≤ 2).
- The existing 15-second sweeper tick also: ends expired invitations and timed-out redemptions,
  drops tombstones, deletes received wallets past 24 h (notice + log). No new thread, no new
  periodic wake (SC-007).
- Lock (any cause, via the `LockObserver`): cancels a not-yet-transferring invitation for that
  wallet.
- Revoke (003): cancels an invitation for that device, aborts any exchange with it, deletes its
  received wallets (FR-023).

## Shutdown (added, before 004 sync shutdown)

Abort the share exchange (`Abort(cancelled | recipient_cancelled)` best effort), delete a
partial `.part`, drop the invitation and wipe its code, release transfer slots.

## Log events (added, closed set)

`share invitation created recipient=<fingerprint>`,
`share invitation ended (<cancelled|replaced|locked|revoked|expired|rejected|completed|failed>)`,
`share redeem refused peer=<fingerprint> (<wrong-code|not-recipient|no-invitation|expired|used|cancelled>)`,
`share redeemed peer=<fingerprint>`, `share accepted peer=<fingerprint>`,
`share transfer completed peer=<fingerprint> bytes=<n>`,
`share transfer aborted peer=<fingerprint> (<reason>) bytes=<n>`,
`share receive started peer=<fingerprint>`, `share received peer=<fingerprint> bytes=<n>`,
`share receive failed peer=<fingerprint> (<reason>)`,
`received wallet opened peer=<fingerprint>`, `received wallet already present peer=<fingerprint>`,
`received wallet discarded peer=<fingerprint> (<person|expired|revoked>)`,
`received cleaned (<partial|orphan|corrupted|expired|unpinned|excess>) count=<n>`,
`share peer unsupported <fingerprint>`.

Never: codes, proofs, `rid`, wallet names, wallet ids, received ids, keys, passwords, contents
(FR-028). (Opening a received wallet also emits the existing 002 `unlocked <wallet>` event for the
new local wallet, as every unlock does.)

## Configuration

No new key. Validity (5 min), rate limit (5 / 10 min), received limit (8) and retention (24 h)
are fixed by the spec.
