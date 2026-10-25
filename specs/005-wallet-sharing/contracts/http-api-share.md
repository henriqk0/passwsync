# Contract: `passwsyncd` HTTP additions for wallet sharing

Extends [002 http-api.md](../../002-local-service-web-ui/contracts/http-api.md),
[003 http-api-network.md](../../003-device-identity-pairing/contracts/http-api-network.md) and
[004 http-api-sync.md](../../004-wallet-sync-protocol/contracts/http-api-sync.md). Every 002
transport rule applies unchanged through the existing guard pipeline: loopback listener, peer
UID, exact `Host`, session cookie, `X-CSRF-Token` on every `/api/*` request, exact `Origin` on
non-GET, header/body size limits, security headers and CSP, fixed rejection bodies, error body
shape `{ "error", "message" }`. All POST routes are state-changing (FR-027). Only
`POST /api/wallets/{name}/share` counts as activity on that wallet (002 idle timer); every other
route leaves idle timers untouched. Rationale: [research.md](../research.md) R11, R13.

`{name}` = 002 wallet name; `{peer}`/`device_id` = 64 lowercase hex device id; `{received_id}` =
32 lowercase hex received-wallet id (else `404 received_not_found`). `{received_id}` is never
the protocol `rid` (a u32 exchange id, share-protocol.md). `peer` objects are
`{ "device_id", "fingerprint", "name" }` from the 003 pins.

## `GET /api/share` (background; polled every 5 s, every 1 s while `invitation` or `receive` is non-terminal)

```json
{
  "available": true,
  "unavailable_reason": null,
  "peers": [ { "device_id": "…", "fingerprint": "…", "name": "Phone",
               "status": "connected", "share": "supported" } ],
  "invitation": {
    "state": "active", "wallet": "Personal",
    "recipient": { "device_id": "…", "fingerprint": "…", "name": "Phone" },
    "code": "1234 5678", "expires_in": 287,
    "qr": { "size": 29, "path": "M4 4h1v1h-1z…" },
    "qr_text": "passwsync://share?v=1&code=12345678&id=<64hex>&addr=192.168.1.5:27472",
    "progress": null, "reason": null
  },
  "receive": null,
  "received": [ { "id": "<32 hex>", "sender": { "device_id": "…", "fingerprint": "…", "name": "Laptop" },
                  "received_at": 1761400000, "expires_at": 1761486400, "size": 2400123 } ],
  "notices": [ { "id": 4, "kind": "received_expired", "sender": "<fingerprint>", "at": 1761486400 } ]
}
```

- `available` = networking on and status `on`; else `unavailable_reason` ∈ `networking_off |
  network_unavailable | received_unusable` (the last one: `received/` has wrong owner or
  permissions; Share and Receive are both disabled so a single availability flag stays simple). `peers[].share` ∈ `supported | unsupported | unknown` (unknown = no
  channel seen this run).
- `invitation` (sender; present while one exists or its result is fresh, 60 s):
  `state` ∈ `active | awaiting_acceptance | transferring | completed | cancelled | expired |
  rejected | refused | failed`. `code`, `qr`, `qr_text` only while `active`. `progress` =
  `{ "sent": n, "size": n }` while `transferring`. `reason` for terminal states:
  `by_person | wallet_locked | recipient_revoked | replaced | wrong_code | not_recipient |
  recipient_cancelled | channel_lost | busy | sender_error | storage | too_large |
  received_limit | timeout` (mapping from wire reasons: [share-protocol.md](share-protocol.md)
  "Reason mapping"). The wallet name is
  the sender's local name (shown only locally).
- `receive` (recipient): `{ "state": "connecting|awaiting_sender|receiving|stored|failed|cancelled",
  "sender": peer | null, "seconds_left": n | null, "progress": { "received", "size" } | null,
  "reason": <data-model Redemption reason> | null, "received_id": "<32 hex>" | null }`.
- `received`: received wallets awaiting a password, oldest first (≤ 8). No wallet name exists for
  them until the person chooses one.
- `notices`: data-model `ShareNotice` kinds.

## Actions

| Route | Body | Success | Errors |
|-------|------|---------|--------|
| `POST /api/wallets/{name}/share` | `{ "device_id": "<64 hex>" }` | `200` invitation object (as above, `state: "active"`) | `409 networking_off`, `404 wallet_not_found`, `423 wallet_locked`, `409 not_eligible` + `"reason": "format_v1|possible_rollback|disabled|no_record|changed"`, `404 device_not_found` (not pinned), `409 peer_unsupported` (current channel < v3), `409 busy` (an invitation is transferring), `429 too_many_invitations` |
| `POST /api/share/cancel` | — | `200 { "state": "cancelled" }`; after completion `200 { "already_delivered": true }`; nothing active `200 {}` | — |
| `POST /api/share/accept` | `{ "device_id": "<64 hex>" }` (must equal the pending recipient) | `200 { "state": "transferring" }` | `409 nothing_pending`, `409 share_mismatch`, `409 expired`, `409 wallet_locked` (invitation cancelled), `409 busy` (no transfer slot; invitation failed) |
| `POST /api/share/reject` | — | `200 {}` | `409 nothing_pending` |
| `POST /api/receive` | `{ "code": "1234 5678", "device_id": "<64 hex>" \| null, "address": "192.168.1.5:27472" \| null }` | `202 {}`; progress in `GET /api/share` `receive` | `400 invalid_code` (not 8 digits after removing spaces/dashes), `400 invalid_address` (003 policy), `400 invalid_device_id`, `400 missing_sender` (neither field), `404 device_not_found` (`device_id` not pinned), `409 self`, `409 networking_off`, `409 busy` (a redemption runs), `409 received_limit` |
| `POST /api/receive/cancel` | — | `200 {}` (sends `Abort(recipient_cancelled)` if an exchange runs) | — |
| `POST /api/received/{received_id}/open` | `{ "name": "Personal", "password": "…" }` | `200 { "name": "Personal", "unlocked": true }` | `400 invalid_name`, `409 wallet_exists`, `422 invalid_password_or_corrupted` (stays), `422 unsupported_version` / `malformed_file` / `kdf_params_out_of_range` / `wallet_too_large` (stays; may be discarded), `409 already_present` + `"existing": "<local name>"` (received files deleted), `404 received_not_found`, `500 storage_error` (nothing created, stays) |
| `POST /api/received/{received_id}/discard` | — | `200 {}` | `404 received_not_found` |
| `POST /api/share/notices/dismiss` | `{ "ids": [4] }` | `200 {}` | — |

Rules:
- When `device_id` and `address` are both given (QR or list + manual address), the channel
  identity at that address must equal `device_id` (FR-012), else `receive.reason = id_mismatch`.
  With only `address`, the answering device must be pinned; it becomes the sender.
- `POST /api/received/{received_id}/open` follows the 002 unlock rules (attempts on one received wallet
  serialized, KDF serialized service-wide, generic error text "invalid password or corrupted
  wallet", password wiped after use). The opened wallet then appears in `GET /api/state` like any
  wallet, with its 004 `sync` object.
- No route returns a code after redemption, a proof, a wallet id or credential data.

## UI (existing single page, keyboard operable, no new asset files)

- Wallet view: "Share" for an unlocked wallet → dialog listing paired devices (name, fingerprint,
  share support; unsupported and offline shown with reason) → invitation panel: code in groups,
  QR as `<svg>` built with DOM APIs from `qr.path`, countdown, Cancel. On `awaiting_acceptance`:
  "Send wallet '<name>' to <device name> (<fingerprint>)?" with Accept / Reject. Progress and
  outcome; after completion Cancel explains "the encrypted copy already reached <device>; to stop
  access, revoke the device and change the master password".
- Devices view: "Receive a wallet": sender from the paired list or manual address + port, code
  field, Cancel while waiting, progress and outcome with the reason text.
- "Received wallets" list: sender name and fingerprint, received time, time left before automatic
  deletion, Open (local name defaulting to "Shared wallet <short fingerprint>", master password)
  and Discard (confirmation dialog). Notices with Dismiss.
- With `available: false`, Share and Receive are disabled with the reason (edge case "networking
  off").
