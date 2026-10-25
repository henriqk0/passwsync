# Contract: `passwsyncd` HTTP additions for sync

Extends [002 http-api.md](../../002-local-service-web-ui/contracts/http-api.md) and
[003 http-api-network.md](../../003-device-identity-pairing/contracts/http-api-network.md).
All 002 transport rules apply (loopback, peer UID, exact Host, session cookie,
`X-CSRF-Token`, exact `Origin` on non-GET, size limits, CSP, keyboard-operable UI). Background
routes never reset idle timers; no route returns credential content for a locked wallet
(`423 wallet_locked`). `{peer}` = 64-hex device ID; `{id}` = 32-hex entry id. Rationale:
[research.md](../research.md) R15.

## `GET /api/state` (existing, background): each wallet gains

```json
{ "name": "Personal", "unlocked": false,
  "sync": { "state": "in_sync", "conflicts": 0, "last_synced_at": 1761200000 } }
```

`state` ∈ `sync_off | disabled | possible_rollback | conflicts | changes_waiting | syncing |
sync_error | not_synced | in_sync` (data-model priority order); `disabled` adds `"reason":
"corrupted_record|duplicate_wallet_id|too_many_conflicts"`; `not_synced` adds `"reason":
"no_peer|unlock_once|format_v1"`.

## `GET /api/sync` (background, polled with `/api/network`)

```json
{ "enabled": true, "interval_minutes": 60, "running": ["<peer>"],
  "peers": [ { "device_id": "<peer>", "fingerprint": "…", "name": "Phone",
               "sync": "supported|unsupported", "last_round_at": 1761200000,
               "last_outcome": "ok|failed|older_state_offered|invalid_copy|null" } ],
  "warnings": [ { "id": 3, "kind": "older_state_offered", "wallet": "Personal",
                  "peer": "<peer>", "at": 1761200000 } ] }
```

Warning kinds: data-model `SyncWarning`. Local wallet names only.

## `GET /api/wallets/{name}/sync` (background)

`{ "state": …, "pending": [ { "peer", "received_at", "status": "waiting|cannot_open|password_conflict|too_many_conflicts" } ],
   "peers": [ { "peer", "name", "position": "in_sync|behind|ahead|diverged|unknown|offline|older_state_offered|error", "last_round_at" } ] }`
Only peers that matched this wallet in some round are listed.

## Actions

| Route | Body | Result / errors |
|-------|------|-----------------|
| `POST /api/sync/now` | `{ "wallet": "<name>" \| null }` | `202 {}`; `409 networking_off`; coalesced while running |
| `POST /api/sync/warnings/dismiss` | `{ "ids": [3] }` | `200 {}`; never changes data or marks |
| `GET /api/wallets/{name}/conflicts` (deliberate) | — | `200 { "entries": [ { "id", "title", "versions": n } ] }`; `423` |
| `GET /api/wallets/{name}/conflicts/{id}` (deliberate) | — | `200 { "versions": [ { "index", "deleted": false, "title", "username", "url", "notes", "modified_at", "device": "<name or 'unknown device'>" } ] }` (no passwords) |
| `POST /api/wallets/{name}/conflicts/{id}/field` | `{ "index": 1, "field": "password\|username" }` | `200 { "value" }` (002 reveal/copy rules) |
| `POST /api/wallets/{name}/conflicts/{id}/resolve` | `{ "keep": 0 }` or `{ "keep": "both" }` | `200 { "created": ["<id>"] }` after save; `409 not_conflicted`; `500 storage_error` (rolled back) |
| `POST /api/wallets/{name}/sync/pending/{peer}/open` | `{ "password": "…" }` | `200 { "merged": true }`; `422 invalid_password_or_corrupted` (copy stays pending) |
| `POST /api/wallets/{name}/sync/pending/{peer}/choose-password` | `{ "keep": "local\|copy", "password": "…" }` | resolves a password conflict; `422` on wrong password |
| `POST /api/wallets/{name}/sync/pending/{peer}/discard` | — | `200 {}` |
| `POST /api/wallets/{name}/sync/accept-older` | `{ "confirm": true }` | unlocked only; logged; resets mark and this wallet's peer marks |
| `POST /api/wallets/{name}/sync/reset` | `{ "confirm": true }` | unlocked only; logged; rebuilds record from the authenticated file |

Search results and entry lists (002) gain `"conflicted": true|false`. With networking off,
`sync/now` is unavailable and every wallet shows `sync_off`.
