# Contract: `passwsyncd` HTTP additions for devices and pairing

Extends [002 http-api.md](../../002-local-service-web-ui/contracts/http-api.md). Every
transport rule there applies unchanged to these routes: loopback listener, peer UID, exact
Host, session cookie, `X-CSRF-Token` on every `/api/*` call, exact `Origin` on POST, size
limits, security headers and CSP, fixed rejection bodies. No route needs a wallet unlock;
none resets wallet idle timers. Error body shape is the 002 one.

`{id}` = 64 lowercase hex device ID (else `404 device_not_found`).

## `GET /api/network` (background poll: 5 s, 1 s while a pairing is active)

```json
{
  "settings": { "network": "on", "peer_port": 27472, "discovery_port": 27473, "interface": null },
  "status": { "state": "on", "port": null,
              "interfaces": [ { "name": "wlan0", "addr": "192.168.1.5", "prefix": 24 } ] },
  "this_device": { "name": "passwsync device ABCD", "fingerprint": "ABCD-EFGH-IJKL-MNOP", "device_id": "<64 hex>" },
  "nearby": [ { "device_id": "…", "fingerprint": "…", "addr": "192.168.1.7:27472", "paired": false } ],
  "paired": [ { "device_id": "…", "fingerprint": "…", "name": "Phone", "paired_at": 1761200000,
                "last_seen": 1761200300, "status": "connected" } ],
  "pairing": null,
  "join": null,
  "warnings": [ { "kind": "unpaired_key_at_address", "addr": "192.168.1.7:27472",
                  "fingerprint": "…", "claimed_fingerprint": "…" } ]
}
```

`status.state`: `off | identity_unusable | peers_unusable | port_in_use | no_local_network
| on` (`port` set for `port_in_use`). `this_device` is present whenever an identity is
loaded (also with networking off). `paired[].status`: `connected | offline |
refused_by_peer`.

`pairing` (initiator, while a code exists or a result is fresh):
`{ "state": "waiting|exchanging|awaiting_acceptance|paired|failed", "code": "1234 5678",
"expires_in": 287, "qr": { "size": 29, "path": "M4 4h1v1h-1z…" }, "qr_text":
"passwsync://pair?v=1&code=12345678&id=<64hex>&addr=192.168.1.5:27472",
"peer": { "device_id", "fingerprint", "name" } | null, "reason": null }`.
`code`, `qr`, `qr_text` are present only while the code is valid.

`join` (joiner): `{ "state": "connecting|exchanging|awaiting_acceptance|paired|failed",
"peer": {…} | null, "seconds_left": n | null, "reason": "<failure reason>" | null }`.

## `POST /api/pairing/start` → `200` pairing object (as above)

Replaces any previous code. Errors: `409 networking_off`, `409 busy` (a join is running),
`409 pair_limit`, `429 too_many_codes`.

## `POST /api/pairing/cancel` → `200 {}` (idempotent)

## `POST /api/pairing/accept` body `{ "device_id": "<64 hex>" }` → `200 { "peer": {…} }`

Must match the pending peer. Errors: `409 nothing_pending`, `409 pairing_mismatch`,
`409 expired`, `500 storage_error` (nothing pinned, pairing failed).

## `POST /api/pairing/reject` → `200 {}`

## `POST /api/pairing/join` body `{ "address": "192.168.1.5:27472", "code": "1234 5678", "device_id": "<64 hex>" | null }` → `202 {}`

`address`: IPv4 literal + port, must pass the address policy (no host names).
`device_id`: set by the UI when A was chosen from the nearby list or a QR was scanned; then
A's proven ID must match. Errors: `400 invalid_address`, `400 invalid_code` (not 8 digits
after removing spaces/dashes), `400 invalid_device_id`, `409 networking_off`, `409 busy`,
`409 already_paired`, `409 pair_limit`, `409 self`. Progress in `GET /api/network` `join`.

## `POST /api/devices/{id}/revoke` → `200 {}`

Confirmation happens in the UI. Removes and saves the pin, closes any channel at once.
Errors: `404 device_not_found`, `500 storage_error` (pin kept, channel untouched).

## `POST /api/network/warnings/clear` → `200 {}`

## UI

New "Devices" view in the existing single page: this device (name, fingerprint, network
status and interfaces, read-only settings), "Pair a device" (code in groups, QR as an
`<svg>` built with DOM APIs from `qr.path`, countdown, Accept/Reject showing name and
fingerprint), "Join" form (nearby list or address, code), paired list with Revoke
(confirmation dialog), warnings. No new asset files are fetched from anywhere but `/static`.
