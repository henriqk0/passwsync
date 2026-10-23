# Contract: `passwsyncd` HTTP interface

Loopback-only HTTP/1.1 interface between the embedded browser UI and the service. Normative
for routes, methods, protection rules, status codes and JSON shapes; field order and exact
English messages may change during TDD if this file is updated in the same change.
Design rationale: [research.md](../research.md) R2, R5–R7, R13.

## Transport rules (all requests)

| Rule | Value | On violation |
|------|-------|--------------|
| Listener | `127.0.0.1:<port>` only (default 27471) | connection impossible |
| Peer UID | client socket owned by the service's UID (`/proc/net/tcp`) | connection closed, reason `peer` |
| Connection | one request per connection; response always `Connection: close` | — |
| Request line + headers | ≤ 16 KiB, ≤ 48 headers, read timeout 10 s | `431`, reason `size` |
| Body | requires `Content-Length` ≤ 8 MiB; `Transfer-Encoding` forbidden | `413` / `400`, reason `size` |
| `Host` | exactly `127.0.0.1:<port>` (checked before routing) | `403`, reason `host` |
| Session | cookie `pws_session` valid for this run (all routes except `/launch/*`, `/static/*`, `/`) | `401`, reason `session` |
| CSRF | header `X-CSRF-Token` equals the session's token (constant time), on every `/api/*` request | `403`, reason `csrf` |
| Origin | on `POST`/`PUT`/`DELETE`: header `Origin` present and exactly `http://127.0.0.1:<port>` | `403`, reason `origin` |
| Suspend | checked before every handler; if detected, all wallets are locked first | — |
| Methods | only those listed below per route | `405` |

Rejection responses carry a fixed plain-text body (`forbidden`, `unauthorized`, `too large`,
`bad request`) and never echo request data.

## Headers on every response

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Connection: close
```

No `Access-Control-*` header is ever sent. JSON responses use
`Content-Type: application/json; charset=utf-8`.

## Pages and assets

| Method + path | Session | Behavior |
|---------------|---------|----------|
| `GET /launch/{token}` | no | Valid unused launch token → create browser session, rotate launch token (rewrite launch file), `303` to `/` with `Set-Cookie: pws_session=<64 hex>; Path=/; HttpOnly; SameSite=Strict`. Otherwise `403` static page "This launch address is no longer valid; open the current one from the launch file." |
| `GET /` | optional | With session: `index.html` with `<meta name="csrf-token" content="<64 hex>">`. Without: static page explaining how to open the launch address. |
| `GET /static/app.js` | no | `text/javascript` |
| `GET /static/app.css` | no | `text/css` |
| `GET /static/icon.svg` | no | `image/svg+xml` (also linked as favicon) |

## JSON API

All `/api/*` routes need session + `X-CSRF-Token`; non-GET also need `Origin`.
`{name}` is a percent-encoded wallet name (decoded value must be a valid name, else `400`).
`{id}` is a 32-hex-char entry id (else `404`).

### Error body

```json
{ "error": "<code>", "message": "<fixed English text>" }
```

| HTTP | `error` code | When |
|------|--------------|------|
| 400 | `invalid_name` | name empty/invalid (FR-015) |
| 400 | `password_too_short` | master password < 12 chars |
| 400 | `password_mismatch` | the two entries differ |
| 400 | `empty_title` / `field_too_large` | vault-core validation |
| 400 | `bad_request` | malformed JSON / unknown field |
| 404 | `wallet_not_found` / `entry_not_found` | — |
| 409 | `wallet_exists` | name already used |
| 423 | `wallet_locked` | operation on a locked wallet (no data returned) |
| 422 | `invalid_password_or_corrupted` | message exactly "invalid password or corrupted wallet" |
| 422 | `malformed_file` / `unsupported_version` / `unsupported_kdf` / `kdf_params_out_of_range` / `wallet_too_large` | format error classes (KDF above the service cap maps to `kdf_params_out_of_range`) |
| 500 | `storage_error` / `internal_error` | save failed (change rolled back) or unexpected |

### `GET /api/state` — background (never resets idle timers)

```json
{
  "settings": { "port": 27471, "auto_lock_minutes": 15, "clipboard_clear_seconds": 30 },
  "wallets": [ { "name": "Personal", "unlocked": true }, { "name": "Work", "unlocked": false } ]
}
```

Wallets sorted by name (byte order). Polled by the UI every 5 s, and every 1 s while a copied value awaits clipboard clearance.

### `POST /api/wallets` — create (and leave unlocked)

Request `{ "name": "Personal", "password": "…", "password_confirm": "…" }` →
`201 { "name": "Personal", "unlocked": true }`. Validation order: name, mismatch, length,
exists. Nothing is written on any validation failure.

### `POST /api/wallets/{name}/unlock` — deliberate

Request `{ "password": "…" }` → `200 { "name": "…", "unlocked": true }`. Already unlocked →
`200` without running the KDF (the password is wiped unused). Attempts on one wallet are
serialized; key derivations are serialized service-wide.

### `POST /api/wallets/{name}/lock` · `POST /api/lock-all`

→ `200 { "locked": ["Personal"] }`. Idempotent.

### `POST /api/wallets/{name}/search` — deliberate

Request `{ "query": "git" }` (empty string → full list). → `200`:

```json
{ "entries": [ { "id": "<32 hex>", "title": "GitHub", "username": "me", "url": "https://github.com" } ] }
```

Never contains passwords or notes (FR-024). Sorted as vault-core `list`/`search`.

### `GET /api/wallets/{name}/entries/{id}` — deliberate

→ `200 { "id", "title", "username", "url", "notes", "created_at", "modified_at" }`
(timestamps: Unix seconds). No password.

### `POST /api/wallets/{name}/entries/{id}/field` — deliberate (reveal / copy)

Request `{ "field": "password" | "username" }` → `200 { "value": "…" }`. The only route that
returns a password, one credential at a time, never cacheable.

### `POST /api/wallets/{name}/entries` — add, deliberate

Request `{ "title", "username", "password", "url", "notes" }` (all strings; missing optional
fields = `""`) → `201 { "id": "<32 hex>" }` after the wallet file has been saved.

### `PUT /api/wallets/{name}/entries/{id}` — update, deliberate

Same body as add, plus optional `"keep_password": true|false` (default `false`); whole-value
replacement → `200 {}` after save. With `keep_password: true` the service keeps the stored
password (merged server-side, so an edit never sends the password to the browser, FR-024);
`keep_password: true` with a non-empty `password` → `400 bad_request`. `keep_password` on
add → `400 bad_request`.

### `DELETE /api/wallets/{name}/entries/{id}` — delete, deliberate

No body (confirmation happens in the UI) → `200 {}` after save.

On any save failure for add/update/delete: `500 storage_error`, the in-memory wallet is
exactly as before the request, the file is unchanged.
