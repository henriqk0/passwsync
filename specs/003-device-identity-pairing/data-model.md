# Data Model: Device Identity and Pairing (003)

Types live in `crates/device-link` unless noted. Rationale: [research.md](research.md).

## DeviceKey (secret)

| Field | Type | Rule |
|-------|------|------|
| private | `Zeroizing<[u8; 32]>` | `OsRng`, never leaves the device, wiped when networking is off or on drop |
| public | `[u8; 32]` | `MontgomeryPoint::mul_base_clamped(private)` |

Persisted only in `device-key` (contracts/host-runtime-network.md). Not `Debug`/`Display`.

## DeviceId / Fingerprint

- `DeviceId([u8; 32])` = `SHA-256("passwsync-device-id-v1" || public)`; text form 64
  lowercase hex; `Ord` by bytes (used by the dedupe rule).
- `Fingerprint` = base32 (RFC 4648, uppercase, no padding) of `DeviceId[0..10]`, displayed
  `XXXX-XXXX-XXXX-XXXX`. Display only.

## DeviceName

UTF-8, 1–64 Unicode scalar values, no control characters, no `"`. Default
`passwsync device <first 4 fingerprint chars>`. Non-secret; on the wire only inside Noise
payloads.

## PairingCode (secret)

`Zeroizing<[u8; 8]>` ASCII digits; created_at (monotonic); expires_at = +300 s; state
`Active → Consumed → (Accepted | Failed)`, or `Active → Expired | Cancelled | Replaced`.
Never stored or logged. Rate limiter: ring of the last 5 creation instants; a 6th within
600 s is refused.

## NearbyDevice (untrusted)

| Field | Type |
|-------|------|
| device_id | `DeviceId` |
| addr | `SocketAddrV4` (source IP + announced peer port) |
| last_heard | monotonic instant |

Map ≤ 64 entries (non-paired); entry removed 90 s after `last_heard`; `paired` flag in
views is computed from the registry, never from the announcement.

## PeerPin (trusted)

| Field | Type | Rule |
|-------|------|------|
| public | `[u8; 32]` | the pinned key; never changed (FR-028) |
| device_id | `DeviceId` | derived from `public`, not stored |
| name | `DeviceName` | from pairing; updatable by `NameUpdate` on an authenticated channel |
| paired_at | Unix seconds | wall clock at commit |
| last_seen | Option Unix seconds | updated in memory on traffic; persisted on close/stop |
| last_addr | Option `SocketAddrV4` | latest authenticated or announced address |

`PeerRegistry`: ≤ 32 pins keyed by `DeviceId`; `pin()` refuses self, duplicates and full;
`revoke()` removes. Persisted via the `PeerStore` port after each change (save before the
change is reported success).

## PeerStatus (runtime, per pin)

`Connected` | `Offline` | `RefusedByPeer` (last attempt got `Refused`). Runtime only.

## PairingSession (runtime, at most one per device)

Initiator side (A): `{ code, state: waiting | exchanging | awaiting_acceptance{peer_id, peer_public, peer_name} | paired | failed(reason) }` (same names as the `pairing.state` values in contracts/http-api-network.md).
Joiner side (B): `{ target: SocketAddrV4, expected_id: Option<DeviceId>, state: Connecting | Exchanging | AwaitingAcceptance{peer_id, seconds_left} | Paired{peer} | Failed(reason) }`.

Failure reasons (closed enum): `wrong_code_or_tampered`, `expired`, `rejected`,
`timeout`, `id_mismatch`, `self`, `already_paired`, `limit`, `refused_not_pairing`,
`unreachable`, `cancelled`, `protocol`.

Transitions (initiator): `start` replaces any previous session → `waiting`;
valid `SPAKE_B` → `Exchanging` (code consumed); msg3 ok → `AwaitingAcceptance`;
`accept(device_id)` (must match) → pin + save → `paired` → send `PairCommit`;
`reject`/expiry/any error → `Failed`, nothing pinned.
Joiner: `PairCommit` received → pin + save → send `PairAck` → `Paired`; connection ends
earlier → `Failed`, nothing pinned.

## Channel (runtime)

`{ peer_id, dialer_id, transport: snow::TransportState, stream handle, last_sent, last_received }`;
≤ 1 per peer after dedupe (keep the one whose `dialer_id` is smaller).

## Warning (runtime)

`UnpairedKeyAtAddress { addr, presented_id, claimed_pin: DeviceId }` and
`IdentityUnusable`/`PeersUnusable` details; keep the 8 most recent; cleared by the UI.

## NetworkSettings (passwsyncd config)

| Key | Default | Rule |
|-----|---------|------|
| `network` | `off` | `on`/`off` |
| `peer_port` | 27472 | 1024–65535, distinct from `port` and `discovery_port` |
| `discovery_port` | 27473 | 1024–65535, distinct |
| `device_name` | default above | DeviceName rules |
| `network_interface` | none (all eligible) | 1–15 chars `[A-Za-z0-9._-]` |

## NetworkStatus

`off` | `identity_unusable` | `peers_unusable` | `port_in_use{port}` | `no_local_network` |
`on{interfaces: [ {name, addr, prefix} ]}`.

## Timing (constants, overridable by 007 within spec bounds)

announce 30 s · nearby expiry 90 s · step timeout 10 s · keepalive 60 s · idle close
150 s · code validity 300 s · dial backoff 30 → 300 s · interface re-scan 30 s.

**Amended by 009 (pending 009 implementation)**: the pairing session starts at the key message, not the Hello, and each peer
gets separate dial paths and a hint table. See `specs/009-lan-dos-hardening/data-model.md`.
