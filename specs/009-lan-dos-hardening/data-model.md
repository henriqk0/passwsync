# Data Model: LAN Denial-of-Service Hardening

All state here is in memory and lost on restart. No file format changes.

## Removed

| Item | Where | Why |
|------|-------|-----|
| `State.max_version: HashMap<DeviceId, (HelloVersion, Duration)>` | `device-link-net/src/lib.rs` | The 24 h memory is finding 1 (R1) |
| `LEGACY_RETRY`, `Node::max_version`, `NetRuntime::max_version` | `device-link-net`, `host-runtime` | Same |

## Code limit (`CodeRateLimiter`, `device-link/src/code.rs`)

| Field | Type | Rule |
|-------|------|------|
| `created` | list of `(created_at, tried)` | entries older than 600 s are dropped |

Constants: `CODES_PER_WINDOW = 5` (untried), `TOTAL_CODES_PER_WINDOW = 20`, `CODE_WINDOW = 600 s`.

- `try_create(now)`: refuse if untried entries >= 5 or all entries >= 20; else add `(now, false)`.
- `mark_tried()`: set `tried` on the newest entry. Idempotent.

## Pairing session (`InitSession`, `device-link-net/src/lib.rs`)

```text
waiting  --Hello (no change)--> waiting
waiting  --malformed key message--> waiting          (machine back to None, code valid)
waiting  --well-formed key message--> exchanging     (code used up, mark_tried)
exchanging --> awaiting_acceptance --> paired
exchanging or awaiting_acceptance --> failed         (code stays used up)
waiting  --expiry, cancel, replacement--> as today
```

`PairingSlot` is acquired at the key message, not at the Hello.

## Peer dial state (`PeerRuntime`, `device-link/src/link.rs`)

| Field | Meaning |
|-------|---------|
| `known_backoff`, `known_next` | backoff of dials to `last_addr` (30 s doubling to 300 s) |
| `known_last_attempt` | lets an announcement wake this path no sooner than `dial_backoff_min` after it |
| `hint_next` | earliest next hint dial: last hint dial + `step_timeout / 2` |
| `next_upgrade` | when to probe a channel below v3 again (6 h); none at v3 |

`State.dialing: HashSet<DeviceId>` splits into `dialing_known` and `dialing_hint`.

## Hint table (`device-link/src/discovery.rs`)

One per paired peer, at most `MAX_HINTS_PER_PEER = 4` entries:

| Field | Meaning |
|-------|---------|
| `addr` | announced `SocketAddrV4`: source IP plus announced port; key is the IP |
| `last_heard` | newest datagram from that source; expires at `nearby_expiry` |
| `last_tried` | for least-recently-tried selection; not tried again before `dial_backoff_min` |

A full table evicts the oldest `last_heard`. An authenticated channel clears the peer's table. Hints
never change `last_addr` or the pin (FR-015). The `nearby` list keeps its behaviour for the UI.

## Duplicate channels

`keep_existing` keeps its smaller-dialer rule. A new wrapper compares versions first: the higher
version wins, and equal versions fall through to `keep_existing`. Both sides compute the same result.

## Bounds summary

| Bound | Value | Requirement |
|-------|-------|-------------|
| Hint addresses per peer | 4 | FR-016 |
| Hint dials per peer | 1 at a time, at most 12 per minute | FR-016 |
| Connections per hint dial | at most 3, sharing one `step_timeout` | FR-016, R9 |
| Dial threads per offline peer | at most 2 | FR-015 |
| Upgrade probes per channel below v3 | 1 per 6 hours | FR-006 |
| Pairing codes per 10 minutes | 5 untried, 20 total | FR-011 |
