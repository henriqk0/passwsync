# Research: LAN Denial-of-Service Hardening

The attacker throughout is an unpaired LAN host. Measurements come from
[evidence/poc_lan.rs.txt](evidence/poc_lan.rs.txt), run over loopback with the fast test timing.

## R1. Version fallback inside one dial

- **Decision**: `dial_negotiated` starts at v3 on every dial. A close before Noise message 2 moves
  that dial to the next lower version. The `max_version` map, `LEGACY_RETRY` and `Node::max_version`
  are removed.
- **Rationale**: an old device's only signal is rejecting the plaintext Hello, which an attacker
  can imitate, so an early close can never be evidence about the peer. Without memory, closing a
  dial to an attacker's own address has no effect on the next dial. The attacker cannot complete the
  handshake with the pinned key, so its dial ends with no channel. Replaces 004 R7's "no worse than
  dropping traffic", which assumed an on-path attacker and overlooked that the effect outlasts it.
- **Alternatives**: authenticated version statement (no v1 or v2 peer can send one, and it needs a
  new message); v3 only (user decision against, 2026-11-05: it breaks older builds, and a future v4
  needs negotiation again); fall back only when dialing the last known address (still poisons state
  for an on-path attacker, and keeps the memory).
- **Residual**: an on-path attacker can close v3 and v2 and let v1 through, producing an
  authenticated v1 channel. Bounded by R10.

## R2. Where the "unsupported" status comes from

- **Decision**: `Node::is_legacy(peer)` becomes "a channel is up with this peer at v1". `PeerLegacy`
  and `PeerNoShare` are emitted once an authenticated channel registers below the version, not when
  a Hello is refused. `peer_share` reads the channel version, then its existing `seen` map (fed only
  by authenticated channels), then answers `unknown`.
- **Rationale**: FR-004. `share_old_peer.rs` still passes: its peer closes v3, authenticates at v2,
  and the log line `share peer unsupported` follows the channel.
- **Consequence**: an old peer that is offline shows `supported` for sync (`sync` is two-valued in
  the frozen API). The status is about the current channel and corrects itself on connect.

## R3. When the code is used up

- **Decision**: unchanged point. `on_spake_b` calls `code.consume` before answering, so a well-formed
  key message (`SPAKE_B`) uses up the code whatever the contact does next.
- **Rationale**: the answer leads to a Noise message 2 that depends on the code, which lets the
  contact test its one guess offline. Waiting for a "checked" result at message 3 would let an
  attacker test a guess and abort, giving unlimited online guesses. This corrects the first draft
  of the spec.
- **Consequence**: anyone can burn a code with 33 well-formed bytes, needing no knowledge of it.
  That is inherent to one guess per code, and the reason R5 and R11 exist.
- **Alternatives**: several guesses per code (raises the attacker's odds and still burns); a longer
  code (FR-013, and the attacker burns it equally).

## R4. A Hello takes no state

- **Decision**: `serve_pairing` validates the Hello and reads the next frame within the step timeout
  holding no lock, no `machine` and no `PairingSlot`. Only then does it check for an active code,
  acquire the slot and feed the frame to a new `PairingInitiator`. If the exchange ends without using
  up the code (`on_spake_b` refused a malformed frame), `session.machine` returns to `None`.
- **Rationale**: FR-008, FR-012. Today `machine` is set at the Hello and never cleared, which is the
  whole of finding 2's one-packet form. Holding no slot also stops idle contacts refusing the real
  device. They still occupy one of the 16 unauthenticated connections until the step timeout, which
  is the separately deferred slot exhaustion finding.
- **Consequence**: the `exchanging` state starts at the key message, and an unused code keeps showing
  `waiting`. `PairingInitiator` itself is unchanged apart from a read accessor for its `consumed`
  flag, so its fuzz targets and machine tests still apply.

## R5. Two-tier code limit

- **Decision**: `CodeRateLimiter` keeps `(created_at, tried)` per code over the sliding 600 s. A new
  code is refused if untried codes reach 5 or all codes reach 20. The adapter calls `mark_tried` when
  an exchange uses up the current code. `start_pairing` keeps returning `TooManyCodes`, so the HTTP
  status and error code are the same. The message text changes because "at most 5" is no longer the
  whole rule.
- **Rationale**: user decisions, 2026-11-05. The frozen test (5 starts, then 429) still passes, and
  five burned codes no longer lock anyone out. Guess rate stays bounded: 20 per 10 minutes at 10^-8
  each, and every code needs a person.
- **Alternatives**: flat 20 (needs a gate exception); burned codes uncounted (no fixed bound on
  guesses); keep 5 (the lockout survives with one extra frame).

## R6. Two dial paths

- **Decision**: per peer, `known` dials the pin's `last_addr` and `hint` dials announced addresses.
  Each has its own `dialing` entry and backoff in `Link`. A failure on one never delays the other.
  An announcement may wake `known` no sooner than `dial_backoff_min` after its last attempt, because
  that path only ever reaches an address proven by authentication. `Node::dial_now` keeps using the
  `known` entry.
- **Rationale**: FR-014, FR-015, SC-006. In finding 3 the flood wins the only slot. Letting an
  announcement wake `known` also keeps today's fast reconnect: the existing test
  `an_announcement_resets_the_backoff` changes to a bounded form.
- **Alternatives**: announcements never wake anything (a device returning after a long absence waits
  up to 300 s, failing SC-006).

## R7. Hint table

- **Decision**: one table per paired peer, at most **4** addresses, keyed by source IP, expiring at
  `nearby_expiry`. The newest datagram from a source updates its port; a full table evicts the oldest
  heard. One hint dial runs at a time per peer, choosing the least recently tried address, each
  address retried no sooner than `dial_backoff_min`, with dials spaced at least `step_timeout / 2`
  apart (5 s, so at most 12 per minute per peer). The table clears when a channel authenticates.
- **Rationale**: FR-016, SC-005. A single-source flood takes one entry, so the real address is tried
  next: within one step timeout plus the spacing, about 15 s, inside the 30 s budget. Values derive
  from `Timing` because the struct cannot gain a field (`crates/passwsyncd/tests/common/server.rs`).
- **Residual**: forged sources can crowd the table. A device still at its last known address is
  unaffected (R6); one that also moved may wait until the flood ends, though its own outgoing dial
  to us still connects.

## R8. No datagram rate limit

- **Decision**: no token bucket. One thread handles one datagram at a time with constant work and
  fixed tables; the kernel socket buffer drops the excess.
- **Rationale**: a shared bucket would drop the real device's single announcement per 30 s during a
  flood, recreating finding 3. A per-source bucket needs a table that forged sources can fill.
  Simplicity principle: nothing here needs it, and SC-007 measures the effect.
- **Amendment**: spec FR-016 is reworded to match.

## R9. One deadline per dial

- **Decision**: all waits before Noise message 2 in one dial share one `step_timeout`, across
  fallback versions.
- **Rationale**: otherwise a tarpit that closes just before each timeout holds a dial for 30 s, past
  the SC-005 budget. Real old peers close immediately, so they are unaffected.

## R10. Retry at v3

- **Decision**: a channel below v3 gets a probe every **6 hours**, driven by the existing 30 s tick:
  a dial to `last_addr` starting at v3 that stops at the current channel's version. If it
  authenticates higher, the higher channel replaces the old one. `register` applies: higher version
  wins, then today's smaller-dialer rule. Both sides compute the same answer.
- **Rationale**: FR-006. Today a reduced channel stays reduced until it drops. 6 hours is well inside
  the 24 h bound, costs an old peer one rejected Hello per interval, and adds nothing for v3 channels,
  so B-13 (idle traffic in one simulated hour) is unchanged.
- **Alternatives**: close and redial (interrupts sync even when the peer is really old); 1 hour
  (faster recovery, more wake-ups on Android for no real benefit).

## R11. The notice

- **Decision**: the initiator's `pairing.reason` values stay. After R4, an initiator failure with
  `wrong_code_or_tampered`, `timeout` or `protocol` always means an attempt used up the code, so the
  UI shows "Another device tried to pair. Show a new code." for those on the showing side. The joining
  side's text does not change.
- **Rationale**: FR-010, FR-021. No API shape changes, and `FAIL_REASONS` already separates reason
  codes from text. The notice holds no code, guess or key material (FR-023).
- **To confirm at implementation**: how the Android pairing screen presents initiator reasons. The
  Kotlin text search found no reason mapping in `screens/Pairing.kt`, so it may need a new string.
