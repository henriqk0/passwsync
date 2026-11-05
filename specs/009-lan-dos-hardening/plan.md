# Implementation Plan: LAN Denial-of-Service Hardening

**Branch**: `feat/009-lan-dos-hardening` | **Date**: 2026-11-05 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/009-lan-dos-hardening/spec.md`

## Summary

An unpaired LAN host can turn sync off for 24 hours, lock pairing out and keep disconnected
devices apart (working attacks: [evidence/poc_lan.rs.txt](evidence/poc_lan.rs.txt)). This feature
changes three decisions inside `device-link` and `device-link-net`, with no change to the wire
format or any cryptography:

1. **Version fallback lives inside one dial.** Each dial starts at v3 and nothing about the peer's
   version outlives its channel. A channel below v3 is re-tried at v3 every 6 hours.
2. **A pairing exchange starts at the key message, not the Hello.** A Hello takes no state, so only
   a complete key message can use up a code. The code limit gets two tiers (5 untried, 20 total).
3. **Dials to the last known address and to announced addresses are separate paths** with their own
   slot and backoff, and announced addresses live in a small bounded table per peer.

The result does not make a code immune: sending a guess needs no knowledge of the code, so an
attacker who is present can still burn each one. It removes the lockout and tells the person.

## Technical Context

**Language/Version**: Rust (workspace `rust-version` 1.85, `rust-toolchain.toml`); no Kotlin logic
beyond one reason text.

**Primary Dependencies**: none added. `snow` and `spake2` are used exactly as today.

**Storage**: none. All new state is in memory, and no file format changes.

**Testing**: `cargo test` over real loopback nodes (`crates/device-link-net/tests/support`) and
fake clocks (`crates/device-link/tests`). Regression tests are ported from the evidence file.
Gates: `scripts/gate.sh`, `android/verify.sh`, `scripts/check_threat_model.py`.

**Target Platform**: Linux desktop (`passwsyncd`) and Android (`passwsync-ffi`); both share these
crates.

**Project Type**: networking library inside a local service and a mobile app.

**Performance Goals**: SC-005 (connect within 30 s under a flood of at least 1000 datagrams/s);
SC-006 (no slower than today without an attack).

**Constraints**:

- `crates/passwsyncd/tests` stays identical to main (`android/verify.sh`). This pins the 6th-code
  429 (`api_pairing.rs:332`), the old-peer fallback and its log line (`share_old_peer.rs`) and the
  `Timing` struct literal (`common/server.rs`), so **`Timing` gains no field**.
- No new timer: periodic work runs on the existing 30 s discovery tick (FR-020).

**Scale/Scope**: at most 32 pins; about 5 source files changed, no new crate.

## Constitution Check

*Gate: passed before research and re-checked after design.*

| Principle | Status | Evidence |
|-----------|--------|----------|
| I. Security first | Pass | No primitive changes. One guess per code holds (R3 rejects a later consume point because it would allow unlimited guesses). Guess rate is bounded: 20 per 10 minutes, each 10^-8, each needing a person to show a code. |
| II. Simplicity | Pass, see Complexity Tracking | Removes the 24 h memory. Two dial paths and the two-tier limit are justified by FR-015 and FR-011. |
| III. TDD | Pass | Every fix starts from a failing test ported from the evidence file (FR-022). |
| IV. Hexagonal | Pass | Decisions go in `device-link` (`Link`, `CodeRateLimiter`, no I/O) and are tested with fake clocks; `device-link-net` stays the adapter. |
| V. Resource efficiency | Pass | Fixed-size tables, no new timers, no growth under a flood (SC-007). At most two dial threads per peer, only while it is offline. |
| VI. Decentralization | Pass | No new dependency on any service. Reconnection after a partition gets more robust. |

## Project Structure

### Documentation (this feature)

```text
specs/009-lan-dos-hardening/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── peer-behaviour.md
├── evidence/
│   └── poc_lan.rs.txt     # the review's attacks and measurements (not compiled)
├── checklists/requirements.md
└── tasks.md               # /speckit.tasks
```

### Source Code (repository root)

```text
crates/device-link/src/
├── code.rs           # CodeRateLimiter: two tiers
├── link.rs           # two dial paths; on_announce; versioned duplicate rule
├── discovery.rs      # hint table per peer (bounded)
└── pairing.rs        # accessor: did this exchange use up the code?

crates/device-link-net/src/
├── conn.rs           # serve_pairing: Hello takes no state; duplicate rule in register
├── dialer.rs         # per-dial fallback, shared deadline, hint path, upgrade retry
├── discovery.rs      # on_datagram feeds the hint table; tick drives both paths
└── lib.rs            # dialing sets per path; removes max_version; is_legacy from the channel

crates/host-runtime/src/
├── net_runtime.rs    # drops the max_version wrapper
└── share_runtime.rs  # peer_share without max_version

crates/passwsyncd/
├── src/http/api_network.rs   # 429 message text only (code and status unchanged)
└── ui/app.js                 # initiator-side notice text

android/app/src/main/         # initiator-side notice text, if the screen shows reasons

crates/device-link-net/tests/lan_attacks.rs   # new: regression tests from the evidence file
crates/device-link/tests/{code,link}.rs       # new and changed cases
crates/device-link-net/tests/channel_v{2,3}_loopback.rs   # rewritten where they pin the 24 h memory
```

**Structure Decision**: no new module or crate. Each change sits where the decision is made today.

## Design Decisions (summary; details in research.md)

| Id | Decision |
|----|----------|
| R1 | Fallback runs inside one dial, starts at v3 every time, keeps nothing on failure |
| R2 | `is_legacy` and "supported" come from the current channel; lower-version log events fire only after authentication |
| R3 | The code is used up when a well-formed key message is answered (unchanged point), never later |
| R4 | A Hello takes no state and no slot; a failure before use leaves the code valid |
| R5 | Two tiers in `CodeRateLimiter`: 5 untried, 20 total, over the same 10 minutes |
| R6 | Two dial paths per peer, each with its own slot and backoff |
| R7 | Bounded hint table: 4 addresses per peer, one dial at a time, spacing `step_timeout / 2` |
| R8 | No datagram rate limit: constant work per datagram instead |
| R9 | All early waits of one dial share one `step_timeout` |
| R10 | A channel below v3 re-tries v3 every 6 hours on the existing tick; higher version wins duplicates |
| R11 | The initiator-side notice is UI text over the existing `reason` values |

## Plan amendments to the spec

- **FR-016**: "processing of announcements ... per source and overall" has a fixed limit by constant
  work per datagram rather than a rate limit, because a shared rate limit would drop the real
  device's announcements during a flood (R8). The spec text is updated to match.

## Later documentation step (this feature's documentation pass)

These edits describe a **pending** change until the code lands, so nothing claims a fix that does
not exist yet:

- `specs/003-device-identity-pairing/spec.md` FR-021 and `research.md` (code invalidation, limit,
  announcement-triggered dial, backoff); `contracts/peer-protocol.md` where it states them.
- `specs/004-wallet-sync-protocol/research.md` R7 and `contracts/sync-protocol.md`.
- `specs/005-wallet-sharing/research.md` and `contracts/share-protocol.md` (negotiation).
- `docs/threat-model.md`: correct T-B05-5, T-B04-1, T-B04-5; add a downgrade row in B-06; add
  residual-risk rows and audit findings; add a change-log entry. Findings stay Open until implemented.

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| A key message sent later than today, or a consume point moved, reopens online guessing | R3 keeps the point; a test asserts the code is used up even when the contact aborts right after the answer |
| An old peer now costs up to 3 connections per dial | Only on the dial itself, not while connected; accepted (spec edge case) |
| The upgrade retry interrupts a running sync on a v2 peer that became v3 | Happens once at most; a round interrupted by a channel change already recovers (004) |
| Two dial paths double threads per offline peer | At most 2 x 32 x 128 KiB of stack, only while dialing; checked by SC-007 |
| Many forged sources crowd the hint table and delay a device that also moved | Accepted residual risk (spec US3.5); the last known path is unaffected, and the moved device's own dial still arrives |

## Complexity Tracking

| Added complexity | Why needed | Simpler alternative rejected because |
|------------------|------------|--------------------------------------|
| Two dial paths per peer | FR-015: a tarpit must not hold the only dial | One shared slot is exactly finding 3 |
| Hint table per peer | FR-016, SC-005 with a device that moved | A single "latest address" is overwritten by every flood datagram |
| Two-tier code limit | FR-011 with the frozen 6th-code test | A flat 20 needs an exception to the `android/verify.sh` gate (user decision, 2026-11-05) |
| Periodic retry at v3 | FR-006: on-path reduction must end | Retrying only on reconnect leaves a reduced channel up indefinitely |
