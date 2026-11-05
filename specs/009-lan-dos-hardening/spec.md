# Feature Specification: LAN Denial-of-Service Hardening

**Feature Branch**: `feat/009-lan-dos-hardening`

**Created**: 2026-11-05

**Status**: Draft

**Input**: User description: "Feature 009 lan-dos-hardening: harden device networking against denial-of-service by an unpaired host on the same local network. A security review (2026-11-05) with working proof-of-concept attacks against real nodes found three availability issues: (1) a forced protocol downgrade that outlasts the attacker, (2) a pairing code burn by a contact that made no guess, (3) an announcement flood that starves the dial to a paired device. No credential, key or wallet data disclosure was found."

## Context

Specs 003 (device identity and pairing), 004 (wallet sync protocol) and 005 (sharing) assume a
hostile local network but accept some availability risks. A review on 2026-11-05 ran
proof-of-concept attacks against real nodes. The attacker is an **unpaired host on the same LAN**:
it holds no key, no pin and no pairing code, and can send any LAN traffic (discovery datagrams,
TCP connections that it accepts, closes or ignores). **No disclosure of credentials, keys or
wallet data was found. All three findings are availability issues**, but each one silently
switches off a core promise (sync, sharing, pairing) and two outlast the attacker.

- **Finding 1, forced protocol downgrade.** Paired devices negotiate a channel protocol version:
  v3 (sync and sharing), v2 (sync), v1 (neither). When a connection closes before the second
  handshake message, the dialing device lowers the maximum version it will use for that peer,
  remembers this for 24 hours or until restart, and redials. Any LAN host can trigger it by
  announcing a paired device's id with the attacker's own port and closing the connection when
  the victim dials. Measured: both devices were poisoned in about 60 ms with 7 TCP accepts; after
  the attacker left, the real devices connected at v1 with no sync channels (control run without
  attacker: v3 with sync). Consequences: sync and sharing stay off for up to 24 hours after the
  attacker is gone, a changed password stops propagating, and the interface wrongly reports
  "sync unsupported by peer". An already established channel cannot be affected. Spec 004
  research R7 accepted this as "no worse than dropping traffic"; the review shows it is worse,
  because it needs no on-path position and outlasts the attacker.
- **Finding 2, pairing code burn.** While a device shows a pairing code, a single pairing Hello
  from anyone, containing no guess at the code, makes that code permanently unusable; the real
  device that holds the correct code is then refused. Five such rounds (about 200 ms) exhaust the
  limit of 5 codes per 10 minutes and block pairing for 10 minutes. Showing a code broadcasts an
  announcement immediately, so the attacker can time the attack easily. Spec 003 FR-021 currently
  says any failed attempt, including an aborted exchange, invalidates the code.
- **Finding 3, announcement flood.** Discovery announcements are not rate limited, each one
  resets the dial backoff, and each peer gets only one dial at a time. A flood of announcements
  naming a paired device's id with an attacker address keeps that single dial stuck on the
  attacker. Measured: in 3 of 3 runs, two paired but disconnected devices never connected during
  an 8 s flood of about 950 datagrams per second while real announcements were also being sent,
  and connected once the flood stopped. Only disconnected devices are affected.

Fixing Finding 2 has a limit: the one guess per code must be spent before the guess can be checked,
and sending one needs no knowledge of the code. An attacker can therefore still burn a code with one
extra frame; this feature removes the lockout and tells the person, but cannot make a code immune.

This feature changes **availability behaviour only**. It adds no primitive cryptography change,
no new wire message type where avoidable, and keeps every older paired device working. The local
HTTP API keeps its response shapes where possible (`android/verify.sh` requires the
`crates/passwsyncd/tests` tree to match main).

**Verification classes** (as in 008): **[H]** host-verifiable offline, the gate for this
feature; **[CI]** CI-runner-only; **[M]** manual on reference hardware; **[D]** device-only.

## Clarifications

### Specification defaults 2026-11-05

Decisions taken while writing the specification (non-interactive), each the most secure option
that still fixes the availability issue.

- Q: Is the one-guess-per-code property weakened? → A: No. At most one guess per code; a guess
  still uses up the code permanently.
- Q: Who is told that another device tried? → A: The person at the device showing the code, in
  plain words, when a guess that did not lead to pairing used up the code.
- Q: Are 003 FR-021, 004 R7 and the threat model edited by this specification? → A: No. This
  specification only records what changes; the later documentation step amends 003 FR-021, 004 R7
  and `docs/threat-model.md`.

### Session 2026-11-05

- Q: How does the device treat paired devices running an older protocol version, given that an old
  device's only signal is an early close, which an attacker can fake? → A: Per-dial fallback. Each
  dial tries the newest version, then lower ones, and remembers nothing afterwards. Older devices
  keep working; only an on-path attacker can still force a lower version, and only until the next
  periodic retry at the newest version.
- Q: When exactly is the pairing code used up? → A: As soon as a contacting device submits its
  pairing key message and the device showing the code answers it. It cannot wait for a checked
  result: an attacker could read the answer, test one guess offline and abort before any check,
  which would give it unlimited online guesses. A Hello alone, or a contact that stops before the
  key message, does not use up the code.
- Q: How does the limit of 5 codes per 10 minutes change, given that an attacker can submit a key
  message without knowing the code? → A: Two tiers. Codes nobody tried still count against the
  limit of 5, so repeated requests get the same refusal as today. Codes used up by an attempt count
  only against a hard cap of 20 codes per 10 minutes. This needs no change to
  `crates/passwsyncd/tests/api_pairing.rs` or the `android/verify.sh` gate.
- Q: How can announcements stop shortening backoff without slowing a returning device? → A: Two
  separate dial paths. The dial to the last known address has its own state, which an announcement
  may wake (bounded to the normal retry rate), because it only ever reaches an authenticated
  address. Dials to addresses named by announcements are a separate, rate-limited path that can
  never block the first.
- Q: Who sets the exact flood bounds? → A: The plan, within the limits stated in FR-016.

## User Scenarios & Testing *(mandatory)*

The "users" are the person who owns two or more paired devices on a home or office network that
other people also use, and the maintainers who must trust that the network layer degrades only
while an attacker is actually present.

### User Story 1 - An attacker cannot lock sync off for 24 hours (Priority: P1)

A stranger on the same network announces a paired device's id with the stranger's own address and
closes the connection when the victim dials. After the stranger leaves, the person's two paired
devices connect at the full protocol version and sync and sharing work again without waiting and
without a restart. A genuinely older paired device still connects at the highest version both sides
support.

**Why this priority**: It silently disables sync and sharing for a day, stops password changes
from propagating (a security-relevant effect) and shows a misleading message.

**Independent Test**: [H] Two paired test devices plus a hostile peer that announces a paired id
and closes connections before the handshake's second message. After the hostile peer stops, the
paired devices reach a full-version sync channel within the normal reconnect time, with no
restart. Control: same run without the hostile peer gives the same version.

**Acceptance Scenarios**:

1. **Given** two paired devices that support the newest version and an attacker that forces
   many early connection closes, **When** the attacker stops, **Then** the devices connect at the
   newest version and sync and sharing become available without waiting for any timer to expire
   and without a restart.
2. **Given** a paired device that genuinely supports only an older version, **When** the devices
   connect, **Then** they interoperate at the highest version both support, as before this feature.
3. **Given** early connection closes caused by an attacker, **When** the person looks at the
   peer's state, **Then** the interface does not say "sync unsupported by peer"; it shows the peer
   as unreachable or retrying.
4. **Given** an established channel, **When** the attacker acts, **Then** the channel is unaffected
   (unchanged behaviour).
5. **Given** a paired device connected below the newest version, **When** the periodic retry runs,
   **Then** the channel moves to the newest version both devices support.

---

### User Story 2 - An attacker cannot burn the pairing code (Priority: P1)

A person shows a pairing code on one device and types it on the other. A stranger on the network
opens connections and sends pairing Hellos at the moment the code appears. The code stays valid and
the real pairing succeeds. If the stranger goes further and submits a guess, the code is used up as
before, and the person is told plainly that another device tried. The person can immediately show a
new code and is not locked out at five. A stranger who keeps burning every code can still block
pairing while present; the block ends with the attack, within the cap in FR-011.

**Why this priority**: Without this, a few packets block pairing for 10 minutes, and the person
cannot pair a new device at all.

**Independent Test**: [H] Show a code, run a hostile contact that opens, sends a pairing Hello and
aborts, repeat well beyond five rounds, then pair with the correct code: pairing succeeds. A second
test submits one guess: that code is refused afterward, and a new code can be shown. A third test
requests six codes with no contact: the sixth is refused as it is today.

**Acceptance Scenarios**:

1. **Given** a code on display, **When** any number of contacts open, send a Hello and abort
   without a guess, **Then** the code remains valid and the real device pairs with it.
2. **Given** a code on display, **When** a contact submits a guess that does not lead to pairing,
   **Then** the code is used up, a later correct attempt on that code is refused, and the person
   sees a plain notice that another device tried to pair and a new code is needed.
3. **Given** a code, **When** two guesses arrive at once, **Then** at most one is answered.
4. **Given** five codes that were each used up by an attempt, **When** the person requests another
   code, **Then** it is granted, up to the cap of 20 per 10 minutes.
5. **Given** five codes nobody tried, **When** the person requests another code within 10 minutes,
   **Then** it is refused exactly as today.
6. **Given** contacts that stop before the guess, **When** the real device starts its exchange,
   **Then** those contacts do not hold the one exchange at a time that a device allows.

---

### User Story 3 - A discovery flood cannot starve reconnection (Priority: P1)

A stranger floods fake announcements naming a paired device's id with the stranger's address while
the person's two devices are disconnected. During and right after the flood, the real devices still
reach each other at the real or last known address, and the device does no unbounded dialing work.

**Why this priority**: Without this, one cheap datagram flood keeps devices disconnected for as
long as it lasts, and costs the device battery and CPU.

**Independent Test**: [H] Two paired disconnected test devices, a flood of at least 1000
announcements per second naming a paired id with an attacker address, plus real announcements:
the devices connect within the budget in SC-005 in every one of at least 10 runs. A counter shows
dial attempts per peer stay under a fixed bound per minute.

**Acceptance Scenarios**:

1. **Given** a flood of announcements for a paired id with an attacker address, **When** the real
   device is reachable, **Then** the dial to its real or last known address is not starved and the
   devices connect.
2. **Given** the same flood, **When** it continues for minutes, **Then** dial attempts, memory and
   CPU stay within fixed bounds.
3. **Given** an unauthenticated announcement for a paired id, **When** it arrives, **Then** it does
   not reset or shorten the backoff of dials to addresses named by announcements, and can wake the
   dial to the last known address no faster than the normal retry rate.
4. **Given** normal use (no flood), **When** a device returns to the network and announces,
   **Then** the peer reconnects as quickly as before this feature.
5. **Given** a flood from many forged source addresses, **When** the real device is still at its
   last known address, **Then** the devices connect; a device that also moved may be delayed until
   the flood ends (residual risk).

---

### User Story 4 - Maintainers see the residual risk and the out-of-scope list (Priority: P3)

A reviewer can read what is fixed, what remains (an attacker can still burn a code with one guess
it needs no knowledge to send; an on-path attacker can still force a lower version until the next
retry; an attacker can still delay connection while present) and what is explicitly deferred.

**Why this priority**: Honest scoping avoids the false belief that LAN DoS is solved.

**Independent Test**: [H] The out-of-scope list in this specification matches the later threat-model
update.

**Acceptance Scenarios**:

1. **Given** this specification, **When** a reviewer reads Out of Scope, **Then** each deferred item
   is named and none is addressed by a requirement here.

---

### Edge Cases

- A genuinely older paired device: each dial reaches it through the per-dial fallback, at the cost
  of up to two extra connection attempts per dial.
- A paired device that closes connections for reasons other than version: the fallback ends in a
  plain failed dial, and nothing is remembered.
- A paired device that is truly offline: dial attempts follow backoff and do not become a tight
  loop.
- A pairing contact that stops after the Hello or partway through its key message: the code is not
  used up. A complete key message uses it up even if the contact then aborts, because the answer
  already gave it its one guess.
- A malformed key message: refused without using up the code (unchanged). A well-formed one with a
  random value is still a guess, and burns the code.
- A wrong code typed by a legitimate person: the code is used up as before (inherent to one attempt
  per code) and the notice tells them to request a new code.
- Attacker announces a paired id before the real device does, or announces the real address
  alongside false ones: the last known good address stays dialed.
- Announcements with a changed address from a real device that moved: reconnection must still
  occur promptly after authentication proves it is the real device.
- Duplicate or reordered announcements, announcements for unknown ids, and malformed datagrams:
  ignored without changing dial state.
- Device restart during an attack: no persistent state left behind that keeps the reduction.

## Requirements *(mandatory)*

### Functional Requirements

**Protocol version integrity (Finding 1)**

- **FR-001** [H]: An unauthenticated event (a connection closed, reset, refused or timed out before
  the peer is authenticated, or any datagram) MUST NOT lower the protocol version that any later
  dial starts at, in memory or in storage.
- **FR-002** [H]: Every dial to a paired device MUST start at the newest version. A close before the
  handshake's second message MAY move that same dial to the next lower version; when the dial ends
  without an authenticated channel, nothing about the peer's version is kept.
- **FR-003** [H]: A genuinely older paired device MUST still interoperate: devices connect at the
  highest version both support, through the per-dial fallback, for all version pairs v1, v2 and v3
  that interoperate today.
- **FR-004** [H]: The person MUST NOT be shown "sync unsupported by peer" (or equivalent) unless an
  authenticated channel with that peer is currently up below the version needed. Failures before
  authentication MUST be shown as the peer being unreachable or retrying.
- **FR-005** [H]: After an attack that forced early closes ends, paired devices MUST reach the full
  common version without waiting for a timer (including the previous 24 hour memory) and without a
  restart.
- **FR-006** [H]: A channel below the newest version MUST be retried at the newest version
  periodically, at most every 24 hours, so that an on-path attacker's forced reduction and a
  since-upgraded peer both recover. The plan sets the interval within the idle budgets of FR-020.
- **FR-007** [H]: Established channels at the newest version MUST remain unaffected, and the
  handshake bytes of valid devices MUST be unchanged so that older devices keep working.

**Pairing code integrity (Finding 2)**

- **FR-008** [H]: A pairing contact that has not submitted a complete key message (Hello only,
  connection opened and closed, abort before or during the key message, or a malformed key message)
  MUST NOT use up the code on display.
- **FR-009** [H]: The code MUST be used up no later than the moment the device showing it answers a
  key message, including under concurrent contacts, whether or not the contact continues; at most
  one key message is answered per code. This replaces the "aborted exchange invalidates the code"
  part of spec 003 FR-021 and keeps the rest.
- **FR-010** [H]: When a code was used up without leading to pairing, the person at the device
  showing the code MUST be told plainly that another device tried to pair and that a new code is
  needed; the notice MUST NOT reveal the code, the guess or any key material.
- **FR-011** [H]: The code limit has two tiers, over the same sliding 10 minutes: codes nobody tried
  count against a limit of 5, and refuse a further code exactly as today; codes used up by an attempt
  count only against a hard cap of 20 total codes. A person is still needed to create every code.
- **FR-012** [H]: Contacts that stop before a complete key message MUST NOT hold the one exchange a
  device allows at a time, and MUST NOT produce a lasting block: after any number of them the person
  can pair with the correct code immediately. A contact that holds a connection open without sending
  its key message MUST be ended by the existing step timeout.
- **FR-013** [H]: The offline-guess and online-guess resistance of the pairing code MUST be
  unchanged (no change to primitives, code length or alphabet). At most 20 guesses per 10 minutes
  are possible, each with probability 10^-8.

**Announcement flood resistance (Finding 3)**

- **FR-014** [H]: Unauthenticated announcements MUST NOT reset, shorten or bypass the backoff of
  dials to addresses named by announcements. They MAY wake the dial to the last known address, no
  faster than the minimum dial backoff.
- **FR-015** [H]: Unauthenticated announcements MUST NOT displace an in-progress or scheduled dial
  to a paired device's last known address: that dial and dials to announced addresses MUST NOT share
  a slot, and the last known address MUST stay a dial target while announcements name other
  addresses. Only an authenticated channel changes the last known address (unchanged).
- **FR-016** [H]: Announcement handling MUST be bounded under floods of at least 1000 announcements
  per second: the work per announcement is constant, and the number of pending address candidates
  per peer and the dial attempts per peer per minute have fixed upper limits. A shared rate limit on
  announcements MUST NOT be used, because it would also drop the real device's announcements. The
  plan sets the values; a tarpit MUST NOT hold more than one network thread per peer on the path of
  dials to announced addresses.
- **FR-017** [H]: A paired device that returns to the network or moves address MUST still
  reconnect promptly after normal operation resumes, within the budget in SC-006.
- **FR-018** [H]: Malformed, duplicate, reordered or unknown-id announcements MUST be ignored
  without changing dial state.

**Cross-cutting constraints**

- **FR-019** [H]: No primitive cryptography changes. No new wire message type unless it is shown
  unavoidable in the plan; older devices keep working with devices running this feature.
- **FR-020** [H]: Idle resource budgets from 001-004 (wake-ups, CPU, memory) MUST NOT regress,
  and the hardening MUST NOT add timers that run while no peer is being dialed or paired.
- **FR-021** [H]: Local HTTP API response shapes MUST remain unchanged where possible; any
  unavoidable change is additive and recorded. The `crates/passwsyncd/tests` tree stays identical
  to main so the `android/verify.sh` gate still passes.
- **FR-022** [H]: Each finding MUST be reproduced by a failing automated test before the fix, and
  the test MUST remain as a regression test; every test MUST run offline.
- **FR-023** [H]: Logs and notices MUST NOT contain pairing codes, keys, passwords or wallet data.

### Key Entities

- **Paired peer**: another device the person paired with; has an id, a pinned identity, a last
  known good address and a dial state.
- **Channel version**: the protocol version of the channel currently up with a peer. Each dial
  starts at the newest version; nothing about a peer's version outlives its channel.
- **Pairing code**: single-use short code shown on a device; has a state (valid, used up by an
  attempt, accepted) and counts toward one of two rolling limits per 10 minutes.
- **Key message**: the contacting device's first pairing message that depends on the code it holds;
  submitting a complete one is a guess.
- **Announcement**: unauthenticated discovery datagram naming a device id and an address; a hint
  only, never trusted.
- **Dial state**: per-peer state with two separate paths (last known address; announced addresses),
  each with its own backoff, plus bounded candidates and attempt counters.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001** [H]: After an early-close attack that previously poisoned both devices in about 60 ms,
  paired devices reach the full common version in 10 of 10 runs, with sync active, within the
  normal reconnect time and with zero restarts and zero waits for the old 24 hour period.
- **SC-002** [H]: For each interoperating version pair (v1, v2, v3 on either side), devices connect
  at the highest common version, as before this feature (zero regressions).
- **SC-003** [H]: In every attack run the interface never shows "sync unsupported by peer" for a
  peer whose real capability is the newest version.
- **SC-004** [H]: After 20 pairing contacts that stop before a key message, the correct code still
  pairs in 10 of 10 runs; after exactly one key message that does not lead to pairing, the code is
  refused in 10 of 10 runs and the person sees the plain notice. After 5 codes each used up by an
  attempt, a sixth is granted; the 21st code in 10 minutes is refused; a sixth code after 5 untried
  codes is refused with today's response.
- **SC-005** [H]: Under a flood of at least 1000 announcements per second for a paired id with an
  attacker address, two disconnected paired devices connect in at least 10 of 10 runs (previously
  0 of 3), within 30 seconds of both being reachable, while the flood continues. This holds for a
  flood from one source whether or not the device moved, and for a flood from many forged sources
  when the device is still at its last known address.
- **SC-006** [H]: Without any attack, a returning or moved paired device reconnects no slower than
  before this feature, measured against the existing reconnect scenario.
- **SC-007** [H]: During a 5 minute flood, dial attempts per peer stay under a fixed per-minute
  bound and the device's memory use stays flat (no growth beyond a fixed ceiling).
- **SC-008** [H]: Idle resource measurements from 001-004 show no regression and the
  `crates/passwsyncd/tests` tree is byte-identical to main.
- **SC-009** [H]: A search of notices and logs from all attack runs finds no pairing code, key or
  wallet data.

## Assumptions

- The attacker is an unpaired host on the same local network with no key, pin or code; it can
  send arbitrary LAN traffic but cannot read traffic between other hosts (no on-path position is
  assumed or required).
- The roles and protocol versions (v1 neither, v2 sync, v3 sync and share) stay as defined in
  003-005; no new version is introduced by this feature.
- A guess burning a code is inherent to one attempt per code, and sending one needs no knowledge
  of the code, so an attacker who is present can burn every code. This is accepted; this
  specification guarantees the person is told, and that the lockout at 5 codes no longer applies.
- An on-path attacker can still force a lower version for one channel by closing higher-version
  dials and letting a lower one through; this lasts until the FR-006 retry and is accepted.
- While an attacker is present and actively blocking the network path, reconnection may be delayed;
  the guarantee is that the delay ends with the attack, with no lasting state.
- The earlier research decision R7 in spec 004 and FR-021 in spec 003 are superseded for the
  points stated here; the later documentation step amends those files and the threat model.

## Out of Scope

Separate later work, not addressed by any requirement here:

- Weak master password policy.
- Unauthenticated slot exhaustion.
- The pairing oracle.
- TCP subnet checks and virtual interfaces.
- Local port impersonation.
