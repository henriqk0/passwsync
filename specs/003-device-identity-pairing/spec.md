# Feature Specification: Device Identity and Pairing

**Feature Branch**: `feat/003-device-identity-pairing`

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "FEATURE 003: device-identity-pairing. Per-device keypair, LAN discovery, pairing by short code or QR, mutually authenticated encrypted channel, key pinning, revocation. Expanded: each device running the app gets a per-device long-term keypair (a device identity, NOT a person identity; no accounts); devices running the app discover each other on the local network without any central server; two devices are paired by a short code or QR shown in the browser UI of one device and entered (or scanned) on the other; paired devices talk over a mutually authenticated, end-to-end encrypted channel with the peer's device key pinned after pairing, resistance to man-in-the-middle during pairing, and replay protection; the person lists and revokes paired devices from the UI; behavior on a changed or revoked peer key is defined. This is the first feature that opens network connections, so the earlier 'no network' guarantees are re-scoped precisely (which listeners and sockets, which interfaces, opt-in and off by default). It carries NO wallet data (wallet sync is 004, wallet sharing is 005): only identity, discovery, pairing and the secure channel. Low CPU, RAM and battery use is a requirement because the same code will later run on Android in the background. Global rules: offline except device sync, no accounts, email or login, the wallet master password is the only secret, no central servers, non-interactive."

## Context

Features 001 (vault-core) and 002 (passwsyncd, a per-user service on 127.0.0.1 with a browser
UI) give one person encrypted wallets on one computer, with no network use at all. Features
004 (wallet sync) and 005 (wallet sharing) need devices to find each other and talk securely.
This feature builds only that foundation: **who is this device, which other devices are near,
which of them does this device trust, and a secure pipe to the trusted ones.** No wallet,
credential, wallet name or master password ever travels over the network in this feature.

**Operating model (inherited, binding)**:

- No accounts, no email, no login, no person identity. A **device identity** is a keypair
  that names one installation of the app on one device; it says nothing about who uses it.
- No central server, relay, cloud discovery, NAT traversal or internet service of any kind.
  Devices meet only on the same local network.
- Each wallet's master password remains the only long-lived secret the person knows or types.
  The one-time pairing code is an ephemeral, single-use, 5-minute credential that the person
  types or scans; it is never stored or logged. The device private key is machine secret
  material that the person never sees or types; it is protected by owner-only storage (see
  FR-004) and never leaves the device.
- Network use is **opt-in and off by default**. With networking off, the service behaves
  exactly as in feature 002: it listens only on 127.0.0.1 and opens no other socket.

**Network re-scoping (replaces the 002 "never any network" guarantee only as stated here)**:

- With networking off (default): only the 002 loopback UI listener exists; zero other
  sockets.
- With networking on: exactly one LAN peer listener (connection-oriented, encrypted channel
  only) and one local discovery socket (small datagram announcements on the local subnet),
  both on a configured port pair; outbound connections only to discovered or entered
  addresses in private LAN address ranges, and only to perform pairing or open the secure
  channel. Nothing else: no DNS lookups, no internet destinations, no update checks, no
  telemetry.
- The browser UI listener stays loopback-only with all 002 protections; the UI is never
  reachable from the network.

## Clarifications

### Session 2026-10-23

Non-interactive session: each answer is the recommended option, chosen as the most secure and
then simplest consistent with the constitution and roadmap global rules.

- Q: After the joiner enters a correct code, must the person on the initiating device also approve the new device before it is trusted? → A: Yes. When the code exchange succeeds, A shows B's name and fingerprint and the person must press "Accept" on A before the code expires; "Reject" or no answer before expiry aborts pairing and nothing is pinned on either side. This stops a shoulder-surfed or leaked code from silently adding a device.
- Q: When does a device send discovery announcements on the local network? → A: Only while it has at least one paired device or is showing a valid pairing code. A device with networking on but no pairings and no active code sends nothing (it can still listen to find an initiator), which limits exposure of its device ID and saves battery.
- Q: On which network interfaces do the peer listener and discovery socket operate? → A: On every interface that has an IPv4 private or link-local address by default (with the FR-011 source filter), and the configuration file may restrict them to one named interface; the UI shows which interfaces are in use.
- Q: How do the two devices avoid ending up "half-paired" when the last pairing message is lost? → A: A device pins its peer only after it has received the peer's explicit confirmation of the authenticated transcript (key confirmation) and A's person accepted; the initiator commits first and the joiner commits on receiving the initiator's commit. If the final message is lost, the joiner pins nothing and shows "pairing failed, try again"; if only the joiner's acknowledgement is lost, the initiator keeps the pin and the next channel attempt succeeds normally.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Each device has its own identity (Priority: P1)

When the service starts for the first time, it creates this device's identity on its own,
without asking the person anything. The UI shows this device's name and a short fingerprint
of its identity so the person can recognise it later on another device.

**Why this priority**: Every other capability (discovery, pairing, pinning, the channel)
depends on a stable, unforgeable device identity.

**Independent Test**: Start the service with an empty configuration directory, verify an
identity is created and its fingerprint shown in the UI; restart and verify the same
fingerprint; verify the private part is stored only in an owner-only file and never appears
in the UI, logs or any network message.

**Acceptance Scenarios**:

1. **Given** a first start, **When** the service starts, **Then** it creates a new device
   identity and shows the device name and fingerprint in the UI, without requesting any
   password or input.
2. **Given** an existing identity, **When** the service restarts (including after a computer
   restart), **Then** the same identity and fingerprint are used.
3. **Given** an identity file that is unreadable, corrupted or has permissions wider than
   owner-only, **When** the service starts, **Then** networking stays off, the UI shows that
   the device identity is unusable, and the service never silently creates a new identity
   over the old one.
4. **Given** two installations on two devices, **When** both start, **Then** their
   fingerprints differ.

---

### User Story 2 - Pair two devices with a short code or QR (Priority: P1)

The person has networking enabled on two devices on the same network. On device A they open
the "Pair a device" view, which shows a short one-time pairing code and a QR code. On device
B they choose device A from the list of nearby devices (or type its address) and enter the
code (or scan the QR). Both devices then show each other as paired, with the other's name
and fingerprint.

**Why this priority**: Pairing establishes trust between devices; without it no secure
channel, sync (004) or sharing (005) is possible.

**Independent Test**: With two service instances on one test network, start pairing on A,
enter A's code on B, and verify each lists the other as paired with the correct fingerprint;
repeat with a wrong code, an expired code, and a third device impersonating A, and verify no
pairing is created in any of those cases.

**Acceptance Scenarios**:

1. **Given** networking on for A and B on the same LAN, **When** the person opens "Pair a
   device" on A, **Then** A shows a one-time code and a QR code encoding the code, A's
   fingerprint and A's LAN address, plus a countdown to expiry.
2. **Given** a code shown on A, **When** the person enters it correctly on B for device A,
   **Then** A shows B's name and fingerprint with "Accept" and "Reject"; after the person
   accepts on A, both devices pin each other's identity and list each other as paired with
   name and fingerprint, and the code becomes invalid.
7. **Given** a correct code entered on B, **When** the person rejects on A or does not accept
   before the code expires, **Then** pairing fails on both devices and nothing is pinned.
3. **Given** a code shown on A, **When** a wrong code is entered on B, **Then** pairing fails
   on both devices, the code on A is invalidated, nothing is pinned, and A must generate a
   new code to try again.
4. **Given** a code shown on A, **When** it is not used within its validity period, **Then**
   it expires and cannot be used.
5. **Given** an attacker device on the LAN that intercepts or relays the pairing traffic
   without knowing the code, **When** pairing runs, **Then** pairing fails and the attacker's
   key is never pinned by A or B.
6. **Given** a QR code scanned on B (where B has a camera), **When** pairing runs, **Then** B
   additionally refuses to complete unless the identity proven by A matches the fingerprint
   in the QR code.

---

### User Story 3 - See nearby devices without any server (Priority: P2)

With networking on, the UI lists other devices running the app on the same local network
and, for paired devices, whether each is currently reachable over the secure channel.

**Why this priority**: Discovery makes pairing easy and gives later sync (004) its peers;
pairing by typed address still works without it, so it ranks below pairing.

**Independent Test**: Start three instances on one test LAN, pair two of them and show a
pairing code on a third; verify the paired and code-showing instances appear in each other's
lists within the discovery window with no central server present; stop one paired instance
and verify it is shown as offline or disappears within the stated time; verify an instance
with networking off neither appears nor lists others, and that an instance with networking on
but no pins and no code appears in no list (FR-013a).

**Acceptance Scenarios**:

1. **Given** two devices with networking on in the same subnet, and one of them is showing a
   pairing code or is already paired with the other, **When** both run, **Then** the device
   showing the code (or the paired one) is listed as a nearby device by the other within 60
   seconds. A device with neither a pin nor a code is listed by no one (FR-013a).
2. **Given** a paired device that is reachable, **When** the secure channel is established,
   **Then** the UI shows it as connected; when it stops or leaves the network, it is shown as
   offline within 3 minutes.
3. **Given** a device with networking off, **When** others run discovery, **Then** it sends
   no announcements, does not appear in their lists and lists no one.
5. **Given** a device with networking on but no paired devices and no active pairing code,
   **When** others listen, **Then** it sends no announcements and does not appear in their
   lists, while still listing initiators that are showing a code.
4. **Given** discovery announcements, **When** anyone on the LAN captures them, **Then** they
   reveal only what FR-014 allows (no device name, no wallet information).

---

### User Story 4 - Talk to paired devices only, securely (Priority: P1)

Paired devices automatically open a mutually authenticated, end-to-end encrypted channel
with each other. Unpaired devices, devices with a different key, and replayed or tampered
traffic are refused.

**Why this priority**: Security-First: the channel is what 004 and 005 will trust with
encrypted wallet blocks; it must be correct before any wallet data uses it.

**Independent Test**: Pair A and B; verify a channel is established and a test message
exchanged end to end; then connect with an unpaired device, with a device presenting a
different key under A's name and address, replay captured channel traffic, and tamper with
bytes in transit, verifying each is refused or detected and logged by reason.

**Acceptance Scenarios**:

1. **Given** A and B paired and on the same LAN, **When** both run with networking on,
   **Then** they establish a channel in which each proves possession of its pinned identity
   and all traffic is encrypted and integrity-protected.
2. **Given** an unpaired device, **When** it connects to A's peer listener, **Then** the
   connection is closed during the handshake and nothing beyond the handshake is processed.
3. **Given** a device that presents a key different from the one pinned for the device at the
   same address (the pinned device's last known address), **When** it connects, **Then** it is refused,
   it is treated as an unknown device, and A's UI shows a warning that an unpaired key was
   presented at that address; the pin is never updated automatically.
4. **Given** recorded channel traffic, **When** it is replayed (in the same or a new
   connection), **Then** it is rejected and causes no effect.
5. **Given** a channel, **When** any byte is modified, reordered, dropped or injected in
   transit, **Then** the channel detects it and closes.
6. **Given** a device key later stolen from one device, **When** an attacker has recorded
   earlier channel traffic, **Then** the attacker cannot decrypt that earlier traffic
   (forward secrecy).

---

### User Story 5 - List and revoke paired devices (Priority: P2)

The person sees all paired devices (name, fingerprint, date paired, last seen) and can
revoke any of them, for example after a device is lost or sold.

**Why this priority**: Revocation limits damage from a lost device; it is needed before sync
(004) moves real data, but pairing and the channel come first.

**Independent Test**: Pair A with B and C, revoke B on A, and verify A drops any open channel
with B immediately, refuses B's future connections, still connects with C, and that B shows
A as no longer reachable (refused by peer).

**Acceptance Scenarios**:

1. **Given** paired devices, **When** the person opens the devices view, **Then** each is
   listed with name, fingerprint, pairing date and last-seen time.
2. **Given** a paired device B, **When** the person revokes it on A and confirms, **Then** A
   removes B's pin, closes any open channel with B at once, and refuses every later
   connection from B.
3. **Given** B was revoked by A, **When** B tries to connect, **Then** B's UI shows A as
   "refused by peer"; B keeps its own pin of A until its person revokes A on B.
4. **Given** a revoked device, **When** the person wants it back, **Then** the only way is a
   new pairing with a fresh code; no other action restores trust.

---

### Edge Cases

- Networking enabled but the configured peer or discovery port is in use: networking stays
  off, the UI and log state which port failed, and the loopback UI keeps working.
- No private LAN address available (offline laptop, only public addresses): no peer or
  discovery socket is opened; the UI shows "no local network".
- Network changes (Wi-Fi switch, address change, suspend/resume): sockets are re-evaluated;
  channels are re-established without re-pairing; no traffic goes to non-private addresses.
- Connection attempts or datagrams from non-private (public) source addresses: dropped
  without processing.
- Two devices pairing with each other at the same time from both sides: at most one pairing
  succeeds; the result is a single pin on each side.
- Final pairing message lost: handled by FR-022b (no half-pairing on the joiner; the
  initiator's pin is harmless until the joiner pairs again or the person revokes it).
- Interface with a private address that belongs to a VPN: in use by default; the person can
  restrict networking to one named interface in the configuration file (FR-010a).
- Pairing started on A while A is already in a pairing session: the previous code is
  invalidated; only one pairing code is valid at a time per device.
- Pairing with a device that is already paired (same key): refused with "already paired".
- Pairing with oneself (own fingerprint): refused.
- Many devices on the LAN or a flood of announcements/connection attempts: the nearby list
  and connection handling are bounded (FR-016, FR-030); excess is dropped without growing
  memory, and the loopback UI stays responsive.
- Paired device limit reached: new pairing is refused until a device is revoked.
- Peer goes silent mid-handshake or mid-channel: timeouts close the connection; no resources
  are held indefinitely.
- Clock differences between devices: pairing, channel and replay protection do not depend
  on clocks agreeing across devices.
- Identity file deleted by the person: on next start a new identity is created; former peers
  see an unknown key and must re-pair (they are shown the warning of US4 scenario 3).
- Service stopped during pairing: the code is invalid after restart; nothing half-paired is
  kept.

## Requirements *(mandatory)*

### Functional Requirements

**Device identity**

- **FR-001**: On first start, the service MUST generate a long-term device keypair from a
  cryptographically secure random source, without any user input.
- **FR-002**: The device identity MUST NOT contain or be derived from any person data
  (name, email, account) or hardware identifier; it identifies an installation only.
- **FR-003**: The service MUST derive from the public key a fingerprint shown in the UI in a
  form short enough to compare by eye, and a full device ID used internally for pinning;
  both MUST be computed deterministically from the public key alone.
- **FR-004**: The private key MUST be stored only in the per-user configuration directory in
  a file readable and writable only by the owner, written atomically; it MUST never be sent
  over the network, shown in the UI, logged, or included in any other file.
- **FR-005**: If the identity file exists but is unreadable, corrupted, or has permissions
  wider than owner-only, the service MUST keep networking off and report the problem in the
  UI and log; it MUST NOT overwrite or replace it automatically.
- **FR-006**: Each device MUST have a human-readable device name (non-secret, set in the
  configuration file, defaulting to a generic label such as "passwsync device" followed by
  the first 4 fingerprint characters, never the hostname or user name by default); it is sent
  to a peer only inside an authenticated encrypted pairing or channel exchange.
- **FR-007**: The private key MUST be held in memory only while networking is on and wiped
  when released, consistent with the 002 memory protections.

**Networking switch and scope**

- **FR-008**: Networking MUST be off by default and enabled only through the per-user,
  owner-only configuration file read at service start; the UI MUST show the networking state
  read-only and MUST NOT turn networking on.
- **FR-009**: With networking off, the service MUST open no socket other than the 002
  loopback UI listener.
- **FR-010**: With networking on, the service MUST open exactly one peer listener and one
  discovery socket, on configured ports (defaults chosen by the plan, distinct from the UI
  port, both 1024-65535), and MUST NOT open any other listener.
- **FR-011**: The service MUST accept peer connections and discovery datagrams only from,
  and initiate connections and announcements only to, IPv4 private and link-local addresses
  (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16); everything else MUST be
  dropped without processing. IPv6 is out of scope for this feature.
- **FR-012**: The service MUST NOT perform DNS lookups, contact any internet host, relay,
  discovery server or update service, or use NAT traversal.
- **FR-010a**: By default the peer listener and discovery socket MUST operate on every
  interface that has an IPv4 private or link-local address; the configuration file MAY
  restrict them to one named interface. The UI MUST show the interfaces in use.
- **FR-013**: Discovery MUST work without any central server, using announcements on the
  local subnet sent no more often than once every 30 seconds, plus an immediate announcement
  when networking starts, the network changes, or a pairing code is shown, in each case only
  while FR-013a holds.
- **FR-013a**: A device MUST send announcements only while it has at least one paired
  device or is showing a valid pairing code; otherwise it MUST send none (it may still
  receive announcements so it can find an initiator).

**Discovery**

- **FR-014**: A discovery announcement MUST contain only a protocol version, the device ID,
  and the peer listener port; it MUST NOT contain the device name, any wallet information or
  any secret. Announcements are unauthenticated hints: an announcement never causes trust,
  pinning or display of a peer as "paired".
- **FR-015**: The UI MUST list nearby devices (fingerprint, address, paired or not); entries
  not re-announced within 3 announcement intervals MUST be removed.
- **FR-016**: The nearby-device list MUST be bounded (at most 64 entries); excess
  announcements MUST be dropped, and malformed or oversized datagrams MUST be ignored.

**Pairing**

- **FR-017**: The person MUST be able to start pairing from the UI on one device ("initiator
  A"), which then displays a one-time pairing code and a QR code encoding the code, A's
  device ID and A's LAN address and port. Only one code per device is valid at a time.
- **FR-018**: The pairing code MUST be at least 8 decimal digits generated from a
  cryptographically secure random source, displayed in groups for easy entry, valid for at
  most 5 minutes, and single-use.
- **FR-019**: On the other device ("joiner B") the person MUST be able to choose A from the
  nearby list or enter A's address and port manually, then enter the code; a device with a
  camera MAY scan the QR code instead (desktop scanning is not required in this feature).
- **FR-020**: Pairing MUST use a vetted password-authenticated key exchange keyed by the
  code, so that an active attacker on the network who does not know the code learns nothing
  useful and gets at most one guess per code; the exchange MUST mutually authenticate both
  devices' long-term identities and bind them to the session transcript.
- **FR-021**: Any failed pairing attempt (wrong code, aborted exchange, transcript mismatch,
  timeout) MUST invalidate the code on A; A MUST accept at most one pairing attempt per code
  and at most 5 pairing codes per 10 minutes.
- **FR-022**: When B pairs via the QR code, B MUST refuse to complete unless A's proven
  identity matches the device ID in the QR code.
- **FR-022a**: After the code exchange succeeds, A MUST show B's name and fingerprint and
  require the person to accept on A before the code expires; rejection or expiry aborts
  pairing on both devices with nothing pinned.
- **FR-022b**: Pins MUST be committed only after key confirmation of the authenticated
  transcript: A commits after acceptance and sends its commit; B commits only on receiving
  A's commit. A lost commit leaves B without a pin and shows "pairing failed, try again";
  a lost acknowledgement from B leaves A's pin in place.
- **FR-023**: On success, each device MUST pin the other's full device ID and public key,
  peer name and pairing date, and MUST show the peer's name and fingerprint to the person on
  both sides.
- **FR-024**: Pairing MUST be refused with oneself, with an already paired device, and when
  the paired-device limit (32) is reached.
- **FR-025**: A device MUST accept incoming pairing exchanges only while it is displaying a
  valid pairing code; at all other times pairing requests MUST be refused at once.

**Secure channel**

- **FR-026**: Paired devices that discover each other (or are at a known address) MUST
  establish a channel using a vetted authenticated key-exchange protocol in which both sides
  prove possession of their pinned long-term keys; custom cryptographic protocols are
  prohibited.
- **FR-027**: The channel MUST provide confidentiality, integrity, mutual authentication,
  forward secrecy (fresh ephemeral keys per connection), and replay protection (per-message
  ordering within a connection and fresh session keys per connection, so traffic from one
  connection is never accepted in another); any violation MUST close the connection.
- **FR-028**: A peer whose presented key is not pinned MUST be refused during the handshake;
  if its address matches the last known address of a paired device, the UI MUST show a warning
  that an unpaired key was presented. Names are revealed only inside encrypted exchanges and
  are not used for this check. Pins MUST NOT be changed automatically under any condition;
  only revocation followed by a new pairing replaces a key.
- **FR-029**: At most one channel per paired device MUST be kept; duplicates (both sides
  connecting at once) MUST be resolved deterministically to a single channel.
- **FR-030**: Handshakes, pairing exchanges and idle channels MUST have timeouts (handshake
  and pairing steps at most 10 seconds each); simultaneous incoming connections MUST be
  bounded (at most 16 unauthenticated connections) and message sizes MUST be bounded, with
  excess refused without unbounded buffering.
- **FR-031**: In this feature the channel MUST carry only channel-maintenance messages
  (keepalive, close, and peer name updates); it MUST NOT carry any wallet, credential,
  wallet name or master password. Idle keepalives MUST be sent no more often than once every
  60 seconds.

**Listing and revocation**

- **FR-032**: The UI MUST list paired devices with name, fingerprint, pairing date, last-seen
  time and current status (connected, offline, refused by peer).
- **FR-033**: The person MUST be able to revoke a paired device from the UI with a
  confirmation step; revocation MUST remove its pin, close any open channel with it
  immediately and refuse all its later connections; its pairing attempts are refused unless A
  shows a new code (a new pairing with a fresh code is the only way back).
- **FR-034**: Revocation is local: the revoked device is not notified other than by being
  refused; it MUST show the revoking peer as "refused by peer".
- **FR-035**: Pinned peers MUST be stored in the per-user configuration directory in an
  owner-only file written atomically; a corrupted file MUST keep networking off with a clear
  message instead of being discarded.

**UI and request protection**

- **FR-036**: All new UI views and actions (identity, nearby devices, pairing, paired
  devices, revocation) MUST be served by the existing loopback UI with all 002 protections
  (Host, Origin, CSRF, session, CSP, no external assets); starting pairing and revoking are
  state-changing requests.
- **FR-037**: Pairing and revocation MUST NOT require unlocking any wallet or entering any
  master password.
- **FR-038**: The QR code MUST be generated by the service or embedded UI code without any
  external resource.

**Resources and logging**

- **FR-039**: With networking on and no activity, the service MUST not busy-poll: network
  work is driven by socket readiness and the timers in FR-013 and FR-031 only.
- **FR-040**: The log MUST contain only non-secret events: networking on/off, listener ports,
  pairing started/succeeded/failed by reason, peer connected/disconnected/refused by reason
  (identified by fingerprint), revocations, and dropped traffic counts by reason; it MUST
  NOT contain pairing codes, keys, session keys or message contents.

**Scope exclusions**

- **FR-041**: This feature MUST NOT include wallet sync or transfer, wallet sharing, any
  account, email or login, internet or relay connectivity, IPv6, desktop QR scanning, or
  regeneration of the device identity from the UI.

### Key Entities

- **Device identity**: This installation's long-term keypair; public part yields the device
  ID and fingerprint; private part stays in an owner-only file and memory only.
- **Device ID / fingerprint**: Full identifier derived from the public key (used for pins and
  announcements) and its short, human-comparable form shown in the UI.
- **Device name**: Non-secret human label for a device; sent only inside encrypted exchanges.
- **Nearby device**: Unauthenticated, transient entry from a discovery announcement (device
  ID, address, port, last heard); never trusted by itself.
- **Pairing code**: One-time, short-lived secret shown on the initiator; single attempt;
  never stored on disk or logged.
- **Paired device (pin)**: A trusted peer: device ID, public key, name, pairing date, last
  seen; persisted in an owner-only file; removed only by revocation.
- **Secure channel**: A per-connection, mutually authenticated encrypted session between two
  paired devices, with fresh session keys; in this feature it carries only maintenance
  messages.
- **Networking settings**: On/off (default off), peer port, discovery port, device name,
  optional single interface restriction;
  stored in the owner-only configuration file, read-only from the UI.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person can pair two devices on the same network in under 1 minute from
  opening "Pair a device", without reading documentation.
- **SC-002**: With networking off, a socket inventory of the service shows only the loopback
  UI listener in 100% of tests; with networking on, it shows only the UI listener, one peer
  listener, one discovery socket and channels to paired or pairing devices.
- **SC-003**: 100% of pairing attempts with a wrong, expired or reused code, and 100% of
  simulated man-in-the-middle and impersonation attempts, end with no pin created on either
  device.
- **SC-004**: 100% of connections from unpaired or revoked devices, or with a key different
  from the pinned one, are refused during the handshake; 100% of replayed, tampered or
  reordered channel traffic is rejected.
- **SC-005**: Nearby devices that are paired or showing a code appear within 60 seconds; paired devices that leave are shown
  offline within 3 minutes; a revoked device's open channel is closed within 1 second.
- **SC-006**: Captured network traffic in tests contains zero occurrences of device names in
  clear, wallet names, credential data, master passwords or pairing codes.
- **SC-007**: With networking on, idle with 5 paired devices online, the service adds less
  than 10 MB of memory over its networking-off baseline and averages under 1% of one CPU
  core, with no more than one network wake-up every 30 seconds per peer on average.
- **SC-008**: Under a flood of 10,000 announcements or connection attempts per minute from
  the LAN, memory stays bounded and the loopback UI keeps responding within 1 second.

## Assumptions

- Platform for this feature is the 002 Linux desktop service; the same behavior will be
  reused by the Android app (007), which adds QR scanning with its camera.
- The device private key is protected by owner-only file permissions (the same trust level
  as the 002 configuration and Syncthing's device key), not by a password, because the only
  secret the person manages is each wallet's master password. Anyone who can read the
  person's files can impersonate the device until it is revoked on the peers; wallet
  contents remain protected by the master password.
- The 002 device identifier used for vault-core change tracking stays as is; how it relates
  to the device key is decided by feature 004.
- Discovery announcements reveal a stable device ID to anyone on the same LAN, as in
  Syncthing; this is accepted because no person data or wallet information is included and
  networking is opt-in.
- Both devices are on the same IPv4 subnet (or the person types the address) and the LAN
  allows local broadcast or multicast; routed, IPv6-only, or client-isolated networks need
  the manual address entry or are out of scope.
- Cryptographic protocol and algorithm choices (key type, key exchange, PAKE, transport
  framing) are made in the plan using vetted libraries, following the constitution.
- Port defaults are chosen in the plan; they are configurable in the configuration file.
