# Feature Specification: Wallet Sharing

**Feature Branch**: `feat/005-wallet-sharing`

**Created**: 2026-10-25

**Status**: Draft

**Input**: User description: "Feature 005 \"wallet-sharing\" (short name wallet-sharing): share an existing wallet with another already-paired device on the same network via invite code / QR / manual address. The wallet stays encrypted; the master password is NEVER sent (recipient types it to unlock); consent on both sides, expiry, scoped single-wallet single-use invitations, revocation of an invite; no accounts/email/login; reuse the 003 channel and 004 sync (a shared wallet then syncs)."

## Context

Feature 001 provides encrypted wallet files. Feature 002 provides the per-user service with a
browser UI on 127.0.0.1. Feature 003 gives each device an identity, pairs devices on the same
LAN and keeps a mutually authenticated, key-pinned, end-to-end encrypted channel to every
reachable paired device. Feature 004 keeps a wallet that two paired devices **both already
hold** in sync, exchanging only encrypted wallet files, and explicitly never creates a wallet
on a device that does not hold it.

This feature closes that gap: the person **puts an existing wallet on another of their paired
devices**, deliberately and with consent on both devices, through a short-lived, single-use
invitation. The wallet travels only as its encrypted file over the 003 channel. The master
password is never sent: the person types it on the receiving device to open the wallet there,
and from that moment 004 keeps both copies in sync.

**Operating model (inherited, binding)**:

- No accounts, no email, no login, no person identity, no central server or relay; devices
  meet only on the same local network through the 003 networking switch (off by default).
- The master password of each wallet is the only secret protecting it. It is never sent,
  stored or logged; the derived key lives in service memory only while the wallet is
  unlocked. A shared wallet opens with the same master password on every device.
- Sharing is only between devices already paired in 003; sharing never pairs devices and
  never trusts an unpaired device.
- A one-time invite code, like the 003 pairing code, is an ephemeral, single-use, short-lived
  value the person types or scans; it authorizes one transfer of one wallet to one paired
  device and never protects a wallet.

**Trust model**: A paired device is trusted to be one of the person's own devices (003, 004).
Sharing adds the risk that a wallet is sent to the wrong paired device, sent without the
person's intent, or that an invite code leaks (shoulder-surfing, photo of the QR). The
invitation is therefore bound to one chosen paired device, one wallet and one use, expires
quickly, requires explicit acceptance on both devices, and can be cancelled. A device that
receives the encrypted file but not the master password learns nothing about its contents;
a malicious paired peer can send only garbage or authentic old files, which the recipient
rejects or merges safely as in 004.

## Clarifications

### Session 2026-10-25

Non-interactive session: each answer is the recommended option, chosen as the most secure and
then simplest consistent with the constitution and roadmap global rules.

- Q: Is an invitation bound to one recipient device chosen on the sending device, or usable by any paired device that knows the code? → A: Bound to exactly one paired device chosen when the invitation is created; a redemption from any other device (even a paired one with the correct code) is refused and invalidates the invitation. A leaked code alone can then never deliver the wallet elsewhere.
- Q: What happens to an active invitation when the wallet locks on the sending device (manual lock, auto-lock or restart) before the transfer has started? → A: The invitation is cancelled immediately. Sharing therefore happens only while someone who knows the master password has the wallet open on the sending device, and the file sent is always the current authenticated state; no locked-state sending path exists. A transfer already started completes from the file snapshot taken at its start.
- Q: How long may a received wallet that has not been opened stay on the receiving device? → A: At most 24 hours after receipt; then it is deleted automatically (as on discard) and the person is told. Stale encrypted copies of a wallet do not accumulate on a device that never proved it knows the master password.
- Q: Must the person on the sending device explicitly accept after the recipient enters the correct code, even though the recipient is already fixed? → A: Yes. The sending device shows the recipient's name and fingerprint and the wallet's local name and requires "Accept" before expiry; "Reject" or no answer sends nothing. Entering the code on the receiving device is that side's consent, and opening with the master password is its final acceptance.
- Q: How long is an invitation valid, and must the transfer finish within that time? → A: 5 minutes from creation, the same as the 003 pairing code; redemption, acceptance and the start of the transfer must all happen within it. A transfer started before expiry may finish (it is bounded by the 004 transfer timeouts and size limit); a transfer not started by expiry is never started.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Share a wallet with another paired device (Priority: P1)

The person has wallet "Personal" unlocked on device A and wants it on device B, which is
already paired with A. On A they choose "Share" on the wallet, pick B from the list of
paired devices, and A shows a one-time invite code, a QR code and a countdown. On B they open
"Receive a wallet", pick A from the paired devices (or type A's address), and enter the code
(or scan the QR). A shows "Send wallet 'Personal' to B?" with B's name and fingerprint; the
person presses "Accept" on A. B receives the encrypted wallet, the person gives it a local
name and types the wallet's master password on B, and the wallet opens on B with the same
credentials.

**Why this priority**: This is the whole value of the feature: a wallet reaches a new device
without accounts, servers, file copying or ever sending the master password.

**Independent Test**: With two paired service instances on a test LAN, share a wallet from A
to B as above, verify B shows identical credentials after unlocking with the same master
password, and verify captured traffic contains no plaintext credential, title, wallet name or
master password.

**Acceptance Scenarios**:

1. **Given** wallet W unlocked on A, networking on, and B paired with A, **When** the person
   chooses "Share" on W and selects B, **Then** A shows a one-time invite code, a QR code
   encoding the code, A's device ID, A's LAN address and port, and a countdown to expiry.
2. **Given** an active invitation for W to B, **When** the person on B selects A (from the
   paired list or by typing A's address and port) and enters the correct code, **Then** A shows
   B's name and fingerprint and the local name of W with "Accept" and "Reject".
3. **Given** the person accepts on A before expiry, **When** the transfer completes, **Then** B
   stores the encrypted wallet as a received wallet awaiting its master password, shows it with
   the sender's name, and the invitation becomes unusable.
4. **Given** a received wallet on B, **When** the person enters a local name and the correct
   master password, **Then** the wallet opens on B with the same credentials as on A and is
   listed as a normal wallet from then on.
5. **Given** any sharing session, **When** its traffic is captured, **Then** it contains only
   003 channel-encrypted data whose inner content is the wallet ciphertext and the non-secret
   invitation messages; never the master password, wallet key, wallet name or credential data.

---

### User Story 2 - The shared wallet stays in sync (Priority: P1)

After the wallet is opened once on B, edits on either device reach the other through 004 sync
with no further sharing step.

**Why this priority**: A shared wallet that drifts apart would be worse than not sharing;
reuse of 004 is required by the roadmap.

**Independent Test**: After Story 1, add a credential on A and edit another on B; verify both
devices converge within the 004 time bounds, and that a conflict made while partitioned is
shown on both devices.

**Acceptance Scenarios**:

1. **Given** a wallet shared to B and opened once on B, **When** a credential is changed on A,
   **Then** B receives the change through 004 sync within the 004 bounds (60 seconds while
   unlocked).
2. **Given** a received wallet not yet opened on B, **When** A changes the wallet, **Then** B
   does not sync it yet; after the person opens it on B, it syncs normally, including A's
   later changes.
3. **Given** a shared wallet held on A, B and a third paired device C, **When** any of them
   edits it, **Then** all converge as specified in 004.

---

### User Story 3 - Invitations are scoped, single-use and expire (Priority: P1)

An invite code works only for the wallet it was created for, only on the paired device it was
created for, only once, and only before it expires; a wrong code ends the invitation.

**Why this priority**: Security-First: a leaked or guessed code must never deliver a wallet to
an unintended device, and an old code must never be reusable.

**Independent Test**: Try to redeem an invitation from a different paired device, with a
wrong code, after expiry, a second time after success, after cancellation and after a service
restart; verify every attempt fails, nothing is sent, and the failure reason is shown on both
devices and logged.

**Acceptance Scenarios**:

1. **Given** an invitation for W to B, **When** paired device C enters the correct code,
   **Then** it is refused, nothing is sent, and the invitation is invalidated.
2. **Given** an invitation, **When** a wrong code is entered on B, **Then** the invitation is
   invalidated, nothing is sent, and A must create a new invitation to try again.
3. **Given** an invitation, **When** its transfer has not started within its validity period,
   **Then** it expires and cannot be used, and nothing is sent; a transfer started before
   expiry is allowed to finish within the 004 transfer timeouts.
4. **Given** a completed invitation, **When** its code is entered again, **Then** it is refused.
5. **Given** an unpaired or revoked device, **When** it tries to redeem any invitation,
   **Then** it never gets past the 003 handshake.

---

### User Story 4 - Consent and cancellation on both sides (Priority: P2)

Either person can stop a share at any point before it completes: on A by cancelling the
invitation or rejecting the request, on B by declining or discarding the received wallet.

**Why this priority**: Consent on both devices is a stated requirement; cancellation limits
the damage of a mistaken or leaked invitation.

**Independent Test**: Cancel an invitation on A before and during redemption; reject on A;
decline on B before acceptance; discard a received wallet on B; verify that in each case no
wallet is created on B and no data is left behind.

**Acceptance Scenarios**:

1. **Given** an active invitation, **When** the person cancels it on A, **Then** the code is
   invalid immediately and any redemption or transfer in progress is aborted.
2. **Given** a redemption waiting for acceptance, **When** the person rejects it on A or the
   person on B cancels the wait, **Then** nothing is sent and the invitation is invalidated.
3. **Given** a received wallet not yet opened on B, **When** the person discards it on B,
   **Then** its ciphertext is deleted and no wallet is created.
4. **Given** a completed transfer, **When** the person on A cancels, **Then** A explains that
   the encrypted copy already reached B and that stopping access means revoking B (003) and
   changing the master password (004).

---

### User Story 5 - Received wallet cannot be opened (Priority: P3)

The person on B types a wrong master password, or the received file is corrupted or not a
valid wallet. Nothing is created on B; the person may retry or discard it.

**Why this priority**: Robustness and protection against a malicious or faulty peer.

**Independent Test**: Deliver a valid file and enter a wrong password; deliver a corrupted
file; deliver a file whose wallet B already holds; verify the outcomes below.

**Acceptance Scenarios**:

1. **Given** a received wallet, **When** a wrong password is entered, **Then** the generic
   002 unlock error is shown, the received wallet stays pending, and the 002 unlock rate
   limits apply.
2. **Given** a received file that fails authentication with the correct password or is
   malformed, **Then** nothing is created and the received wallet can only be discarded or
   retried.
3. **Given** a received wallet whose authenticated wallet identifier matches a wallet B
   already holds (with a 004 sync record), **When** it is opened, **Then** no second copy is
   created, the received file is discarded, and B tells the person the wallet is already present
   and syncs automatically. (If the held wallet has never been unlocked since 004, the second
   copy is created and 004 disables the pair as `duplicate_wallet_id`; see FR-020.)

---

### Edge Cases

- Networking off on A or B: "Share" and "Receive a wallet" are unavailable with the reason.
- B is paired but offline or unreachable: the invitation can be created; redemption waits for
  the channel; the invitation still expires on time.
- Wallet W is flagged "possible rollback", "disabled", or is in format version 1 on A:
  sharing is refused with the reason (a version 1 wallet must be saved once in the current
  format first).
- Wallet W locks on A (manual lock, auto-lock or restart) before the transfer has started: the
  invitation is cancelled and B is told "invitation cancelled by sender" (FR-009a).
- W is changed on A after acceptance but before the transfer ends: B receives the state saved
  at the moment the transfer started; later changes reach B through 004 after first unlock.
- A received wallet is not opened on B within 24 hours: it is deleted automatically and the
  person on B is told (FR-022a).
- Service on A or B restarts during an invitation or transfer: invitations are lost (held in
  memory only); partial received data is removed on restart.
- Storage full on B: the transfer is aborted, nothing is created, both sides show the error.
- The paired device B is revoked on A while an invitation exists: the invitation is cancelled.
- Several invitations: creating a new invitation on A cancels any previous active one.
- B already has the maximum number of received wallets awaiting a password: new redemptions
  are refused until one is opened or discarded.
- The received wallet was encrypted under a master password that A has since changed:
  B opens it with the password valid when the file was sent; 004 then handles the password
  change marker as specified there.
- Clock differences: expiry is measured only on A's clock.

## Requirements *(mandatory)*

### Functional Requirements

**Scope and preconditions**

- **FR-001**: The service MUST allow sharing a wallet only with a device paired in 003 (pinned,
  not revoked), only while networking is on, and only over the 003 channel.
- **FR-002**: Creating an invitation MUST require the wallet to be unlocked on the sending
  device at that moment and its state to be eligible for sync (current format version, not
  flagged "possible rollback", not "disabled").
- **FR-003**: Sharing MUST NOT require, create or use any account, email, login, relay or
  internet service, and MUST NOT pair devices.

**Invitations**

- **FR-004**: An invitation MUST be scoped to exactly one wallet and exactly one recipient
  paired device chosen by the person on the sending device, and MUST be usable at most once.
- **FR-005**: The invite code MUST be at least 8 decimal digits generated from a
  cryptographically secure random source and displayed in groups. The invitation MUST be valid
  for 5 minutes from creation: redemption, acceptance and the start of the transfer MUST all
  happen before expiry; a transfer started before expiry MAY finish within the 004 transfer
  timeouts, and a transfer not started by expiry MUST never start.
- **FR-006**: The sending device MUST display the code and a QR code encoding the code, its
  device ID and its LAN address and port, generated without external resources.
- **FR-007**: A device MUST have at most one active invitation at a time; creating a new one
  MUST cancel the previous one. At most 5 invitations MAY be created per 10 minutes.
- **FR-008**: Invitations and codes MUST be held only in service memory; they MUST NOT be
  written to disk or logged, and a service restart MUST invalidate them.
- **FR-009**: The person MUST be able to cancel an active invitation at any time before the
  transfer completes; cancellation MUST take effect immediately and abort any redemption or
  transfer in progress.
- **FR-009a**: An invitation whose transfer has not started MUST be cancelled immediately when
  its wallet locks on the sending device (manual lock, auto-lock or service restart); the
  recipient MUST be told "invitation cancelled by sender". A transfer already started
  completes from the file snapshot taken at its start.
- **FR-010**: An invitation MUST be invalidated by: success, expiry, cancellation, rejection,
  locking of its wallet before the transfer starts, one wrong code, a redemption attempt from
  any device other than its recipient (even with the correct code), revocation of the
  recipient device, or a service restart.

**Redemption and consent**

- **FR-011**: On the receiving device the person MUST be able to select the sender from the
  paired devices (as listed by 003) or enter its address and port manually, then enter the
  code or scan the QR (scanning optional on desktop, as in 003).
- **FR-012**: When the QR code is used, the receiving device MUST refuse to continue unless the
  sender's channel identity matches the device ID in the QR code.
- **FR-013**: The redemption request MUST travel only over the 003 channel; the sender MUST
  verify the code in constant time and accept it only if it matches an active invitation
  whose recipient is the authenticated channel peer.
- **FR-014**: After a valid redemption, the sending device MUST show the recipient's name and
  fingerprint and the wallet's local name, and require the person to press "Accept" before the
  invitation expires; "Reject" or no answer before expiry MUST abort with nothing sent.
- **FR-015**: Entering the code on the receiving device is the recipient's consent to receive;
  the person on the receiving device MUST be able to cancel while waiting, and the received
  wallet MUST NOT become a wallet on that device until the person there opens it with its
  master password (FR-019).

**Transfer**

- **FR-016**: The transfer MUST consist only of the sending device's current stored encrypted
  wallet file (as saved by vault-core) and non-secret invitation messages. The master password,
  wallet key, wallet name, wallet identifier in plaintext and any credential data MUST NEVER
  be sent, even inside the channel.
- **FR-017**: The transfer MUST reuse the 004 transfer rules: bounded chunks, the 64 MiB
  wallet size limit enforced as soon as it is exceeded, bounded memory per transfer, and the
  service-wide transfer concurrency limit.
- **FR-018**: The receiving device MUST store the received file only as ciphertext,
  atomically, in an owner-only location in the per-user data area, as a "received wallet"
  recording the sender and receipt time; a partially received file MUST never be used and MUST
  be removed on abort or restart. At most 8 received wallets MAY await opening at once.

**Opening and sync**

- **FR-019**: A received wallet MUST become a held wallet only after the person on the
  receiving device enters a local name and the wallet's master password and the file
  authenticates (002 unlock rules, rate limits and generic error apply). Only then MUST the
  wallet file be placed among the device's wallets and its 004 sync record be created from
  the authenticated state.
- **FR-020**: If the authenticated wallet identifier of a received wallet matches a wallet the
  device already holds, the received file MUST be discarded without creating a second wallet,
  and the person MUST be told that the wallet is already present. Detection is possible for every
  wallet that has a 004 sync record on the device (a wallet that has been unlocked since 004 was
  introduced). A wallet that has never been unlocked since then has no readable identifier before
  its password is typed; in that residual case the second copy is created and 004 marks the pair
  `disabled (duplicate_wallet_id)` on its first unlock, with no data loss and no sync between the
  two copies (documented in research R10).
- **FR-021**: Once opened, a shared wallet MUST be synchronized by 004 exactly like any wallet
  both devices hold, with no further sharing step; a received wallet not yet opened MUST NOT
  take part in sync.
- **FR-022**: The person MUST be able to discard a received wallet that has not been opened;
  discarding MUST delete its ciphertext and leave no wallet behind.
- **FR-022a**: A received wallet not opened within 24 hours of receipt MUST be deleted
  automatically as on discard, checked at service start and by the existing 15-second service
  timer (no per-wallet polling and no new timer or thread), and the person MUST be told in the UI
  and log.
- **FR-023**: Received wallets from a device revoked in 003 MUST be deleted at revocation.

**Protocol, UI and logging**

- **FR-024**: Sharing messages MUST be an additive, versioned extension of the 003/004 peer
  protocol, negotiated so a device without sharing support keeps 003/004 behavior and the
  person sees "this device does not support sharing".
- **FR-025**: All sharing messages MUST have bounded size and timeouts, and MUST be bound to
  their channel session so they have no effect in another session (replay protection).
- **FR-026**: The UI MUST provide: "Share" per unlocked wallet with recipient choice, the
  invitation view (code, QR, countdown, cancel), the acceptance prompt, "Receive a wallet"
  (sender choice, manual address, code entry), progress and outcome on both devices, and the
  list of received wallets with "Open" and "Discard".
- **FR-027**: All new UI views and actions MUST use the 002 protections (session, CSRF,
  Host/Origin, CSP, no external assets, keyboard operable); creating, cancelling, accepting,
  rejecting, redeeming, opening and discarding are state-changing requests.
- **FR-028**: The log MUST contain only non-secret sharing events (invitation created,
  cancelled, expired, redeemed, accepted, rejected, refused by reason, transfer completed or
  aborted with byte count, received wallet opened or discarded), identifying peers by
  fingerprint; it MUST NOT contain codes, wallet names, keys, passwords or contents.

**Scope exclusions**

- **FR-029**: This feature MUST NOT include sharing with unpaired devices, sharing over the
  internet or a relay, person-to-person sharing with different passwords, per-credential
  sharing, read-only or permission levels, remote removal ("unshare") of a copy already
  delivered, or sending the master password in any form.

### Key Entities

- **Invitation**: in-memory, short-lived authorization on the sending device: wallet, recipient
  device ID, code, creation time, expiry, state (active, awaiting acceptance, transferring,
  completed, cancelled, expired, rejected, refused, failed).
- **Invite code**: one-time numeric secret shown on the sending device (and in the QR); never
  stored or logged; one attempt.
- **Received wallet**: encrypted wallet file received on the recipient device, with sender and
  receipt time, awaiting the master password; not a held wallet and not synced until opened;
  deleted automatically 24 hours after receipt if not opened.
- **Shared wallet**: a wallet held on two or more paired devices, kept consistent by 004.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person can share a wallet to an already-paired device and open it there in
  under 2 minutes from pressing "Share", without documentation.
- **SC-002**: Captured traffic of sharing sessions in tests contains zero occurrences of the
  master password, wallet name, credential fields or invite code in clear.
- **SC-003**: 100% of redemption attempts with a wrong, expired, cancelled, reused or
  restarted invitation, or from a non-recipient, unpaired or revoked device, result in no data
  sent and no wallet created.
- **SC-004**: 100% of shares that are rejected, cancelled, interrupted or discarded leave no
  wallet and no partial data on the receiving device.
- **SC-005**: After first opening on the receiving device, a change on either device reaches
  the other within the 004 bound (60 seconds while unlocked) in 95% of trials.
- **SC-006**: Sharing a wallet of 10,000 credentials completes its transfer in under 10
  seconds over a LAN on the reference laptop, with additional memory within the 004 per
  transfer bound.
- **SC-007**: With no active invitation, the feature adds zero network traffic and no
  background activity beyond 003/004.

## Assumptions

- Features 003 and 004 are in place: pins, channel, revocation, the networking switch, 004
  transfer limits, sync records, and the rewrite of version 1 wallets to the current format.
- The recipient device belongs to the same person, who knows the wallet's master password;
  sharing between different people with separate passwords is out of scope.
- The invite code complements the authenticated channel (which already proves the recipient's
  device identity); it proves the person's intent at both devices and selects the invitation.
- Wallet names are local; the recipient chooses its own name (default "Shared wallet" plus
  the sender's short fingerprint), consistent with 004 never sending names.
- Desktop QR scanning is not required; the Android app (007) adds camera scanning.
- Stopping a device's access to an already delivered wallet is done with existing tools:
  revoke the device (003) and change the master password (004).
