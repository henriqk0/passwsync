# Feature Specification: Wallet Sync Protocol

**Feature Branch**: `feat/004-wallet-sync-protocol`

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "FEATURE 004: wallet-sync-protocol. Version/block exchange between already-paired devices (feature 003) using the per-entry version vectors and tombstones from 001, eventual consistency, conflict handling that preserves both versions, rollback and replay protection, low-resource scheduling. Expanded: between devices already paired in 003, synchronize only the wallets that BOTH devices already hold (same wallet id); making a wallet available to a new device is feature 005, not this one. Sync runs over the 003 mutually authenticated, pinned, encrypted channel. Eventual consistency across any number of paired devices and network partitions. The exchanged data is only encrypted wallet bytes (or encrypted blocks), so a peer or the network never sees plaintext and sync works without the master password ever being sent. Reconciliation uses the 001 per-entry version vectors and tombstones: equal/newer/older/concurrent; concurrent edits are NEVER silently overwritten (both versions are kept and the conflict is surfaced in the UI for the person to resolve). Merging needs the wallet key, so define precisely what happens when a wallet is locked on one or both sides (exchange and stage ciphertext, merge on unlock). Rollback and replay protection: an attacker or a stale peer must not be able to make a device accept an older wallet state without it being detected and surfaced. Atomic, crash-safe application of received state. Low-resource scheduling: sync only on change or after a long interval, backoff, no polling storms, bounded memory and bandwidth, battery-friendly for later Android background use. Behavior with many devices and network partitions. UI additions: sync status per wallet and per peer, conflict list and resolution, manual 'sync now'. Additive, versioned changes to the 001 file format as needed. Global rules: offline except device sync, no accounts/email/login, the wallet master password is the only secret that protects a wallet and is never sent, no central servers, non-interactive."

## Context

Feature 001 provides encrypted wallet files whose credentials carry per-entry version
vectors and tombstones. Feature 002 provides the per-user service (passwsyncd) with a browser
UI on 127.0.0.1. Feature 003 gives each device an identity, lets the person pair devices on
the same LAN, and keeps a mutually authenticated, key-pinned, end-to-end encrypted channel
open to every reachable paired device; in 003 that channel carries no wallet data.

This feature makes the **same wallet, held on several paired devices, converge to the same
contents** without a server and without ever sending the master password or any plaintext.
It does not put a wallet on a device that does not already hold it (that is feature 005,
wallet sharing). In this feature, "holding the same wallet" means both devices have a wallet
file with the same wallet identifier, for example because the person copied the encrypted
file manually; this is how tests and early users obtain it until 005 exists.

**Operating model (inherited, binding)**:

- No accounts, no email, no login, no person identity, no central server or relay.
- The master password of each wallet is the only secret protecting it. It is never sent,
  stored, or logged; the derived key lives in service memory only while the wallet is
  unlocked (001 FR-005a, 002).
- Network use only through the 003 networking switch (off by default) and only over the 003
  channel to pinned peers. With networking off, nothing in this feature uses the network.
- Peers exchange only encrypted wallet bytes and the minimum non-secret metadata needed to
  decide whether to exchange them (see FR-010). A peer, even a paired one, and anyone on the
  network never see a credential, title, wallet name, or the master password.

**Trust model**: A paired peer is trusted to be one of the person's own devices, but it may
be stale (offline for a long time, restored from a backup), compromised without the wallet
password, or replaying old but authentic data. A peer that does not know a wallet's master
password cannot forge or alter that wallet's contents (authenticated encryption from 001);
it can only offer authentic old copies, garbage, or nothing. Merging is therefore safe
against such a peer as long as old copies are detected (rollback protection) and garbage is
rejected without damage. A device on which the attacker can write arbitrary files as the
person's OS user is out of scope (as in 002 and 003).

## Clarifications

### Session 2026-10-23

Non-interactive session: each answer is the recommended option, chosen as the most secure and
then simplest consistent with the constitution and roadmap global rules.

- Q: Which device may decrypt and merge, and what happens when the wallet is locked on one or both sides? → A: Only a device with the wallet unlocked merges. A device whose wallet is locked still answers summaries from its stored file, sends its own stored encrypted file when the peer lacks changes, and stores received copies that contain changes it lacks as pending ciphertext (at most one per peer); it never modifies or replaces its wallet file while locked and never forwards pending copies. Pending copies are merged automatically right after the next successful unlock. With the wallet locked on both sides, both exchange and stage copies, and each merges on its own next unlock.
- Q: How are older wallet states detected and surfaced (rollback)? → A: Each device persists, per wallet, a high-water mark (the state vector of the newest authenticated state it has saved) and, per peer, the newest state vector that peer has sent in an authenticated copy. A local file whose state vector is not greater than or equal to the high-water mark is flagged "possible rollback": it is not offered to peers, it still receives and merges copies, and the flag clears automatically when a merge brings it back to at least the mark; otherwise the person may explicitly "accept this older state" after unlocking (logged, resets the mark). A peer summary or copy older than that peer's recorded mark is refused and shown as "older state offered". Merge never moves an entry backwards.
- Q: What happens when copies of a wallet are encrypted under different master passwords because the password was changed on one device? → A: The wallet carries an authenticated password-change marker compared like a version vector. At unlock, each pending copy is opened with the entered password (deriving a key for a copy with a different salt before the password is wiped). A copy that still cannot be opened stays pending with the warning "cannot open: different master password or corrupted", and the person may enter that copy's password to merge it or discard it. The merged wallet keeps the password of the copy with the newest password change; concurrent password changes are shown as a conflict and the person chooses which password to keep (by typing it).
- Q: Does sync activity reset the auto-lock timer or keep a wallet unlocked? → A: No. Sync rounds, transfers and merges are background activity: they never reset the 002 idle timer, never unlock a wallet, and a merge in progress at auto-lock is abandoned without saving (the pending copy stays pending).
- Q: Must the person enable sync per wallet, or does every wallet held by both devices sync automatically? → A: Automatic. Turning networking on (003, off by default) and pairing are the opt-in; every wallet both devices hold syncs, with no per-wallet toggle.
- Q: Where may the wallet identifier and state vector that a locked device needs be stored, given they are then readable without the password? → A: In the wallet file's header, unencrypted but authenticated (bound to the ciphertext), and nowhere else. They are non-secret (random identifier, opaque device identifiers, counters); a separate index could drift from the file and would weaken the rollback check, which must inspect the file itself. Header values are treated as untrusted until the file is authenticated, and a copy whose authenticated wallet identifier differs from the expected one is rejected.
  **Superseded by plan amendment 2026-10-24 (research R2)**: a plaintext state vector in the
  file would reveal device count, edit activity and cross-wallet device linkage to anyone who
  sees a backup or shared copy, and its values are unauthenticated while locked anyway. The
  wallet identifier and state vector are therefore stored only inside the encrypted payload;
  a locked device uses its own owner-only sync record, bound to the exact wallet file by a
  digest, so any external change to the file is detected.

### Plan amendment 2026-10-24

Recorded by `/speckit-plan` (see plan.md Complexity Tracking, research R2, R5, R9, R10):
FR-010 (summary carries a session-bound state digest, full state only when states differ),
FR-012 (no plaintext metadata; digest-bound sync record), FR-013 (equal vector with different
content is a conflict), FR-021 (rollback check via record digest and authenticated state at
unlock), FR-030 (v2 header unchanged apart from the version).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Edits on one device appear on the other (Priority: P1)

The person holds the same wallet on two paired devices with networking on. They add, edit,
or delete a credential on device A. Within 60 seconds, the change is present on device B,
without typing anything on B except the wallet's master password when B's wallet is
unlocked.

**Why this priority**: This is the core value of the feature; everything else protects or
improves it.

**Independent Test**: Pair two service instances on a test LAN, place copies of the same
wallet on both, unlock it on both, add/edit/delete credentials on A, and verify B shows the
same credentials (identical fields, version vectors, and tombstones) within the stated time;
capture all traffic and verify no plaintext credential, title, wallet name, or password is
present.

**Acceptance Scenarios**:

1. **Given** the same wallet unlocked on paired devices A and B with a connected channel,
   **When** the person adds a credential on A, **Then** it appears on B within 60 seconds
   with identical fields and metadata.
2. **Given** the same setup, **When** the person deletes a credential on A, **Then** it
   disappears from B within 60 seconds and B keeps the tombstone.
3. **Given** the same setup, **When** a credential is edited on A only, **Then** B takes A's
   version (A's version is newer) and no conflict is reported.
4. **Given** A and B where B is offline while A changes, **When** B comes back on the
   network, **Then** B receives A's changes within 60 seconds of the channel being
   re-established, and A receives any changes B made meanwhile.
5. **Given** any sync session, **When** its traffic is captured, **Then** it contains only
   channel-encrypted data whose inner content is wallet ciphertext and the non-secret
   metadata allowed by FR-010.
6. **Given** a wallet held by A only, **When** A and B sync, **Then** B learns nothing that
   identifies that wallet, and the wallet is never created on B.

---

### User Story 2 - Concurrent edits are never lost (Priority: P1)

The person edits the same credential on A and on B while the devices cannot reach each
other. When they reconnect, both versions are kept, the credential is marked as conflicted
on both devices, and the person chooses how to resolve it in the UI.

**Why this priority**: Constitution Principle VI forbids silently overwriting conflicting
versions; a password manager that loses a newly set password locks the person out.

**Independent Test**: With the channel down, edit one credential differently on A and on B
(and, separately, edit on A while deleting on B), reconnect, and verify that both devices
show the same conflict with both versions, that no version is lost after restarts, and that
resolving on one device clears the conflict on both.

**Acceptance Scenarios**:

1. **Given** credential X edited on A and on B while partitioned, **When** they sync,
   **Then** both devices show X as conflicted with both versions available, and both
   devices show the same version as the current one (deterministic choice).
2. **Given** credential X edited on A and deleted on B while partitioned, **When** they
   sync, **Then** X stays visible (live) and is marked as conflicted with "deleted on B" as
   the other version; it is never silently deleted.
3. **Given** a conflicted credential, **When** the person opens the conflict list, **Then**
   it shows every conflicted credential of the unlocked wallet with, for each version, the
   device name (if known), modification time and fields (passwords hidden until revealed).
4. **Given** a conflicted credential, **When** the person chooses "keep this version",
   "keep the other version", or "keep both" (the other version becomes a separate new
   credential), **Then** the conflict is cleared and the resolution reaches the other
   devices as a normal newer change, clearing the conflict there too.
5. **Given** a conflict resolved on A and a different further edit made on B to the same
   credential before they sync, **When** they sync, **Then** a new conflict is shown rather
   than either result being lost.

---

### User Story 3 - Sync works while a wallet is locked (Priority: P1)

The wallet is unlocked on A but locked on B (B was restarted and the person has not typed
the master password there yet). The devices still exchange encrypted copies; B merges what
it received as soon as the person unlocks the wallet on B.

**Why this priority**: Wallets spend most of their time locked (auto-lock, restarts);
without this, sync would rarely happen. It also defines who may decrypt to merge.

**Independent Test**: Lock the wallet on B, change it on A, verify B receives and stores an
encrypted copy without its wallet file changing; unlock on B and verify the changes appear
and the merged result is saved; repeat with the wallet locked on both sides and verify the
copies are exchanged and merged on whichever device is unlocked first.

**Acceptance Scenarios**:

1. **Given** the wallet unlocked on A and locked on B, **When** A has changes B lacks,
   **Then** B stores A's encrypted copy as a pending copy, B's own wallet file is not
   modified, and B's UI shows the wallet as "changes waiting: unlock to merge".
2. **Given** a pending copy on B, **When** the person unlocks the wallet on B, **Then** B
   merges every pending copy for that wallet, saves the result, discards the pending
   copies, and the UI shows the merged credentials without any further input.
3. **Given** the wallet locked on both A and B with different contents, **When** they
   sync, **Then** each stores the other's encrypted copy as pending, and each merges on its
   own next unlock.
4. **Given** a locked wallet on B, **When** B syncs with C, **Then** B never forwards
   copies it received from A; it offers only its own stored wallet file.
5. **Given** a pending copy that cannot be opened with the password entered when B
   unlocks, **Then** B's wallet is unchanged, the copy stays pending, and the UI shows
   "cannot open: different master password or corrupted" naming the peer that sent it, with
   actions to enter another password for that copy or discard it.
6. **Given** a copy received while the wallet is unlocked on B, **When** it arrives,
   **Then** B merges it immediately without storing it as pending longer than needed for
   the merge.

---

### User Story 4 - Old wallet states are detected, never silently accepted (Priority: P2)

An attacker restores an old backup of the wallet file on a device, or a paired device that
was offline for months offers an old copy, or old traffic is replayed. No device ever goes
back to an older state without the person being told, and newer data is never replaced by
older data.

**Why this priority**: Roadmap global rule: sync MUST resist rollback and replay. A rolled
back wallet could silently reinstate a leaked password the person had changed.

**Independent Test**: Save several states of a wallet; restore an older file on B's disk
while the service is stopped and start it; make a peer offer an older authentic copy than
the one it offered before; replay a captured sync session; verify each case is detected,
surfaced in the UI and log, and that no newer data is lost.

**Acceptance Scenarios**:

1. **Given** B has held state S2 of a wallet, **When** B's wallet file is replaced by an
   older authentic state S1, **Then** at the next service start or file check B shows
   "possible rollback" for that wallet and does not offer that state to peers until a merge
   brings it back to at least S2 or the person explicitly accepts the older state (FR-021).
2. **Given** peer A previously offered state S2, **When** A later offers an older state S1,
   **Then** B rejects it, records "peer offered an older state" for A, and shows it in the
   per-peer sync status.
3. **Given** any received copy whose state is older than or equal to B's own, **When** it
   is processed, **Then** B's wallet does not change.
4. **Given** captured sync traffic, **When** it is replayed into the same or a new
   connection, **Then** it is rejected by the 003 channel and has no effect.

---

### User Story 5 - See sync status and sync now (Priority: P2)

The person sees, for each wallet and each paired device, whether they are in sync, when they
last synced, whether changes are waiting for an unlock, and whether there are conflicts or
warnings. A "Sync now" action triggers an immediate sync.

**Why this priority**: The person must be able to trust that a change has reached their
other devices before relying on it; status also surfaces conflicts and rollback warnings.

**Independent Test**: With two peers (one connected, one offline), verify the status views
show the correct state for each wallet and peer; press "Sync now" and verify a sync attempt
starts immediately even inside the long interval, and that repeated presses do not start
more than one attempt at a time.

**Acceptance Scenarios**:

1. **Given** the wallets view, **When** the person opens it, **Then** each wallet shows one
   sync state: "not synced" (with reason "no peer holds it", "unlock once to enable sync", or
   "format version 1"), "in sync", "syncing", "changes waiting: unlock to merge", "conflicts
   (N)", "possible rollback", "sync error", "disabled" (with reason, for example a corrupted
   record), or "sync off" when networking is off, plus the last successful sync time.
2. **Given** a wallet, **When** the person opens its sync details, **Then** each paired
   device that holds it is listed with its status (in sync, behind, ahead, diverged, unknown,
   offline, older state offered, error) and last sync time.
3. **Given** networking on, **When** the person presses "Sync now" (globally or for one
   wallet), **Then** a sync with every connected peer holding that wallet starts within 2
   seconds; while one is running, further presses do not start another.
4. **Given** networking off, **When** the person views sync status, **Then** every wallet
   shows "sync off (networking disabled)" and "Sync now" is unavailable.

---

### User Story 6 - Many devices and partitions converge (Priority: P3)

The person uses the same wallet on several devices (for example 5) that are connected only
some of the time and in different combinations. Eventually, once changes have had a path
between devices, all devices hold the same contents and the same conflicts.

**Why this priority**: Required by Principle VI; builds on Stories 1-3.

**Independent Test**: Simulate 5 devices with random edits, random partitions and random
merge orders; when every device has been unlocked and connected (directly or through
unlocked intermediaries) after the last edit, verify all devices hold identical entries,
tombstones and conflict sets.

**Acceptance Scenarios**:

1. **Given** devices A-B and B-C connected but never A-C, and the wallet unlocked on B,
   **When** A and C edit different credentials, **Then** all three converge through B.
2. **Given** any order in which the same set of copies is merged, **When** merging
   completes, **Then** the result is identical on every device (merge is order
   independent).
3. **Given** a device revoked in 003, **When** sync runs, **Then** no data is exchanged with
   it and any pending copies it sent are discarded.

---

### Edge Cases

- A wallet held on both devices but never yet saved in the new format version (FR-030):
  it is not synced until it has been unlocked and saved once on that device; the UI says so.
- Two devices hold files with the same wallet identifier but unrelated contents (a copied
  file edited independently since): handled like any other divergence; all entries merge and
  real conflicts are shown.
- The master password was changed on one device: copies under the new password stay
  pending on devices that unlocked with the old one until the person enters the new
  password for them (FR-022); the newest password change wins after merge.
- A peer offers a copy that is too large (over the 001 64 MiB limit), malformed, or of an
  unsupported format version: rejected before storing more than the limit; peer status shows
  "error"; nothing local changes.
- The transfer is interrupted (channel closes, device sleeps, crash): the partial data is
  discarded; the next attempt starts over; the local wallet is untouched.
- The service crashes or the device loses power during merge or save: on restart the wallet
  is either the old state or the fully merged state, never a mix (001 atomic save), and
  pending copies not yet merged are still pending.
- The person edits the wallet while a merge is being prepared: the merge applies on top of
  the latest local state; no local edit is lost.
- Storage is full: pending copies are not stored, the wallet is not changed, the status
  shows "sync error"; sync retries with backoff.
- A peer holds hundreds of wallets: each round summarizes at most 512 wallets, chosen by a
  rotating window (FR-005, FR-029); excess wallets are synced in later rounds, and every wallet
  both devices hold is reached within a bounded number of rounds.
- Clocks differ between devices: ordering uses version vectors only; timestamps are shown
  for information and used only as a deterministic tie-breaker for display order.
- A conflict is resolved on two devices differently before they sync: produces a new
  conflict (Story 2, scenario 5).
- A wallet is deleted from one device's data directory: it simply stops being held there;
  sync never recreates it and never deletes it on other devices.
- The person changes a wallet's name (file name) on one device: names are local and never
  sent; sync matches wallets by identifier only.

## Requirements *(mandatory)*

### Functional Requirements

**Scope and transport**

- **FR-001**: The service MUST synchronize a wallet only with paired (pinned, not revoked)
  devices that hold a wallet with the same wallet identifier, only while networking (003) is
  on, and only over the 003 channel.
- **FR-002**: Sync MUST NEVER create a wallet on a device that does not already hold it,
  and MUST NEVER delete a wallet file; it only updates the contents of wallets both sides
  hold.
- **FR-003**: Sync data MUST consist only of encrypted wallet files as produced by the
  vault-core save (authenticated encryption with the wallet key) plus the metadata allowed
  by FR-010. No plaintext credential field, title, wallet name, master password, or wallet
  key MAY be sent, even inside the encrypted channel.
- **FR-004**: The sync messages MUST be an additive, versioned extension of the 003 peer
  protocol, negotiated so that a device without sync support keeps working with 003-only
  behavior (the channel stays up, no wallet data is exchanged). This supersedes the 003
  restriction that the channel carries only maintenance messages, for sync messages only.
- **FR-005**: Every sync message and transfer MUST have bounded size; an encrypted wallet
  copy is transferred in bounded chunks, and a copy larger than the vault-core wallet size
  limit (64 MiB) MUST be refused as soon as the limit is exceeded.

**Who decrypts and merges (locked wallets)**

- **FR-006**: Only a device on which the wallet is currently unlocked MAY decrypt and merge
  copies of that wallet. A copy received while the wallet is unlocked is merged
  immediately. While the wallet is locked, the device MUST: answer summaries from its stored
  file; send its stored encrypted file when the peer lacks changes; store each received copy
  that contains changes it lacks as a pending copy (ciphertext only, FR-029a); and never
  modify or replace its wallet file. When the wallet is next unlocked, all its pending
  copies MUST be merged automatically, with no further input, and removed once the merged
  result is saved.
- **FR-006a**: A device MUST only offer and send its own stored wallet file; it MUST NEVER
  forward a pending copy received from another peer.
- **FR-006b**: Sync rounds, transfers and merges MUST NOT reset the 002 auto-lock idle timer
  and MUST NOT unlock a wallet. If the wallet locks while a merge is in progress, the merge
  is abandoned without saving and its pending copies stay pending.
- **FR-006c**: Sync MUST apply automatically to every wallet both devices hold while
  networking is on; there is no per-wallet sync switch (networking and pairing are the
  opt-in).
- **FR-007**: Receiving or storing copies MUST NOT require the master password, and the
  master password MUST NEVER be requested by sync except through the normal 002 unlock.
- **FR-008**: A received copy MUST be authenticated (decrypted successfully with the wallet
  key) before any of its content is used; a copy that fails authentication MUST NOT change
  the local wallet, MUST be reported as a warning naming the peer, and stays pending until
  the person opens it with another password (FR-022) or discards it, or a newer copy from
  the same peer replaces it. Its header state vector MUST NOT be trusted for anything but
  deciding whether to store it.

**Summaries and identification**

- **FR-009**: Peers MUST decide what to transfer by exchanging per-wallet summaries; a
  wallet copy MUST be transferred only when the receiver's summary shows it lacks some change
  the sender has (no transfer when in sync).
- **FR-010**: A summary MUST contain only (a) a per-session blinded wallet tag from which a
  peer that does not hold the wallet cannot learn or link the wallet identifier, and (b) the
  wallet-level state vector (a map of opaque device identifiers to change counters), sent in
  full only for wallets both sides hold whose session-bound state digests differ. Wallet
  names, entry counts, sizes beyond the transfer itself, and any credential data MUST NOT be
  included.
- **FR-011**: Each wallet MUST carry a wallet-level state vector that summarizes every change
  it contains: a device's counter increases by one for each change that device makes, and a
  merge sets each counter to the maximum of the merged copies. A copy whose state vector is
  greater than or equal to another's in every component contains all of the other's changes.
- **FR-012** *(amended 2026-10-24)*: The wallet identifier and state vector MUST be stored in
  the wallet file only inside the encrypted payload; the file MUST NOT carry them in
  plaintext. So that a locked wallet can be summarized and checked for rollback, the device
  keeps an owner-only sync record per wallet, written only from authenticated state (unlock,
  local save, merge), holding the identifier, the state vector, a digest of the exact wallet
  file it describes, the high-water and per-peer marks, pending and warning entries, and the
  local file name; none of these is ever sent to a peer. A file whose digest differs from the
  record is flagged "possible rollback" until its next unlock authenticates it. Values claimed by peers are untrusted
  until the copy is authenticated; a received copy whose authenticated wallet identifier
  differs from the wallet it was sent for MUST be rejected like a copy that fails
  authentication.

**Reconciliation and conflicts**

- **FR-013**: Merging MUST compare each entry (live or tombstone) by its 001 version vector:
  equal → keep; one newer → take the newer; concurrent → conflict (FR-014). Two versions
  with equal version vectors but different content are treated as concurrent (kept as a
  conflict). Entries present on only one side are taken as they are.
- **FR-014**: On a conflict, the merged wallet MUST keep all concurrent versions of the
  entry. One of them is shown as the current version, chosen deterministically (latest
  modification time, then the larger device identifier, then the larger content hash), and
  a live version always takes precedence over a tombstone in that choice. The entry MUST be
  marked as conflicted until resolved. No concurrent version is ever discarded except by
  the person's resolution or by a later version that dominates it (FR-017).
- **FR-015**: Merging MUST be deterministic, commutative, associative and idempotent: the
  same set of copies merged in any order and any number of times on any device yields the
  same entries, tombstones, conflict versions and state vector.
- **FR-016**: The person MUST be able to resolve a conflict in the UI of a device where the
  wallet is unlocked by choosing one version, or keeping both (each non-current live
  version becomes a new credential with a new identifier). A resolution is a normal change by
  the resolving device: its version vector dominates all resolved versions, so it propagates
  and clears the conflict on every device.
- **FR-017**: A conflict whose versions are later superseded by a newer version that
  dominates all of them (for example a resolution made elsewhere) MUST be cleared
  automatically during merge.
- **FR-018**: Tombstones MUST be kept indefinitely in this feature (no garbage collection),
  so a deletion can never be undone by a device that missed it.

**Rollback and replay protection**

- **FR-019**: Replay of sync traffic MUST be prevented by the 003 channel (fresh session keys
  and message ordering per connection); sync messages MUST additionally be bound to their
  session so a message from one session has no effect in another.
- **FR-020**: Merging MUST never move any entry to an older version: a received copy that
  is older than or equal to the local state changes nothing.
- **FR-021**: Each device MUST persist, per wallet, a high-water mark: the state vector of
  the newest authenticated state it has saved (updated after each local save or merge).
  When the local wallet file's state vector is not greater than or equal to the high-water
  mark (checked at service start and before each sync round from the sync record when the
  file digest matches it; a file whose digest does not match is flagged until unlock, where
  its authenticated state vector is compared), the wallet MUST be flagged
  "possible rollback" in the UI and log, MUST NOT be offered to peers, and MUST still
  receive and merge copies. The flag MUST clear automatically when a merge brings the state
  back to at least the mark; otherwise the person may, with the wallet unlocked, explicitly
  choose "accept this older state", which is logged and resets the mark to the current
  state.
- **FR-021a**: Each device MUST persist, per wallet and peer, the newest state vector that
  peer has sent in an authenticated copy. A summary or copy from that peer whose state
  vector is not greater than or equal to it MUST be refused (not stored, not merged) and
  recorded as "older state offered" in the peer's sync status and the log.
- **FR-022**: Each wallet MUST carry, inside its authenticated content, a password-change
  marker (device identifier and counter, compared like a version vector) that changes on
  every master-password change. At unlock, each pending copy MUST be opened with the entered
  password, deriving a separate key for a copy with different key-derivation settings before
  the password is wiped (one derivation at a time, 002 limits apply). A copy that still
  cannot be opened stays pending (FR-008); the person MAY enter that copy's master password
  to merge it. The merged wallet MUST be saved under the password of the copy with the
  newest password change; concurrent password changes MUST be shown as a conflict, and the
  person resolves it by choosing and typing the password to keep. A master password is
  never sent or stored as part of this.

**Atomic application and crash safety**

- **FR-023**: A merged result MUST be applied with the vault-core atomic save: after any
  crash or power loss the wallet file is either the complete previous state or the complete
  merged state.
- **FR-024**: Received copies MUST be written to storage only as ciphertext, atomically,
  in owner-only files in the per-user data area; a partially received copy MUST never be
  used and MUST be removed on restart.
- **FR-025**: Records the service persists for sync (summaries, high-water marks, peer
  status) MUST be written atomically, owner-only, and updated only after the wallet state they
  describe is saved; a corrupted record MUST disable sync for the affected wallet with a
  clear message, never be silently reset.
- **FR-026**: Local edits made while a merge is prepared MUST NOT be lost: the merge applies
  to the latest local state at the moment it is saved.

**Scheduling and resource use**

- **FR-027**: Sync MUST be event-driven: a sync round with a peer starts only when (a) the
  channel to that peer is established, (b) a wallet held by both is changed and saved
  locally (after a 5-second quiet period that coalesces bursts of edits), (c) a wallet is
  unlocked and has pending copies, (d) the person presses "Sync now", or (e) a safety
  interval (default 1 hour, configurable 15 minutes to 24 hours in the per-user
  configuration file) has elapsed since the last round with that peer. There MUST be no
  other periodic activity.
- **FR-028**: After a failed round, retries with the same peer MUST back off exponentially
  from 30 seconds to at most 1 hour, with random jitter; a successful round resets the
  backoff. "Sync now" bypasses the backoff once.
- **FR-029**: At most one round per peer and at most two transfers service-wide MUST run at
  the same time; transfer buffers MUST be bounded (at most 1 MiB in memory per transfer),
  and a wallet copy MUST NOT be held fully in memory except while it is being decrypted for
  a merge.
- **FR-029a**: Pending copies MUST be bounded: at most one pending copy per wallet per peer
  (a newer copy from the same peer replaces the older one, a copy dominated by another
  pending or local state is not stored), and pending copies from a revoked peer MUST be
  deleted at revocation.
- **FR-029b**: A round in which both sides are in sync MUST exchange only summaries (no
  wallet data).

**File format (vault-core, additive)**

- **FR-030** *(amended 2026-10-24)*: The vault-core wallet format MUST gain a new format
  version whose header is unchanged apart from the version number and whose encrypted payload
  adds the wallet state vector, the conflict versions of each entry and the password-change
  marker (FR-022); the wallet identifier stays in the encrypted payload as in version 1.
  Version 1 files MUST still be readable; a version 1 wallet is rewritten in the new version
  on its next save, and only wallets in the new version are synced. A version 1 wallet is also
  rewritten at unlock when networking is on and at least one paired device exists (plan
  Complexity Tracking, research R3); otherwise an unlock never rewrites a version 1 file. All version 1 rules
  (parse order, size and range checks, generic authentication error) continue to apply.
- **FR-031**: The new format version MUST bound the state vector (at most 256 devices) and
  the number of versions per entry (at most 16: the current version plus at most 15
  conflicting versions; further concurrent versions are still never discarded but make the merge
  fail with a clear "too many conflicts, resolve first" status for that wallet). A received
  state component may exceed both the local state and the recorded peer mark by at most 2^32;
  a larger value makes the copy invalid (FR-008), which is rejected without any local change.

**UI**

- **FR-032**: The wallet list MUST show each wallet's sync state and last successful sync
  time as in Story 5, scenario 1.
- **FR-033**: A per-wallet sync details view MUST list each paired device holding that
  wallet with status and last sync time; the paired-devices view (003) MUST show, per
  device, the time of the last sync round and its outcome.
- **FR-034**: The UI MUST provide "Sync now" globally and per wallet (Story 5, scenario 3).
- **FR-035**: The UI MUST provide a conflict list per unlocked wallet and a conflict view
  with the resolution actions of FR-016; conflicted credentials MUST be marked in the
  credential list and search results. Passwords in conflict versions MUST be hidden until
  revealed, with the same reveal and clipboard rules as 002.
- **FR-036**: Rollback warnings, failed authentication of received copies and "older state
  offered" events MUST be shown in the UI until the person dismisses them; dismissal never
  causes older data to be accepted.
- **FR-037**: All new UI views and actions MUST use the 002 protections (session, CSRF,
  Host/Origin, CSP, keyboard operable) and MUST NOT show any credential content while the
  wallet is locked.

**Logging and scope**

- **FR-038**: The log MUST contain only non-secret sync events: round start/end per peer
  fingerprint, outcome class, bytes transferred, conflicts detected (count only), rollback and
  authentication warnings. It MUST NOT contain credential data, titles, wallet keys,
  passwords, or wallet names of other devices.
- **FR-039**: This feature MUST NOT include wallet sharing or sending a wallet to a device
  that does not hold it (005), credential history, tombstone garbage collection, relays,
  internet sync, or sync of settings, device names or pairing data.

### Key Entities

- **Wallet state vector**: per wallet, a map from opaque device identifier to change
  counter, summarizing every change the wallet contains; compared component-wise.
- **Wallet summary**: blinded wallet tag plus state vector, exchanged per sync round.
- **Pending copy**: an encrypted wallet file received from a peer, stored as ciphertext
  until the wallet is unlocked and merged; at most one per wallet per peer.
- **Conflict**: an entry with two or more concurrent versions (live or tombstone), one shown
  as current, kept until the person resolves it or a dominating version arrives.
- **Sync record**: per wallet, the high-water mark (newest authenticated state saved) and,
  per peer, the newest authenticated state that peer sent, plus status; used for rollback
  detection (non-secret, owner-only).
- **Password-change marker**: authenticated per-wallet marker identifying the latest
  master-password change; decides which password a merged wallet keeps.
- **Sync round**: one exchange of summaries with a peer, followed by zero or more transfers.
- **Peer sync status**: per peer and wallet, last round time, outcome and position (in sync,
  behind, ahead, older state offered, error).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A change made on one device appears on a connected paired device that has the
  wallet unlocked within 60 seconds in 95% of trials, and within 10 seconds of unlock when
  the receiving device had the wallet locked.
- **SC-002**: In randomized multi-device tests (5 devices, random edits, partitions and merge
  orders), 100% of runs converge to identical wallet contents and conflict sets once every
  device has been unlocked and connected after the last edit.
- **SC-003**: 100% of concurrent edit/edit and edit/delete cases keep every version until the
  person resolves them; zero silent overwrites.
- **SC-004**: 100% of rollback scenarios in the test suite (restored old file, older peer
  offer, replayed traffic) are detected or have no effect, and none causes newer data to be
  lost.
- **SC-005**: Captured sync traffic in tests contains zero occurrences of known plaintext
  markers (credential fields, titles, wallet names, master password).
- **SC-006**: With 5 connected peers and 10 wallets all in sync, idle sync activity costs less
  than 1 KiB of traffic per peer per hour and adds less than 1% average CPU and less than 8 MiB
  of memory over the 003 idle baseline.
- **SC-007**: In 100% of tested crash points during transfer, merge and save, the wallet
  remains unlockable with either its previous or its fully merged contents.
- **SC-008**: Syncing a 10,000-credential wallet that differs by one credential completes in
  under 10 seconds on the reference laptop over a LAN, with peak additional memory below the
  001 unlock budget.

## Assumptions

- Feature 003 is in place: identities, pins, revocation and an always-on channel to
  reachable peers; this feature adds message types to that channel.
- Whole encrypted wallet files are the transfer unit (wallets are at most 64 MiB and usually
  far smaller); block-level delta transfer is not needed for these sizes and can be added in
  a later protocol version.
- Wallets reach additional devices only through feature 005 or manual file copy in this
  feature.
- The vault-core device identifier from 002 is the device key in version vectors and state
  vectors; it is opaque, non-secret and stable per installation.
- The person's paired devices are their own; the paired-device limit (32) from 003 bounds
  the number of peers.
- Default timings (5-second quiet period, 1-hour safety interval, 30 s to 1 h backoff) are
  chosen for low battery use and can be tuned only in the configuration file.
