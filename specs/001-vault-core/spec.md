# Feature Specification: Vault Core

**Feature Branch**: `001-vault-core` (no git branch created; work tracked via `specs/001-vault-core` on `main`)

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "FEATURE 001: vault-core. Pure-domain Rust core for a wallet (encrypted vault) holding many credentials (title, username, password, URL, notes, timestamps). Includes: wallet creation protected by a master password; a versioned encrypted file format (KeePassXC-inspired) using Argon2id key derivation and AES-256-GCM, with tamper detection and KDF parameters stored in the header; open/unlock, add/edit/delete/list/search credentials, save; secret zeroization in memory; a vault-storage port (interface) with an in-memory fake and a file adapter; per-entry version/modification metadata designed so later sync and conflict resolution can work. No networking, no UI, no service in this feature."

## Context

This feature delivers the foundational wallet ("vault") capability of a peer-to-peer password
manager. Later features will expose it through a local service with a browser UI, an Android
background app, and LAN synchronization between devices. This feature has **no** network, UI,
or service surface: its "users" are the person who owns the wallet (through future front-ends)
and the developers of those future features, who consume the core as a library.

**Operating model (binding for this and later features)**:

- The application runs 100% offline. Network is used only by the later device-sync feature;
  neither this feature nor normal operation uses the network.
- There are no user accounts, no email, and no login or identity of any kind. A person is
  never identified; only wallets exist.
- The only secret is each wallet's master password. It is needed solely to unlock a wallet
  (one created locally or one shared from another device), once per device restart per
  wallet. After unlock, the derived key is held in memory only and is wiped on lock, process
  exit, or an auto-lock timeout enforced by the host application; it is never persisted.
- A wallet shared from another device is opened with that same wallet's master password; the
  password itself is never transmitted or stored anywhere.

## Clarifications

### Session 2026-10-23

Non-interactive session: each answer is the recommended option, chosen for security first,
then simplicity, per the constitution.

- Q: Should a wrong master password be distinguishable from a tampered or corrupted wallet? → A: No. Any authentication failure (wrong password, modified header, modified body) yields one generic "invalid password or corrupted wallet" error; only structural problems detected before decryption (bad magic, unsupported version, truncated header, out-of-range KDF parameters) get distinct format errors.
- Q: What change-tracking metadata should each credential carry so future sync can detect concurrent edits without silently losing one? → A: A per-entry version vector (a map of device identifier → change counter), plus last-modified device and timestamp; a single revision counter is insufficient because it cannot detect concurrent edits on two devices.
- Q: What is the minimum master password length? → A: 12 characters (after Unicode NFC normalization), no composition rules.
- Q: Should the core keep a per-credential history of previous versions (as KeePassXC does)? → A: No; only the current version (or tombstone) is kept in this feature. History can be added in a later format version.
- Q: Are groups/folders, tags, custom fields, or attachments in scope? → A: No; only the fixed fields (title, username, password, URL, notes) plus metadata. The versioned format allows adding them later.
- Q: (User correction) Does the product have accounts, logins, or online operation, and what secrets exist? → A: It is 100% offline (network only in the later sync feature); there are no accounts, email, login, or identity; the only secret is each wallet's master password, used solely to unlock (once per device restart per wallet), with the derived key kept in memory only and never persisted; a shared wallet is opened on another device with the same master password, which is never transmitted. Applied in the Operating model, FR-005/005a/005b, FR-032/033, US1 scenarios 5–6, and Key Entities.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create a wallet and store credentials securely (Priority: P1)

A user creates a new wallet protected by a master password, adds one or more credentials
(title, username, password, URL, notes), and saves the wallet. Later, the user unlocks the
wallet with the same master password and finds exactly the credentials they stored.

**Why this priority**: This is the minimum viable password manager: without create, add,
save, and unlock, nothing else has value.

**Independent Test**: Create a wallet with a master password, add a credential, save it to
storage, discard all in-memory state, unlock from storage with the same password, and verify
the credential's fields are identical.

**Acceptance Scenarios**:

1. **Given** no existing wallet, **When** the user creates a wallet with an acceptable master
   password, **Then** an empty, unlocked wallet is available and can be saved.
2. **Given** an unlocked wallet, **When** the user adds a credential with a title and any of
   username, password, URL, and notes, **Then** the credential is listed with a unique
   identifier and creation/modification timestamps.
3. **Given** a saved wallet, **When** the user unlocks it with the correct master password,
   **Then** all saved credentials are restored with identical field values and metadata.
4. **Given** a saved wallet, **When** the user attempts to unlock with a wrong master
   password, **Then** unlocking fails with a generic "invalid password or corrupted wallet"
   error and no credential data is exposed.
5. **Given** a wallet saved on device A, **When** its bytes are unlocked on device B (a
   different device identifier) with the same master password, **Then** it unlocks with all
   credentials intact, and no other secret or identity is required.
6. **Given** an unlocked wallet, **When** the user saves several times, **Then** no
   password re-entry is needed and the stored bytes never contain the password or the key.

---

### User Story 2 - Manage credentials: edit, delete, list, search (Priority: P2)

A user with an unlocked wallet edits an existing credential, deletes credentials they no
longer need, lists all credentials, and searches for credentials by text.

**Why this priority**: Day-to-day use of a password manager requires maintaining and finding
entries; it builds on Story 1.

**Independent Test**: In an unlocked wallet containing several credentials, edit one, delete
another, search for a known title fragment, and verify list/search results reflect the
changes before and after a save/unlock round trip.

**Acceptance Scenarios**:

1. **Given** an unlocked wallet with a credential, **When** the user edits its password,
   **Then** the new value is stored, the modification timestamp advances, and the entry's
   version-vector counter for the current device increases by one.
2. **Given** an unlocked wallet with a credential, **When** the user deletes it, **Then** it
   no longer appears in list or search results, and a deletion marker (tombstone) is retained
   so future synchronization can propagate the deletion.
3. **Given** an unlocked wallet with credentials titled "GitHub", "GitLab", and "Bank",
   **When** the user searches for "git", **Then** "GitHub" and "GitLab" are returned
   (case-insensitive match) and "Bank" is not.
4. **Given** an unlocked wallet, **When** the user lists credentials, **Then** every
   non-deleted credential is returned exactly once, ordered by title (case-insensitive).

---

### User Story 3 - Tamper and corruption detection (Priority: P2)

A user's wallet file is modified by an attacker, damaged by a disk error, or truncated. When
the user tries to unlock it, the system refuses to open it rather than returning altered or
partial data.

**Why this priority**: Security-First is non-negotiable; integrity is as important as
confidentiality for a password store.

**Independent Test**: Save a wallet, flip a single byte anywhere in the stored data (header
or body), truncate it, or change its format version, and verify that unlocking fails every
time with no partial data exposed.

**Acceptance Scenarios**:

1. **Given** a saved wallet, **When** any single byte of the header or encrypted body is
   altered, **Then** unlocking fails with either the generic "invalid password or corrupted
   wallet" error or a format error, and never succeeds.
2. **Given** a saved wallet, **When** the data is truncated or padded, **Then** unlocking
   fails with the generic authentication error or a format error.
3. **Given** data with an unknown or unsupported format version, **When** the user tries to
   unlock it, **Then** unlocking fails with an "unsupported format version" error before any
   key derivation is attempted.

---

### User Story 4 - Pluggable storage (Priority: P3)

A developer of a future feature (service, Android app, sync engine) stores and loads wallets
through a storage interface, using an in-memory implementation for tests and a file-based
implementation for real use, with identical behavior.

**Why this priority**: Required by the Hexagonal Architecture principle and to enable later
features, but provides no new end-user capability by itself.

**Independent Test**: Run the same behavioral test suite against both the in-memory and the
file-based storage implementations and verify both pass.

**Acceptance Scenarios**:

1. **Given** the in-memory storage, **When** a wallet is saved and loaded, **Then** the
   result is byte-for-byte identical to what was saved.
2. **Given** the file-based storage, **When** a save is interrupted (e.g., process killed
   mid-write), **Then** the previously saved wallet remains intact and unlockable.
3. **Given** no wallet exists at the requested location, **When** a load is requested,
   **Then** a distinct "not found" error is returned.

---

### User Story 5 - Sync-ready metadata (Priority: P3)

A developer of the future sync feature can determine, for every credential (including
deleted ones), its stable identity, its version vector, when and on which device it was last
modified, so that two copies of a wallet can later be compared (newer, older, or concurrent)
and merged deterministically without data loss.

**Why this priority**: No sync is built now, but the data model must not need a breaking
change when sync arrives.

**Independent Test**: Create a credential, edit it twice, delete it, and verify that its
identifier is unchanged, its version vector advanced on each change, its last-modifying device
and timestamp were updated each time, and the tombstone survives a save/unlock round trip.

**Acceptance Scenarios**:

1. **Given** a credential, **When** it is modified on device D, **Then** the counter for D in
   its version vector increases by exactly one, other devices' counters are unchanged, and its
   last-modified device identifier and timestamp are updated.
2. **Given** a wallet created on one device, **When** it is unlocked, **Then** the wallet's
   own unique identifier and each entry's identifier are preserved.
3. **Given** two copies of the same credential edited independently on devices A and B,
   **When** their version vectors are compared, **Then** the comparison reports "concurrent"
   (neither dominates); if only one copy changed, it reports that copy as newer.

---

### Edge Cases

- Empty master password, or one shorter than the minimum length: creation is rejected.
- Master password containing non-ASCII (Unicode) characters: accepted; it is normalized
  consistently so the same visual password always unlocks the wallet.
- Credential with an empty title: rejected (title is the only required field).
- Very large notes field or many credentials (e.g., 10,000 entries): handled within the
  performance and memory targets below. Any single text field over 1 MiB is rejected, and a
  stored wallet over 64 MiB is rejected at unlock, to keep memory bounded.
- Editing or deleting a credential identifier that does not exist or is already deleted:
  returns a "not found" error, wallet unchanged.
- Operating on a locked wallet: not possible; locking discards all decrypted data.
- Search with an empty query: returns all non-deleted credentials (same as list).
- Search never matches on the password field, so secrets are not revealed by search behavior.
- Wallet saved with stronger-than-default key-derivation parameters: still unlockable, since
  parameters are read from the header.
- Header claims absurd key-derivation parameters (e.g., memory far beyond limits): rejected
  before key derivation to avoid resource-exhaustion attacks.
- Two credentials with the same title: allowed; they are distinct entries.

## Requirements *(mandatory)*

### Functional Requirements

**Wallet lifecycle**

- **FR-001**: System MUST allow creating a new, empty wallet protected by a master password.
- **FR-002**: System MUST reject master passwords shorter than 12 characters (Unicode
  characters after NFC normalization) at creation and at master-password change; no
  composition rules are imposed.
- **FR-003**: System MUST allow unlocking a stored wallet with its master password and MUST
  fail with a single generic "invalid password or corrupted wallet" error for any
  authentication failure (wrong password, modified header, or modified body), without
  revealing which one occurred. Distinct format errors are allowed only for structural
  problems detected before decryption (bad magic, unsupported version, truncated header,
  out-of-range key-derivation parameters).
- **FR-004**: System MUST allow saving an unlocked wallet to storage; every save MUST produce
  freshly encrypted output (a new random nonce on every save) so identical content
  never yields identical ciphertext.
- **FR-005**: System MUST allow locking an unlocked wallet, which discards all decrypted data
  and derived keys from memory. Lock MUST also occur implicitly when the unlocked wallet is
  dropped (process exit); auto-lock timeouts are a host-application policy that invokes lock.
- **FR-005a**: The master password MUST be used only to derive the wallet key at create,
  unlock, and master-password change, and MUST be wiped immediately afterwards. The derived
  key MUST be held in memory only while the wallet is unlocked, so later saves need no
  password re-entry, and MUST NEVER be written to storage, logs, or any other output.
- **FR-005b**: A wallet file produced on one device MUST unlock on any other device using
  only that wallet's master password; all other parameters needed (KDF settings, salt) are
  read from the file header. No device-specific or person-specific secret is involved.
- **FR-006**: System MUST allow changing the master password of an unlocked wallet; the next
  save uses a newly derived key with a new random salt.

**Credentials**

- **FR-007**: System MUST allow adding a credential with: title (required, non-empty),
  username, password, URL, and notes (all optional, free text).
- **FR-008**: System MUST assign each credential a globally unique, random, immutable
  identifier at creation.
- **FR-009**: System MUST record for each credential a creation timestamp and a
  last-modified timestamp (UTC).
- **FR-010**: System MUST allow editing any field of an existing credential except its
  identifier and creation timestamp.
- **FR-011**: System MUST allow deleting a credential; deletion MUST clear the credential's
  field contents and retain a tombstone (identifier, version vector, deletion timestamp, device)
  so the deletion can be propagated by future synchronization. No history of previous
  credential versions is kept; only the current version or tombstone exists.
- **FR-012**: System MUST list all non-deleted credentials ordered by title,
  case-insensitively.
- **FR-013**: System MUST support case-insensitive substring search over title, username,
  URL, and notes; the password field MUST NOT be searched.

**Sync-ready metadata**

- **FR-014**: Each wallet MUST have a unique, immutable wallet identifier.
- **FR-015**: Each credential (including tombstones) MUST carry a version vector: a map from
  device identifier to change counter. On creation the creating device's counter is 1; every
  change (edit or delete) increments exactly the acting device's counter by 1.
- **FR-016**: Each credential MUST record the identifier of the device that last modified
  it; the device identifier is supplied by the caller and stored as-is.
- **FR-016a**: The core MUST provide a deterministic comparison of two version vectors
  returning one of: equal, newer, older, or concurrent. (Merging is out of scope.)
- **FR-017**: All metadata in FR-014 to FR-016 MUST survive save/unlock round trips
  unchanged.

**Encrypted file format**

- **FR-018**: The stored wallet format MUST begin with a format identifier ("magic") and a
  format version number, followed by a header containing the key-derivation algorithm and
  parameters (memory cost, iterations, parallelism, salt) and the encryption nonce.
- **FR-019**: The wallet key MUST be derived from the master password using Argon2id, with
  parameters stored in the header; defaults MUST meet or exceed current OWASP
  recommendations, and the core MUST reject parameters below a safe minimum or above a
  resource ceiling.
- **FR-020**: All credential data and wallet metadata MUST be encrypted with AES-256-GCM
  using a unique random nonce per save.
- **FR-021**: The entire header MUST be authenticated (bound as associated data) so any
  modification of the header or the body is detected at unlock.
- **FR-022**: Unlocking MUST be all-or-nothing: either the full wallet is decrypted and
  validated, or an error is returned and no partial data is exposed.
- **FR-023**: Unknown format versions MUST be rejected with a distinct error; the format
  MUST allow future versions to be introduced without ambiguity.

**Memory hygiene**

- **FR-024**: The master password, derived keys, and decrypted credential secrets (password
  and notes) MUST be wiped from memory when no longer needed (on lock, drop, replacement, or
  after use), where the platform allows.
- **FR-025**: Secrets MUST NOT appear in error messages, debug output, or logs.
- **FR-025a**: Because a library cannot control its host process, the core MUST document
  (in its public API docs) that every host executable embedding it MUST lock its memory
  against swapping where the OS allows and disable core dumps; implementing this is a
  required acceptance item of the first host feature (service / Android app), not of this
  feature.

**Storage**

- **FR-026**: The core MUST perform all persistence through a storage interface that
  stores and loads opaque encrypted wallet bytes; the core MUST NOT depend on any concrete
  storage mechanism.
- **FR-027**: An in-memory storage implementation MUST be provided for testing.
- **FR-028**: A file-based storage implementation MUST be provided; saves MUST be atomic
  (a failed or interrupted save never corrupts the previous file).
- **FR-029**: The storage interface MUST distinguish "not found" from other I/O failures.
- **FR-030**: Only encrypted data may be written through the storage interface; no plaintext
  credential data or temporary plaintext files may be written anywhere.

**Scope exclusions**

- **FR-031**: This feature MUST NOT include networking, synchronization, user interface,
  background service, clipboard handling, password generation, credential history,
  groups/folders, tags, custom fields, attachments, or merging of wallet copies.
- **FR-032**: The core MUST operate fully offline: it MUST NOT open network connections or
  depend on any network-reachable service.
- **FR-033**: The core MUST NOT contain user accounts, email addresses, login, or any person
  identity. The device identifier (FR-016) is an opaque per-device tag used only for change
  tracking; it is not secret and does not authenticate anyone.

### Key Entities

- **Wallet (Vault)**: An encrypted collection of credentials. Attributes: wallet identifier,
  format version, creation timestamp, key-derivation settings, set of credential records
  (live and tombstoned). Exists in two states: locked (only encrypted bytes) and unlocked
  (decrypted in memory).
- **Credential (Entry)**: A set of credentials the person saved for some website or app.
  Attributes: identifier, title, username, password,
  URL, notes, created-at, modified-at, version vector, last-modified-by device. Password and
  notes are secret.
- **Tombstone**: A deleted credential's remaining record: identifier, version vector,
  deleted-at, last-modified-by device; no field contents.
- **Version Vector**: Map of device identifier → change counter for one credential; compared
  to classify two copies as equal, newer, older, or concurrent.
- **Master Password / Wallet Key**: The wallet's only secret and the key derived from it.
  The password is wiped right after key derivation; the key lives in memory only while the
  wallet is unlocked. Neither is ever stored or transmitted.
- **Encrypted Wallet File**: Header (magic, version, KDF parameters, salt, nonce) plus
  authenticated ciphertext of the wallet contents.
- **Vault Storage (port)**: The abstraction through which encrypted wallet bytes are saved
  and loaded; implemented by in-memory and file adapters.
- **Device Identifier**: An opaque caller-supplied tag of the device making changes; not a
  person identity, not secret, not used for authentication.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of save/unlock round trips in the test suite reproduce every credential
  field and metadata value exactly.
- **SC-002**: 100% of single-byte modifications, truncations, and version changes to a saved
  wallet are detected at unlock (verified by exhaustive single-byte mutation tests on a
  sample wallet).
- **SC-003**: Unlocking with default key-derivation settings completes in under 2 seconds on
  the reference laptop and under 4 seconds on the reference Android phone, while costing at
  least 0.3 s per guess on the reference laptop to slow brute-force guessing. Reference
  devices are a laptop CPU from 2022 or later with 4+ cores and an Android phone with a 2021+
  mid-range SoC; the exact models used are recorded in quickstart.md.
- **SC-004**: List and search over a 10,000-credential wallet return results in under 100 ms
  once unlocked.
- **SC-005**: Peak memory while unlocked with 10,000 typical credentials stays below 64 MB
  in addition to the transient key-derivation memory.
- **SC-006**: No plaintext credential data is found in stored wallet bytes, error messages,
  or debug output (verified by automated tests that search for known plaintext markers).
- **SC-007**: The same behavioral test suite passes against both storage implementations.
- **SC-008**: An interrupted save leaves the previous wallet unlockable in 100% of tested
  interruption points.

## Assumptions

- Master password minimum length is 12 characters; no further complexity rules (length is
  the meaningful factor; strength meters are a UI concern for later features).
- Master passwords are Unicode-normalized (NFC) before key derivation so the same visual
  password always produces the same key across platforms.
- Default Argon2id parameters follow OWASP guidance (at least 19 MiB memory, 2 iterations,
  parallelism 1), tuned upward within the SC-003 time budget; accepted ranges are bounded to
  prevent resource-exhaustion from a malicious header.
- A wallet's contents are small enough (thousands of entries) to be decrypted as a whole;
  streaming of individual entries is not required for this feature.
- Timestamps are UTC with at least second precision; they are informational for conflict
  resolution, while the version vector is the authoritative ordering data for future sync.
- Tombstones are kept indefinitely in this feature; garbage collection is deferred to the
  sync feature.
- Auto-lock timeouts and "unlock once per device restart" are host-application policies
  (service/Android features); the core provides explicit lock and lock-on-drop.
- Only a master password protects the wallet in this feature; key files and hardware keys
  are out of scope but the header format leaves room for them in a future version.
- The device identifier is provided by the calling application; generating and persisting it
  is the responsibility of later features.
- Only one process writes a given wallet file at a time; concurrent-writer coordination is
  deferred to the service/sync features.
- Use of Argon2id and AES-256-GCM is mandated by the project constitution and the feature
  request, and is therefore stated as a requirement rather than an implementation choice.
