# Feature Specification: Android App

**Feature Branch**: `feat/007-android-app`

**Created**: 2026-10-28

**Status**: Draft

**Input**: User description: "Feature 007 android-app: Android app reusing the Rust core via UniFFI bindings (a new Rust crate for the FFI boundary, hexagonal: adapters for storage in the app-private directory, networking via the existing LAN channel), same flows as the desktop (create/unlock wallet with master password once per app restart, credential CRUD/search, copy with clipboard auto-clear and sensitive-clipboard flag, auto-lock, pairing, sync, sharing), battery-aware background sync (Doze-aware, LAN only, minimal wakeups), Android Keystore usage that never persists the master password or derived key, FLAG_SECURE screen-capture protection, no cloud backup, no internet exposure beyond the local network, minimal permissions, no accounts. FR-025a host obligations: memory locking where possible, no core dumps, auto-lock. The build environment has no Android SDK/NDK and no phone: separate host-testable checks from device-only manual checks."

## Context

Features 001-006 deliver the Rust core and the desktop host:

- **001 vault-core**: encrypted wallet (Argon2id key derivation, AES-256-GCM), credentials,
  version vectors, the storage port and an in-memory fake; `vault-storage-file` is the atomic
  file adapter. Host obligation FR-025a: every host executable must lock memory against swap
  where the OS allows, disable core dumps and enforce auto-lock.
- **wallet-service** (002): the application layer shared by hosts: wallet registry
  (locked/unlocked slots), idle auto-lock, suspend detection; no OS calls.
- **003 device-link / device-link-net**: per-device keypair, LAN discovery, pairing by short
  code, mutually authenticated encrypted channel, key pinning, revocation, IPv4
  private/link-local address filter.
- **004 wallet-sync**: summaries, transfers, deterministic merge, conflict preservation,
  rollback and replay protection, event-driven low-resource scheduling.
- **005 sharing**: single-use, scoped, expiring invitations; the master password is never sent.
- **passwsyncd** (002-006): the desktop host: a loopback browser UI and the runtime wiring of
  the above (networking, sync and sharing runtimes, stores, hardening).

This feature adds a second host: an **Android app** that offers the same flows as the
desktop UI on a phone, reuses the Rust core unchanged through a new foreign-function boundary
crate, and syncs with desktop and other Android devices over the existing LAN protocol. It
adds no new protocol, file format or cryptography.

**Operating model (inherited, binding)**:

- 100% offline except the 003-005 LAN channel to paired devices; networking is off by
  default. No accounts, email, login, cloud backup, relay or internet host.
- The master password of each wallet is the only secret protecting it, entered once per app
  process lifetime per wallet (subject to auto-lock); the derived key stays in process memory
  only and is never persisted, sent, or wrapped by any platform key store.
- Device pairing uses the 003 one-time pairing code; sharing uses the 005 invite code.

**Verification constraint**: The build environment has no Android SDK, no Android NDK, no
Android Rust targets and no phone. Every requirement is therefore classified as
**host-verifiable** (checked offline on the Linux development host: Rust unit and integration
tests of the boundary crate, the boundary crate and its generated binding scaffolding building
for the host target, binding source generation, static checks of the manifest and resource XML,
and policy-scanning scripts over the app sources) or **device-only** (a documented manual check
on a real Android device or emulator with the SDK installed). Host checks are the gate for this
feature; device-only checks are recorded as pending until run (as in 004-006).

## Clarifications

### Specification defaults 2026-10-28

Decisions taken while writing the specification (non-interactive): each is the most secure
and then simplest option consistent with the constitution and the roadmap global rules.

- Q: Can biometric re-unlock be offered? → A: No. Any biometric unlock requires persisting the
  wallet key (or a key that can recover it) wrapped by the platform key store, which the
  roadmap forbids. Biometric unlock is out of scope; every unlock uses the master password.
- Q: What is the platform key store used for, then? → A: Only to protect the device identity
  private key (003) and the pinned-peer records at rest: they are stored encrypted with a
  non-exportable, app-bound key held in the platform key store (hardware-backed when the
  device offers it). That key never touches a master password, a wallet key or a wallet file,
  and needs no user authentication so background sync can open the channel.
- Q: How is the FR-025a "lock memory against swap" obligation met when Android apps cannot
  lock their whole address space (low per-app locked-memory limit)? → A: Best effort, never
  silent. The app locks all memory if the platform limit allows it; otherwise it locks the
  pages that hold secret buffers (master password input, derived keys, decrypted entries) up
  to the limit, and the security status screen states which level was achieved. Disabling core
  dumps and marking the process non-dumpable are mandatory: if either fails, the app refuses
  to create or unlock any wallet (fail closed for those two).
- Q: Is networking on by default, and how is it turned on without a configuration file? →
  A: Off by default. The person turns it on in the app's settings with an explicit
  confirmation that states what it does (LAN only, paired devices only). The desktop rule
  "the UI must not turn networking on" (003 FR-008) protects a browser UI from cross-site
  requests; a native app screen has no such exposure, so an in-app switch with confirmation
  is the simplest secure equivalent.
- Q: Does the phone scan QR codes for pairing and sharing? → A: No. Camera access would add a
  permission; the phone pairs and redeems invitations by typing the code and comparing the
  fingerprint shown on both devices (003 FR-022a, 005 FR-014). The phone does not display QR
  codes either.
- Q: How does background sync run? → A: No permanent background service. Networking runs
  while the app is in the foreground; in the background the app uses the platform's deferrable
  job scheduling to open a short, bounded sync window at the 004 safety interval (default 1
  hour, 15 minutes to 24 hours), only on a Wi-Fi or Ethernet connection and when the battery
  is not low, deferred by the platform's power management (Doze) as it decides. No exact
  alarms, no exemption from battery optimisation, no persistent notification.
- Q: Minimum Android version? → A: Android 13 (API level 33), the first version with the
  platform sensitive-clipboard marking, per-app control of recents screenshots and the
  current backup/data-extraction rules; older versions are not supported.
- Q: Autofill service, wallet import/export, password generator? → A: Out of scope (the desktop
  has none of them either).

### Session 2026-10-28

Non-interactive `/speckit-clarify` session: each answer is the recommended option (most
secure, then simplest).

- Q: Should all wallets lock when the screen turns off, always, or only after the idle timeout
  (or as a setting)? → A: Always lock all wallets on screen-off, with no setting to disable it
  (FR-017). This also guarantees no wallet is unlocked while the platform's deep-sleep mode
  (Doze) can delay timers, so background windows never merge unless the screen is on.
- Q: Should a pending clipboard clearance also run when the screen turns off? → A: Yes. Screen-off
  locks all wallets and lock clears immediately (FR-018), so the clipboard never keeps a copied
  value while the device sleeps and timers may be delayed (FR-022).
- Q: Which network interfaces may the app use when a VPN, hotspot or mobile data is also
  active? → A: Only Wi-Fi or Ethernet interfaces with an IPv4 private or link-local address;
  never a VPN, mobile-data or other tunnel interface. If no such interface exists, networking
  shows "no local network" and background windows do not run (FR-039, FR-044).
- Q: What happens to a sync or share transfer already in progress when the app leaves the
  foreground? → A: It may finish inside a bounded window of at most 2 minutes from leaving the
  foreground (the FR-045 limit); then sockets close and an unfinished transfer is discarded and
  retried by the 004 rules (sync) or must be redone (share). Invitations not yet started are
  cancelled at once (FR-051).
- Q: Should the non-secret sync, share and settings records also be encrypted with the
  platform key store key? → A: No. They hold no secrets (as on the desktop) and live in the
  owner-only app-private directory; only the device identity and pins are key-store encrypted
  (FR-034). This keeps one encrypted blob and avoids key-store calls on every sync. Constitution Principle I ("All data at rest MUST be encrypted") is not met by this choice; the exception is recorded in plan.md Complexity Tracking and needs maintainer approval.

### Plan amendments 2026-10-28

Made by `/speckit-plan` where a technical limit or an existing reviewed constant must be stated
(details in plan.md and research.md R3, R6, R10, R12, R13):

- FR-005: the single unsafe module is a *memory-protection* module that holds memory locking
  **and** a wipe-on-free global allocator. The allocator wipes the transport copies that the
  binding generator frees without wiping, and wipes the key copies of the channel library.
- FR-008: the "secrets only" level covers the secret buffers the boundary crate holds
  (password inputs, reveal/copy values, the identity plaintext). It does not cover
  key-derivation scratch memory or entries held inside vault-core, which are page-locked only
  at the "full" level.
- FR-014 and the first edge case: the memory-cost ceiling is the existing service cap of
  128 MiB, not 256 MiB. This is stricter than the spec, and desktop and phone share the same
  value.
- FR-033: settings changes are saved at once and take effect at the next app start. The
  settings screen offers "Restart now".
- FR-044: background jobs are not kept across a device reboot, because that would need the
  forbidden boot-completed permission. The app plans them again at its next start.
- FR-054: with target SDK 37 the app declares the local-network permission
  (`ACCESS_LOCAL_NETWORK`) and requests it only when the person confirms turning networking on.
- FR-005 and FR-009: per-module `#![forbid(unsafe_code)]` in every non-memory-protection module; platform-text exception for the clipboard entry and the revealed-password display (see the FR text).
- FR-028: screen-reader operability is device-only (tag [H+D], check D25).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create and unlock a wallet on the phone (Priority: P1)

The person installs the app, creates a wallet with a name and a master password (twice), and
later unlocks it with the master password. The wallet stays unlocked for the rest of the app
process lifetime until auto-lock, a manual lock, or the screen turning off.

**Why this priority**: Without a local encrypted wallet nothing else has value; this is the MVP.

**Independent Test**: Host: boundary-crate tests create, lock and unlock a wallet in a
temporary directory through the exported interface, check wrong-password handling and that no
secret appears in errors. Device: create a wallet, kill the app, reopen, unlock.

**Acceptance Scenarios**:

1. **Given** no wallets, **When** the person creates wallet "Personal" with a 12+ character
   master password entered twice identically, **Then** an encrypted wallet file appears in the
   app-private storage and the wallet is shown unlocked.
2. **Given** a locked wallet, **When** the person enters the wrong master password, **Then**
   unlocking fails with the same generic message for wrong password and corrupted file.
3. **Given** an unlocked wallet, **When** the app process is ended by the system or the person,
   **Then** on next start the wallet is locked and requires the master password.
4. **Given** an unlocked wallet, **When** the screen turns off, the idle timeout elapses, or the
   person presses "Lock", **Then** the wallet is locked and its decrypted data is wiped.
5. **Given** core dumps could not be disabled, **When** the person tries to create or unlock a
   wallet, **Then** the action is refused with a message naming the failed protection.

---

### User Story 2 - Manage credentials and copy safely (Priority: P1)

For an unlocked wallet the person lists, searches, adds, views, edits and deletes credentials,
reveals a password, and copies a username or password to the clipboard; the copied value is
marked sensitive and cleared automatically.

**Why this priority**: Daily use of a password manager on a phone is reading and copying.

**Independent Test**: Host: boundary-crate tests cover CRUD and search through the exported
interface, that list/search results carry no passwords, and that reveal/copy values are
returned as wipeable byte buffers. Policy scan checks the clipboard code sets the sensitive
marking. Device: copy a password, see no clipboard preview of it, wait for clearance.

**Acceptance Scenarios**:

1. **Given** an unlocked wallet, **When** the person searches "mail", **Then** credentials whose
   title, username, URL or notes contain "mail" (case-insensitive) are listed without passwords.
2. **Given** a credential, **When** the person copies its password, **Then** the clipboard holds
   it marked as sensitive (the system does not show its content in previews), a countdown is
   shown, and after the clipboard timeout (default 30 seconds) the clipboard is cleared.
3. **Given** a pending clipboard clearance, **When** the wallet locks, the screen turns off, or
   the app goes to the background, **Then** clearance still happens no later than the deadline
   (immediately on lock or screen-off).
4. **Given** a revealed password, **When** the timeout elapses, the wallet locks, or the person
   leaves the credential view, **Then** the password is hidden again.
5. **Given** an edit, **When** the person saves, **Then** the change is written atomically to the
   wallet file before success is shown.

---

### User Story 3 - Screen, storage and backup protections (Priority: P1)

The app's content never appears in screenshots, screen recordings, the recents overview or
cloud/device-transfer backups, and its files live only in app-private storage.

**Why this priority**: Phone-specific leak channels must be closed before any secret is shown.

**Independent Test**: Host: static checks of the manifest and XML (backup disabled, data
extraction rules exclude everything, no exported components except the launcher, network
security configuration denies cleartext) and a source scan that every screen applies the
secure-window flag. Device: attempt a screenshot, open recents, attempt a backup.

**Acceptance Scenarios**:

1. **Given** any app screen, **When** the person or another app takes a screenshot or records
   the screen, **Then** the app content is blank or blocked.
2. **Given** the app in the recents overview, **Then** no app content is visible in its preview.
3. **Given** wallets on the device, **When** a cloud backup or device-to-device transfer runs,
   **Then** no app file is included.
4. **Given** the master-password and password fields, **Then** the keyboard is asked not to
   learn, suggest or autofill-save their contents.

---

### User Story 4 - Pair the phone with a desktop or another phone (Priority: P2)

With networking turned on in settings, the person pairs the phone with a passwsyncd desktop
(or another phone) on the same LAN using the 003 pairing code and fingerprint confirmation,
sees paired devices, and can revoke one.

**Why this priority**: Pairing is the prerequisite for sync and sharing.

**Independent Test**: Host: boundary-crate tests pair two in-process instances over loopback
through the exported interface, using the 003 test kit with the private-address filter adapted
for tests. Device: pair the phone with a desktop running passwsyncd.

**Acceptance Scenarios**:

1. **Given** networking off (default), **Then** the app opens no network socket at all.
2. **Given** networking turned on after confirmation and a desktop showing a pairing code,
   **When** the person picks the desktop from the nearby list on the phone and enters the code,
   **Then** both devices show each other's name and fingerprint, the person confirms on the
   initiator, and both pin each other.
3. **Given** a paired device, **When** the person revokes it with confirmation, **Then** its pin
   is removed, its channel is closed, and wallets received from it but not opened are deleted.
4. **Given** pairing in progress, **When** the app leaves the foreground, **Then** pairing is
   cancelled and the code invalidated.

---

### User Story 5 - Sync wallets in the foreground and in the background (Priority: P2)

Wallets held by the phone and a paired device converge: immediately while the app is open, and
in battery-friendly background windows otherwise, only on the local network.

**Why this priority**: Multi-device consistency is the product's purpose, but local use works
without it.

**Independent Test**: Host: boundary-crate tests run two instances that converge after edits
on both, preserve conflicts, refuse rollback, and run a bounded background window that ends
when rounds finish or the window limit is reached. Device: edit on the desktop, background
the phone, observe convergence after a window; check no wakeups when networking is off.

**Acceptance Scenarios**:

1. **Given** the app open, networking on, and a paired desktop holding the same wallet, **When**
   the person edits a credential on either device, **Then** the other device holds the change
   within 30 seconds of the 5-second quiet period.
2. **Given** the app in the background on Wi-Fi with battery not low, **When** the safety
   interval elapses and the platform allows work, **Then** the app opens one sync window of at
   most 2 minutes, syncs with reachable paired peers, and closes every socket.
3. **Given** the device on mobile data only, battery low, or networking off, **Then** no
   background window runs.
4. **Given** a wallet locked on the phone, **When** a newer copy arrives, **Then** it is stored as
   ciphertext only and merged at the next unlock (004 rules).
5. **Given** concurrent edits of the same credential, **Then** both versions are kept and the
   person can resolve the conflict on the phone when the wallet is unlocked.

---

### User Story 6 - Share and receive wallets (Priority: P3)

The person shares an unlocked wallet with a paired device using a 005 invitation code, or
receives one from a paired device, and opens it with the same master password.

**Why this priority**: Sharing builds on pairing and sync and is used rarely.

**Independent Test**: Host: boundary-crate tests run a full invitation between two instances
(create, redeem, confirm, transfer, open with master password) and expiry/cancellation.
Device: share from a desktop to the phone and open it.

**Acceptance Scenarios**:

1. **Given** an unlocked wallet and a paired device, **When** the person shares it, **Then** the
   phone shows the invite code and expiry, and the transfer happens only after the person
   confirms the recipient's name and fingerprint.
2. **Given** a received wallet, **When** the person opens it with the correct master password,
   **Then** it becomes a held wallet and syncs like any other.
3. **Given** a received wallet not opened within 24 hours, **Then** it is deleted and the person
   is told on the next app start or window.
4. **Given** an invitation in progress, **When** the app leaves the foreground, **Then** the
   invitation is cancelled.

---

### Edge Cases

- Wallet whose key-derivation memory cost is above the phone ceiling (128 MiB, plan amendment): unlocking is
  refused before derivation with a distinct message (the parameters are read first, 002
  FR-017a); the app never attempts a derivation that could exhaust device memory.
- App killed by the system while unlocked: all keys are lost with the process; next start
  shows every wallet locked. A pending clipboard clearance is performed at the next start.
- App killed during a save: the atomic save leaves the previous file intact.
- App killed during a transfer: partial received data is removed at the next start.
- Storage full: saves and transfers fail with a clear message; existing files are untouched.
- Uninstalling the app deletes all app data, including wallets held only on this device; the
  app states this in its settings/about screen (it cannot intercept uninstall).
- App data cleared by the person: equivalent to a fresh install; a new device identity is
  generated and previous pairings must be redone on both sides.
- Platform key store unavailable or the identity key invalidated (e.g., after a device reset
  of credentials): the device identity cannot be opened; networking stays off and the app
  offers to create a new identity (requiring re-pairing); wallets are unaffected.
- Network changes during a window (Wi-Fi lost): the window ends, sockets close, rounds back
  off per 004.
- Connected to a network whose addresses are not private/link-local (e.g., public IPv4 or
  IPv6-only): nothing is sent or accepted (003 FR-011); status shows "no local network".
- Clock jump or device time change: auto-lock uses elapsed time since boot (including sleep),
  so changing the wall clock neither extends nor shortens the idle timeout.
- The person switches to another app with a wallet unlocked: the wallet stays unlocked until
  the idle timeout or screen-off; screen content is already hidden from recents.
- Accessibility services or other apps reading the screen: secure-window protection blocks
  capture; reading through accessibility is a residual risk documented for the person.
- Multiple app windows (split screen): every window carries the same protections.
- A second process (e.g., isolated background worker) must not hold wallet keys; only the main
  app process ever unlocks.

## Requirements *(mandatory)*

Each requirement is tagged **[H]** (host-verifiable: automated on the development host),
**[D]** (device-only: manual check on a device or emulator), or **[H+D]** (host check of
the static artifact plus device confirmation of the behaviour).

### Functional Requirements

**Architecture and reuse**

- **FR-001** [H]: The app MUST reuse the existing Rust crates (vault-core, vault-storage-file,
  wallet-service, device-link, device-link-net, wallet-sync and their sharing support) for all
  wallet, crypto, storage-format, pairing, channel, sync and sharing logic; the app's
  platform-language code MUST NOT re-implement any of it.
- **FR-002** [H]: A new Rust crate MUST form the foreign-function boundary, exposing a small,
  coarse-grained application interface to the app (wallet, credential, settings, networking,
  pairing, sync and sharing operations plus status/events), generated with a vetted binding
  generator, and MUST depend on the core crates, never the reverse.
- **FR-003** [H]: The boundary crate MUST follow the hexagonal rule: domain and application
  crates stay free of Android specifics; Android-specific concerns (app-private directory path,
  platform key store, clipboard, job scheduling, lifecycle, screen-off events) reach the Rust
  side only through ports with in-memory fakes usable in host tests.
- **FR-004** [H]: Runtime wiring that both hosts need (networking, sync and sharing runtimes
  and their stores) MUST be shared code used by passwsyncd and the boundary crate, not a copy;
  any move of such code out of passwsyncd MUST leave passwsyncd's behaviour unchanged with its
  full test suite passing.
- **FR-005** [H]: Unsafe code MUST be confined to the generated binding scaffolding and, if
  unavoidable, to one documented memory-protection module (memory locking and wipe-on-free
  allocation; plan amendment); every other hand-written module of
  the boundary crate MUST forbid unsafe code (`#![forbid(unsafe_code)]` at the top of each such file), and the workspace-wide prohibition stays in force
  for every other crate.
- **FR-006** [H]: The boundary crate and its generated scaffolding MUST build and pass their
  tests for the host target, and binding source generation for the app language MUST run on
  the host, so the exported interface is checked without the Android toolchain.

**Process and memory protections (FR-025a)**

- **FR-007** [H+D]: Before any wallet is created or unlocked, the app MUST disable core dumps for
  its process and mark it non-dumpable; if either fails, creating and unlocking MUST be refused
  with a message naming the failed protection (no option to continue).
- **FR-008** [H+D]: Before any wallet is created or unlocked, the app MUST lock all its memory
  against swapping if the platform limit permits; otherwise it MUST lock the memory holding
  secret buffers (master-password input, derived keys, decrypted entries) up to the limit. The
  achieved level ("full", "secrets only", "none") MUST be shown on a security status screen
  and logged without secrets.
- **FR-009** [H]: Master passwords and credential secrets MUST cross the language boundary only
  as mutable byte buffers that both sides wipe immediately after use; they MUST NOT be passed as
  immutable platform strings by the app's own code, logged, persisted, or kept after submission. Amendment (plan, 2026-10-28): the clipboard entry (FR-021) and the displayed revealed password (FR-024) need the platform text type; the app converts secret bytes only in one helper, callable only from those two places (research R7).
- **FR-010** [H]: List and search results crossing the boundary MUST NOT contain passwords or
  notes; a password crosses only for an explicit reveal or copy of one credential.
- **FR-011** [H+D]: Only the main app process MUST ever hold unlocked wallets; background sync
  windows run in that process and MUST NOT require or cache a master password.
- **FR-012** [D]: The release build MUST be non-debuggable and MUST NOT include debug-only
  logging of any app data.

**Wallets, unlock and auto-lock**

- **FR-013** [H]: The person MUST be able to create a wallet with a name and a master password
  entered twice (001 rules: at least 12 characters), and list all wallets with locked/unlocked
  state.
- **FR-014** [H]: The person MUST be able to unlock a wallet with its master password; wrong
  password and corrupted file MUST produce the same generic message; the key-derivation
  parameters MUST be read before derivation and wallets whose memory cost exceeds 128 MiB
  (the existing service cap; plan amendment) MUST be refused with a distinct message.
- **FR-015** [H+D]: An unlocked wallet MUST stay unlocked for the rest of the app process
  lifetime unless it is locked by FR-016, FR-017 or FR-018; a new process always starts with
  every wallet locked.
- **FR-016** [H]: The app MUST lock each wallet after an idle timeout (default 15 minutes,
  range 1-240 minutes, cannot be disabled) measured on a clock that counts time since boot
  including deep sleep, from the last deliberate person action on that wallet (002 FR-020
  list); sync activity MUST NOT reset the timer.
- **FR-017** [H+D]: The app MUST lock all wallets immediately when the device screen turns off
  (the phone equivalent of 002 FR-020a suspend detection); this is always on and has no
  setting.
- **FR-018** [H]: The person MUST be able to lock one wallet or all wallets at any time; locking
  wipes decrypted data and cancels reveals; a pending clipboard clearance runs immediately.
- **FR-019** [H]: Changing a wallet's master password MUST use the 001 operation and require the
  current master password.

**Credentials and clipboard**

- **FR-020** [H]: For an unlocked wallet the person MUST be able to add, view, edit and delete
  credentials (001 fields) and search them with the 001 case-insensitive substring search;
  every change MUST be saved atomically before success is shown.
- **FR-021** [H+D]: The person MUST be able to copy a username or password with one action; the
  clipboard entry MUST carry the platform's sensitive-content marking so the system does not
  display it in clipboard previews.
- **FR-022** [H+D]: Every copied value MUST be cleared from the clipboard after the clipboard
  timeout (default 30 seconds, range 5-300 seconds) and immediately on lock (including the
  screen-off lock of FR-017), also while the app is in the background, only if the clipboard still holds the copied value or its content
  cannot be checked; a countdown MUST be shown while a clearance is pending.
- **FR-023** [H]: If the app process ends before a pending clearance, the app MUST clear the
  clipboard at its next start when a clearance-pending marker (non-secret, no value or hash of
  it) exists.
- **FR-024** [H+D]: A revealed password MUST hide itself after the clipboard timeout, on lock,
  and when the person leaves the credential view.
- **FR-025** [H+D]: Master-password and password fields MUST be marked as password input that
  the keyboard must not learn from, suggest, or offer to save to any autofill provider.

**Screen and UI protections**

- **FR-026** [H+D]: Every app window, including dialogs, MUST set the platform's secure-window
  flag (blocks screenshots, screen recording, casting of content and insecure displays); it is
  always on and not configurable.
- **FR-027** [H+D]: The app MUST disable its recents-overview screenshot so no app content
  appears in the task switcher.
- **FR-028** [H+D]: The UI MUST be in English, every control MUST have an accessibility label,
  and all flows MUST be operable with the system screen reader (host check: labels and strings; device check: D25).
- **FR-029** [H]: The app MUST NOT embed a web view or load any web content.

**Storage and backup**

- **FR-030** [H]: Wallets MUST be stored only in the app's private internal storage directory,
  one encrypted file per wallet, using the existing atomic file adapter; the app MUST NOT use
  shared or external storage, media stores or any file-sharing provider.
- **FR-031** [H]: Every file the app writes (wallets, sync and share records, settings,
  identity) MUST be created owner-only in the app-private directory; plaintext secrets MUST
  never be written. Non-secret sync, share and settings records are stored as on the desktop
  (not key-store encrypted); only the identity and pins are (FR-034).
- **FR-032** [H+D]: Platform backup MUST be disabled and the data-extraction rules MUST exclude
  every app file from both cloud backup and device-to-device transfer.
- **FR-033** [H]: Settings (idle timeout, clipboard timeout, networking on/off, device name,
  sync safety interval 15 minutes-24 hours default 1 hour, optional interface restriction) MUST
  be stored in an app-private file, validated on load (invalid values fall back to the
  defaults with networking off, and the person is told), and changed only from the settings
  screen.

**Device identity and the platform key store**

- **FR-034** [H+D]: The 003 device identity private key and the pinned-peer records MUST be
  stored only encrypted with a non-exportable app key held in the platform key store
  (hardware-backed when available); the encrypted blob MUST be authenticated so tampering is
  detected (003 FR-005 behaviour: refuse and report).
- **FR-035** [H]: The platform key store MUST NOT be used for, and MUST NEVER receive, any master
  password, wallet key, derived key or wallet content; no key that can recover a wallet key may
  be persisted anywhere.
- **FR-036** [H]: The device name MUST default to a generic label ("passwsync device" plus the
  first 4 fingerprint characters, 003 FR-006), never the device owner's name or the
  platform's user-visible device name.
- **FR-037** [H+D]: If the identity cannot be opened (key store failure or invalidated key),
  networking MUST stay off and the app MUST offer to create a new identity, which removes all
  pins; wallets are not affected.

**Networking (LAN only)**

- **FR-038** [H+D]: Networking MUST be off by default; turning it on MUST require an explicit
  confirmation in settings stating that it uses the local network only and only with paired
  devices. With networking off, the app MUST open no socket.
- **FR-039** [H]: With networking on, the app MUST use exactly the 003 peer listener and
  discovery socket (configured ports, defaults 27472/27473) and apply the 003 IPv4
  private/link-local filter to every inbound and outbound packet and connection; IPv6 and
  every other destination are out of scope and dropped. Sockets MUST be used only on Wi-Fi or
  Ethernet interfaces with such an address, never on a VPN, mobile-data or other tunnel
  interface; with no eligible interface the status shows "no local network".
- **FR-040** [H]: The app MUST NOT perform DNS lookups or contact any internet host, relay,
  discovery server, update, analytics, crash-reporting or advertising service, and MUST NOT
  include any library that does.
- **FR-041** [H+D]: The network security configuration MUST forbid cleartext traffic to every
  host without exceptions (the app has no loopback server, so no loopback exception), trust no
  user-added certificate authorities, and declare no domain-specific overrides.
- **FR-042** [H+D]: Networking MUST be active only while the app is in the foreground or inside
  a background sync window (FR-044); sockets MUST be closed within 10 seconds after the app
  leaves the foreground unless a window is running or a transfer is in progress. A transfer in
  progress when the app leaves the foreground MAY continue for at most 2 minutes from that
  moment; then every socket closes and an unfinished transfer is discarded (retried by 004
  rules for sync; a share must be redone).
- **FR-043** [H+D]: Any platform facility needed to receive discovery datagrams (e.g., a
  multicast/broadcast reception lock) MUST be held only while networking is active and
  released when it stops.

**Background sync (battery-aware)**

- **FR-044** [H+D]: Background sync MUST use the platform's deferrable job scheduling to run a
  sync window at the 004 safety interval, only when networking is on, at least one paired
  device exists, an eligible Wi-Fi or Ethernet interface exists (FR-039), and the battery is
  not low; the
  platform's power management (Doze, app standby, battery saver) MAY defer it and the app
  MUST NOT try to bypass it (no exact alarms, no battery-optimisation exemption request, no
  persistent foreground service or notification).
- **FR-045** [H]: A sync window MUST last at most 2 minutes: it announces, connects to reachable
  paired peers, runs 004 rounds, and ends early as soon as every reachable peer's round has
  finished; it then closes every socket and releases every lock it took.
- **FR-046** [H+D]: When the app leaves the foreground with local changes not yet received by
  any paired peer, exactly one additional window MUST be scheduled under the same conditions
  as FR-044; no other background work may be scheduled.
- **FR-047** [H]: Inside windows and in the foreground the 004 rules apply unchanged: event
  triggers, 5-second coalescing, exponential back-off (30 seconds to 1 hour with jitter),
  concurrency and buffer bounds, rollback and replay protection, ciphertext-only storage of
  received copies, and merge only while the wallet is unlocked.
- **FR-048** [H+D]: With networking off or no paired device, the app MUST schedule no
  background work and cause no wakeups.
- **FR-049** [H]: Sync status (per wallet and per paired device), "Sync now" (foreground only),
  the conflict list and conflict resolution MUST be available as on the desktop (004
  FR-032-FR-036).

**Pairing and sharing**

- **FR-050** [H]: Pairing MUST follow 003 exactly (code at least 8 digits, PAKE, key
  confirmation, fingerprint and name confirmation on the initiator, pin on success, refusal
  rules, timeouts) with the phone able to act as initiator (shows the code) or joiner (types
  the code); QR display and scanning are not offered.
- **FR-051** [H]: Pairing, revocation, invitation creation and redemption MUST be possible only
  while the app is in the foreground; leaving the foreground MUST cancel an active pairing or
  an invitation whose transfer has not started.
- **FR-052** [H]: Sharing MUST follow 005 exactly (scoped single-use invitation, at least 8
  digits, held in memory only, recipient confirmation, ciphertext-only transfer, explicit
  open with the master password, 24-hour deletion of unopened received wallets checked at app
  start and at each window, deletion at revocation).
- **FR-053** [H]: Pairing and revocation MUST NOT require unlocking a wallet or entering a
  master password.

**Permissions and app components**

- **FR-054** [H+D]: The app MUST request only the permissions needed for LAN sockets, network
  state and discovery-datagram reception (and any local-network permission the target Android
  version requires for LAN access); it MUST NOT request camera, location, contacts, accounts,
  storage, notifications, boot-completed, battery-optimisation exemption, exact alarm, or
  foreground-service permissions. The host check enforces an explicit allow-list on the
  app's own manifest; the device check confirms the final merged manifest of the built app.
- **FR-055** [H]: Only the launcher screen MUST be exported; every other component MUST be
  non-exported; the app MUST declare no content providers for other apps, no deep links, no
  intent filters other than the launcher, and accept no data from other apps.
- **FR-056** [H]: The app MUST NOT use any account, sign-in, platform account manager, cloud
  service, proprietary platform services library, or advertising identifier.

**Logging**

- **FR-057** [H]: Logs MUST contain only the non-secret events of 002-005 plus app lifecycle
  events (protection level, networking on/off, window start/end with counts); secrets,
  credential titles, usernames, URLs, codes and file contents MUST never be logged.

**Verification**

- **FR-058** [H]: The project MUST provide one offline host verification entry point that runs:
  the boundary-crate and affected-crate tests, the host build of the scaffolding, binding
  source generation, XML well-formedness of the manifest and resources, the manifest/XML
  policy checks (FR-032, FR-041, FR-054, FR-055), the source policy scan (FR-021 sensitive
  marking, FR-025, FR-026, FR-027, FR-029, FR-030, FR-040, FR-056, FR-057), and the app-language
  linter when one is installed (skipped with a notice otherwise).
- **FR-059** [H]: Each policy check MUST have a negative test (a deliberately violating sample
  that the check rejects) so a check cannot silently pass.
- **FR-060** [D]: The feature documentation MUST list the device-only manual checks (build and
  install, every user story on a device, desktop interoperability, screenshot/recents/backup
  attempts, clipboard preview, screen-reader operation, protection level on the status screen, merged-manifest
  permissions, background-window behaviour under Doze and on mobile data, battery and wakeup
  measurement) with expected results, recorded as pending until run.

**Scope boundaries**

- **FR-061**: This feature MUST NOT include biometric unlock, an autofill service, QR scanning
  or display, wallet import/export, a password generator, root/tamper detection, app-store
  publishing or release signing, IPv6, internet or relay sync, or any change to the wallet
  format or the 003-005 protocols.

### Key Entities

- **App host instance**: the single app process; holds the wallet registry, the networking
  runtime when active, settings and the achieved protection level.
- **Wallet file**: the 001/004 encrypted file, one per wallet, in app-private storage.
- **Device identity**: the 003 keypair and name; the private key is stored encrypted under the
  platform key store app key.
- **Pinned peer**: a paired device (003), stored encrypted with the identity.
- **Sync records / pending copies**: the 004 per-wallet and per-peer records and ciphertext
  copies, in app-private storage.
- **Invitation / received wallet**: the 005 in-memory invitation and stored received
  ciphertext awaiting open or deletion.
- **Settings**: idle timeout, clipboard timeout, networking switch, device name, safety
  interval, optional interface.
- **Sync window**: a bounded background run (at most 2 minutes) scheduled by the platform.
- **Clearance-pending marker**: a non-secret flag that a clipboard clear is due.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001** [H]: The offline host verification entry point passes every check on a clean
  checkout with a pre-fetched dependency cache, no network and no Android SDK/NDK.
- **SC-002** [H]: 100% of policy checks reject their violating sample and accept the real app
  sources (manifest, XML, source scan).
- **SC-003** [H]: Host tests of the boundary crate cover every exported operation, and in 100%
  of secret-handling tests no master password, key or credential password appears in an error,
  log line or list/search result.
- **SC-004** [H]: passwsyncd's full test suite passes unchanged after shared runtime code is
  reused by the boundary crate (zero behaviour regressions).
- **SC-005** [D]: On a mid-range device, a person can create a wallet, add a credential and copy
  its password in under 2 minutes, and unlock an existing wallet (default key-derivation
  parameters) in under 3 seconds.
- **SC-006** [D]: In 100% of attempts, screenshots, screen recordings and the recents preview
  show no app content, and a backup/transfer contains no app file.
- **SC-007** [D]: A copied password is gone from the clipboard within the timeout plus 5 seconds
  in 100% of trials, including with the app in the background.
- **SC-008** [D]: With networking off, the app causes zero background wakeups over 24 hours; with
  networking on, the default interval and no changes, it runs at most 1 window per hour plus at
  most 1 per foreground exit with unsent changes, each closing within 2 minutes.
- **SC-009** [D]: With networking on and an hourly interval, the app's battery use attributed by
  the system over 24 hours idle is under 1% of battery capacity.
- **SC-010** [D]: A phone and a passwsyncd desktop pair, sync a change in both directions and
  share a wallet in both directions with no behaviour difference from two desktops.
- **SC-011** [D]: The app's memory use with one unlocked wallet of 1,000 credentials stays under
  128 MiB outside key derivation.
- **SC-012** [D]: The status screen shows the achieved memory-protection level on 100% of
  launches, and core dumps are confirmed disabled on the device.

## Assumptions

- Target: Android 13 (API 33) or newer phones; the plan picks the compile/target version and
  confirms whether the target version needs a runtime local-network permission.
- The app's UI language is Kotlin with the platform UI toolkit; the binding generator is UniFFI
  (as named by the feature input); both are confirmed and pinned in the plan, adding as few
  third-party libraries as possible (platform job scheduling, platform key store, platform
  clipboard).
- Building the app, cross-compiling the Rust crates for Android targets, running it, and
  measuring battery need the Android SDK/NDK and a device or emulator; these are not in the
  development environment and are manual checks.
- The binding generator crate is fetched once into the local dependency cache (security review
  and exact pinning per the constitution); host verification then runs offline.
- No app-language linter or compiler is installed on the host; the source policy scan works on
  text and the linter step is skipped with a notice until one is installed.
- Android does not swap process memory to persistent storage by default (compressed in-memory
  swap only); this is why partial memory locking is accepted as "where possible" for FR-025a,
  while core-dump/non-dumpable protections remain mandatory.
- The 002 settings ranges, 003 ports and address filter, 004 timings and 005 rules are reused
  as-is; desktop and phone use the same protocol versions.
- Distribution (app store or side-loading) and release signing are decided later; the person
  is assumed to install a build they trust.
- Screen-reader access to visible content is an accepted residual risk of any app UI and is
  documented, not mitigated.
