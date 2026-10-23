# Feature Specification: Local Service with Web UI

**Feature Branch**: `feat/002-local-service-web-ui`

**Created**: 2026-10-23

**Status**: Draft

**Input**: User description: "FEATURE 002: local-service-web-ui. A local background service (daemon) bound only to the loopback interface 127.0.0.1 that exposes a browser UI for the vault-core wallets from feature 001. Capabilities: create a wallet protected by a master password (12-char minimum per 001); list the wallets known to this service; unlock a wallet with its master password once per device restart (the derived key stays in service memory only until lock, auto-lock or service stop; never persisted or sent); credential CRUD (add, view, edit, delete) and search; reveal and copy a credential password to the clipboard with automatic clipboard clearing after a short timeout; manual lock and auto-lock of unlocked wallets. Security: listener on loopback only; Host and Origin header checks against DNS rebinding; CSRF protection on all state-changing requests; a per-run random session token generated at service start and required by the UI; a strict Content-Security-Policy; all UI assets embedded and served locally with no external assets, fonts, CDNs or telemetry. Implements the FR-025a host obligations from feature 001: lock process memory against swap (mlock) where the OS allows, disable core dumps, and enforce auto-lock. Global rules: 100% offline, no accounts, no email, no login; each wallet's master password is the only secret; non-interactive."

## Context

Feature 001 (vault-core) delivered an encrypted wallet library with no user interface. This
feature is the first **host application**: a per-user background service, running on the
person's own computer, that serves a web interface reachable only from that same computer
through a browser at a loopback address. It is the desktop front-end later packaged for AUR
(feature 006) and extended with device sync (features 003-005).

**Operating model (inherited, binding)**:

- 100% offline. This feature never opens outbound network connections and listens only on
  the loopback interface. No external assets, fonts, CDNs, update checks, or telemetry.
- No accounts, no email, no login, no person identity. The "session token" in this feature
  is a per-run, machine-local capability that proves a browser tab was opened by the person
  who started the service; it is not a login and identifies no one.
- Each wallet's master password is the only secret. It is entered only to create or unlock a
  wallet, once per device restart per wallet (subject to auto-lock, see FR-020). The derived
  key lives only in the service's memory and is never persisted, logged, or sent to the
  browser.
- The service is a host executable embedding vault-core and therefore MUST satisfy the
  vault-core FR-025a obligations (memory locked against swap, core dumps disabled, auto-lock).

## Clarifications

### Session 2026-10-23

Non-interactive session: each answer is the recommended option, chosen as the most secure and
then simplest consistent with the constitution and roadmap global rules.

- Q: What counts as activity that resets a wallet's auto-lock idle timer? → A: Only requests caused by a deliberate person action on that wallet (view, reveal, copy, search, add, edit, delete). Background or automatic requests from an open page (status refresh, list polling) never reset the timer, so an open tab cannot keep a wallet unlocked forever.
- Q: Should unlocked wallets lock when the computer suspends or hibernates? → A: Yes. When the service detects that the computer was suspended (a gap between the wall-clock and the monotonic clock, checked before serving any request and by the auto-lock timer), it locks all wallets before serving anything. Desktop screen-lock detection is out of scope.
- Q: Can the launch address (session token) be used more than once? → A: No. The token is single-use: once exchanged for a browser session, the service invalidates it and writes a fresh token to the owner-only launch file, so a leaked or reused launch address grants nothing. Browser sessions stay valid until the service stops.
- Q: How long may a revealed password stay visible, and which copied values are auto-cleared? → A: A revealed password hides itself after the clipboard clear timeout (default 30 seconds), on lock, and when leaving the credential view; every copied value (username or password) is cleared from the clipboard by the same rule.
- Q: What may the service write to its log? → A: Only non-secret operational events: start/stop, the listening address and port, protections applied, wallet lock/unlock/auto-lock events identified by wallet name, rejected requests counted by reason (Host, Origin, CSRF, session, size, peer), and error classes. Never request bodies, tokens, cookies, query strings, credential titles, or any secret.
- Q: Where are the settings (port, auto-lock timeout, clipboard timeout) changed? → A: Only in a per-user, owner-only configuration file read at service start; the web UI shows them read-only and cannot change them, so a compromised browser page cannot weaken auto-lock or clipboard clearing. Invalid or out-of-range values make the service refuse to start with a clear message.
- Q: What language and accessibility baseline must the UI meet? → A: English only in this feature; every action is operable by keyboard alone, form fields have labels, and focus is visible. Localization is deferred.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create a wallet and add credentials from the browser (Priority: P1)

The person starts the service, opens the UI in their browser via the launch address the
service provides, creates a new wallet by choosing a name and a master password, and adds
credentials (title, username, password, URL, notes). The wallet is saved encrypted to disk
after every change.

**Why this priority**: This is the minimum viable desktop password manager: without a way to
create a wallet and store credentials through a UI, nothing else in this feature has value.

**Independent Test**: Start the service with an empty data directory, open the launch
address, create a wallet, add a credential, stop the service, and verify the wallet file on
disk exists, contains no plaintext marker of the credential, and unlocks with vault-core
using the chosen master password.

**Acceptance Scenarios**:

1. **Given** a running service with no wallets, **When** the person creates a wallet with a
   name and a master password of at least 12 characters entered twice identically, **Then**
   the wallet is created, saved encrypted to the data directory, appears in the wallet list,
   and is open (unlocked) in the UI.
2. **Given** the create form, **When** the master password is shorter than 12 characters or
   the two entries differ, **Then** creation is refused with a clear message and nothing is
   written to disk.
3. **Given** the create form, **When** the chosen name is empty, invalid, or already used by
   another wallet, **Then** creation is refused with a clear message and no existing wallet
   is changed.
4. **Given** an unlocked wallet, **When** the person adds a credential with a title, **Then**
   it appears in the credential list and the wallet file on disk is updated before the UI
   reports success.

---

### User Story 2 - Unlock once, use all day (Priority: P1)

After the computer restarts, the person opens the UI, sees the list of wallets, and unlocks
the one they want by entering its master password. From then on, reloading the page, closing
and reopening the browser tab, or opening the UI in another tab does not ask for the master
password again until the wallet is locked (manually, by auto-lock, or by service stop).

**Why this priority**: "Unlock once per device restart per wallet" is a global product rule;
without it every interaction would require re-entering the only secret.

**Independent Test**: With an existing wallet file, start the service, unlock the wallet
through the UI, reload the page and open a second tab, and verify credentials are visible in
both without re-entering the password; stop and restart the service and verify the wallet is
locked again.

**Acceptance Scenarios**:

1. **Given** wallets in the data directory, **When** the person opens the UI, **Then** every
   wallet is listed by name with its locked/unlocked state, and no secret is shown or
   required to see the list.
2. **Given** a locked wallet, **When** the person enters the correct master password,
   **Then** the wallet becomes unlocked and its credentials are listed.
3. **Given** a locked wallet, **When** the person enters a wrong master password, **Then**
   unlock fails with the single generic message "invalid password or corrupted wallet" and
   the wallet stays locked.
4. **Given** an unlocked wallet, **When** the page is reloaded or a new UI tab is opened
   within the same service run, **Then** the wallet is still unlocked and no password is
   requested.
5. **Given** an unlocked wallet, **When** the service process stops (including computer
   restart), **Then** the next service run starts with every wallet locked.
6. **Given** a wallet file copied from another device, **When** it is placed in the data
   directory and unlocked with its master password, **Then** it opens with all credentials;
   no other secret or identity is required.

---

### User Story 3 - Manage and find credentials (Priority: P2)

The person views a credential's details, edits any of its fields, deletes credentials they
no longer need, and searches across their credentials by text.

**Why this priority**: Day-to-day maintenance and lookup; builds on Stories 1 and 2.

**Independent Test**: In an unlocked wallet with several credentials, edit one, delete one,
search for a known fragment, and verify list, search, and the on-disk wallet (after
restart and unlock) all reflect the changes.

**Acceptance Scenarios**:

1. **Given** an unlocked wallet, **When** the person opens a credential, **Then** its title,
   username, URL, and notes are shown and the password is hidden until explicitly revealed.
2. **Given** an open credential, **When** the person edits any field and saves, **Then** the
   change is persisted and visible in the list.
3. **Given** a credential, **When** the person deletes it and confirms, **Then** it no longer
   appears in the list or search results.
4. **Given** credentials "GitHub", "GitLab", and "Bank", **When** the person searches "git",
   **Then** only "GitHub" and "GitLab" are shown; the password field is never searched.

---

### User Story 4 - Copy a password safely (Priority: P2)

The person copies a credential's username or password to the clipboard with one action to
paste it into another application; any copied value is cleared from the clipboard
automatically after a short time.

**Why this priority**: Copying is the primary way a password manager is used; auto-clear
limits exposure of secrets left in the clipboard.

**Independent Test**: Copy a password, verify the clipboard holds it, wait for the clear
timeout, and verify the clipboard no longer holds it.

**Acceptance Scenarios**:

1. **Given** an open credential, **When** the person activates "copy password", **Then** the
   password is placed in the clipboard and the UI shows a visible countdown until clearing.
2. **Given** a copied password, **When** the clear timeout (default 30 seconds) elapses,
   **Then** the clipboard is cleared if it still holds the copied value.
3. **Given** a copied password, **When** the wallet is locked before the timeout, **Then** the
   clipboard is cleared immediately (if it still holds the copied value).

---

### User Story 5 - Lock and auto-lock (Priority: P2)

The person can lock a wallet (or all wallets) at any time. Unlocked wallets lock themselves
automatically after a period without activity, so an unattended computer does not leave
credentials accessible indefinitely.

**Why this priority**: Auto-lock is a mandatory host obligation (vault-core FR-025a) and the
main mitigation against an unattended unlocked computer.

**Independent Test**: Unlock a wallet, wait past the idle timeout without interacting, and
verify the wallet is locked and its credentials cannot be retrieved; separately, use "lock"
and verify the same.

**Acceptance Scenarios**:

1. **Given** an unlocked wallet, **When** the person activates "lock", **Then** the wallet's
   decrypted data and key are discarded from service memory and every UI tab shows it as
   locked.
2. **Given** an unlocked wallet, **When** no deliberate person action touches that wallet for
   the idle timeout (default 15 minutes), even while a UI tab stays open and refreshes in the
   background, **Then** the wallet is locked automatically.
3. **Given** unlocked wallets, **When** the computer is suspended and later resumed, **Then**
   all wallets are locked before any request is served.
4. **Given** a locked wallet, **When** any request tries to read or change its credentials,
   **Then** the request is refused and no credential data is returned.

---

### User Story 6 - Only the local person's browser can use the service (Priority: P1)

Other computers on the network, other websites open in the same browser, and other local
users cannot use the service, even when a wallet is unlocked.

**Why this priority**: Security-First (non-negotiable). An unlocked wallet served over HTTP
is a high-value target for DNS-rebinding, CSRF, and cross-site attacks.

**Independent Test**: With a wallet unlocked, send requests from another host, with a
foreign Host header, with a foreign Origin, without the session token, and without the CSRF
token, and verify every one is refused without returning wallet data or changing state.

**Acceptance Scenarios**:

1. **Given** the running service, **When** another machine tries to connect, **Then** the
   connection cannot be established because the service listens on loopback only.
2. **Given** a request whose Host header is not the service's exact loopback address and
   port, **When** it arrives, **Then** it is rejected before any processing (DNS rebinding).
3. **Given** a state-changing request whose Origin is missing or not the service's own
   origin, or that lacks a valid CSRF token, **When** it arrives, **Then** it is rejected and
   nothing changes.
4. **Given** a request without a valid session for the current service run, **When** it asks
   for anything other than the session-establishment step, **Then** it is rejected.
5. **Given** a session established in a previous service run, **When** it is used after the
   service restarts, **Then** it is rejected and the person must use the new launch address.
6. **Given** any served page, **When** the browser loads it, **Then** it loads no resource
   from outside the service and the content-security policy forbids inline scripts, framing,
   and external connections.

---

### Edge Cases

- Service started while another instance is running for the same user: the second instance
  refuses to start with a clear message; the first continues unaffected.
- Configured port already in use by another program: the service refuses to start with a
  clear message (it does not silently pick another port or bind another interface).
- Memory locking unavailable or core-dump disabling fails: the service refuses to start and
  reports which protection failed (fail closed; see FR-028 to FR-031).
- Wallet file in the data directory that is corrupted, truncated, or of an unsupported
  version: listed by name, unlock fails with the vault-core error class, other wallets work.
- Wallet file deleted or replaced on disk while unlocked: the next save writes the in-memory
  wallet atomically; the service does not attempt merging (sync is out of scope).
- Disk full or write error on save: the UI reports the failure, the in-memory change is
  rolled back, and the previous file stays intact.
- Two browser tabs editing the same credential: last successful save wins; each save is
  whole-credential replacement as in vault-core.
- Several unlock attempts submitted in parallel: processed one at a time per wallet, and key
  derivations run one at a time service-wide, so they cannot be used to multiply
  key-derivation work; requests for other wallets and the wallet list keep being served.
- Very many wallets (e.g., 100) or a 10,000-credential wallet: list and search remain
  within the success criteria.
- Browser closes before the clipboard timeout: clearing is best effort; the UI states that
  the clipboard is cleared only while the UI page remains open (see Assumptions).
- Request bodies larger than 8 MiB, or header blocks larger than 16 KiB: rejected without
  being fully buffered.
- Computer suspended with wallets unlocked: on resume, all wallets are locked before any
  request is served (FR-020a).
- Launch address opened a second time (reused, leaked, or from browser history): refused,
  because the token is single-use; the person uses the fresh address in the launch file.

## Requirements *(mandatory)*

### Functional Requirements

**Service lifecycle and launch**

- **FR-001**: The service MUST run as a per-user background process and listen only on the
  IPv4 loopback address 127.0.0.1, on a configurable port with a fixed default. It MUST NOT
  listen on any other interface and MUST NOT open outbound network connections.
- **FR-002**: At each start the service MUST generate a fresh random session token (at least
  128 bits from a cryptographically secure source) valid only for that run.
- **FR-003**: The service MUST make a launch address containing the session token available
  only to the user who started it, by writing it to a file readable only by that user in the
  per-user runtime directory, and MUST NOT write the token to logs or standard output.
- **FR-004**: Visiting the launch address MUST exchange the token for a session credential
  held by the browser that is inaccessible to page scripts, restricted to the service's own
  origin, and not sent on cross-site requests; the browser MUST then be redirected to a URL
  without the token. The launch token is single-use: on exchange the service MUST invalidate
  it and write a fresh token to the launch file. Browser sessions stay valid until the service
  stops, except that at most 32 are kept at once: creating a 33rd evicts the oldest (bounded
  memory; an evicted browser reopens the current launch address).
- **FR-005**: Only one service instance per user MUST run at a time; a second start MUST
  fail with a clear message.
- **FR-006**: The service MUST generate a device identifier on first run, persist it in the
  per-user configuration directory, and use it for all vault-core change tracking.

**Request protection**

- **FR-007**: Every request MUST be rejected unless its Host header exactly equals the
  service's loopback address and port (`127.0.0.1:<port>`); this check runs before routing.
- **FR-007a**: Every connection MUST originate from a socket owned by the same OS user that
  started the service (checked in the kernel socket table before any request is read); other
  local users are refused even if a launch token or session leaks. Such connections are closed
  without a response and counted as reason `peer`.
- **FR-008**: Every state-changing request MUST be rejected unless its Origin header is
  present and exactly equals the service's own origin.
- **FR-009**: Every state-changing request MUST carry a valid per-session CSRF token bound to
  the session and checked in constant time.
- **FR-010**: Every request other than session establishment and static UI assets MUST
  require a valid session for the current run; sessions from earlier runs MUST be rejected.
- **FR-011**: Every response MUST carry a strict content-security policy that allows scripts,
  styles, images, and connections only from the service itself, forbids inline scripts and
  `eval`, forbids being framed, and forbids form submission elsewhere; plus headers that
  disable caching of responses, MIME sniffing, and referrer leakage.
- **FR-012**: All UI assets (markup, scripts, styles, icons) MUST be embedded in the service
  executable and served by it; no page may reference any external resource, font, CDN, or
  analytics endpoint.
- **FR-013**: Request bodies and header sizes MUST be bounded, and requests exceeding the
  bounds MUST be rejected without being fully read into memory.

**Wallets**

- **FR-014**: The service MUST store wallets as one encrypted file per wallet in a per-user
  data directory (created with owner-only permissions), using the vault-core file adapter.
- **FR-015**: The person MUST be able to create a wallet by giving a name and entering a
  master password twice; the service MUST enforce the vault-core 12-character minimum and
  matching entries, and MUST refuse names that are empty, already used, or contain
  characters outside a safe set (ASCII letters A-Z and a-z, digits 0-9, space, `-`, `_`, `.`;
  1 to 64 characters; not starting with `.`; not ending with a space).
- **FR-016**: The service MUST list every wallet file in the data directory by name, with its
  locked/unlocked state, without requiring any secret.
- **FR-017**: The person MUST be able to unlock a wallet with its master password; failures
  MUST show only the vault-core generic error (or a format error), never which part failed.
  Unlock attempts for the same wallet MUST be processed one at a time, and key derivations
  run one at a time service-wide.
- **FR-017a**: Before any key derivation, the service MUST read the wallet's KDF parameters
  without the password and refuse a wallet whose Argon2 memory exceeds 128 MiB (131 072 KiB)
  with `kdf_params_out_of_range`; no key derivation runs for such a wallet.
- **FR-018**: An unlocked wallet MUST remain unlocked for the rest of the service run, across
  page reloads and tabs, until manual lock, auto-lock, or service stop; the master password
  MUST NOT be requested again in that period.
- **FR-019**: The person MUST be able to lock one wallet or all wallets at any time; locking
  MUST discard the wallet's decrypted data and key from service memory (vault-core lock).
- **FR-020**: The service MUST automatically lock each unlocked wallet after a configurable
  idle timeout (default 15 minutes; allowed range 1 to 240 minutes; it cannot be disabled),
  measured from the last deliberate person action on that wallet (view, reveal, copy,
  search, add, edit, delete; unlock is deliberate too). Background or automatic requests from an open page (status
  refresh, list polling) MUST NOT reset the idle timer.
- **FR-020a**: When the service detects that the computer was suspended or hibernated (the
  wall clock advanced more than the monotonic clock by more than 5 seconds), it MUST lock all wallets before serving
  any further request. Desktop screen-lock detection is out of scope.
- **FR-021**: The master password MUST be passed to vault-core and wiped right after key
  derivation; it MUST NOT be stored, logged, echoed back, or kept by the UI after submission.

**Credentials**

- **FR-022**: For an unlocked wallet, the person MUST be able to add, view, edit, and delete
  credentials with the vault-core fields (title required; username, password, URL, notes
  optional), with deletion requiring confirmation.
- **FR-023**: Every successful change MUST be saved atomically to the wallet file before the
  UI reports success; if saving fails, the in-memory wallet MUST be returned to its previous
  state and the failure shown.
- **FR-024**: The credential list and search results MUST NOT include passwords; a password
  MUST be sent to the browser only when the person explicitly reveals or copies it for one
  credential.
- **FR-025**: The person MUST be able to search credentials with the vault-core
  case-insensitive search (title, username, URL, notes; never password).

**Clipboard**

- **FR-026**: The person MUST be able to copy a credential's username or password to the
  clipboard with one action.
- **FR-027**: After copying any value (username or password), the UI MUST clear the clipboard
  after a configurable timeout (default 30 seconds) and immediately when the wallet is locked,
  in each case only if the clipboard still holds the copied value or its contents cannot be
  checked; the UI MUST show a countdown while a copied value is pending clearance.
- **FR-027a**: A revealed password MUST hide itself after the same timeout, on lock, and when
  the person leaves the credential view.

**Host obligations (vault-core FR-025a)**

- **FR-028**: Before any wallet is unlocked or created, the service MUST lock all its current
  and future memory against swapping. The process memory-lock limit (`RLIMIT_MEMLOCK`) MUST be
  at least 256 MiB or unlimited; a lower limit is a protection failure under FR-031.
- **FR-029**: At start the service MUST disable core dumps for itself and mark itself
  non-dumpable so other unprivileged processes of the same user cannot read its memory.
- **FR-030**: Auto-lock (FR-020) and lock-on-stop MUST be enforced by the service itself; on
  normal stop (including termination signals) every unlocked wallet MUST be locked before
  exit.
- **FR-031**: If any protection in FR-028 or FR-029 cannot be applied, the service MUST
  refuse to start and report which protection failed; there is no option to run without
  them.

**Settings and UI baseline**

- **FR-031a**: Settings (port 1024–65535, default 27471; idle auto-lock 1–240 minutes, default 15; clipboard clear 5–300 seconds, default 30) MUST be read
  only from a per-user, owner-only configuration file at service start; missing values use the
  defaults, and invalid or out-of-range values MUST make the service refuse to start with a
  clear message. The UI MAY display settings but MUST NOT change them.
- **FR-031b**: The UI MUST be in English, with every action operable by keyboard alone,
  labelled form fields, and visible focus.

**Confidentiality of outputs**

- **FR-032**: Secrets (master passwords, keys, credential passwords and notes, session and
  CSRF tokens) MUST NOT appear in logs, error messages, URLs (after the launch exchange),
  or any file other than the encrypted wallet files and the owner-only launch file.
- **FR-033**: Responses carrying credential data MUST NOT be cacheable by the browser.
- **FR-033a**: The service log MUST contain only non-secret operational events: start/stop,
  listening address and port, protections applied, wallet lock/unlock/auto-lock events
  identified by wallet name, rejected requests counted by reason (Host, Origin, CSRF,
  session, size, peer), and error classes. It MUST NOT contain request bodies, tokens, cookies,
  query strings, credential titles, or any secret.

**Scope exclusions**

- **FR-034**: This feature MUST NOT include device sync, pairing, sharing, packaging,
  password generation, credential history, import/export, master-password change, wallet
  deletion or renaming through the UI, remote access, or any account, email, or login.

### Key Entities

- **Service run**: One execution of the service; owns the session token, the set of unlocked
  wallets, and their idle timers. Nothing from a run survives its end except encrypted wallet
  files and the device identifier.
- **Session token / launch address**: Per-run random capability delivered to the local user
  through an owner-only file; single-use, exchanged for a browser session and then replaced
  by a fresh token in the launch file.
- **Browser session**: A browser's proof of having presented the run's token; carries a CSRF
  token; invalid in any other run.
- **Wallet (file)**: A vault-core encrypted wallet stored as one file in the data directory;
  its file name is its display name (not secret).
- **Unlocked wallet**: A vault-core vault held in service memory with its last-activity time.
- **Device identifier**: Opaque per-device tag created on first run, persisted in the
  configuration directory, used only for vault-core change tracking.
- **Settings**: Port, idle auto-lock timeout, clipboard clear timeout; non-secret, per-user,
  stored in an owner-only configuration file, read-only from the UI.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person can go from starting the service to having a new wallet with one saved
  credential in under 2 minutes, without reading documentation beyond the launch address.
- **SC-002**: After one unlock, 100% of page reloads and new tabs in the same run show the
  wallet without asking for the master password; 100% of service restarts start with all
  wallets locked.
- **SC-003**: 100% of tested requests with a foreign Host, foreign or missing Origin on state
  changes, missing/invalid CSRF token, missing/stale session, or from a non-loopback address
  are refused without returning wallet data or changing state.
- **SC-004**: Unlocked wallets are locked within 1 minute after the idle timeout elapses in
  100% of tests (including after a simulated suspend).
- **SC-005**: A copied username or password is cleared from the clipboard within 2 seconds after the
  clear timeout while the UI is open.
- **SC-006**: Automated scans find zero external resource references in served UI assets and
  zero occurrences of known secret markers in logs, stdout/stderr, and files other than
  encrypted wallets and the launch file.
- **SC-007**: List and search over a 10,000-credential wallet appear in the UI in under
  300 ms after the request on the reference laptop.
- **SC-008**: Service memory while idle with one unlocked 1,000-credential wallet stays below
  50 MB, and idle CPU use is negligible (no busy polling).
- **SC-009**: The service refuses to start in 100% of tests where memory locking or core-dump
  disabling is made to fail.

## Assumptions

- Target platform for this feature is Linux desktop (the AUR target); per-user directories
  follow the XDG conventions (data, configuration, runtime). Other OSes are out of scope.
- The person who starts the service is the only intended user; other local OS users are
  excluded by owner-only file permissions, the peer-UID check (FR-007a) and the session token.
- The browser is a current mainstream browser supporting the clipboard API, strict
  same-site session credentials, and content-security policy. Plain HTTP on loopback is
  acceptable because traffic never leaves the machine.
- Clipboard clearing is performed by the UI page; if the page is closed before the timeout,
  clearing cannot be guaranteed. The UI states this when copying.
- Wallet names are not secret; they are visible as file names.
- Starting the service at login and opening the browser are provided by packaging (006) or
  by the person; this feature provides a command to start the service and the launch file.
- The service memory locking requires a sufficient locked-memory limit; packaging (006)
  configures it, and this feature documents the required amount.
- Only this service writes wallet files in the data directory during a run; concurrent
  external writers and merging are handled by the sync features.
- Default timeouts (15-minute auto-lock, 30-second clipboard clear) follow common password
  manager practice (KeePassXC uses comparable defaults).
