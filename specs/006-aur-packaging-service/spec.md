# Feature Specification: AUR Packaging of the Local Service

**Feature Branch**: `feat/006-aur-packaging-service`

**Created**: 2026-10-28

**Status**: Draft

**Input**: User description: "Feature 006 aur-packaging-service: Arch Linux AUR packaging of the passwsyncd service (PKGBUILD source build with cargo, locked deps, checksums, reproducible build flags; hardened systemd user unit; install hooks never auto-enable networking; desktop entry launcher opening localhost URL via launch token; upgrade/uninstall never deletes user wallets; verification via namcap/systemd-analyze security, offline-testable)."

## Context

Features 001-005 deliver `passwsyncd`, a per-user service that serves a browser UI on
`127.0.0.1:27471` (002), and that, only when the person turns networking on in its
configuration file, opens one LAN peer listener (TCP 27472) and one discovery socket
(UDP 27473) restricted to IPv4 private and link-local addresses (003-005). Networking is off
by default. The service already enforces its own protections at start (core dumps off,
non-dumpable, memory locked against swap with a required locked-memory limit of at least
256 MiB, fail closed with exit code 3 otherwise) and keeps its files under the XDG
directories (`$XDG_CONFIG_HOME/passwsync`, `$XDG_DATA_HOME/passwsync`,
`$XDG_RUNTIME_DIR/passwsync`), refusing paths with group/other permission bits.

This feature makes the service installable on Arch Linux from the AUR: a source-building
package recipe, a hardened per-user service definition for the systemd user manager, a
desktop launcher that opens the UI through the single-use launch address, and install,
upgrade and removal behaviour that never touches the person's wallets or settings. It adds
**no** new service behaviour: the binary, its settings, ports, files and protections are
exactly those of 002-005.

**Operating model (inherited, binding)**:

- 100% offline at runtime; no accounts, email or login. Networking stays off unless the
  person edits their own configuration file; nothing in this package turns it on.
- The master password of each wallet is the only secret; the package never sees, stores or
  asks for it.
- The package confines the service further (defense in depth) but never weakens or replaces
  a protection the service itself enforces.

**Verification constraint**: Installing from the AUR, logging in as a desktop user and
running the user manager cannot be exercised in the build environment. Every outcome of this
feature is therefore defined so that it can be checked **offline** from the produced files:
recipe lint, package lint, service-definition analysis, desktop-entry validation, script
tests with a stand-in for the service, and a two-build reproducibility comparison. Real
installation on an Arch host is a documented manual check, not a gate.

## Clarifications

### Specification defaults 2026-10-28

Decisions taken while writing the specification (non-interactive): each is the most secure
and then simplest option consistent with the constitution and the roadmap global rules.

- Q: The per-user service manager on Arch has a hard locked-memory limit of 8 MiB, which a
  per-user service cannot raise, so the service would always fail its 256 MiB memory-lock
  requirement. How does the package provide the limit? → A: The package ships a drop-in for
  the per-user service manager (`user@.service`) that raises its locked-memory limit (soft and
  hard) to exactly 256 MiB, and the service definition requests 256 MiB. The new limit takes
  effect at the person's next login; until then the service fails closed (exit 3) and the
  post-install message says to log out and back in. No other limit is raised and no
  capability is granted.
- Q: Does installing the package enable or start the service? → A: No. Installation never
  enables, starts or restarts anything for any user. The person enables it with one
  documented command (start at login) or starts it on demand through the desktop launcher;
  the launcher starts the service for the current session but never enables it.
- Q: What happens if the person uses custom XDG base directories outside their home
  defaults? → A: The service definition grants write access only to the passwsync
  directories at the default XDG locations under the home directory
  (`~/.config/passwsync`, `~/.local/share/passwsync`) plus the runtime directory; with custom
  locations the service fails closed with its path error (exit 2), and the documentation shows
  the one-file override the person can add. Silent fallback to other locations is not allowed.
- Q: Should the package restrict IP destinations at the service-manager level (address
  allow-lists)? → A: No. The per-user service manager cannot enforce address allow-lists, so
  declaring them would give false assurance; the IPv4 private/link-local filter enforced by
  the service (003 FR-011) remains the control. The service definition restricts socket
  families instead (FR-010).
- Q: Where does the package source come from and how is it authenticated? → A: A tagged
  release source archive of this project, pinned by a strong checksum in the recipe; no
  version-control ("-git") variant and no unpinned download. Signature verification is added
  when the project starts signing releases (out of scope here).
- Q: What does upgrade do to a running service? → A: Nothing automatic. The running service
  keeps running the old binary until the person restarts it; the post-upgrade message says a
  restart locks all wallets and must be done by the person. The package never restarts,
  stops or kills a user's service.
- Q: How does the launcher pass the launch address to the browser, given that command-line
  arguments are visible to other local users? → A: It hands the address to the desktop's
  default URL opener, accepting the brief exposure because the address is single-use (002
  FR-004) and connections from other OS users are refused by the peer-UID check (002
  FR-007a). The launcher never prints, logs or stores the address anywhere else.

### Session 2026-10-28

Non-interactive `/speckit-clarify` session: each answer is the recommended option (most
secure, then simplest).

- Q: Should the confined service see the rest of the person's home directory read-only, or
  not at all? → A: Not at all. The home directory is replaced by an empty private view in
  which only the passwsync configuration and data directories are present (writable); files
  such as SSH keys or browser profiles are invisible to the service.
- Q: Which outputs must be identical across two builds, given that package metadata records
  the build directory path? → A: The service binary MUST be bit-identical across builds in
  different directories; the complete package file MUST be identical when both builds use
  the same build directory path (as reproducible-build rebuilders do), at different times and
  from different source clones.
- Q: Should the package ship debug symbols (a separate debug package or unstripped binary)?
  → A: No. The binary is stripped and no debug package is produced; this keeps the package
  minimal and the reproducibility comparison simple.
- Q: How does the launcher show an error when started from the menu without a terminal? →
  A: Through a desktop notification when a notification service is available (optional
  dependency), and always on standard error (captured by the journal); never through a
  dialog that echoes the launch address.
- Q: What are the package, launcher and unit names? → A: Package `passwsync`; binary
  `/usr/bin/passwsyncd`; launcher `/usr/bin/passwsync-open`; user unit `passwsyncd.service`;
  desktop entry `passwsync.desktop`; manager drop-in
  `/usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf`.

### Analysis remediation 2026-10-28

Decisions taken while fixing `/speckit-analyze` findings (non-interactive; each is the most
secure option that keeps the design working):

- Q: Does a failing pre-start step of the unit count as an "abnormal exit" exempt from the
  restart limit? → A: No exemption. `RestartPreventExitStatus` applies to the service process
  only, so pre-start failures are retried under the 5-in-5-minutes limit (FR-013, edge case).
- Q: Is the one pre-start step outside the sandbox allowed? → A: Yes, limited to creating the
  three passwsync directories and refusing custom XDG locations, as the person, with no added
  privilege (FR-011).
- Q: Must the sandbox probe use a mountpoint check? → A: No. Under `ProtectHome=tmpfs` the tmpfs
  is mounted on `/home`, so the probe checks the mount containing the home directory (research
  R11, measured on systemd 262).
- Q: Which FR-012 checks run offline? → A: The confinement probes (verify.md) run the unit's
  sandbox through the user manager; the regression map (unit-file.md) names the check for each
  directive. Behaviour that needs the real service, a second device or a login stays manual.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Build and install from source with a verifiable recipe (Priority: P1)

An Arch user builds the package from the AUR recipe. The recipe downloads one pinned
release archive, verifies its checksum, fetches the exact dependency versions recorded in the
project lock file, builds the service in release mode with deterministic flags, runs the
project's tests, and produces a package that installs the service binary, the per-user
service definition, the memory-limit drop-in, the launcher, its desktop entry and the
license.

**Why this priority**: Without a trustworthy, buildable package there is nothing to install;
supply-chain integrity (pinned source, locked dependencies, checksums) is the core security
promise of a source package.

**Independent Test**: Run the recipe linter on the recipe, build the package from a local
copy of the release archive with a pre-fetched dependency cache and networking disabled for
the build step, run the package linter on the result, and list the package contents.

**Acceptance Scenarios**:

1. **Given** the recipe, **When** the recipe linter runs, **Then** it reports no errors and
   any warning is listed and justified in the feature documentation.
2. **Given** a release archive whose content differs from the pinned checksum, **When** the
   package is built, **Then** the build stops before any compilation.
3. **Given** a lock file that does not match the dependency manifest, **When** the package
   is built, **Then** the build fails instead of resolving new dependency versions.
4. **Given** a successful build, **When** the package linter runs on the package, **Then**
   it reports no errors, and the package contains exactly the files listed in FR-015.
5. **Given** the build step, **When** it runs, **Then** it performs no network access (all
   dependencies were fetched in the preparation step).

---

### User Story 2 - Run the service confined, with networking still off (Priority: P1)

After installing, the person enables the per-user service (or starts it through the
launcher). It starts with a 256 MiB locked-memory limit, core dumps off, no way to gain
privileges, a read-only view of the system, a home directory in which only the passwsync
directories are visible, a private temporary directory, and only the socket families it needs. Because
nothing changed in their configuration file, networking is off and only the loopback UI
listens.

**Why this priority**: Security-First: the service holds unlocked wallets in memory; the
package must add confinement around it and must not open the network on its own.

**Independent Test**: Run the service-definition verifier and the offline security analysis
on the shipped definition; check the exposure score and that each directive in FR-006 to
FR-011 and FR-013 is present; run the confinement probes (FR-012) offline; inspect the package
for any file or script that writes a networking setting.

**Acceptance Scenarios**:

1. **Given** the shipped service definition, **When** the offline security analysis runs,
   **Then** the overall exposure score is 1.5 or lower.
2. **Given** the shipped service definition, **When** it is inspected, **Then** it sets a
   locked-memory limit of 256 MiB, a core-dump size of 0, no new privileges, an empty
   capability set, a private temporary directory, a strict read-only system, an owner-only
   file-creation mask, a hidden home directory with only the passwsync directories visible,
   and write access only to the passwsync directories.
3. **Given** a fresh install and a person with no passwsync configuration file, **When** the
   service starts, **Then** networking is off (only `127.0.0.1:27471` listens), because no
   package file, script or launcher writes or changes the configuration file.
4. **Given** the person has turned networking on in their own configuration file, **When**
   the confined service starts, **Then** the peer listener and discovery socket work (the
   confinement allows IPv4 and interface enumeration), and nothing else is opened.
5. **Given** the per-user service manager still has the old 8 MiB limit (no re-login since
   install), **When** the service starts, **Then** it fails closed with exit code 3 and its
   status shows the memory-lock failure; it is not restarted in a loop.

---

### User Story 3 - Open the UI from the desktop (Priority: P2)

The person picks "passwsync" from their desktop application menu. The launcher makes sure
the service is running for this session, waits for the current single-use launch address,
and opens it in the default browser, which lands on the UI with a fresh session.

**Why this priority**: Day-to-day convenience; the service is usable without it via the
documented manual command.

**Independent Test**: Validate the desktop entry with the desktop-entry validator; run the
launcher's automated tests with a stand-in service manager, a stand-in launch file and a
stand-in URL opener, covering service already running, service starting, timeout and wrong
permissions.

**Acceptance Scenarios**:

1. **Given** the desktop entry, **When** the validator runs, **Then** it reports no errors.
2. **Given** the service is running and the launch file exists, **When** the launcher runs,
   **Then** it passes exactly the address in the launch file to the default URL opener and
   exits 0.
3. **Given** the service is not running, **When** the launcher runs, **Then** it starts the
   per-user service (without enabling it), waits up to 10 seconds for the launch file, then
   opens it.
4. **Given** the launch file does not appear within 10 seconds, or is not a regular file
   owned by the person with owner-only permissions, or does not match the launch-address
   format `http://127.0.0.1:<port>/launch/<64 lowercase hex>`, **When** the launcher runs,
   **Then** it opens nothing, shows a clear error naming how to see the service status, and
   exits non-zero.
5. **Given** any launcher run, **When** its output and the system journal are inspected,
   **Then** the launch token appears in neither.

---

### User Story 4 - Upgrade and remove without losing wallets (Priority: P1)

The person upgrades to a new package version or removes the package. Their wallets,
received wallets, sync records, device identity, pairings and settings stay exactly as they
were; nothing in the package or its scripts reads, moves or deletes them.

**Why this priority**: Wallet files are the person's only copy of their secrets on that
device; a package manager action that deletes them is unrecoverable data loss.

**Independent Test**: Inspect the package's install script and file list; run the install
script's functions in a sandbox with a populated stand-in home directory and confirm no file
under it changes; confirm the package owns no path under any home directory.

**Acceptance Scenarios**:

1. **Given** a populated passwsync data and configuration directory, **When** the package is
   upgraded, **Then** every file in them is byte-identical and keeps its permissions.
2. **Given** the same, **When** the package is removed (including with the "remove
   configuration" option), **Then** every file in them is byte-identical, and the removal
   message states where the person's data remains and that removing it is their decision.
3. **Given** a running service, **When** the package is upgraded or removed, **Then** the
   package does not stop, restart or kill it, and the message tells the person to restart
   (upgrade) or stop and disable (removal) it themselves.

---

### User Story 5 - Reproducible build (Priority: P2)

A reviewer builds the package twice from the same release archive and toolchain, in
different build directories, at different times, and gets identical results, so anyone can
confirm a published binary came from the published source.

**Why this priority**: Reproducibility lets others audit the supply chain; it builds on
Story 1.

**Independent Test**: An automated script builds twice with the same source-date value in
two different directories and compares the checksums of the installed binary and of the
package file.

**Acceptance Scenarios**:

1. **Given** two builds from the same archive, lock file, toolchain and source-date value in
   different build directories, **When** their outputs are compared, **Then** the service
   binary is bit-identical.
2. **Given** two builds from separate copies of the same inputs using the same build
   directory path at different times, **When** their outputs are compared, **Then** the
   package files have identical checksums.
2. **Given** a build, **When** the binary is searched for the build directory path or the
   builder's home directory path, **Then** neither appears.

---

### Edge Cases

- Release archive download fails or is tampered with: checksum mismatch stops the build
  before compilation (FR-002).
- Builder has a modified global build configuration (custom compiler flags, link-time
  optimisation settings, debug options): the recipe's own deterministic settings still apply
  to the service build; the reproducibility check runs with the documented clean
  configuration.
- Person has an old manual install in `~/.cargo/bin` or elsewhere: the packaged service
  definition always runs the packaged binary by absolute path.
- Person already runs the service manually in a terminal: starting the packaged service
  fails with the existing "already running" result (exit 4) and is not restarted in a loop;
  the launcher still opens the running instance's launch address.
- Configuration error or bad directory permissions (exit 2), protection failure (exit 3) or
  port busy (exit 4) of the service process: the service manager does not restart the service.
  A failing pre-start step of the unit (for example the custom-location refusal or the
  sandbox probe, which run before the service process) is not covered by that rule; it is
  retried at most 5 times in 5 minutes and then stops (FR-013). Any other abnormal exit is
  restarted with a delay and a bounded number of attempts.
- Kernel without unprivileged user namespaces: per-user sandboxing cannot be applied; the
  service definition fails to start rather than running unconfined, and the documentation
  names the requirement.
- The confinement hides `/proc` entries the service relies on (the socket table read by the
  002 peer-UID check): not allowed; the peer-UID check must keep working under the shipped
  definition (FR-012).
- Data directory does not exist yet on first start: the service still starts and creates it
  with owner-only permissions; the confinement does not block first-run creation (FR-011).
- Person's default browser is not set: the launcher reports that no URL opener succeeded and
  exits non-zero without printing the address.
- Package removed while service is enabled: the enablement link in the person's home points
  to a missing definition; the removal message gives the disable command; the package does not
  edit the person's home.
- Package installed on a system with several users: the memory-limit drop-in applies to each
  user's service manager; no user's service is enabled or started by the package.

## Requirements *(mandatory)*

### Functional Requirements

**Package recipe and build integrity**

- **FR-001**: The package MUST be built from source by a recipe that downloads exactly one
  tagged release source archive of this project; no version-control variant, no other
  download and no prebuilt binary.
- **FR-002**: The recipe MUST pin the release archive with a strong cryptographic checksum
  (SHA-256 or stronger); no source entry may use a skip value.
- **FR-003**: All Rust dependencies MUST be the exact versions in the project lock file: the
  preparation step fetches them honouring the lock file, and the build and test steps run
  without network access and fail if the lock file would need to change.
- **FR-004**: The build MUST be deterministic: it MUST NOT embed any build-time timestamp (the
  source-date value is supplied by the builder environment, which makepkg honours; the
  verification fixes it to the release commit time), strip build-directory and home-directory paths from the binary, use
  a fixed set of release settings independent of the builder's global configuration, and
  build only the service package of the workspace. The installed binary MUST be stripped
  and no debug package may be produced.
- **FR-005**: The recipe MUST run the project's test suite for the service crates in its
  check step; failing tests MUST fail the package build. Tests that need privileges or a
  higher locked-memory limit than the build environment provides MAY be skipped only by
  name, listed in the recipe with the reason.

**Hardened per-user service definition**

- **FR-006**: The package MUST ship a per-user (systemd user) service definition that runs
  the packaged service binary by absolute path in the foreground, with no arguments, for the
  person's own account only.
- **FR-007**: The service definition MUST set a locked-memory limit of 256 MiB (soft and
  hard) and a core-dump size limit of 0. These complement and never replace the service's
  own checks (002 FR-028 to FR-031), which remain fail-closed.
- **FR-007a**: The package MUST ship a drop-in for the per-user service manager that raises
  its locked-memory limit to 256 MiB (soft and hard) so FR-007 can take effect, and MUST NOT
  raise any other limit or grant any capability.
- **FR-008**: The service definition MUST forbid gaining privileges (no new privileges, empty
  capability bounding and ambient sets, set-user-ID/set-group-ID file creation restricted)
  and MUST lock the execution personality, deny writable-and-executable memory, restrict
  realtime scheduling, allow only native-architecture system calls, and restrict system calls
  to the system-service set minus privileged calls (keeping exactly what the service needs,
  including memory locking and resource limits).
- **FR-009**: The service definition MUST give the service a private temporary directory,
  no device access beyond the basic pseudo-devices, a strict read-only view of the whole
  file system, protected kernel tunables, modules, logs, control groups, clock and host
  name, hidden processes of other users, and a private kernel keyring; it MUST forbid
  creating any kind of namespace.
- **FR-010**: The service definition MUST allow only the socket families the service needs:
  IPv4 and the kernel interface-listing family (needed by 003 when networking is on); local
  (Unix) and IPv6 sockets MUST be denied unless the plan shows the service requires them.
  It MUST NOT open, forward or declare any listening socket itself (no socket activation).
- **FR-011**: The service definition MUST hide the person's home directory (an empty private
  view) except the passwsync directories at the default XDG locations
  (`~/.config/passwsync`, `~/.local/share/passwsync`), which, with the passwsync runtime
  directory, MUST be the only writable locations, with owner-only permissions; no other home
  file may be readable by the service; on a fresh account these directories MUST be creatable on first
  start without manual steps and without widening access beyond them. It MUST set an
  owner-only file-creation mask. The one pre-start step that runs outside the sandbox (to
  create the directories that the sandbox binds, and to refuse custom XDG locations) runs as
  the person with no added privilege, touches only those three directories, and is the only
  exception to the sandbox; the sandbox is then verified before the service starts.
- **FR-012**: The confinement MUST NOT break any service behaviour from 002-005: loopback
  UI, peer-UID check (002 FR-007a), suspend detection, networking when turned on by the
  person (003), sync (004) and sharing (005). Each confinement directive that could affect
  one of these MUST be listed in the regression map of the unit contract, and each row MUST be
  covered by an automated check where the behaviour can be tested offline (the confinement
  probes) and by a documented manual check otherwise.
- **FR-013**: The service definition MUST restart the service only after abnormal exits of
  the service process other than exit codes 2, 3 and 4, with a delay of at least 5 seconds and
  at most 5 attempts in any 5-minute window. Failures of the unit's pre-start steps are not
  exempt from the attempt limit: they are retried under the same 5-in-5-minutes limit and then
  stop. On stop it MUST send the termination signal the service handles (002 shutdown locks
  every wallet) and allow at least 10 seconds before forced termination.
- **FR-014**: The service log (standard error) MUST go to the per-user journal unchanged; the
  package MUST NOT add log files, change log content, or enable verbose/debug modes.

**Package contents and install hooks**

- **FR-015**: The package (`passwsync`) MUST install exactly: the service binary
  (`/usr/bin/passwsyncd`), the per-user service definition (`passwsyncd.service`), the
  per-user service manager memory-limit drop-in
  (`/usr/lib/systemd/system/user@.service.d/passwsync-memlock.conf`), the launcher
  (`/usr/bin/passwsync-open`), its desktop entry (`passwsync.desktop`), the license, and a
  short README/usage document; nothing under any home directory,
  no system-wide (root) service, no firewall rules, no system configuration file.
- **FR-016**: Package install, upgrade and removal scripts MUST only print messages. They
  MUST NOT enable, start, stop, restart or reload any user's service, MUST NOT create, read,
  edit or delete any file under any home directory, and MUST NOT write any passwsync
  configuration (in particular they MUST NOT turn networking on).
- **FR-017**: The post-install message MUST state: networking is off by default and is
  turned on only by editing the person's own configuration file; how to enable the service at
  login or open it through the launcher; that the new memory limit takes effect after the
  next login.
- **FR-018**: Upgrade MUST leave a running service untouched; the post-upgrade message MUST
  say that restarting the service applies the new version and locks all wallets.
- **FR-019**: Removal (with or without the "remove configuration" option) MUST NOT delete,
  move or change any file in the person's passwsync configuration, data or runtime
  directories; the post-removal message MUST name those directories, say they were kept, and
  give the commands to stop and disable the service.

**Desktop launcher**

- **FR-020**: The package MUST ship a desktop entry (application menu item) that runs the
  launcher; it MUST NOT autostart at login, MUST NOT claim any URL or MIME handler, and MUST
  pass validation.
- **FR-021**: The launcher MUST: start the per-user service if it is not running (never
  enable it); wait at most 10 seconds for the launch file; accept the launch file only if it
  is a regular file (not a symlink) owned by the person, with no group/other permission bits,
  whose content matches exactly `http://127.0.0.1:<port>/launch/<64 lowercase hex>` with a
  port in 1024-65535; and then hand that address to the desktop's default URL opener.
- **FR-022**: The launcher MUST NOT print, log, store or pass the launch address anywhere
  other than to the URL opener; on any failure it MUST open nothing, show a clear message as a
  desktop notification when a notification service is available and always on standard error,
  and exit non-zero. For the timeout and invalid-launch-file failures the message MUST name the
  status command (the service is the likely cause); the other failures name what to fix. No
  message may contain the launch address or token.
- **FR-023**: The launcher MUST NOT change any configuration, MUST NOT touch wallets, and
  MUST NOT require or ask for any password.

**Verification (offline)**

- **FR-024**: The project MUST provide one offline verification entry point that runs: the
  recipe linter and the package linter (no errors), the service-definition verifier (no
  errors), the offline security analysis with a pass threshold of exposure 1.5, a check that
  every directive required by FR-007 to FR-011 and FR-013 is present with the required
  value, desktop-entry validation, the launcher tests (FR-021, FR-022), the install-script
  tests (FR-016 to FR-019), the confinement probes (FR-012), and the reproducibility check
  (FR-025).
- **FR-025**: The reproducibility check MUST build the package twice from the same local
  release archive, lock file, toolchain and source-date value, with dependencies from a
  pre-fetched local cache and no network: (a) in two different build directories, failing
  unless the service binaries are bit-identical; and (b) twice in the same build directory
  path from two separate copies of the source at different times, failing unless the package
  files have identical checksums.
- **FR-026**: The feature documentation MUST include the manual on-host checks that cannot
  run offline (install from the AUR, re-login, enable, launcher from the menu, networking on
  with the confined service, upgrade, removal) with their expected results.

**Scope exclusions**

- **FR-027**: This feature MUST NOT change service behaviour, settings, ports, files or
  protections from 002-005, and MUST NOT include a system-wide service, a prebuilt binary
  package, a version-control package, automatic updates, firewall configuration, packaging
  for other distributions, release signing, publication to the AUR (submitting the recipe is
  a manual maintainer step), or the Android app (007).

### Key Entities

- **Package recipe**: The AUR build description: package metadata, one pinned release
  source with its checksum, preparation (locked dependency fetch), build, check and package
  steps, and the install-script reference.
- **Release source archive**: The tagged project source tarball; its checksum is pinned in
  the recipe and its commit time is the source-date value used by the verification.
- **Per-user service definition**: The systemd user unit that runs the service with the
  required limits and confinement; never shipped as a system-wide service.
- **Memory-limit drop-in**: A per-user service manager override raising only the
  locked-memory limit to 256 MiB.
- **Launcher and desktop entry**: The menu item and the small program that starts the
  service for the session and opens the single-use launch address.
- **Install script**: The package's install/upgrade/removal hooks; message-only.
- **Person's passwsync data**: Configuration, device identity and key, pairings, wallets,
  received wallets, sync records and the runtime launch file; owned by the person, never
  owned, read or changed by the package.
- **Verification report**: The output of the offline verification entry point: each check
  with pass/fail and, for the security analysis, the exposure score.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The offline verification entry point passes every check (FR-024) on a clean
  checkout with a pre-fetched dependency cache and no network.
- **SC-002**: The shipped service definition scores an overall exposure of 1.5 or lower in
  the offline security analysis, and 100% of the directives required by FR-007 to FR-011 and
  FR-013 are present with their required values.
- **SC-003**: In 100% of reproducibility runs, two builds from the same inputs produce a
  bit-identical service binary (even in different build directories) and, when built in the
  same build directory path, package files with identical checksums (FR-025).
- **SC-004**: In 100% of install-script tests (install, upgrade, removal, removal with the
  configuration option), zero files under a populated stand-in home directory are created,
  changed or deleted, and no service is enabled, started, stopped or restarted.
- **SC-005**: Zero package files, scripts or launcher paths write a passwsync configuration;
  a fresh install leaves networking off in 100% of checks.
- **SC-006**: In 100% of launcher tests, a valid launch file leads to exactly one URL-opener
  call with exactly that address, every invalid, late or wrongly-permissioned launch file
  leads to zero URL-opener calls and a non-zero exit, and the launch token appears in zero
  lines of launcher output.
- **SC-007**: On a real Arch host (manual check), a person can go from a built package to the
  UI open in their browser in under 3 minutes, including one re-login, following only the
  post-install message.
- **SC-008**: On a real Arch host (manual check), the confined service starts with networking
  off, and with networking turned on by the person it pairs and syncs with another device,
  with no behaviour difference from an unconfined run.

## Assumptions

- Target is current Arch Linux (and derivatives using the AUR) with the systemd user manager,
  cgroup v2 and unprivileged user namespaces enabled (Arch defaults); per-user sandboxing in
  user services relies on them.
- The person logs into a desktop session that starts their per-user service manager and
  provides a default URL opener (`xdg-open` from xdg-utils).
- The verification tools (`namcap`, `makepkg`, `systemd-analyze`,
  `desktop-file-validate`, `systemd-run` with a working user manager, `ip` from iproute2) are
  installed for the offline checks; installing them is a one-time developer setup step and not
  part of the package.
- Release archives are published as tagged source tarballs of this repository; until a real
  release exists, verification uses a local archive produced from the working tree with the
  same layout and checksum handling.
- The Rust toolchain used by the recipe is the Arch `rust` (or `rustup`) package meeting the
  workspace minimum version; reproducibility is defined for an identical toolchain version.
- The 256 MiB locked-memory requirement and the exit codes are those of 002
  `contracts/host-runtime.md`; ports 27471/27472/27473 and the private-address filter are
  those of 002 and 003 and are not configured by the package.
- The per-user service manager cannot enforce IP address allow-lists, so network-destination
  restriction stays in the service (003 FR-011); the package restricts socket families only.
- Firewall configuration is the person's responsibility; the README already tells them which
  ports to allow on the local network when they turn networking on.
