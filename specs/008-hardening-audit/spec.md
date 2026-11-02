# Feature Specification: Hardening Audit

**Feature Branch**: `feat/008-hardening-audit`

**Created**: 2026-10-30

**Status**: Draft

**Input**: User description: "Feature 008 hardening-audit: fuzzing of the wallet file format (vault-core format parse/unlock, postcard payload decode), the device-link channel framing and Hello/handshake parsing, wallet-sync message codecs, the share message codecs, and the localhost HTTP parser; benchmarks for KDF timing and sync resource use (RAM/CPU budgets from 001-004); a threat-model review document covering the whole system (offline vault, localhost service, LAN sync/sharing, Android, AUR packaging) with STRIDE per trust boundary and the residual risks already recorded in specs 003-007; CI workflow with cargo fmt/clippy/test, cargo audit and cargo deny (and the android/verify.sh and packaging/verify.sh gates) — the CI must not publish or push anything and must not hold secrets. Fuzzing: prefer a dependency-light, deterministic property/fuzz-style test harness runnable offline (proptest/arbitrary only if vetted and already cached; otherwise a seeded mutation fuzzer in-tree) plus an optional cargo-fuzz target that is not required for the gate. No new unsafe. Environment: no internet beyond what is cached, no CI runner here; the spec must make host-verifiable outcomes offline-testable and mark CI-runner-only and device-only items."

## Context

Features 001-007 deliver the whole product:

- **001 vault-core**: the encrypted wallet file (`PWSV` header, Argon2id parameters, salt,
  nonce, AES-256-GCM over a compact binary payload), credentials, version vectors, the storage
  port; **vault-storage-file** is the atomic file adapter. Bounds: wallet files 79 bytes to
  64 MiB, text fields at most 1 MiB, KDF parameters inside a fixed accepted range.
- **002 passwsyncd**: loopback HTTP service and browser UI, bounded request reader (head at
  most 16 KiB and 48 headers, body at most 8 MiB, no chunked bodies), Host/Origin/CSRF/session
  checks, FR-025a host protections.
- **003 device-link / device-link-net**: discovery datagrams, length-prefixed frames, the
  Hello (`PWSC || version || kind`), pairing by short code, Noise-based mutually authenticated
  channel, pinning and revocation.
- **004 wallet-sync**: control messages (fragmented, reassembled up to 24 KiB), copy transfer,
  merge, rollback and replay protection, the per-wallet sync record.
- **005 sharing**: share messages (`stype || rid || fields`), invitations, received copies.
- **006 packaging**: PKGBUILD, hardened systemd user unit, offline `packaging/verify.sh`.
- **007 android-app**: UniFFI boundary crate, Android app, offline `android/verify.sh`.

Every one of these features tested its own behaviour. This feature adds the **cross-cutting
assurance work** the roadmap reserved for the end: robustness of every parser that reads
untrusted bytes, measurement of the resource budgets promised by 001-004, one system-wide
threat model, and a continuous-integration gate that runs all existing checks on every change.

This feature adds **no new product behaviour, no new protocol, no new file format, no new
cryptography and no new runtime dependency**. Product code changes only where the audit finds
a defect; each such fix makes a parser stricter or bounds a resource and keeps every encoding
produced by the current encoders valid.

**Verification classes** (every requirement and success criterion is tagged):

- **[H] host-verifiable**: checked offline on the Linux development host with the cached
  toolchain, crates and advisory database; this is the gate for this feature.
- **[CI] CI-runner-only**: can only be confirmed by a run on a hosted CI runner (network,
  fresh machine, Arch Linux container). Recorded as pending until a maintainer runs the
  workflow; never run from this environment.
- **[M] manual on reference hardware**: timing and resource verdicts on the 001 reference
  laptop or reference Android phone; recorded as pending until run.
- **[D] device-only**: needs a real Android device or emulator; recorded as pending (as in 007).

## Clarifications

### Specification defaults 2026-10-30

Decisions taken while writing the specification (non-interactive): each is the most secure
and then simplest option consistent with the constitution and the roadmap global rules.

- Q: Which fuzzing harness? → A: An in-tree, seeded, deterministic mutation fuzzer built only
  from the standard library and crates already in the lockfile. Neither `proptest` nor
  `arbitrary` is in the lockfile or in the local crate cache, so they are not used (adding them
  would need network access and a security review for test-only value). No new dependency
  enters the workspace lockfile.
- Q: Where do fuzz inputs come from? → A: From the project's own encoders at test time (valid
  wallets, frames, Hellos, control messages, share messages, HTTP requests), then mutated by
  the seeded fuzzer. No opaque binary corpus is committed; reproducers of fixed defects are
  committed as small, readable hex or text literals inside regression tests.
- Q: What is the optional cargo-fuzz target? → A: A separate directory excluded from the
  workspace whose targets only call the same fuzz entry points as the in-tree harness. It is
  never built by any gate (it needs a nightly toolchain and an uncached dependency), its
  dependencies never enter the workspace lockfile, and its build is unverified here.
- Q: How do expensive key derivations fit into fuzzing of unlock? → A: The pre-derivation
  header checks and the decrypted-payload decoder are fuzzed directly and at volume; the full
  unlock path (derivation plus authenticated decryption) is fuzzed with a small fixed number
  of mutated wallets using the minimum accepted KDF parameters. Authenticated decryption
  rejects almost every mutation before decoding, so the payload decoder MUST also be reachable
  with mutated plaintext through a test-only entry point that is absent from release builds.
- Q: Do benchmarks fail the gate? → A: Only deterministic quantities fail the gate (bytes on
  the wire, bounded buffer sizes, message counts, idle wake-ups over simulated time). Wall-clock
  time, CPU share and peak memory are measured and reported with a pass/fail verdict against the
  budget, but never fail the host or CI gate, because shared and development machines are not
  the reference devices; the binding verdict is the manual run on reference hardware [M].
- Q: Where does the threat model live? → A: In `docs/threat-model.md`, one system-wide living
  document (not per feature), with a short offline structure check so that every trust boundary
  carries all six STRIDE categories and every residual risk recorded in specs 003-007 appears.
- Q: What may the CI workflow do? → A: Read-only. Triggers: push, pull request (never the
  privileged pull-request-target trigger) and manual dispatch. Repository token permission
  read-only for contents and nothing else; no secrets or environment secrets referenced;
  checkout without persisted credentials; no release, publish, upload of build outputs, cache
  write to shared caches, tag, push, deploy or comment step. Every third-party action and
  container image pinned by full immutable digest.
- Q: How does CI stay identical to the host checks? → A: The workflow calls one in-repo gate
  script; the same script runs offline on the host. The workflow file holds no check logic of
  its own beyond installing pinned tools and invoking that script and the two existing
  verify scripts.
- Q: Does this feature fix what the audit finds? → A: Yes, within scope: every crash, hang,
  unbounded allocation or budget violation found is first reproduced by a failing test (TDD)
  and then fixed in this feature, provided the fix only rejects invalid input or tightens a
  bound. A finding whose fix would change a valid file or wire encoding is recorded in the
  threat model as an open finding with severity and is not fixed here.
- Q: Which other untrusted-input parsers are in scope? → A: The listed ones plus the LAN
  discovery datagram decoder and the pairing messages, because they read unauthenticated bytes
  from the network. Parsers of the person's own local files (configuration, peers file, sync
  record, received-wallet metadata, launch file) are inputs under the same OS user, which
  002-005 place outside the attacker model; they are listed in the threat model with that
  rationale and are not fuzzed in this feature.

### Session 2026-10-30

Non-interactive `/speckit-clarify` session: each answer is the recommended option (most
secure, then simplest).

- Q: Which advisory kinds should fail the gate: only vulnerabilities, or also unsound,
  unmaintained and yanked notices? → A: All kinds (vulnerability, unsound, unmaintained,
  yanked) fail the gate unless the advisory is explicitly ignored with a written reason that
  also appears in the threat-model risk register (FR-030, FR-036).
- Q: Should CI also run on a schedule so that newly published advisories are caught without a
  code change? → A: Yes, once a week, with the same read-only permissions and no secrets; a
  scheduled run never publishes or opens issues (FR-031, FR-032).
- Q: Which severity scale does the threat model use for residual risks and findings? → A: A
  three-level qualitative scale (High, Medium, Low) defined in the document from impact and
  likelihood; the structure check accepts only these three values (FR-026, FR-029).
- Q: Should CI run the measured benchmark command? → A: No. CI runs only the deterministic
  budget assertions, which are part of the test suite; the timing, CPU and memory report runs
  on the host and on reference hardware only, because shared runners give meaningless timings
  (FR-020).
- Q: Should the dependency policy now deny duplicate versions of the same crate? → A: No; it
  stays a warning, because removing the existing duplicates would require dependency changes
  this feature forbids (FR-037). The gate prints the duplicate count and the threat model lists
  it under the supply-chain boundary (FR-030).

## User Scenarios & Testing *(mandatory)*

The "users" of this feature are the maintainers and reviewers who must trust that the product
fails safely on hostile input, meets its resource promises, and stays that way on every change.

### User Story 1 - Hostile bytes never crash or exhaust the service (Priority: P1)

A maintainer runs one offline command and every parser that reads untrusted bytes (wallet
files, channel frames and Hellos, pairing messages, discovery datagrams, sync and share
messages, loopback HTTP requests) is fed tens of thousands of deterministic, seeded mutations
of valid inputs. Every input ends in a success or a documented error, quickly, within the
documented memory bounds, and without leaking secret material in errors.

**Why this priority**: A single panic, hang or unbounded allocation on attacker-controlled
input is a denial of service against an always-on background service, and parser bugs are the
most common path to worse defects. This is the core value of the audit.

**Independent Test**: [H] Run the fuzz gate offline twice with the same seed; both runs execute
the same inputs, report the same counts, and end green. Inject a known defect (for example a
removed length check) in a scratch copy and confirm the fuzz gate catches it.

**Acceptance Scenarios**:

1. **Given** the default seed, **When** the maintainer runs the fuzz gate offline, **Then** each
   target executes at least its minimum number of inputs and reports zero panics, zero time
   overruns and zero allocation-bound violations.
2. **Given** a valid input produced by the project's own encoder, **When** it is decoded and
   re-encoded, **Then** the result is byte-identical (every accepted input has exactly one
   encoding).
3. **Given** any mutated input that a decoder accepts, **When** it is re-encoded, **Then** the
   re-encoded bytes decode to an equal value (no decoder accepts a value the encoder cannot
   represent).
4. **Given** a failing input, **When** the fuzzer reports it, **Then** the report names the
   target, the seed and the iteration and prints the input in a form that can be pasted into
   a regression test, and re-running with that seed and iteration reproduces it.
5. **Given** a mutated wallet file, **When** it is unlocked with the correct password, **Then**
   it fails with the generic corrupted-or-wrong-password error and no decrypted content is
   returned.

---

### User Story 2 - Every change is checked by a read-only CI gate (Priority: P1)

On every push and pull request, and once a week, a CI workflow runs formatting, lint, the full
test suite, the fuzz gate, the advisory and dependency-policy checks, and the existing Android and packaging
verify scripts. It holds no secrets and cannot publish, push or change anything.

**Why this priority**: Without a gate, every hardening result decays with the next change; the
gate is what keeps 001-008 guarantees true.

**Independent Test**: [H] Run the in-repo gate script offline on the host (same steps as CI)
and get a green result; run the offline workflow-policy check against the workflow file and
against deliberately bad copies (a secret reference, a write permission, an unpinned action,
a push step, the pull-request-target trigger) and see each bad copy rejected. [CI] A real run
on a hosted runner passes.

**Acceptance Scenarios**:

1. **Given** a clean tree, **When** the gate script runs offline on the host, **Then** it runs
   formatting check, lint with warnings denied, all workspace tests, the fuzz gate, advisory
   check and dependency-policy check, and exits 0.
2. **Given** a change that breaks formatting, adds a lint warning, fails a test, introduces a
   crate with a known advisory, a banned crate, a disallowed license or an unknown source,
   **When** the gate runs, **Then** it exits non-zero naming the failed step.
3. **Given** the workflow file, **When** the workflow-policy check runs, **Then** it finds no
   secret reference, no write permission, no privileged trigger, no unpinned action or image,
   no persisted checkout credentials and no publish, push, release, upload or deploy step.
4. **Given** a pull request from a fork, **When** CI runs, **Then** it runs with read-only
   permissions and has no access to secrets [CI].

---

### User Story 3 - A reviewer can read one threat model of the whole system (Priority: P2)

A reviewer opens one document that names every trust boundary of the system (offline vault at
rest, local process and memory, loopback HTTP service and browser, LAN discovery, paired
channel, sync, sharing, Android app and platform, packaging and supply chain, CI), lists STRIDE
threats per boundary with their mitigations and the tests that prove them, and consolidates
every residual risk already accepted in specs 003-007 plus any new finding of this audit.

**Why this priority**: The individual specs each argue their own security; only a single view
shows gaps between features. It does not change runtime behaviour, so it ranks below the gates.

**Independent Test**: [H] The offline structure check confirms every boundary has all six
STRIDE categories filled, every listed mitigation names a requirement or test, and every
residual risk recorded in specs 003-007 appears with its source reference and owner.

**Acceptance Scenarios**:

1. **Given** the threat model, **When** a reviewer looks up the LAN channel boundary, **Then**
   they find spoofing, tampering, repudiation, information disclosure, denial of service and
   elevation of privilege entries, each with a mitigation reference or an explicit residual risk.
2. **Given** a residual risk accepted in a previous spec (for example key copies kept by the
   channel library, the undetected-restore case of 004, JVM copies of secrets on Android, the
   accepted systemd exposure items of 006), **Then** it appears in the residual-risk register
   with its source, rationale, severity and the condition that would remove it.
3. **Given** an item that still awaits maintainer approval (any of the three 007 PENDING
   APPROVAL rows of FR-027), **Then** the threat model lists it as pending approval and
   does not mark it accepted.

---

### User Story 4 - Resource promises are measured, not assumed (Priority: P2)

A maintainer runs one offline benchmark command and gets a report of key-derivation timing at
the default and the maximum accepted parameters, unlock, list and search times, peak memory
while unlocked, idle and active sync traffic, CPU share and memory, each next to its budget from
001-004 with a verdict.

**Why this priority**: Resource efficiency is a constitution principle and the promises of
001-004 were stated but never measured together; brute-force cost (minimum time per guess) is
also a security property.

**Independent Test**: [H] Run the benchmark command offline; it completes, writes the report,
and its deterministic checks (traffic bytes, buffer bounds, wake-ups) pass. [M] Run it on the
reference laptop and record the verdicts in quickstart.

**Acceptance Scenarios**:

1. **Given** the default key-derivation settings, **When** the benchmark runs, **Then** it
   reports median and worst unlock time over repeated runs and compares them with "under
   2 seconds" and "at least 0.3 seconds per guess".
2. **Given** 5 simulated peers and 10 wallets in sync, **When** one simulated hour of idle
   sync elapses, **Then** traffic per peer is below 1 KiB and the count is identical across runs.
3. **Given** a 10,000-credential wallet differing by one credential between two devices,
   **When** they sync over loopback, **Then** the report shows duration and peak additional
   memory against 10 seconds and the 64 MB unlock budget.
4. **Given** the benchmark host is not a reference device, **Then** the report states this and
   the timing verdicts are informational.

---

### User Story 5 - Android-specific inputs and budgets are covered where possible (Priority: P3)

The Android boundary crate's exported decoding and the same fuzz and benchmark entry points run
on the host, and device-only items (timing on the reference phone, battery use of background
sync) are listed as manual checks.

**Why this priority**: Android reuses the same core and protocol, so most coverage comes from
US1 and US4; only device measurements are new and they cannot run here.

**Independent Test**: [H] The Android verify script still passes and the fuzz gate includes the
boundary crate's input-taking functions. [D] Reference phone checks run and are recorded.

**Acceptance Scenarios**:

1. **Given** the host, **When** the Android verify script runs inside the gate, **Then** it ends
   with all steps PASS (the linter step may be SKIPPED as 007 allows).
2. **Given** the reference phone, **When** the device benchmark checklist is run, **Then**
   unlock with default settings takes under 3 seconds (007 SC-005, stricter than the 4 seconds
   of 001 SC-003) [D].

### Edge Cases

- A length field announces more bytes than the frame, message or file contains, or the maximum
  integer value: decoders reject without allocating the announced size.
- A frame or message is exactly at, one below and one above each documented bound (frame
  1024 bytes, control message 24 KiB, fragment 1000 bytes, 512 tags, HTTP head 16 KiB and
  48 headers, body 8 MiB, wallet 79 bytes and 64 MiB, text field 1 MiB).
- A wallet header carries KDF parameters just outside the accepted range, or the maximum
  accepted memory cost: rejection happens before any derivation; the maximum-cost case is
  measured once in the benchmark, never fuzzed in volume.
- A decoded payload contains deeply nested or very long collections (entry lists, version
  vectors, histories) whose announced count exceeds the remaining bytes.
- A control message is split across fragments at every offset, fragments arrive out of order,
  duplicated, or exceeding the reassembly limit.
- An HTTP request has duplicate Host, Origin, cookie or CSRF headers, a Transfer-Encoding
  header, a non-numeric or duplicate Content-Length, bare line feeds, non-UTF-8 bytes in the
  target, or stops mid-header (slow sender).
- A Hello has a known magic with an unknown version or kind, or is shorter or longer by one.
- The fuzzer itself finds nothing for a target: the gate still requires the minimum count of
  executed inputs and a coverage sanity check (at least one accepted and one rejected input),
  so a target that never reaches its decoder fails.
- The advisory database cached on the host is older than the CI one: the host gate reports
  the database date; a new advisory may fail CI before the host [CI].
- An unmaintained, unsound or yanked notice (not only a vulnerability), or an advisory
  without a fixed version, affects a dependency: the gate fails until it is either
  removed or explicitly ignored with a written reason in both advisory configurations and in
  the threat-model risk register.
- A verify script ends with a status other than 0 (a tool missing, a partial run): CI treats it
  as a failure.

## Requirements *(mandatory)*

### Functional Requirements

**Fuzzing harness**

- **FR-001** [H]: The project MUST provide a deterministic, seeded mutation fuzzer that runs
  offline as part of the normal test suite, uses only the standard library and crates already
  in the workspace lockfile, adds no `unsafe` code and is not linked into any release binary or
  library.
- **FR-002** [H]: The fuzzer MUST derive its inputs from valid encodings produced by the
  project's own encoders and apply at least these mutations: bit flips, byte replacements with
  boundary values (0, 1, 0x7F, 0x80, 0xFF), insertions, deletions, truncation at every length up
  to a cap, duplication of ranges, splicing of two valid inputs, and overwriting of length and
  count fields with boundary values (0, bound-1, bound, bound+1, maximum).
- **FR-003** [H]: Each run MUST be fully reproducible from a seed; the default seed MUST be
  fixed in the repository, and a maintainer MUST be able to set a different seed and a larger
  iteration count through an environment setting for extended runs without code changes.
- **FR-004** [H]: The gate run MUST execute at least 10,000 inputs per target, except the full
  unlock target (at least 64 inputs, minimum accepted KDF parameters), and the whole fuzz gate
  MUST finish within 5 minutes on the development host.
- **FR-005** [H]: For every input, a target MUST check: no panic; the call returns within a per-
  input time limit (1 second, 10 seconds for full unlock); no single allocation and no total
  retained buffer exceeds the documented bound of that parser (relative to input size or the
  feature's stated limit); the result is either a decoded value or one of the parser's
  documented error kinds.
- **FR-006** [H]: For every target, decode-then-encode of every encoder-produced input MUST be
  byte-identical, and every mutated input that is accepted MUST re-encode to bytes that decode
  to an equal value.
- **FR-007** [H]: The fuzzer MUST report a failure with target name, seed, iteration and the
  input printed as hex (or as escaped text for HTTP), so that it can be reproduced by re-running
  with the same seed and turned into a regression test.
- **FR-008** [H]: Each target MUST demonstrate that it reaches its decoder: the gate fails if a
  target produces no accepted input or no rejected input during its run.
- **FR-009** [H]: An optional cargo-fuzz target directory MUST exist outside the workspace,
  calling the same entry points as the in-tree harness; it MUST NOT be built or required by the
  host gate or CI, and its dependencies MUST NOT appear in the workspace lockfile.

**Fuzz targets**

- **FR-010** [H]: Wallet file: the header and pre-derivation checks (magic, length bounds,
  version, KDF identifier and parameter range) MUST be fuzzed at volume, including the
  KDF-parameter peek used before unlock.
- **FR-011** [H]: Wallet payload: the decoder of the decrypted payload (both supported format
  versions) MUST be fuzzed with mutated plaintext through a test-only entry point; accepted
  payloads MUST respect the 001 limits (text field at most 1 MiB, file at most 64 MiB).
- **FR-012** [H]: Full unlock: mutated wallet files MUST be unlocked with the correct password.
  Every mutation of the salt, nonce, ciphertext or tag MUST fail with the generic
  corrupted-or-wrong-password error and return no content. A header mutation rejected by the
  FR-010 checks before any derivation fails with that check's error kind (for example
  `KdfParamsOutOfRange`). KDF-parameter bytes are checked by FR-010 only and are never used for a
  derivation in the unlock target (extends 001 SC-002 from single-byte to multi-mutation).
- **FR-013** [H]: Device link: frame decoding (length prefix, bounds), Hello parsing (all
  versions and kinds), payload-type decoding of opened channel messages, discovery datagram
  decoding, and the pairing and channel handshake messages received by a responder and an
  initiator MUST be fuzzed; a malformed handshake message MUST end the attempt with a protocol
  error and leave no pin, no session and no partial state.
- **FR-014** [H]: Wallet sync: control-message decoding of every control type, fragment
  reassembly (order, duplication, size limit) and copy-transfer chunk handling MUST be fuzzed;
  announced copy sizes outside 79 bytes to 64 MiB MUST be rejected before buffering.
- **FR-015** [H]: Sharing: share-message decoding of every share type (unknown types, unknown
  abort reasons, wrong lengths, trailing bytes, out-of-range seconds-left) MUST be fuzzed. Share
  text and the FFI argument functions of the boundary crate (`parse_share_text`, `join_pairing`,
  `redeem_invitation`; US5) MUST also be fuzzed.
- **FR-016** [H]: Loopback HTTP: the bounded request reader MUST be fuzzed from a byte stream,
  including delivery in arbitrary chunk sizes, and accepted requests MUST satisfy the 002 rules
  (head at most 16 KiB and 48 headers, body at most 8 MiB, no Transfer-Encoding, single Host,
  Origin, session cookie and CSRF values); the HTTP target MUST also run the Host/Origin/CSRF
  guard on every accepted request and confirm no guard-bypassing request reaches a state change.
- **FR-017** [H]: Every defect found MUST first be captured as a failing regression test with
  the minimal reproducing input and then fixed in this feature, if the fix only rejects invalid
  input or tightens a bound; otherwise it MUST be recorded as an open finding in the threat
  model with severity and owner.

**Benchmarks and resource budgets**

- **FR-018** [H]: An offline benchmark command MUST measure and report: key-derivation and
  unlock time at the default parameters and at the largest parameters the services accept
  (128 MiB memory cost); list and search over 10,000 credentials; peak memory while unlocked
  with 10,000 credentials; sync of a 10,000-credential wallet differing by one credential
  (duration, peak additional memory); idle sync with 5 peers and 10 wallets over one simulated
  hour (traffic per peer, wake-ups, CPU share, memory over baseline).
- **FR-019** [H]: Each reported value MUST appear next to its budget and source: 001 SC-003
  (unlock under 2 s on the reference laptop, at least 0.3 s per guess), 001 SC-004 (list/search
  under 100 ms), 001 SC-005 (under 64 MB unlocked), 002 SC-008 (idle service under 50 MB, no busy
  polling), 003 SC-007 (networking idle under 10 MB extra, under 1% CPU, at most one wake-up per
  30 s per peer), 004 SC-006 (idle sync under 1 KiB per peer per hour, under 1% CPU, under
  8 MiB), 007 SC-005/SC-011 (phone unlock under 3 s, under 128 MiB; device-only), 007
  SC-008/SC-009 (device wake-ups and battery; device-only), 004 SC-008
  (one-credential sync under 10 s, peak below the unlock budget), 004
  FR-029 (at most 1 MiB transfer buffer per transfer, at most two transfers), and the parser
  bound constants of 001-004 and 007 (B-20: frame, fragment, control message, tags, HTTP head and
  headers, body, wallet, text field, KDF cap). 001 SC-003 also gives the service-cap measurement
  B-04 (informational).
- **FR-020** [H]: Deterministic quantities (traffic bytes, message counts, wake-ups over
  simulated time, buffer and concurrency bounds) MUST be asserted and fail the gate when over
  budget; wall-clock, CPU and memory values MUST be reported with a verdict but MUST NOT fail
  the host gate, and the measured-benchmark command MUST NOT run in CI (CI runs only the
  deterministic assertions inside the test suite).
- **FR-021** [H]: The report MUST record the machine (CPU model, core count, memory), toolchain
  version, build profile and whether the machine is a reference device; benchmarks MUST use an
  optimised build, contain no wallet secrets in output, and use only temporary directories.
- **FR-022** [M][D]: Quickstart MUST contain a manual checklist to run the benchmark on the
  reference laptop [M] and the device timing and battery checks on the reference phone [D], with
  a place to record results; until run they are recorded as pending.

**Threat model**

- **FR-023** [H]: A system-wide threat model document MUST describe the assets (master
  passwords, derived keys, decrypted credentials, wallet files, device private keys, pins,
  pairing and invite codes, session token, sync records), the actors (remote LAN attacker,
  malicious paired device, other local OS user, malicious web page in the person's browser,
  same-user malware, thief of a powered-off device, compromised dependency or build input, CI
  contributor from a fork) and a data-flow view with every trust boundary.
- **FR-024** [H]: The trust boundaries MUST at least be: wallet at rest; process memory and OS
  (swap, core dumps, debuggers); loopback HTTP service and browser; LAN discovery; pairing;
  paired channel; wallet sync; sharing; Android app and platform (clipboard, screen capture,
  backup, key store, background scheduling); packaging and service manager; build, dependency
  and CI supply chain.
- **FR-025** [H]: For every boundary the document MUST list threats under all six STRIDE
  categories; each threat MUST name its mitigation with a reference to the requirement, test or
  check that proves it, or MUST be marked as a residual risk; "not applicable" MUST carry a
  one-line reason.
- **FR-026** [H]: The document MUST contain a residual-risk register that consolidates every
  residual risk accepted in specs and plans 002-007 (at least: unaudited channel and pairing
  libraries and their key copies without wiping; device key protected by file permissions only;
  stable device identifier visible on the LAN; undetected whole-installation restore and the
  unauthenticated sync record; duplicate-detection gap for never-unlocked wallets; invitation
  invalidation by another paired device and non-withdrawable delivered copies; clipboard
  clearance not guaranteed after the page closes; the accepted systemd exposure items; JVM
  copies of secrets, screen-reader access, best-effort memory locking and unencrypted non-secret
  records on Android), each with source reference, rationale, severity (High, Medium or Low,
  defined in the document from impact and likelihood), owner and the condition that would
  close it.
- **FR-027** [H]: Items that still await maintainer approval (the three 007 PENDING APPROVAL rows:
  the Constitution I exception for non-secret Android records, the Constitution I residual for JVM
  copies of secrets, and the Constitution III exception for Kotlin) MUST be listed as pending
  approval, not accepted; this feature MUST NOT grant approval.
- **FR-028** [H]: New findings from fuzzing, benchmarks and the review itself MUST be listed with
  status (fixed with test reference, or open with severity and owner).
- **FR-029** [H]: An offline structure check MUST fail if a boundary misses a STRIDE category,
  a mitigation has no reference, a residual risk lacks source, owner or a severity of High,
  Medium or Low, or a residual
  risk recorded in the earlier specs' residual lists is missing from the register.

**Continuous integration**

- **FR-030** [H]: One in-repo gate script MUST run, offline when the toolchain, crates and
  advisory database are cached: formatting check; lint of all targets with warnings denied;
  all workspace tests (including the fuzz gate and the deterministic benchmark assertions);
  advisory check (every advisory kind fails unless ignored with a reason); dependency-policy
  check (advisories, bans, licenses, sources; duplicate crate versions are a reported warning); the existing
  unsafe-scope check (no `unsafe` outside the reviewed 007 memory-protection module). It MUST
  print one result line per step and exit 0 only if every step passes.
- **FR-031** [H]: A CI workflow file MUST run the gate script, `android/verify.sh` and
  `packaging/verify.sh` on push, pull request, manual dispatch and a weekly schedule, and MUST treat any non-zero
  exit status (including the "incomplete" status 2 of the verify scripts) as failure.
- **FR-032** [H]: The workflow MUST declare read-only contents permission and no other
  permission, reference no secrets or environment secrets, use no privileged trigger, check out
  without persisted credentials, and contain no publish, push, tag, release, deploy, comment,
  artifact-upload or shared-cache-write step.
- **FR-033** [H]: Every action and container image used by the workflow MUST be pinned by full
  immutable digest, and every cargo-installed tool MUST be pinned to an exact version and installed
  with `--locked`; system packages come only from the dated Arch Linux Archive snapshot
  (`ARCH_SNAPSHOT`, research R15); jobs MUST have a time limit.
- **FR-034** [H]: An offline workflow-policy check MUST verify FR-031..FR-033 on the workflow
  file and MUST be part of the gate script; it MUST reject test copies containing each forbidden
  construct.
- **FR-035** [CI]: The packaging gate MUST run in a digest-pinned Arch Linux container with the
  tools `packaging/verify.sh` requires; the Android gate MUST run on a hosted Linux runner with
  the tools `android/verify.sh` requires; both MUST pass on a real run.
- **FR-036** [H]: The advisory check and the dependency-policy check MUST use the same ignore
  list; each ignored advisory MUST carry a written reason and appear in the threat-model risk
  register; the host gate MUST print the date of the advisory database it used.

**Constraints**

- **FR-037** [H]: This feature MUST add no `unsafe` code, no new runtime or third-party
  dependency (the in-tree path package `hardening` is the only lockfile addition, amendment A1),
  no network
  access in product code and no change to any valid file or wire encoding; the unsafe-scope
  check MUST cover the new test and benchmark code.
- **FR-038** [H]: Fuzz and benchmark code MUST NOT write secrets, wallet plaintext or known
  plaintext markers to stdout, stderr or files other than temporary test directories, and test-
  only entry points MUST be absent from release builds (verified by building the release
  library and service and checking those entry points are not exported).

### Key Entities

- **Fuzz target**: a named untrusted-input parser with its seed encoders, mutation set,
  per-input oracle (no panic, time limit, allocation bound, documented error kinds, round trip)
  and minimum input count.
- **Fuzz finding**: target, seed, iteration, reproducing input, failure kind, regression test,
  status (fixed or open).
- **Budget**: a named resource promise from 001-004 (value, unit, source, deterministic or
  measured, reference device).
- **Benchmark report**: machine description, toolchain, per-budget measured value and verdict.
- **Trust boundary**: a named crossing between trust levels with STRIDE threats, mitigations
  and residual risks.
- **Residual risk**: description, source spec/plan reference, rationale, severity, owner,
  closing condition, status (accepted, pending approval, open finding).
- **Gate step**: name, command, PASS/FAIL result, run location ([H] host, [CI] runner).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001** [H]: The fuzz gate covers 100% of the listed untrusted-input parsers (wallet
  header, wallet payload, full unlock, frame, Hello, channel payload types, discovery datagram,
  pairing and channel handshakes, sync control messages and reassembly, copy chunks, share
  messages, HTTP request reader and guard, FFI argument functions and share text) and executes at least 10,000 inputs per target
  (64 for full unlock) with zero panics, time overruns or bound violations.
- **SC-002** [H]: Two runs with the same seed execute identical input sequences and produce
  identical reports; the whole fuzz gate completes in under 5 minutes on the development host.
- **SC-003** [H]: In a defect-injection check (a removed length or bound check in each of the
  wallet, frame, sync, share and HTTP parsers, applied to a scratch copy), the fuzz gate detects
  100% of the injected defects within the default run.
- **SC-004** [H]: 100% of defects found during the audit have a regression test whose red run
  (failing before the fix) is recorded in the PR description, or an open entry in the threat model.
- **SC-005** [H]: The benchmark report contains a value and verdict for 100% of the host budgets
  listed in FR-019 (B-01..B-20), and every deterministic budget passes; the device budgets
  B-21..B-23 are recorded by the quickstart checklist (D-1..D-4) instead.
- **SC-006** [M]: On the reference laptop, unlock at default settings takes under 2 seconds and
  at least 0.3 seconds per guess, and every measured budget of FR-019 passes.
- **SC-007** [D]: On the reference phone, unlock at default settings takes under 3 seconds
  (007 SC-005), memory with one unlocked 1,000-credential wallet stays under 128 MiB (007
  SC-011), and background sync stays within the 007 wake-up and battery limits (007 SC-008,
  SC-009).
- **SC-008** [H]: The threat model covers 100% of the trust boundaries of FR-024 with all six
  STRIDE categories each, and its register contains 100% of residual risks recorded in specs
  and plans 002-007; the structure check passes.
- **SC-009** [H]: The gate script exits 0 offline on the development host, and fails with the
  failed step named for each of: a formatting change, a lint warning, a failing test, a banned
  or advisory-affected or unlicensed or unknown-source dependency.
- **SC-010** [H]: The workflow-policy check passes on the workflow file and rejects 100% of
  test copies containing a secret reference, a write permission, a privileged trigger, an
  unpinned action or image, persisted checkout credentials, or a publish/push/upload step.
- **SC-011** [CI]: A run of the workflow on a hosted runner passes all jobs with zero secrets
  available and read-only repository permission.
- **SC-012** [H]: The change adds zero `unsafe` blocks, zero third-party entries to the
  workspace lockfile (amendment A1: the only new `Cargo.lock` entry is the in-tree path package
  `hardening`) and zero network calls in product code; all existing 001-007 tests and both verify scripts
  still pass.

## Plan amendments 2026-10-30

- **A1 (SC-012, FR-037)**: "zero entries to the workspace lockfile" is read as "zero
  third-party entries". Cargo records every workspace member, so `Cargo.lock` gains exactly one
  `[[package]]` for the in-tree path package `hardening` (no source, no dependencies, used by
  no product crate). Strict zero would force the engine to be copied across several product
  crates' tests (plan.md, research R1). SC-012 and FR-037 above carry the amended wording.
- **A2 (FR-033, FR-035)**: the container digest and Arch Linux Archive date cannot be resolved
  offline; the workflow ships with fail-closed sentinels reported `PENDING [CI]` until a
  maintainer fills them (quickstart CI-0).
- **A3 (FR-006)**: fixed-layout codecs get the stricter canonical oracle
  `encode(decode(x)) == x`; postcard keeps the FR-006 wording (research R6).

## Assumptions

- The cached toolchain, crate registry, `cargo-audit`, `cargo-deny` and advisory database on
  the development host are sufficient to run every [H] item offline; the advisory database may
  be older than the one CI fetches.
- `proptest`, `arbitrary` and `libfuzzer-sys` are not in the lockfile or the local cache; hence
  the in-tree fuzzer, and the cargo-fuzz target is optional and unverified here.
- CI targets a GitHub-compatible workflow format because the repository is hosted there; no CI
  runner is available in this environment, so every [CI] item stays pending until a maintainer
  runs it. The workflow is added to the repository but not pushed by this feature.
- Reference hardware is the one defined in 001 SC-003 and recorded in 001 quickstart; the
  development host is not assumed to be a reference device.
- The attacker model of 002-007 stays unchanged: the person's own OS user and their paired
  devices are trusted; LAN peers, other local users, web pages and dependency authors are not.
- Local same-user files (configuration, peers file, sync record, received-wallet metadata,
  launch file) are not fuzzed; the threat model records why.
- Fixing an open finding that requires a format or protocol version change is out of scope and
  goes to a future feature.
- Never commit, never push (roadmap global rule); this feature produces files only.
