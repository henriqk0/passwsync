# Threat Model

System-wide threat model of passwsync (features 001-008), kept current by every feature that
changes a trust boundary. Its structure is checked by `scripts/check_threat_model.py`
(contract: `specs/008-hardening-audit/contracts/threat-model-structure.md`).

## 1. Scope and method

Parts in scope: the wallet core (`vault-core`, file format v1/v2), the local service
`passwsyncd` (loopback HTTP and web UI), device identity, discovery, pairing and the paired
channel (`device-link`, `device-link-net`), wallet sync and sharing (`wallet-sync`,
`host-runtime`), the Android app and its Rust boundary (`passwsync-ffi`), the Arch package and
systemd user unit (006), and the build, dependency and CI supply chain (008).

Method: data flows are cut into eleven trust boundaries (section 5). For each boundary every
STRIDE category (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege) has at least one row naming the threat, the mitigation and where it
is verified. A threat that is not fully mitigated points to a residual-risk register entry
(section 8). Findings of the 008 audit (fuzzing, review, benchmarks) are in section 9.

The attacker model of 002-007 is unchanged: remote LAN attackers, malicious web pages,
malicious paired devices (bounded by the protocols), other local OS users and thieves of a
powered-off device are in the model; malware running as the same OS user is not (it can read
process memory and every file the user can).

How to update: a feature that adds or changes an input, a stored secret, a boundary or a
residual risk edits the matching boundary table, adds `RR-nn` rows (and, if required by a
spec, a row of `scripts/threat_model_required.tsv`), adds a change-log entry, and runs
`python3 scripts/check_threat_model.py` (also part of `scripts/gate.sh`).

Verification tags used in the references: [H] checked on the development host (tests and
`scripts/gate.sh`), [CI] on the hosted runner (`.github/workflows/ci.yml`, pending until a
maintainer resolves its pins), [M] on the reference laptop, [D] on the reference phone.

## 2. Severity scale

Severity combines impact and likelihood inside the attacker model:

- **High**: disclosure of a master password, derived key or credential, or silent loss or
  corruption of wallet data, reachable by an in-model attacker without unusual preconditions.
- **Medium**: disclosure of non-secret metadata, denial of service of the local service or of
  sync, or a high-impact issue that needs unusual preconditions (physical access to an
  unlocked device, a malicious paired device, a compromised build input).
- **Low**: limited impact (temporary unavailability, metadata visible to the same user,
  degraded diagnostics) or a precondition outside normal use.

## 3. Assets

| Id | Asset | Where | Protection |
|----|-------|-------|------------|
| A-01 | Master password | typed into the web UI or the app; in memory only while deriving | never stored or logged; wiped buffers; Argon2id stretching (001) |
| A-02 | Derived key | memory of the unlocked process | zeroized on lock; memory locked against swap; core dumps off (002, 007) |
| A-03 | Decrypted credential | memory while unlocked; web UI or app screen; clipboard on copy | auto-lock; clipboard clearing (best effort, RR-09); no logs |
| A-04 | Wallet file | wallet directory (desktop) or app-private storage (Android) | AES-256-GCM, authenticated header, owner-only files |
| A-05 | Device private key | owner-only file (desktop) or Keystore-sealed blob (Android) | file permissions (RR-02); Keystore AES-GCM (007) |
| A-06 | Pin (paired device key) | peers file next to the device key | owner-only file; pins only after an authenticated pairing |
| A-07 | Pairing code | memory of the initiating device; shown to the person | one attempt, 300 s validity, SPAKE2 (003) |
| A-08 | Invite code | memory of the sending device; shown to the person | one use, expiry, proof bound to the channel (005) |
| A-09 | Session token | browser cookie and service memory (desktop) | random 256 bit, HttpOnly cookie, CSRF token, loopback only (002) |
| A-10 | Sync record | sync directory (owner-only files) | fail-safe semantics, peer marks; no MAC (RR-05) |

## 4. Actors

| Id | Actor | Capability | In model |
|----|-------|------------|----------|
| X-01 | Remote LAN attacker | sends and observes any LAN traffic, spoofs discovery and connections | yes |
| X-02 | Malicious paired device | holds a pin; sends any well-authenticated channel, sync or share message | yes, bounded by the 003-005 protocols |
| X-03 | Other local OS user | runs processes on the same machine under another account | yes |
| X-04 | Malicious web page | runs script in the person's browser, can target 127.0.0.1 | yes |
| X-05 | Same-user malware | runs as the person's OS user | no (can read memory and files of the user) |
| X-06 | Thief of a powered-off device | reads the disk or the phone storage offline | yes |
| X-07 | Compromised dependency or build input | ships malicious code through a crate, tool or base image | yes (supply-chain controls, B-11) |
| X-08 | CI contributor from a fork | opens a pull request that runs the CI workflow | yes (read-only token, no secrets) |

## 5. Data flows and trust boundaries

```text
 person --(password, credentials)--> web UI / app  --[B-03 / B-09]--> service / core
 core   --(encrypted file)---------> disk          --[B-01]
 core   --(keys, plaintext)--------> process memory, OS (swap, dumps, clipboard) [B-02]
 device --(UDP announce)-----------> LAN [B-04] --(TCP, pairing)--> peer [B-05]
 device --(Noise channel)----------> paired peer [B-06] --(sync rounds)--> [B-07] --(shares)--> [B-08]
 package, systemd unit, launcher ---> user session [B-10]
 crates, toolchain, CI image -------> build and release artifacts [B-11]
```

| Id | Boundary | Crosses |
|----|----------|---------|
| B-01 | Wallet at rest | process memory -> disk / phone storage |
| B-02 | Process memory and OS | process -> kernel, swap, core dumps, clipboard |
| B-03 | Loopback HTTP service and browser | browser (any page) -> 127.0.0.1 service |
| B-04 | LAN discovery | LAN broadcast -> device |
| B-05 | Pairing | unauthenticated LAN peer -> pinned peer |
| B-06 | Paired channel | pinned peer -> device (transport) |
| B-07 | Wallet sync | paired peer's sync messages and copies -> local wallets |
| B-08 | Sharing | another person's device -> received wallets |
| B-09 | Android app and platform | Android platform, other apps -> app process |
| B-10 | Packaging and service manager | package, systemd user manager -> service process |
| B-11 | Build, dependency and CI supply chain | third-party code and infrastructure -> build artifacts |

## 6. Threats by boundary

### B-01 Wallet at rest

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B01-1 | S | a forged wallet file is offered as the person's wallet | header and body authenticated (AES-GCM with the header as AAD); wrong password and tamper give one generic error | crates/vault-core/tests/tamper.rs, crates/hardening/tests/fuzz_wallet_unlock.rs | Mitigated |
| T-B01-2 | T | bytes of the header or body are modified | every modified salt, nonce, ciphertext or tag fails with the generic error (64 derived fuzz inputs per gate run); header checks run before key derivation | crates/hardening/tests/fuzz_wallet_unlock.rs, crates/hardening/tests/fuzz_wallet_header.rs, 008 FR-012 | Mitigated |
| T-B01-3 | R | a person disputes which device changed a credential | N/A: single-person password manager; per-device version vectors record the last writer for conflict handling only | 004 FR-022 | N/A |
| T-B01-4 | I | the offline file reveals credentials to a thief (X-06) | Argon2id at the default cost (B-01..B-03 budgets), AES-256-GCM; KDF parameters validated before deriving | crates/vault-core/tests/peek_kdf.rs, 001 SC-003 | Mitigated |
| T-B01-5 | D | a crafted header forces a huge key derivation or allocation | KDF parameters bounded (memory 19,456..1,048,576 KiB, service cap 131,072 KiB), file length 79 B..64 MiB, payload decoder bounds (text field 1 MiB) | crates/hardening/tests/fuzz_wallet_header.rs, crates/hardening/tests/fuzz_wallet_payload.rs, crates/hardening/tests/budgets.rs | Mitigated |
| T-B01-6 | E | a decoded payload breaks core invariants (duplicate ids, versions beyond the state) | validation after decryption; fuzzed with the production decoder through the test-only entry; a non-minimal postcard varint inside the authenticated payload is accepted (review item) | crates/vault-core/tests/testkit_payload.rs, F-002 | Mitigated |
| T-B01-7 | I | key material copied by the cryptographic libraries is not wiped | accepted residual of 003 | RR-01 | Residual (RR-01) |

### B-02 Process memory and OS

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B02-1 | S | another local user (X-03) attaches to the process | not dumpable, ptrace denied by the service self-checks | crates/passwsyncd/tests/hardening_process.rs | Mitigated |
| T-B02-2 | T | memory of the unlocked service is modified by another user | process isolation of the OS; non-dumpable process | crates/passwsyncd/tests/hardening.rs | Mitigated |
| T-B02-3 | R | actions on wallets cannot be traced afterwards | N/A: no audit log by design (logs carry no wallet data); the local log records service events only | crates/passwsyncd/tests/log.rs | N/A |
| T-B02-4 | I | keys or plaintext reach swap, core dumps, logs or the clipboard | memory locked (desktop memlock check; Android full or secrets-only with status), core dumps off, closed log set, clipboard clearing best effort; fuzz output never prints secrets | crates/passwsync-ffi/tests/memprotect.rs, crates/vault-core/tests/leakage.rs, crates/hardening/tests/leakage.rs, RR-09, RR-13 | Residual (RR-09) |
| T-B02-5 | D | memory exhaustion by many unlocked wallets or large wallets | wallet size cap 64 MiB, KDF cap, measured peak memory budgets B-07, B-08 | crates/vault-core/tests/perf.rs, crates/passwsyncd/tests/perf_memory.rs | Mitigated |
| T-B02-6 | E | `unsafe` code outside the single reviewed module | workspace forbids `unsafe`; the scan covers every crate's src, tests, benches and the optional fuzz workspace | crates/passwsync-ffi/tests/unsafe_scope.rs, 008 FR-037 | Mitigated |

### B-03 Loopback HTTP service and browser

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B03-1 | S | a malicious web page (X-04) uses DNS rebinding to reach the API | exact `Host` checked before routing; exact `Origin` for every non-GET API call; fuzzed guard oracle (`GuardBypass`) | crates/passwsyncd/tests/http_guards.rs, crates/hardening/tests/fuzz_http_request.rs, 002 FR-007 | Mitigated |
| T-B03-2 | T | cross-site requests change wallets | session cookie plus CSRF token plus Origin on every state-changing call | crates/passwsyncd/tests/http_guards.rs, crates/hardening/tests/fuzz_http_request.rs | Mitigated |
| T-B03-3 | R | requests cannot be attributed | N/A: one local person per service; refusals are counted by reason without request content | crates/passwsyncd/tests/log.rs | N/A |
| T-B03-4 | I | session or launch token leaks to another local user or page | tokens random, HttpOnly cookie, launch file owner-only, launch token rotated on use; fuzz seeds use placeholder tokens only | crates/passwsyncd/tests/launch.rs, crates/hardening/tests/leakage.rs | Mitigated |
| T-B03-5 | D | oversize or malformed requests exhaust the service | head 16 KiB, 48 headers, body 8 MiB, no chunked bodies, 10 s read timeout, 4 workers; the body buffer is sized from `Content-Length` before the bytes arrive, so four slow senders can hold up to 32 MiB of (untouched) address space for 10 s; bare-LF heads are now rejected (F-001) | crates/passwsyncd/tests/http_limits.rs, crates/hardening/tests/fuzz_http_request.rs, crates/hardening/tests/regress_008.rs, F-001 | Mitigated |
| T-B03-6 | E | the parser accepts a request the guard misreads (smuggling, duplicate headers) | `Transfer-Encoding` refused, exactly one numeric `Content-Length`, duplicate Host/Origin/cookie/CSRF ignored; checked against an independent scan of the raw head | crates/hardening/tests/fuzz_http_request.rs, scripts/defects/http_request.patch | Mitigated |

### B-04 LAN discovery

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B04-1 | S | a LAN attacker announces a fake device | announcements only list devices; trust comes from pairing and pins, never from discovery | crates/device-link/tests/discovery.rs, crates/hardening/tests/fuzz_discovery.rs | Mitigated |
| T-B04-2 | T | announcements are altered in transit | fixed 39-byte layout, port at least 1024, own id refused; strict round trip fuzzed | crates/hardening/tests/fuzz_discovery.rs | Mitigated |
| T-B04-3 | R | a device denies having announced | N/A: announcements carry no commitment and nothing relies on them | 003 FR-006 | N/A |
| T-B04-4 | I | the stable device id is visible to everyone on the LAN | accepted in 003 | RR-03 | Residual (RR-03) |
| T-B04-5 | D | announcement floods fill the nearby list | at most 64 unpaired nearby devices, expiry, per-reason drop counters | crates/passwsyncd/tests/flood_network.rs | Mitigated |
| T-B04-6 | E | a public address is used to reach the device | address policy: LAN ranges only | crates/device-link/tests/policy.rs | Mitigated |
| T-B04-7 | D | an announcement flood naming a paired id keeps the only dial on an attacker address, so disconnected devices never connect | pending 009: separate dial paths and a bounded hint table (009 FR-014, 009 FR-015, 009 FR-016); no mitigation in the code yet | F-005, RR-22 | Residual (RR-22) |

### B-05 Pairing

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B05-1 | S | a LAN attacker impersonates the other device (MITM) | SPAKE2 keyed by the 8-digit code feeds the Noise XXpsk2 PSK; transcript in the prologue | crates/device-link/tests/pairing_mitm.rs, crates/hardening/tests/fuzz_pairing_initiator.rs | Mitigated |
| T-B05-2 | T | a pairing message is modified | any mutated message ends the attempt failed with no pin and no session; the code is unused or failed | crates/hardening/tests/fuzz_pairing_initiator.rs, crates/hardening/tests/fuzz_pairing_joiner.rs | Mitigated |
| T-B05-3 | R | a person disputes having accepted a pairing | N/A: acceptance is a local decision on the person's own device; pins record the pairing time | 003 FR-022b | N/A |
| T-B05-4 | I | the code is guessed or brute-forced | one attempt per code, 300 s validity, at most 5 codes per 600 s | crates/device-link/tests/code.rs, 003 FR-021 | Mitigated |
| T-B05-5 | D | an attacker blocks pairing by holding the single slot or burning the shown code | step timeouts (10 s), one exchange at a time, code replacement; these do not stop the burn, since one Hello ends the code and five lock pairing for 10 minutes (F-004). Pending 009: a Hello takes no state, and a two-tier code limit (009 FR-008, 009 FR-011). A guess needs no knowledge of the code, so a burn stays possible | crates/device-link/tests/pairing_failures.rs, F-004, RR-21 | Residual (RR-21) |
| T-B05-6 | E | a pin is added without the person's acceptance | pins are written only after the person accepts and both sides commit (two-phase) | crates/device-link/tests/pairing_ack_loss.rs, crates/hardening/tests/fuzz_pairing_joiner.rs | Mitigated |
| T-B05-7 | I | the device private key is protected by file permissions only | accepted in 003 | RR-02 | Residual (RR-02) |

### B-06 Paired channel

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B06-1 | S | an unpaired device connects as a paired one | Noise XX with static keys checked against pins before revealing the dialer's key; `Refused` otherwise | crates/device-link/tests/channel_trust.rs, crates/hardening/tests/fuzz_channel_responder.rs | Mitigated |
| T-B06-2 | T | handshake or transport messages are modified, replayed or reordered | any AEAD failure ends the channel; a mutated handshake message never yields a channel | crates/device-link/tests/channel_attacks.rs, crates/hardening/tests/fuzz_channel_dialer.rs, crates/hardening/tests/fuzz_channel_payload.rs | Mitigated |
| T-B06-3 | R | a peer denies having sent a message | N/A: channels authenticate peers to each other only; no third-party evidence is needed | 003 FR-027 | N/A |
| T-B06-4 | I | traffic analysis or copies of keys inside the unaudited Noise and SPAKE2 crates | exact-pinned crates, no primitive implemented here; key copies inside the libraries are not wiped | RR-01 | Residual (RR-01) |
| T-B06-5 | D | a peer floods frames | frames at most 1024 bytes, per-peer limits, keepalive timeouts | crates/hardening/tests/fuzz_frame.rs, crates/passwsyncd/tests/flood_network.rs | Mitigated |
| T-B06-6 | E | a v1 peer is tricked into sync or share messages | Hello version bound into the Noise prologue; decoders per version reject later payload types | crates/hardening/tests/fuzz_hello.rs, crates/hardening/tests/fuzz_channel_payload.rs | Mitigated |
| T-B06-7 | D | an unpaired host forces a lower channel version, turning sync and sharing off for 24 h after it leaves | pending 009: fallback inside one dial with no memory, retry at v3 every 6 h (009 FR-001, 009 FR-002, 009 FR-006); no mitigation in the code yet. Version integrity of a running channel is unaffected (T-B06-6) | F-003, RR-20 | Residual (RR-20) |

### B-07 Wallet sync

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B07-1 | S | a paired device offers someone else's wallet as ours | copies are adopted only if they unlock with the local key (authenticated) and the wallet id matches | crates/wallet-sync/tests/protocol_attacks.rs, crates/hardening/tests/fuzz_sync_copy.rs | Mitigated |
| T-B07-2 | T | control messages or copy chunks are modified by a malicious peer | strict codec (512 tags, 24 KiB messages, copy sizes 79 B..64 MiB), reassembly bounds, pending copy stored only at the exact announced size | crates/hardening/tests/fuzz_sync_ctl.rs, crates/hardening/tests/fuzz_sync_reassembly.rs, crates/hardening/tests/fuzz_sync_copy.rs | Mitigated |
| T-B07-3 | R | edits after an undetected restore are attributed wrongly | accepted in 004 | RR-04 | Residual (RR-04) |
| T-B07-4 | I | sync reveals wallet contents to the peer | only wallets the peer already holds are synced; tags are keyed per session | crates/wallet-sync/tests/tags.rs | Mitigated |
| T-B07-5 | D | transfers exhaust memory or bandwidth | at most two transfers, at most 1 MiB buffered per transfer, idle traffic under 1 KiB per peer per hour | crates/hardening/tests/budgets.rs, crates/passwsyncd/tests/resources_sync.rs | Mitigated |
| T-B07-6 | E | a tampered sync record changes sync decisions | no MAC on the record; same-user writers are out of model; fail-safe semantics | RR-05 | Residual (RR-05) |

### B-08 Sharing

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B08-1 | S | a device redeems an invitation meant for another device | invitation bound to the recipient device id and an 8-digit code with proof | crates/wallet-sync/tests/share_proof.rs | Mitigated |
| T-B08-2 | T | share messages or data are modified | strict codec (types, abort reasons, lengths, no trailing bytes, `seconds_left` 1..300); received copies must open | crates/hardening/tests/fuzz_share_msg.rs, crates/wallet-sync/tests/share_attacks.rs | Mitigated |
| T-B08-3 | R | a paired device invalidates an invitation addressed to another device | accepted in 005 | RR-07 | Residual (RR-07) |
| T-B08-4 | I | a delivered copy cannot be withdrawn after the person changes their mind | accepted in 005 | RR-08 | Residual (RR-08) |
| T-B08-5 | D | share floods or oversize offers | one exchange at a time, shared transfer slots, size bound, received-wallet limit | crates/passwsyncd/tests/flood_share.rs, crates/wallet-sync/tests/share_limits.rs | Mitigated |
| T-B08-6 | E | a received wallet is treated as one of ours | received wallets are kept apart and adopted only by the person's explicit action; duplicate detection limited to wallets with a sync record | RR-06 | Residual (RR-06) |

### B-09 Android app and platform

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B09-1 | S | another app impersonates the UI or drives the exported activity | single exported activity, no web view, manifest policy checked | android/policy/check_manifest.py, android/verify.sh | Mitigated |
| T-B09-2 | T | another app tampers with app files or backups | app-private storage, backup and device-to-device transfer excluded, Keystore-sealed identity | android/policy/check_manifest.py | Mitigated |
| T-B09-3 | R | N/A on the device: a single person uses the app | N/A: no multi-user accountability requirement in 007 | 007 SC-005 | N/A |
| T-B09-4 | I | secrets in JVM text objects, the clipboard service or the screen | FLAG_SECURE, recents off; JVM copies and screen-reader access are documented residuals | RR-11, RR-12 | Residual (RR-11) |
| T-B09-5 | D | the app drains battery or wakes too often | background work budgets (B-23), pending device checks D-1..D-4 | 007 SC-008, 007 SC-009 | Mitigated |
| T-B09-6 | E | malformed arguments cross the FFI boundary into the core | every input-taking boundary function returns only `CoreError` kinds; fuzzed with networking off | crates/hardening/tests/fuzz_ffi_args.rs, crates/passwsync-ffi/tests/errors.rs | Mitigated |
| T-B09-7 | I | non-secret records are stored in plaintext; memory locking may be partial | pending maintainer approval; status shown to the person | RR-14, RR-13 | Residual (RR-14) |

### B-10 Packaging and service manager

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B10-1 | S | a different binary is started as the service | package installs fixed paths; launcher checks the peer UID; checksum-pinned source archive | packaging/verify.sh, packaging/PKGBUILD | Mitigated |
| T-B10-2 | T | the unit or its drop-ins weaken the sandbox | hardened systemd user unit verified by `systemd-analyze` and directive checks | packaging/passwsyncd.service, packaging/verify.sh | Mitigated |
| T-B10-3 | R | service starts and stops cannot be traced | N/A: the user journal records unit events; no further accountability is required | 006 FR-001 | N/A |
| T-B10-4 | I | the launch token leaks through the opener or logs | token handed only to the opener, opener output discarded, never logged | packaging/passwsync-open, crates/passwsyncd/tests/launch.rs | Mitigated |
| T-B10-5 | D | the unit restarts in a loop or lacks memory lock limits | restart limits; memlock drop-in; service self-checks exit 3 when a protection is missing | packaging/passwsync-memlock.conf, crates/passwsyncd/tests/hardening_process.rs | Mitigated |
| T-B10-6 | E | sandbox exceptions (network, netlink, `/proc` subset) | each justified in 006; accepted | RR-10 | Residual (RR-10) |

### B-11 Build, dependency and CI supply chain

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B11-1 | S | a dependency or tool is substituted (typosquat, unknown registry or git source) | locked and frozen builds; `cargo deny` sources rule (unknown registry and git denied); banned network and runtime crates | scripts/gate.sh, scripts/tests/fixtures/deny-ws/Cargo.toml, 008 FR-036 | Mitigated |
| T-B11-2 | T | the CI image or system packages change under the same name | image pinned by digest and pacman on one dated Arch Linux Archive snapshot; both are fail-closed sentinels until a maintainer resolves them (quickstart CI-0); the runner VM image itself is not pinnable | scripts/check_workflow.py, RR-18 | Residual (RR-18) |
| T-B11-3 | R | a CI result cannot be tied to a commit | every job checks out exactly `$GITHUB_SHA` anonymously; logs only, nothing published | scripts/check_workflow.py, 008 FR-031 | Mitigated |
| T-B11-4 | I | CI leaks secrets or a write token to a fork contributor (X-08) | no secrets referenced, `contents: read` only, no `pull_request_target`, no persisted credentials, no third-party actions | scripts/check_workflow.py, scripts/tests/test_check_workflow.py, 008 SC-010 | Mitigated |
| T-B11-5 | D | an advisory or a yanked crate goes unnoticed | `cargo audit --deny warnings` and `cargo deny` with every advisory kind failing; weekly scheduled run; the ignore list is one list in `deny.toml`, each entry in the register | scripts/gate.sh, RR-16, RR-17 | Residual (RR-16) |
| T-B11-6 | E | test-only code (`testkit`, the fuzz engine) reaches a release build; or duplicate crate versions widen the attack surface | release dependency graphs and symbols checked by the gate (`release-isolation`); duplicate count printed, warning only | scripts/gate.sh, crates/hardening/tests/leakage.rs, RR-19 | Residual (RR-19) |
| T-B11-7 | T | the optional cargo-fuzz workspace pulls an unverified dependency | never built by any gate; outside the lock and policy scope until reviewed (fuzz/README.md) | scripts/gate.sh, 008 FR-009 | Mitigated |

## 7. Out-of-model inputs

The following inputs are read only from files that belong to the person's own OS account and
are therefore written by the same user or by malware running as that user (X-05), which the
attacker model of 002-005 excludes. They are parsed defensively (bounded sizes, fail-safe
defaults) but are not fuzzed by feature 008 (spec Clarifications):

- the configuration file `config` (002 settings, 003 networking settings);
- the peers file (pins) and the device key file (003);
- the sync records and journals of the sync directory (004; see RR-05);
- the received-wallet metadata of sharing (005);
- the launch file read by the opener (002, 006).

A change that lets another party write any of these files (for example a shared directory)
moves the file into the model and needs a fuzz target and a boundary row first.

## 8. Residual-risk register

| Id | Risk | Source | Rationale | Severity | Owner | Closing condition | Status |
|----|------|--------|-----------|----------|-------|-------------------|--------|
| RR-01 | Noise and SPAKE2 libraries copy keys into internal state without zeroize on drop | specs/003-device-identity-pairing/research.md (R2, R4) | vetted, exact-pinned crates; writing our own primitives is worse; copies live only for one handshake | Medium | maintainer | the libraries wipe their key state, or a vetted replacement does | Accepted |
| RR-02 | The device private key is protected by owner-only file permissions only (desktop) | specs/003-device-identity-pairing/spec.md (Assumptions) | same trust level as the wallet directory; same-user malware is out of model | Medium | maintainer | an OS key store for the desktop identity is adopted | Accepted |
| RR-03 | Discovery announcements reveal a stable device id to anyone on the same LAN | specs/003-device-identity-pairing/spec.md (Assumptions) | needed for pinned reconnection; ids are public-key hashes, not names | Low | maintainer | rotating or private discovery is specified | Accepted |
| RR-04 | Edits made after an undetected restore of a device's files can be attributed or ordered wrongly | specs/004-wallet-sync-protocol/plan.md (R10) | detection needs trusted storage the design does not have; peer marks limit the damage | Medium | maintainer | a restore-detection mechanism is specified | Accepted |
| RR-05 | No MAC on the sync record | specs/004-wallet-sync-protocol/plan.md (Complexity Tracking) | only same-user writers can change it; a MAC adds key management without protecting against them | Low | maintainer | the record moves into an authenticated store | Accepted |
| RR-06 | Duplicate detection limited to wallets with a sync record | specs/005-wallet-sharing/plan.md (Complexity Tracking) | ids of never-unlocked wallets are encrypted; the residual case ends disabled without data loss | Low | maintainer | duplicate detection without the record is specified | Accepted |
| RR-07 | A paired device can invalidate an invitation addressed to another device | specs/005-wallet-sharing/plan.md (Constitution Check) | the paired device is trusted for availability; the person can re-invite | Low | maintainer | invitations become unforgeable by other paired devices | Accepted |
| RR-08 | An already delivered copy cannot be withdrawn | specs/005-wallet-sharing/plan.md (Constitution Check) | inherent to sharing data; revoke the device and change the password | Medium | maintainer | none (inherent); documented to the person | Accepted |
| RR-09 | Clipboard clearing cannot be guaranteed (other apps and clipboard managers keep copies) | specs/002-local-service-web-ui/spec.md (FR on clipboard) | best effort clearing; the UI says so when copying | Medium | maintainer | the platforms offer a guaranteed sensitive clipboard | Accepted |
| RR-10 | Sandbox exceptions of the systemd user unit (network, AF_INET, netlink, no IP allow-list, /proc subset for the peer-UID check) | specs/006-aur-packaging-service/plan.md (Constitution Check, Accepted residuals) | each needed by 002-005 functions and justified in 006 research R8/R10 | Low | maintainer | the user manager supports the missing restrictions | Accepted |
| RR-11 | JVM copies of secrets (Editable, TextView, ClipData, clipboard service) on Android | specs/007-android-app/plan.md (Complexity Tracking) | the platform text and clipboard APIs need platform strings; conversion minimised to two call sites | Medium | maintainer | maintainer approval of the 007 Constitution I residual, or a byte-only platform path | Pending approval |
| RR-12 | Screen-reader access to visible content on Android | specs/007-android-app/spec.md (Assumptions) | accepted residual of any app UI; secrets hidden by default | Low | maintainer | none (platform behaviour) | Accepted |
| RR-13 | Android memory locked full or secrets-only, with the status shown to the person | specs/007-android-app/plan.md (Constitution Check) | platform limits on `mlock`; the person sees which mode applies | Medium | maintainer | full locking is always available on supported devices | Accepted |
| RR-14 | Non-secret records stored in plaintext on Android (settings, sync and share records, device id, wallet file names) | specs/007-android-app/plan.md (Complexity Tracking) | same pattern as the desktop; encrypting needs a storage seam; 008 never grants the approval | Low | maintainer | maintainer approval of the 007 exception, or encrypted records | Pending approval |
| RR-15 | Constitution III exception: Kotlin and Gradle behaviour has no red-first unit test | specs/007-android-app/plan.md (Complexity Tracking) | no Kotlin toolchain or device on the host; Kotlin kept thin, policy checks and device checks instead | Low | maintainer | maintainer approval, or a Kotlin test toolchain in CI | Pending approval |
| RR-16 | Advisory RUSTSEC-2023-0089 (atomic-polyfill unmaintained, via postcard and heapless 0.7) ignored | deny.toml | unmaintained notice only, no vulnerability; inactive on x86_64 and aarch64 | Low | maintainer | postcard moves to a heapless without atomic-polyfill | Accepted |
| RR-17 | Advisory RUSTSEC-2026-0374 (basic-toml unmaintained, via askama in the binding generator) ignored | tools/uniffi-bindgen/deny.toml | build-time generator only, never shipped | Low | maintainer | UniFFI drops basic-toml | Accepted |
| RR-18 | The hosted runner VM image (ubuntu-24.04 label) is not pinnable; the container image digest and the Arch Linux Archive date are fail-closed sentinels until resolved | specs/008-hardening-audit/research.md (R15) | GitHub offers no digest pin for runner images; the container isolates build steps from most of it; sentinels keep CI from running unpinned | Medium | maintainer | CI-0 resolved (digest and date written) and a pinnable runner image is available | Open |
| RR-19 | Duplicate crate versions (cargo-deny multiple-versions stays a warning); the gate prints the duplicate count | specs/008-hardening-audit/research.md (R18) | duplicates come from upstream version splits (getrandom, syn); denying them needs dependency changes forbidden by 008 | Low | maintainer | upstream crates converge; then multiple-versions = "deny" | Accepted |
| RR-20 | An unpaired LAN host can force a channel below v3 for up to 24 h. Pending 009; after it, an on-path attacker can still force a lower version until the next 6 h retry | specs/009-lan-dos-hardening/spec.md | availability only: no wallet data flows on a lower channel, but changed passwords stop propagating | Medium | maintainer | 009 implemented; the on-path remainder then needs an authenticated version statement | Open |
| RR-21 | An attacker on the LAN can burn every shown pairing code. Pending 009, five burns lock pairing for 10 minutes; after it, the burn stays and the lockout goes | specs/009-lan-dos-hardening/spec.md | inherent to one guess per code: sending a guess needs no knowledge of the code | Medium | maintainer | 009 implemented; the burn itself needs a pairing design that does not spend a guess before checking it | Open |
| RR-22 | An announcement flood keeps disconnected paired devices apart. Pending 009; after it, forged sources can only delay a device that also moved | specs/009-lan-dos-hardening/spec.md | availability only, ends with the attack; an established channel is unaffected | Medium | maintainer | 009 implemented; the remainder needs authenticated discovery | Open |

## 9. Audit findings

Findings of the 008 audit (fuzzing, review items of research R20, benchmarks). Regression
tests of findings owned by `passwsyncd` live in `crates/hardening/tests/regress_008.rs`
because `crates/passwsyncd/tests` stays unchanged in 008 (gate rule of `android/verify.sh`).

| Id | Target | Finding | Severity | Status | Test or owner |
|----|--------|---------|----------|--------|---------------|
| F-001 | http_request | `read_request` accepted a bare LF as a line end in the request head (httparse is lenient); FR-016 requires CRLF only. Found at seed 0x505753594e430008, iteration 3439. Fixed by rejecting any LF not preceded by CR in the head (rejects invalid input only) | Low | Fixed | crates/hardening/tests/regress_008.rs::f_001_bare_lf_in_the_request_head_is_rejected |
| F-002 | wallet_payload | review item (research R20 item 3): postcard accepts a non-minimal varint inside the authenticated payload; the value re-encodes canonically (rule P holds). Not fixed: rejecting it needs a stricter decoder of the file format, and only a holder of the key can produce such a payload | Low | Open | vault-core maintainer |
| F-003 | peer dialing | security review 2026-11-05: an unpaired host forces a lower channel version with one announcement and closed connections; sync and sharing stay off up to 24 h after it leaves, with a misleading status. Measured about 60 ms, 7 TCP accepts. Spec 004 research R7 accepted this on a wrong rationale. Pending 009 | Medium | Open | maintainer (009) |
| F-004 | pairing | security review 2026-11-05: one pairing Hello ends the shown code with no guess, and the correct code is then refused; five rounds (about 200 ms) block pairing for 10 minutes. Pending 009 | Medium | Open | maintainer (009) |
| F-005 | discovery | security review 2026-11-05: announcements have no bound, reset the backoff and win the single dial slot; disconnected devices never connected during a flood of about 950 datagrams/s in 3 of 3 runs. Pending 009 | Medium | Open | maintainer (009) |
| F-006 | wallet creation | security review 2026-11-05: the master password rule is length only, so `aaaaaaaaaaaa` is accepted; Argon2id is then the only barrier for a stolen file or a copy on a paired device. No unlock throttling. Not in 009 | Medium | Open | maintainer |
| F-007 | listener | security review 2026-11-05: the limit of 16 unauthenticated connections is global, so one host can fill it and delay real dials (first success after 1.5 to 9.2 s at a 1.5 s step timeout). Not in 009 | Low | Open | maintainer |
| F-008 | discovery | security review 2026-11-05: a device dials back only for ids it has paired with, so announcing an id reveals who is paired with whom; wider than RR-03. Not in 009 | Low | Open | maintainer |
| F-009 | listener, interfaces | security review 2026-11-05 (code reading, not exploited): TCP accepts any private address with no subnet check, and desktop uses Docker and VPN interfaces by default. Not in 009 | Low | Open | maintainer |
| F-010 | loopback service | security review 2026-11-05 (code reading, not exploited): nothing authenticates the service to the browser, so another OS user holding the port while the service is down can collect a master password from a stale tab. T-B10-1 says the launcher checks the peer UID, but it only validates the launch file. Not in 009 | Low | Open | maintainer |

Review items of research R20 without a finding: (1) the 8 MiB `Content-Length` buffer per
request is within the 002 bound; worst case four workers hold 32 MiB of untouched address space
for the 10 s read timeout (noted in T-B03-5). (2) Serde's pre-allocation while decoding
postcard showed no address-space growth over the baseline at the 4 MiB resolution of the
allocation oracle. (4) The reassembler refuses `CopyData` during reassembly and resets after an
oversize sequence, as 004 specifies (fuzz target `sync_reassembly` and the engine check).

Benchmarks (`scripts/bench.sh`, development host, `reference=no`, 2026-11-02): every
budget B-01..B-20 has a value and PASS (B-04 information only); no OVER verdict, so no
benchmark finding. Binding timing verdicts wait for the reference laptop (quickstart M-1) and
the reference phone (D-1..D-4).

## 10. Change log

- 2026-10-30 (008 hardening audit): first system-wide version. Assets, actors, eleven
  boundaries with all STRIDE categories, register RR-01..RR-19 (19 required entries, including
  both advisory ignores), audit findings F-001 (fixed) and F-002 (open), out-of-model inputs.
- 2026-11-02 (008): fuzz target 17 `ffi_args` added (T-B09-6); benchmark results recorded in
  section 9 (no finding); `deny.toml` advisory keys tightened without new ignores (no new
  register row).
- 2026-11-05 (009 specification): findings F-003 to F-010 of the security review recorded, all Open.
  T-B05-5 corrected from Mitigated to Residual, since a pairing code could be burned; T-B04-7 and
  T-B06-7 added; register RR-20 to RR-22 added. Fixes for F-003 to F-005 are specified in
  `specs/009-lan-dos-hardening/` and pending 009 implementation, so no status here claims them yet.
