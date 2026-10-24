# Tasks: Device Identity and Pairing

**Input**: Design documents from `/specs/003-device-identity-pairing/`
**Prerequisites**: plan.md, spec.md, research.md (R1-R16), data-model.md, contracts/ (peer-protocol.md, http-api-network.md, host-runtime-network.md), quickstart.md
**Tests**: MANDATORY (Constitution III, TDD). Every implementation task is preceded by a test task that MUST be run and seen to FAIL (red) before the implementation task starts. Refactor with tests green.
**Organization**: By user story. Priority order: US1 identity (P1), US2 pairing (P1), US4 secure channel (P1), US3 discovery (P2), US5 list/revoke (P2). No wallet data crosses the network in this feature (FR-041).

## Format: `- [ ] T### [P?] [Story?] Description with file path`

- **[P]**: different file, no dependency on an incomplete task
- Paths are relative to the repo root. `DL` = `crates/device-link`, `DN` = `crates/device-link-net`, `PD` = `crates/passwsyncd`.
- Test tasks write the test only (red); the next numbered implementation task makes it green.
- **(MANUAL)** = needs a human, a browser, two hosts or network namespaces (root); cannot be automated here.

---

## Phase 1: Setup

- [X] T001 Add `crates/device-link` and `crates/device-link-net` to workspace `members` and shared dependency versions with exact pins (`snow` =0.10.0 `default-features = false` features `use-chacha20poly1305`,`use-blake2`,`use-curve25519`,`use-getrandom` and NOT `std`; `spake2` =0.4.0; `curve25519-dalek` 4.1; `sha2` 0.10; `if-addrs` =0.15.0 feature `link-local`; `qrcodegen` =1.8.0) in `Cargo.toml`
- [X] T002 [P] Create `crates/device-link/Cargo.toml` (deps: snow, spake2, curve25519-dalek, sha2, zeroize, rand_core, subtle; `testkit` feature; `[lints] workspace = true`) and empty `crates/device-link/src/lib.rs`; no dependency on `wallet-service` or `vault-core`
- [X] T003 [P] Create `crates/device-link-net/Cargo.toml` (deps: device-link, if-addrs, rustix; `testkit` feature; `[lints] workspace = true`) and empty `crates/device-link-net/src/lib.rs`
- [X] T004 Add `device-link`, `device-link-net`, `qrcodegen` to `crates/passwsyncd/Cargo.toml`; verify `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` pass and `unsafe_code = "forbid"` applies to both new crates (`Cargo.toml`, crate manifests)
- [X] T005 [P] Early dependency gate: run `cargo deny check` and `cargo audit`; only RUSTSEC-2023-0089 may remain; confirm `cargo tree -p device-link -e features` shows `snow` without `ring` (R16). Fix `Cargo.toml` features if `ring` appears

---

## Phase 2: Foundational (blocks all user stories)

### device-link core types (data-model.md)

- [X] T006 [P] Write failing tests for `DeviceKey` (public = X25519 base-point multiply of clamped private with an RFC 7748 known-answer vector; `Zeroizing` private; no `Debug`/`Display` impl via compile-fail or trait-absence test), `DeviceId` (`SHA-256("passwsync-device-id-v1" || public)` known-answer, 64 lowercase hex round-trip, `Ord` by bytes) and `Fingerprint` (base32 RFC 4648 of the first 10 ID bytes, `XXXX-XXXX-XXXX-XXXX`, known-answer) in `crates/device-link/tests/identity.rs`
- [X] T007 Implement `DeviceKey`, `DeviceId`, `Fingerprint` in `crates/device-link/src/identity.rs`
- [X] T008 [P] Write failing tests for `DeviceName::parse` (1-64 scalars, multi-byte ok, empty, 65, control chars, `"` rejected; default `passwsync device <4 fingerprint chars>`) in `crates/device-link/tests/name.rs`
- [X] T009 Implement `DeviceName` in `crates/device-link/src/name.rs`
- [X] T010 [P] Write failing tests for the LAN address policy (accept 10/8, 172.16/12, 192.168/16, 169.254/16; reject loopback, public, multicast, broadcast, unspecified, IPv6 of any kind; `testkit` policy additionally allows 127.0.0.0/8 only under the feature) in `crates/device-link/tests/policy.rs`
- [X] T011 Implement `AddressPolicy` in `crates/device-link/src/policy.rs`
- [X] T012 [P] Write failing tests for the closed `Error` enum and failure-reason enum (`wrong_code_or_tampered`, `expired`, `rejected`, `timeout`, `id_mismatch`, `self`, `already_paired`, `limit`, `refused_not_pairing`, `unreachable`, `cancelled`, `protocol` render to the exact snake_case strings; no variant carries free-form text) in `crates/device-link/tests/error.rs`
- [X] T013 Implement `Error`, `FailReason` in `crates/device-link/src/error.rs`
- [X] T014 [P] Write failing tests for ports fakes: `FakeMonoClock`/`FakeWallClock` (settable), `MemoryPeerStore` (save failure on demand, load/save round trip) in `crates/device-link/tests/ports.rs`
- [X] T015 Implement ports `PeerStore`, `MonoClock`, `WallClock` and `testkit` fakes in `crates/device-link/src/ports.rs`; wire modules in `crates/device-link/src/lib.rs`

### file codecs (host-runtime-network.md)

- [X] T016 [P] Write failing tests for `device-key` and `peers` text codecs (exact header lines; 64 hex; 0..=32 peer lines `<pk hex64> <paired_at> <last_seen|-> <a.b.c.d:port|-> <name hex>`; reject bad header, uppercase hex, wrong field count, 33 lines, duplicate keys, public key = own key, bad name, non-private address, trailing garbage; round trip) in `crates/device-link/tests/files.rs`
- [X] T017 Implement `device-key` / `peers` encode and strict decode in `crates/device-link/src/files.rs`

### passwsyncd config and files

- [X] T018 [P] Write failing tests for the config grammar extension (`on`/`off`, `"string"` without escapes or inner `"`; new keys `network`, `peer_port`, `discovery_port`, `device_name`, `network_interface` with defaults; ports 1024-65535 and pairwise distinct from `port`; bad name, bad interface (>15 chars, illegal chars), duplicate/unknown key each produce `config: <key>: <problem>` and exit 2; all 002 config tests still pass) by extending `crates/passwsyncd/tests/config.rs`
- [X] T019 Implement the grammar extension and `NetworkSettings` in `crates/passwsyncd/src/config.rs`
- [X] T020 [P] Write failing tests for device identity and peers file handling (missing `device-key` created once with `OsRng`, mode 0600, atomic; second run reuses same fingerprint; mode 0644, foreign owner, malformed content, symlink -> status `identity_unusable`, file byte-for-byte unchanged, NOT exit 2; same for `peers` -> `peers_unusable`; `peers` written atomically 0600 via temp + rename) in `crates/passwsyncd/tests/device_files.rs`
- [X] T021 Implement device-key and peers file handling in `crates/passwsyncd/src/paths.rs` and the `PeerStore` adapter in `crates/passwsyncd/src/net_store.rs`
- [X] T022 [P] Write failing tests for the added closed `LogEvent` variants (every variant in host-runtime-network.md renders exactly its contract text; none accepts free-form strings; `dropped public=.. malformed=.. oversized=.. overflow=.. timeout=..` at most once/minute and only when non-zero, then reset) by extending `crates/passwsyncd/tests/log.rs`
- [X] T023 Implement the added `LogEvent` variants and drop counters in `crates/passwsyncd/src/log.rs`

**Checkpoint**: core types, codecs, config, files, log events ready.

---

## Phase 3: User Story 1 - Each device has its own identity (P1)

**Goal**: first start creates a device identity; Devices view shows name and fingerprint; networking stays off by default.
**Independent test**: start with empty config dir; `GET /api/network` returns `this_device`, `status.state = off`; restart gives same fingerprint; `ss` shows only the loopback listener.

### Tests (red first)

- [X] T024 [P] [US1] Write failing test that with `network = off` the process holds no socket except the 002 loopback listener (socket inventory from `/proc/self/net` + fd scan) and that the private key is wiped (zeroized) after start-up when networking is off, in `crates/passwsyncd/tests/network_off.rs` (SC-002, FR-007, FR-009)
- [X] T025 [P] [US1] Write failing raw-HTTP tests for `GET /api/network` with networking off: shape per http-api-network.md, `this_device` present, `nearby`/`paired` empty, `status.state` for `identity_unusable`/`peers_unusable`; 002 guards apply (no cookie -> 403, no CSRF token -> 403, bad Host -> rejected, fixed rejection bodies), no route can change network settings (requests to any settings path answer 404 or 405, FR-008), no wallet unlock needed, wallet idle timers not reset, in `crates/passwsyncd/tests/api_network_status.rs`
- [X] T026 [P] [US1] Write failing UI static tests: Devices view present in `index.html`/`app.js`, no inline script or style, no external URL, CSP unchanged, all DOM built with `textContent`/DOM APIs (no `innerHTML` with data), in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T027 [US1] Implement start-up step 5a (load or create identity, set status, wipe key when networking off) in `crates/passwsyncd/src/app.rs`
- [X] T028 [US1] Implement `GET /api/network` (off/unusable states only for now) behind the unchanged 002 guards in `crates/passwsyncd/src/http/api_network.rs`; route it from `crates/passwsyncd/src/http/api.rs`
- [X] T029 [US1] Add the Devices view (this device: name, grouped fingerprint, network status, read-only settings; 5 s poll) in `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/app.css`
- [ ] T030 [US1] (MANUAL) Quickstart scenarios 1 and 2 in a browser; record results in the PR description — NOT DONE: needs a person with a browser; automated equivalents: network_off.rs, api_network_status.rs, device_files.rs

**Checkpoint**: US1 delivers identity with networking off.

---

## Phase 4: User Story 2 - Pair two devices with a short code or QR (P1)

**Goal**: SPAKE2 + Noise XXpsk2 pairing with human acceptance on A and two-phase pin commit.
**Independent test**: two in-memory state machines pair; every failure mode leaves nothing pinned; over loopback sockets and HTTP the same holds.

### wire and code (device-link)

- [X] T031 [P] [US2] Write failing tests for `wire` (frame `len:u16` 1..=1024, len 0 and 1025 rejected, truncated frame, Hello `PWSC 01 kind` valid/unknown magic/version/kind, payload codec for every type in the table, name length rules, trailing bytes -> protocol error, unknown type rejected) in `crates/device-link/tests/wire.rs`
- [X] T032 [US2] Implement `wire` (frame limits, Hello, payload encode/decode) in `crates/device-link/src/wire.rs`
- [X] T033 [P] [US2] Write failing tests for `PairingCode` (8 ASCII digits uniformly from injected RNG incl. leading zeros, no modulo bias test with a rejection-sampling fake RNG, 300 s expiry via fake clock, state transitions `Active -> Consumed -> Accepted|Failed`, `Expired|Cancelled|Replaced`, rate limiter refuses the 6th creation within 600 s, wipe on drop, no `Debug`) in `crates/device-link/tests/code.rs`
- [X] T034 [US2] Implement `PairingCode` and rate limiter in `crates/device-link/src/code.rs`
- [X] T035 [P] [US2] Write failing tests for `PeerRegistry` (`pin` refuses self, duplicate, 33rd pin; `revoke`; save via `PeerStore` happens before success is reported and a save failure leaves the registry unchanged; key never replaced for an existing ID) in `crates/device-link/tests/registry.rs`
- [X] T036 [US2] Implement `PeerPin`, `PeerRegistry` in `crates/device-link/src/registry.rs`

### pairing state machines (device-link)

- [X] T037 [P] [US2] Write failing known-answer tests that pin crypto behaviour: SPAKE2 side A/B with fixed seeds and ids `passwsync-pair-initiator-v1`/`passwsync-pair-joiner-v1` reproduce fixed messages and key; a Noise XXpsk2 handshake with fixed ephemerals and fixed psk reproduces fixed transcript bytes; official `snow` cacophony-style vector for `Noise_XX_25519_ChaChaPoly_BLAKE2s` (unaudited-crate mitigation, R16) in `crates/device-link/tests/known_answer.rs`
- [X] T038 [P] [US2] Write failing sans-IO tests for the happy pairing path A/B (frames 1-9 of peer-protocol.md; code consumed by first valid frame 2; A accepts matching `device_id`; both registries hold the other's key; `PairCommit` only after A saved; `PairAck` only after B saved; both devices show the same fingerprints) in `crates/device-link/tests/pairing_success.rs`
- [X] T039 [P] [US2] Write failing sans-IO tests for pairing failures, each leaving BOTH registries empty and the code unusable: wrong code (`wrong_code_or_tampered` on both), code expired, code reused after a failed attempt, A not showing a code (`refused_not_pairing`), second concurrent pairing refused, both sides joining each other at once (at most one succeeds), Reject on A (`rejected`), B closes before `PairCommit`, A's save fails, pair with self (`self`), already paired (`already_paired`), 33rd pin (`limit`), step timeout 10 s, awaiting-acceptance expiry in `crates/device-link/tests/pairing_failures.rs`
- [X] T040 [P] [US2] Write failing MITM tests: attacker relaying between A and B without the code cannot complete (both sides fail, nothing pinned); attacker that guesses the code once gets exactly one try and the code is consumed; transcript tampering of any single byte of frames 2-5 (prologue binding) fails; QR mode with wrong expected `device_id` -> `id_mismatch`; replay of a recorded full session against a fresh code fails; frame-1 SPAKE_B replayed to a new session fails in `crates/device-link/tests/pairing_mitm.rs`
- [X] T041 [P] [US2] Write failing malformed-input tests for the pairing machines: oversized frame (1025), zero-length, wrong SPAKE length (32, 34), junk Noise messages, payload with trailing bytes, out-of-order frames, unknown payload type; every case ends in `protocol` failure without panic and nothing pinned in `crates/device-link/tests/pairing_malformed.rs`
- [X] T042 [US2] Implement `PairingInitiator` and `PairingJoiner` state machines (SPAKE2 output as XXpsk2 psk, SPAKE2 transcript in prologue, two-phase commit, all secrets `Zeroizing`) in `crates/device-link/src/pairing.rs`; use only `snow` and `spake2` APIs, no custom primitives

### network adapter (device-link-net)

- [X] T043 [P] [US2] Write failing tests for `framed` I/O (reads exactly one frame, enforces 1024 max before allocating, 10 s step timeout via short injected timeout, partial frame then stall -> timeout, EOF) over loopback in `crates/device-link-net/tests/framed.rs`
- [X] T044 [US2] Implement `framed` read/write with read timeouts in `crates/device-link-net/src/framed.rs`
- [X] T045 [P] [US2] Write failing tests for interface enumeration (`if-addrs` results filtered by `AddressPolicy`, IPv4 only, link-local kept, loopback dropped unless `testkit`, `network_interface` filter, directed-broadcast computed from addr/prefix, `no_local_network` when empty) in `crates/device-link-net/tests/interfaces.rs`
- [X] T046 [US2] Implement `interfaces` in `crates/device-link-net/src/interfaces.rs`
- [X] T047 [P] [US2] Write failing loopback tests for `listener` (binds `0.0.0.0:<port>`, at most 16 unauthenticated connections - the 17th is closed immediately and counted `overflow`; connections from addresses failing the policy closed and counted `public`; Hello timeout counted `timeout`) in `crates/device-link-net/tests/listener.rs`
- [X] T048 [US2] Implement bounded `listener` and `conn` (per-connection thread, peer address check, drop counters) in `crates/device-link-net/src/listener.rs`, `crates/device-link-net/src/conn.rs`
- [X] T049 [P] [US2] Write failing loopback test running a full pairing between two `device-link-net` endpoints over TCP (testkit policy) for success, wrong code and reject, in `crates/device-link-net/tests/pairing_loopback.rs`
- [X] T050 [US2] Implement `dialer` (policy-checked connect with timeout, runs `PairingJoiner`) and the acceptor-side driver for `PairingInitiator` in `crates/device-link-net/src/dialer.rs`, `crates/device-link-net/src/conn.rs`

### passwsyncd routes and UI

- [X] T051 [P] [US2] Write failing tests for QR generation (`qrcodegen` matrix -> `{size, path}` where path is a valid SVG path of 1x1 modules; `qr_text` format `passwsync://pair?v=1&code=<8>&id=<64hex>&addr=<ip:port>`; known matrix for a fixed text) in `crates/passwsyncd/tests/qr.rs`
- [X] T052 [US2] Implement QR to SVG path in `crates/passwsyncd/src/qr.rs`
- [X] T053 [P] [US2] Write failing raw-HTTP tests for `POST /api/pairing/start|cancel|accept|reject|join` (all errors and codes from http-api-network.md: `networking_off`, `busy`, `pair_limit`, `too_many_codes`, `nothing_pending`, `pairing_mismatch`, `expired`, `storage_error` with nothing pinned, `invalid_address` incl. host names and public IPs, `invalid_code` accepting spaces/dashes, `invalid_device_id`, `already_paired`, `self`; a second `start` invalidates the first code (the old code then fails with `wrong_code_or_tampered` or `nothing_pending`); `code`/`qr`/`qr_text` present only while valid; and the full 002 guard matrix on every new route: missing cookie, missing/wrong CSRF, wrong Origin, wrong Host, wrong peer UID, oversize body, wrong method, fixed rejection bodies) in `crates/passwsyncd/tests/api_pairing.rs`
- [X] T054 [P] [US2] Write failing test that the pairing code, session keys and private key never appear in captured stderr, runtime and config dirs, or `/proc/self` environment after a full pairing, by extending `crates/passwsyncd/tests/scans.rs` (FR-040, SC-006)
- [X] T055 [US2] Implement start-up step 5b (peers load, interface enumeration, TCP bind, `port_in_use` / `no_local_network` states, network log events) and the pairing coordinator thread in `crates/passwsyncd/src/app.rs`, `crates/passwsyncd/src/net_runtime.rs`
- [X] T056 [US2] Implement the pairing routes and `pairing`/`join` objects in `GET /api/network` in `crates/passwsyncd/src/http/api_network.rs`; ensure none call wallet unlock or reset idle timers (FR-037)
- [X] T057 [US2] Add "Pair a device" (grouped code, QR as `<svg>` built with DOM APIs from `qr.path`, countdown, Accept/Reject with name and fingerprint), Join form (address, code, optional device id), 1 s poll while pairing, in `crates/passwsyncd/ui/index.html`, `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/app.css`
- [ ] T058 [US2] (MANUAL) Quickstart scenarios 3, 4 and 5 on two hosts or two network namespaces with a veth pair (root needed); verify a human can pair in under 1 minute (SC-001) and compare fingerprints; record in the PR description — NOT DONE: needs two hosts or root for network namespaces and a person timing SC-001; loopback equivalents: device-link-net tests/pairing_loopback.rs, passwsyncd tests/api_pairing.rs
- [X] T100 [P] [US2] Write regression test for FR-022b lost messages in `crates/device-link/tests/pairing_ack_loss.rs`: a transport that drops B's final `PairAck` leaves A holding its pin (committed) while B holds no pin and reports `pairing failed, try again`, and a later channel attempt from B succeeds without re-pairing; a transport that drops `PairCommit` leaves B with no pin and A's pin harmless (no channel possible). Written after T042 as a regression test; if it fails, fix T042
- [X] T101 [P] [US2] Write failing UI static tests in `crates/passwsyncd/tests/ui_static.rs` for the Devices view parts not covered by T026/T082: "Pair a device" (grouped code, QR as `<svg>` built with `createElementNS` from `qr.path`, countdown, Accept/Reject showing name and fingerprint), Join form (address, code, nearby pick), paired list status, warnings list with clear button; no `innerHTML` with data, no inline script or style, no external URL, CSP unchanged. These MUST be red before T057, T069 and T078 start (Constitution III)

**Checkpoint**: US2 pairs devices with MITM, wrong-code, replay and malformed-input protection.

---

## Phase 5: User Story 4 - Talk to paired devices only, securely (P1)

**Goal**: mutually authenticated, forward-secret channel restricted to pins; keepalive, dedupe, name update, offline detection.
**Independent test**: two paired in-memory endpoints open a channel; unpaired, revoked, changed-key peers are refused; replay and tamper close the channel.

### Tests (red first)

- [X] T059 [P] [US4] Write failing sans-IO tests for `channel` handshake (frames 1-5 of peer-protocol.md: dialer verifies responder static equals the pin or closes with warning; responder replies `Welcome` only for pinned dialer else `Refused` then close; prologue includes Hello; forward secrecy test: record a complete handshake and transport bytes of one session, then with both static private keys known every decryption attempt that lacks the session's ephemeral private keys fails; distinct ephemerals per session asserted) in `crates/device-link/tests/channel_handshake.rs`
- [X] T060 [P] [US4] Write failing tests for channel attacks: replayed transport message (nonce reuse) fails AEAD and closes; reordered messages close; flipped bit in any ciphertext byte closes; message from another connection's session does not decrypt; cross-connection replay of msg3 rejected; truncated and oversized (1025) frames close; unknown payload type (e.g. a wallet-sync type) closes; trailing bytes close; only `Keepalive`, `NameUpdate`, `Close` accepted after Welcome (FR-031) in `crates/device-link/tests/channel_attacks.rs`
- [X] T061 [P] [US4] Write failing tests for unpaired/changed/revoked keys: stranger key refused (`Refused`, close, `peer refused unpaired`); a pinned ID presented with a different key at the pinned address -> dialer refuses, registry unchanged, `UnpairedKeyAtAddress` warning recorded (max 8, oldest dropped, clearable); revoked key refused with `revoked` reason; pin never overwritten in `crates/device-link/tests/channel_trust.rs`
- [X] T062 [P] [US4] Write failing tests for `Link` decision logic with fake clocks: dial backoff 30 -> 300 s, reset on success; keepalive after 60 s idle; close after 150 s silence; duplicate channels resolved keeping the one whose dialer has the smaller device ID (both orders, simultaneous dial); `NameUpdate` updates the pin name only on an authenticated channel; status `Connected`/`Offline`/`RefusedByPeer`; `Close(shutdown)` on stop in `crates/device-link/tests/link.rs`
- [X] T063 [P] [US4] Write failing loopback tests over TCP: two `device-link-net` endpoints connect, reconnect after one restarts, re-establish after a simulated interface change without re-pairing, unpaired third endpoint refused, at most one channel per peer, handshake step timeout 10 s, a flood of 10 000 connection attempts/minute from one address keeps memory bounded and the legitimate peer connects (`#[ignore]` for the flood variant, SC-008) in `crates/device-link-net/tests/channel_loopback.rs`
- [X] T064 [P] [US4] Write failing raw-HTTP + captured-traffic tests that peer traffic on the loopback test network contains no device names, codes or wallet strings in clear (SC-006) and that `paired[].status` reflects connected, offline and refused_by_peer in `crates/passwsyncd/tests/api_channel.rs`

### Implementation

- [X] T065 [US4] Implement `channel` (Noise XX handshake, `TransportState` wrapper, payload dispatch limited to the v1 set, zeroize) in `crates/device-link/src/channel.rs`
- [X] T066 [US4] Implement `Link` decisions and warnings in `crates/device-link/src/link.rs`
- [X] T067 [US4] Implement channel accept/dial threads, bounded connection table, keepalive timers using blocking reads with timeouts (no busy-poll, FR-039) in `crates/device-link-net/src/conn.rs`, `crates/device-link-net/src/dialer.rs`, `crates/device-link-net/src/lib.rs`
- [X] T068 [US4] Wire channels into the passwsyncd runtime, add `paired[]`, `status`, `warnings[]` to `GET /api/network`, `POST /api/network/warnings/clear`, and persist `last_seen`/`last_addr` on close and stop in `crates/passwsyncd/src/net_runtime.rs`, `crates/passwsyncd/src/http/api_network.rs`
- [X] T069 [US4] Add paired list (status, last seen) and warnings (with clear button) to the Devices view in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html`
- [ ] T070 [US4] (MANUAL) Quickstart scenarios 7 and 8 (offline detection within 3 min, reconnect without re-pairing, `tcpdump` shows no names or codes, impersonation warning) on two hosts or netns; record in the PR description — NOT DONE: needs two hosts or netns (root) and tcpdump; loopback equivalents: channel_loopback.rs, api_channel.rs (recording proxy)

**Checkpoint**: US4 delivers the authenticated channel (no wallet data).

---

## Phase 6: User Story 3 - See nearby devices without any server (P2)

**Goal**: UDP broadcast discovery, only while there are pins or an active code; untrusted, bounded.
**Independent test**: datagram codec and `NearbyList` in memory; loopback UDP; flood.

### Tests (red first)

- [X] T071 [P] [US3] Write failing tests for the discovery codec (exactly 39 bytes `PWSD 01 <id32> <port u16>`; 38 and 40 bytes, wrong magic, wrong version, port < 1024, own ID all counted `malformed` and ignored) and `NearbyList` (<= 64 entries with the 65th dropped as `overflow`, expiry 90 s via fake clock, update on re-announce, paired flag computed from registry never from the datagram, source IP failing the policy dropped as `public`) in `crates/device-link/tests/discovery.rs`
- [X] T072 [P] [US3] Write failing tests for announce policy in `Link`: no packet is ever sent with zero pins and no active code; first announce immediately on start, network change and code shown, only while ≥1 pin or an active code exists (FR-013a); then every 30 s; none after the last pin is revoked or the code expires/cancels, in `crates/device-link/tests/announce.rs`
- [X] T073 [P] [US3] Write failing loopback UDP tests: a datagram is sent to each in-use interface's directed broadcast (testkit: loopback), receiver ignores datagrams from non-policy sources, a testkit interface change triggers an immediate announcement on the new subnet, a flood of 10 000 datagrams/minute keeps `NearbyList` <= 64 and the receiver loop non-blocking, announce sockets closed when networking turns off, in `crates/device-link-net/tests/discovery_loopback.rs`
- [X] T074 [P] [US3] Write failing raw-HTTP test that `GET /api/network` lists `nearby` with fingerprint/addr/`paired`, remains bounded under a 10 000-packet/min flood and answers within 1 s while flooded (`#[ignore]`, SC-008), in `crates/passwsyncd/tests/api_nearby.rs`

### Implementation

- [X] T075 [US3] Implement discovery codec and `NearbyList` in `crates/device-link/src/discovery.rs`; announce decisions in `crates/device-link/src/link.rs`
- [X] T076 [US3] Implement the UDP discovery socket/thread (bounded counters, 30 s interface re-scan, `network interfaces changed` event) in `crates/device-link-net/src/discovery.rs`
- [X] T077 [US3] Start the discovery thread in passwsyncd, bind order TCP then UDP with `port_in_use` handling (close the other socket), add `nearby[]` to `GET /api/network` in `crates/passwsyncd/src/net_runtime.rs`, `crates/passwsyncd/src/http/api_network.rs`
- [X] T078 [US3] Add the nearby list (pick to prefill Join address and `device_id`) to the Devices view in `crates/passwsyncd/ui/app.js`
- [ ] T079 [US3] (MANUAL) Quickstart scenarios 3 (socket inventory) and 6 (`tcpdump` shows silence without pins/code, 39-byte packets with no names otherwise) on two hosts or netns; record in the PR description — NOT DONE: needs two hosts or netns (root) and tcpdump; loopback equivalents: discovery_loopback.rs, api_nearby.rs, network_on.rs

**Checkpoint**: US3 delivers serverless discovery.

---

## Phase 7: User Story 5 - List and revoke paired devices (P2)

**Goal**: revoke a pin locally; the channel closes in under 1 s; the revoked side only learns via `Refused`.
**Independent test**: revoke in the API closes the channel and refuses reconnect; re-trust requires new pairing.

### Tests (red first)

- [X] T080 [P] [US5] Write failing tests for `Link`/`PeerRegistry` revoke: pin removed and saved before success; save failure keeps the pin and the channel; channel closed immediately and no message sent to the peer (FR-034); reconnect attempt from the revoked key is `Refused`; peer sees `RefusedByPeer`; a Hello(pair) from the revoked key with no active code is refused (`refused_not_pairing`) and a fresh code pairs again, re-pairing restores trust in `crates/device-link/tests/revoke.rs`
- [X] T081 [P] [US5] Write failing raw-HTTP tests for `POST /api/devices/{id}/revoke` (`404 device_not_found` for unknown and for malformed ids, `500 storage_error` keeps pin, success closes channel within 1 s measured, full 002 guard matrix, no wallet unlock needed) in `crates/passwsyncd/tests/api_revoke.rs`
- [X] T082 [P] [US5] Write failing UI static test for the revoke confirmation dialog and that no revoke call is issued without it, in `crates/passwsyncd/tests/ui_static.rs`

### Implementation

- [X] T083 [US5] Implement revoke in `crates/device-link/src/registry.rs`, `crates/device-link/src/link.rs`, and channel close signalling in `crates/device-link-net/src/conn.rs`
- [X] T084 [US5] Implement `POST /api/devices/{id}/revoke` and the `device revoked` / `refused by peer` log events in `crates/passwsyncd/src/http/api_network.rs`, `crates/passwsyncd/src/net_runtime.rs`
- [X] T085 [US5] Add Revoke with confirmation dialog to the paired list in `crates/passwsyncd/ui/app.js`, `crates/passwsyncd/ui/index.html`
- [ ] T086 [US5] (MANUAL) Quickstart scenario 9 (revoke closes in < 1 s; B shows A "refused by peer"; only new pairing restores trust); record in the PR description — NOT DONE: needs two hosts or netns (root) and a browser; loopback equivalent: api_revoke.rs (channel closed < 1 s, refused_by_peer)

---

## Phase 8: Host runtime obligations

- [X] T087 [P] Write failing test that shutdown order holds: `Close(shutdown)` sent, sockets closed, `last_seen` saved, private key and pairing code wiped, then wallets locked, and a code shown before stop is gone after restart, in `crates/passwsyncd/tests/shutdown_network.rs`
- [X] T088 [P] Write failing hardening tests that networking does not weaken 002: process still non-dumpable with core dumps off and `mlockall` active with the network threads running; no thread or socket is created when `network = off`; no IPv6 socket, no DNS resolution call (resolver path never reached: `address` with a host name rejected before any lookup) in `crates/passwsyncd/tests/hardening_network.rs`
- [X] T089 Implement graceful network shutdown and verify `hardening.rs` coverage of the new threads in `crates/passwsyncd/src/app.rs`, `crates/passwsyncd/src/hardening.rs`
- [X] T090 [P] Add resource-budget `#[ignore]` tests (run with `--release -- --ignored`): idle with 5 in-process paired peers for a bounded window adds < 10 MB RSS over `network = off`, CPU < 1 %, <= 1 wake per 30 s per peer (count of `epoll`/timer wakes via counters in the net loops), in `crates/passwsyncd/tests/resources_network.rs` (SC-007)
- [X] T091 [P] Add flood `#[ignore]` test: 10 000 UDP announcements and 10 000 TCP attempts per minute from one address; memory bounded, loopback UI responds < 1 s, in `crates/passwsyncd/tests/flood_network.rs` (SC-008)

---
- [X] T102 [P] Write failing test with `network = on`: socket inventory (`/proc/self/fd` + `/proc/net/{tcp,udp}`) shows exactly the UI listener, one TCP listener on `peer_port`, one UDP socket on `discovery_port`, plus only pairing/channel connections to policy-passing addresses; no other listener and no IPv6 socket, in `crates/passwsyncd/tests/network_on.rs` (SC-002, FR-010)
- [X] T103 [P] Write failing test that with `network = on` and `peer_port` already in use, networking stays off with status `port_in_use` naming the port, no other socket is left open, the log names the port, and the loopback UI still answers `GET /api/network`, in `crates/passwsyncd/tests/port_in_use.rs` (edge case; FR-010)

## Phase 9: Polish & Cross-Cutting

- [X] T092 [P] Run dependency review again after all code is in: `cargo deny check` and `cargo audit`; only RUSTSEC-2023-0089 accepted; update `deny.toml` only with a written reason; confirm lock file new crates match R16 list and `snow`/`spake2` are exact-pinned
- [X] T093 [P] Record the unaudited-crate mitigations as verifiable items in `specs/003-device-identity-pairing/research.md` R16 status line: exact pins (T001), known-answer tests (T037), fingerprint compare plus human accept on A (T038/T057), fuzzing and re-review deferred to 008
- [X] T094 [P] Add a log/secret scan covering the new feature end to end (pair, channel, revoke) over stderr, runtime and config dirs for codes, keys, names-in-transit by extending `crates/passwsyncd/tests/scans.rs` (FR-040)
- [X] T095 [P] Run `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`; confirm no `unsafe` in the new crates
- [X] T096 [P] Add README section on enabling `network = on`, the new config keys, ports 27472/tcp and 27473/udp, and the pairing procedure in `README.md`
- [X] T097 Run `cargo test --workspace` and `cargo test --workspace --release -- --ignored`; all 002 tests (guards, hardening, scans) must stay green
- [ ] T098 (MANUAL) Final quickstart validation: scenarios 1-10 of `specs/003-device-identity-pairing/quickstart.md` including scenario 10 resource check (`pidstat -p <pid> 60` for 10 min, RSS delta < 10 MB, CPU < 1 %); record results in the PR description — NOT DONE: needs two hosts/netns, a browser and pidstat; automated SC-007 equivalent passed (`device-link-net/tests/resources.rs --ignored`: CPU 0.01 %, 18 wakes / 95 s for 5 peers, RSS +1 MiB)
- [X] T099 Verify SC-001..SC-008 each map to a passing test or a recorded manual scenario and update the mapping in the PR description and record the FR map: FR-001..006 -> T006-T009, T020, T024, T027, T038; FR-011 -> T010, T045, T047, T073; FR-012 -> T088; FR-013/013a -> T072, T073; FR-014/015/016 -> T071, T074; FR-017..025 -> T033, T038-T041, T053, T057; FR-026..031 -> T059-T064; FR-032..035 -> T064, T080-T081, T016, T020; FR-036..038 -> T025, T026, T051, T053, T081; FR-039 -> T090; FR-040 -> T022, T054, T094; FR-041 -> T094 (negative scan) (SC-001 -> T058, SC-002 -> T024/T030/T102, SC-003 -> T039/T040, SC-004 -> T060/T061, SC-005 -> T070/T079, SC-006 -> T054/T064/T094, SC-007 -> T090/T098, SC-008 -> T063/T074/T091)

---

## Dependencies & Execution Order

- Phase 1 -> Phase 2 -> US1 (Phase 3) -> US2 (Phase 4) -> US4 (Phase 5) -> US3 (Phase 6) and US5 (Phase 7) -> Phase 8 -> Phase 9.
- US2 needs US1 (identity, `GET /api/network`). US4 needs US2 (pins) and its `wire`/`framed`/`listener`. US3 needs only Foundational + `interfaces` (T046) and the runtime (T055), so it can start after US2; pairing also works by typed address without it. US5 needs US4 (channels to close).
- Within device-link: T006-T017 are independent files; T032 before T042; T034, T036 before T042; T037 before T042/T065 (known-answer first).
- Always: test task (red) before its implementation task; commit nothing red.
- Shared files (`api_network.rs`, `net_runtime.rs`, `app.js`, `link.rs`) are edited across stories: run those implementation tasks sequentially.

## Parallel Examples

- Phase 2: T006, T008, T010, T012, T014, T016, T018, T020, T022 touch different files.
- US2 tests T031, T033, T035, T037-T041, T043, T045, T047, T051, T053, T054 are all different files and may be written together.
- US4 tests T059-T064 are parallel; US3 tests T071-T074 and US5 tests T080-T082 are parallel (UI static tests share `ui_static.rs`: split by module if concurrent).
- Phase 8 T087, T088, T090, T091 and Phase 9 T092-T096 are parallel.

## Implementation Strategy

- MVP = Phases 1-4 (setup, foundations, identity, pairing): a device can be identified and securely paired. Then US4 (channel), then P2 stories (discovery, revoke).
- Deliver incrementally; at each checkpoint run `cargo test --workspace` and clippy.
- Manual/hardware tasks: T030, T058, T070, T079, T086, T098 (two hosts or netns, browser, tcpdump, pidstat).

## Verification map (T099, recorded at implementation; no PR exists yet)

| Criterion | Automated evidence | Manual |
|-----------|--------------------|--------|
| SC-001 pair < 1 min | `device-link-net/tests/pairing_loopback.rs`, `passwsyncd/tests/api_pairing.rs` (flow works end to end) | T058 (timing by a person) |
| SC-002 socket inventory | `passwsyncd/tests/network_off.rs`, `network_on.rs`, `port_in_use.rs`, `hardening_network.rs` | T030, T079 |
| SC-003 no pin on failure/MITM | `device-link/tests/pairing_failures.rs`, `pairing_mitm.rs`, `pairing_malformed.rs`, `pairing_ack_loss.rs` | - |
| SC-004 refuse unpaired/revoked/changed, reject replay/tamper | `device-link/tests/channel_trust.rs`, `channel_attacks.rs`, `revoke.rs`; `device-link-net/tests/channel_loopback.rs` | - |
| SC-005 nearby <= 60 s, offline <= 3 min, revoke <= 1 s | `discovery_loopback.rs`, `link.rs` (150 s idle close), `api_channel.rs` (offline), `api_revoke.rs` (< 1 s) | T070, T079 |
| SC-006 no names/codes/wallet data in traffic or logs | `api_channel.rs` (recording proxy), `pairing_success.rs`, `channel_handshake.rs`, `scans.rs` | - |
| SC-007 resources | `device-link-net/tests/resources.rs` (`--ignored`: CPU, wakes, RSS), `passwsyncd/tests/resources_network.rs` (`--ignored`) | T098 |
| SC-008 flood | `discovery_loopback.rs` (10 000 datagrams), `channel_loopback.rs`, `api_nearby.rs`, `flood_network.rs` (`--ignored`) | - |

FR map as listed in T099 above; every listed task has its test file in the tree.

## Phase 10: Convergence

- [X] T104 Remove the self-connection and self-datagram used to wake blocked threads in `Node::shutdown` (`crates/device-link-net/src/lib.rs`), using bounded accept and receive timeouts instead; first a red test in `crates/device-link-net/tests/listener.rs` that stop never initiates a TCP connection or UDP datagram to a non-policy destination and still returns within the step timeout per FR-011 (contradicts)
- [X] T105 Make a red test that an unauthenticated announcement from a new address never changes a pinned peer's stored `last_addr` (`crates/device-link/tests/registry.rs`), then stop `note_addr` in `crates/device-link-net/src/discovery.rs` from overwriting pins: dial the announced address for that attempt only and persist the address solely from an authenticated channel in `register` per FR-014 and FR-028 (partial)
- [X] T106 Make a red test that `DeviceKey` is zeroize-on-drop (bound check in `crates/device-link/tests/identity.rs`) and that no unwiped copy of the private bytes is made when networking starts (`crates/passwsyncd/src/net_runtime.rs`, `try_start_node`, `*inputs.key.private_bytes()`); then move or wrap the key so the temporary is wiped, per FR-007 and Constitution V (partial)
- [X] T107 Make a red test that revoking sends nothing to the revoked peer (capture frames B receives after A's revoke in `crates/passwsyncd/tests/api_revoke.rs` or `crates/device-link-net/tests/channel_loopback.rs`; only the next Hello is answered with Refused), and replace the vacuous unit test `a_failed_save_keeps_the_pin_and_the_channel` in `crates/device-link/tests/revoke.rs` with one that drives the save-before-`link.revoked` order used by `Node::revoke` per FR-034 and T080 (missing test coverage)
