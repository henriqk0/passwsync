# Research: Device Identity and Pairing (003)

Phase 0 output. Every choice the spec left open is decided here. Questions that would have
been asked were answered non-interactively with the most secure, then simplest, option
consistent with the constitution and roadmap. No NEEDS CLARIFICATION remains.

## R1. Crate layout (hexagonal boundary)

- **Decision**: Two new crates.
  - `crates/device-link` (core, no I/O): device key and ID types, fingerprint, device name,
    pairing code, discovery packet codec, frame and message codecs, the pairing and channel
    state machines (sans-IO, built on `snow` and `spake2`), the peer registry (pins, limit,
    revocation), the nearby list, the networking state (`Link`) that decides when to
    announce, dial, accept, dedupe and refuse, the address policy, and the file-content
    codecs for the key and peers files (bytes <-> structs). Ports: `PeerStore`
    (load/save pins), `MonoClock` (monotonic time), `WallClock` (Unix seconds for dates),
    plus an injected `CryptoRngCore` for codes. Fakes behind a `testkit` feature.
  - `crates/device-link-net` (adapter library): `std::net` TCP listener, UDP discovery
    socket, outbound dialing, per-connection threads with timeouts, interface enumeration
    (`if-addrs`), framing over `TcpStream`. Reused unchanged by the Android app (007).
  - `crates/passwsyncd` (existing binary): file adapters for `device-key` and `peers`
    (XDG, permissions, atomic writes, reusing `paths::write_private_atomic` and
    `check_private`), config keys, start-up wiring, HTTP routes, UI view, log events.
- **Rationale**: Protocol and trust decisions are pure and testable with fakes (Principle
  IV). The socket adapter must be reusable by 007 without dragging HTTP/desktop hardening,
  so it cannot live inside the `passwsyncd` binary. `wallet-service` is not touched: device
  identity is independent of wallets (FR-037).
- **Alternatives**: one crate with modules (rejected: cannot keep the core free of
  `std::net`); adapters inside `passwsyncd` (rejected: not reusable by 007); putting
  networking state into `wallet-service` (rejected: unrelated responsibility).

## R2. Handshake and channel construction (no hand-rolled cryptography)

- **Decision**: The **Noise Protocol Framework** via the `snow` crate, one cipher suite:
  `25519_ChaChaPoly_BLAKE2s`.
  - **Secure channel** (paired devices): `Noise_XX_25519_ChaChaPoly_BLAKE2s`. The dialer is
    the Noise initiator. Prologue = `"passwsync-channel-v1"` || Hello frame bytes.
    - msg1 `-> e`; msg2 `<- e, ee, s, es` (empty payload); msg3 `-> s, se` with payload
      `ChannelHello{name}`.
    - Dialer, after msg2: the responder's static key MUST equal the pin of the peer it
      dialed, else close (and record an "unpaired key at address" warning). It reveals its
      own static only in msg3, after that check.
    - Responder, after msg3: initiator static MUST be a current pin, else it sends one
      transport message `Refused` and closes (lets the far side show "refused by peer";
      reveals nothing secret). If pinned: transport `Welcome{name}`; channel is up.
  - Transport phase: snow `TransportState` with its sequential 64-bit nonces over TCP; any
    decryption failure (tamper, reorder, drop, injection, replay) closes the connection.
    Fresh ephemeral keys per connection give forward secrecy and make traffic from one
    connection undecryptable in another (FR-027).
- **Rationale**: Noise XX is a well-analysed construction (formal analyses: Noise Explorer,
  Kobeissi et al.; used by WireGuard-family, libp2p, Lightning, WhatsApp) giving mutual
  authentication, identity hiding for the initiator, KCI resistance and forward secrecy
  with no 0-RTT replay window. One pattern family for pairing and channel keeps the code
  small. XX (1.5 RTT) is chosen over IK (no 0-RTT replay/KCI caveats, and the responder
  need not know who is calling) and over KK (the responder would have to trial every pin).
- **Alternatives**: TLS 1.3 with raw public keys via `rustls` (rejected: audited but far
  larger tree — `ring`/`aws-lc-rs`, cert generation — plus a custom verifier and exporter
  plumbing for the PAKE binding; more code to get wrong); `noise-protocol` crate
  (rejected: much smaller user base); a hand-made DH + AEAD design (prohibited).

## R3. Key types, device ID and fingerprint

- **Decision**:
  - Device identity = one **X25519 static keypair** (the Noise static key). Private key: 32
    random bytes from `OsRng` (FR-001). Public key derived with
    `curve25519_dalek::MontgomeryPoint::mul_base_clamped` (same clamping as snow), so only
    the private key is stored and the public key is re-derived on load.
  - **Device ID** = `SHA-256("passwsync-device-id-v1" || public_key)`, 32 bytes; rendered
    as 64 lowercase hex chars internally, in the API and in the QR.
  - **Fingerprint** = first 10 bytes (80 bits) of the device ID in RFC 4648 base32
    (uppercase, no padding), shown as 4 groups of 4: `ABCD-EFGH-IJKL-MNOP` (FR-003). Pins
    and all trust decisions use the full ID and public key, never the fingerprint.
  - Device name default: `passwsync device ABCD` (first 4 fingerprint chars), FR-006.
- **Rationale**: A single key type avoids a separate signing key (Noise authenticates with
  DH). A domain-separated hash gives a fixed-size ID independent of the key encoding.
  80 bits gives a 2^80 second-preimage cost for a look-alike fingerprint, ample for eye
  comparison while short enough to read. Base32 avoids ambiguous case.
- **Alternatives**: Ed25519 signing key + X25519 (rejected: two keys, conversion or extra
  signatures, no benefit with Noise); raw public key as ID (rejected: conventional hashing
  is clearer and domain-separated); 64-bit hex fingerprint (rejected: weaker).

## R4. Pairing: PAKE and how the code binds into the handshake (anti-MITM)

- **Decision**: **SPAKE2** (RFC 9382 family; `spake2` crate 0.4, Ed25519 group) keyed by
  the code, whose 32-byte output is the **Noise PSK** of
  `Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s`; the SPAKE2 messages are bound into the Noise
  prologue.
  - Roles: A = initiator in the user sense (shows the code) = SPAKE2 side A = Noise
    **responder**; B = joiner (enters code) = SPAKE2 side B = Noise **initiator** (B dials).
  - SPAKE2 identities: `id_a = "passwsync-pair-initiator-v1"`,
    `id_b = "passwsync-pair-joiner-v1"`; password = the 8 ASCII digits.
  - Prologue = `"passwsync-pair-v1"` || Hello || spake2_msg_B || spake2_msg_A.
  - Flow (frames, see contracts/peer-protocol.md): Hello(pair) → `SPAKE_B` → `SPAKE_A` →
    msg1 `-> e` → msg2 `<- e, ee, s, es, psk` → msg3 `-> s, se` (payload
    `PairHello{name}`) → transport `PairPending{seconds_left}` → person decides on A →
    `PairCommit{name}` | `PairReject` → B pins, sends `PairAck` → close.
  - Wrong code: B cannot decrypt msg2 (psk2 places the PSK in A's message), so B detects
    it before revealing its static key or name; A detects it if B were the impostor when
    msg3 fails. Either way the code on A is already consumed (one attempt per code).
  - QR or nearby-list pairing: B knows the expected device ID and, after msg2, refuses
    unless `device_id(A's proven static)` equals it (FR-022). Manual address entry has no
    expected ID; the PAKE plus the person comparing fingerprints on both screens protects.
  - Key confirmation: msg2 (PSK-keyed) proves A knew the code; msg3 proves B did. Pins are
    committed per FR-022b: A after the person accepts, then `PairCommit`; B only on
    receiving `PairCommit`.
- **Rationale**: An 8-digit code (~26.6 bits) is far too weak to be a Noise PSK directly:
  an active attacker would get a PSK-keyed message and brute-force 10^8 codes offline.
  SPAKE2 turns the code into a high-entropy key while allowing exactly one online guess per
  run; feeding it as the PSK and binding its transcript in the prologue means a relay MITM
  without the code ends up with different keys on each side and fails, and the Noise
  handshake hash binds both static keys and ephemerals to the same transcript (FR-020).
  This is composition of vetted primitives through Noise's standard PSK mechanism, not a
  new primitive; the same SPAKE2-then-channel pattern is used by magic-wormhole.
- **Alternatives**: CPace (rejected: no maintained Rust crate); OPAQUE/`opaque-ke` (audited,
  but an augmented client/server PAKE with registration — wrong shape for a one-time code);
  code as PSK (rejected: offline brute force); SAS / short authentication string compare
  only (rejected: spec mandates code entry with a PAKE).
- **Security of failure**: guess probability per code 10^-8; at most 5 codes per 10 min.
  **Amended by 009 (pending 009 implementation)**: at most 20 guesses per 10 min; 009 research R5.

## R5. Pairing code format and lifecycle

- **Decision**: 8 decimal digits, uniform via rejection sampling from `OsRng`, displayed
  `1234 5678`; input accepts spaces/dashes, normalized to 8 digits. Valid 300 s, one code
  per device (a new start invalidates the previous), consumed by the first well-formed
  `SPAKE_B` received (garbage before that just closes the connection without consuming),
  invalidated on any failure, rejection, expiry, service stop. Rate limit: 5 codes per
  sliding 10 min (monotonic clock). Held only in `Zeroizing` memory; never logged or stored.
  **Amended by 009 (pending 009 implementation)**: the consume point above stays, and must not move later (009
  research R3). The implementation breaks the "garbage does not consume" rule, because a Hello
  alone also ends the code; 009 research R4 fixes that. Rate limit: 009 research R5.
  B waits for the acceptance up to `seconds_left + 10 s`; that wait is the person's
  decision, not a protocol step, so the 10 s step timeout (FR-030) applies to every other
  read.
- **Rationale**: Meets FR-018/FR-021 with the simplest format to type and read aloud.

## R6. Discovery mechanism and packet format

- **Decision**: **IPv4 UDP broadcast** (Syncthing-style local discovery), one socket bound
  `0.0.0.0:<discovery_port>` with `SO_BROADCAST`, sending to the **directed broadcast
  address** of each in-use interface (from `if-addrs`; link-local uses `169.254.255.255`).
  - Datagram: exactly 39 bytes: `"PWSD"` (4) | version `0x01` (1) | device_id (32) |
    peer_port u16 big-endian (2). Any other length, magic or version → ignored and counted
    `malformed`. Only the FR-014 fields; the magic is part of the version identifier.
  - Sent: immediately on networking start, on network change, when a code is shown, then
    every 30 s — only while FR-013a holds (≥1 pin or an active code).
  - Received: source must pass the address policy (R9) and be inside the subnet of an
    in-use interface; own ID ignored; entries keyed by device ID, refreshed with latest
    address; expire after 90 s; at most 64 non-paired entries (new ones dropped when full,
    `overflow`). Paired peers' last address is tracked in the pin record, not the 64 list,
    so a flood cannot hide paired devices.
  - A received announcement from a paired, unconnected peer triggers one dial attempt.
    **Amended by 009 (pending 009 implementation)**: it feeds a bounded per-peer table served by a separate dial
    path, and cannot displace the dial to the last known address; 009 research R6, R7.
- **Rationale**: Broadcast needs no group membership, works on every LAN where Syncthing
  local discovery works, and is one `std::net::UdpSocket`. Announcements are untrusted
  hints only (FR-014).
- **Alternatives**: mDNS/DNS-SD (rejected: larger dependency and parser surface, multicast
  joins per interface, leaks names); IPv4 multicast group (rejected: needs per-interface
  joins and IGMP; no benefit for one subnet); IPv6 (out of scope).

## R7. Transport and framing

- **Decision**: TCP via `std::net`. Every frame = u16 big-endian length (1..=1024 in this
  feature) + body. The first frame of every connection is the plaintext Hello: `"PWSC"` |
  version `0x01` | kind (`0x01` channel, `0x02` pairing) = 6 bytes. All later frames are
  SPAKE2 messages (33 bytes), Noise handshake messages, or Noise transport messages. A
  length of 0 or above the limit closes the connection without reading the body. Buffers
  are allocated per frame up to 1024 bytes (004 may raise the limit with a new version).
  `TCP_NODELAY` on; read/write timeouts 10 s during handshake and pairing steps.
- **Rationale**: Length-prefixed Noise messages is the framing recommended by the Noise
  spec; a tiny limit bounds memory per connection (FR-030).
- **Alternatives**: QUIC (rejected: large dependency, UDP state); one port for both
  protocols via UDP (rejected: needs our own reliability).

## R8. Ports, interfaces and network change

- **Decision**: Defaults: peer listener **TCP 27472**, discovery **UDP 27473** (UI stays
  27471). Configurable; all three MUST be distinct and in 1024–65535. TCP listener bound
  `0.0.0.0:27472` (std sets `SO_REUSEADDR`), UDP bound `0.0.0.0:27473`. In-use interfaces:
  every non-loopback interface with an IPv4 private or link-local address, or only the one
  named by `network_interface`. Accepted TCP connections are dropped unless the peer
  address passes the policy and the local address (`local_addr()`) belongs to an in-use
  interface. Interfaces are re-scanned every 30 s on the discovery timer (no extra wake-up);
  a change triggers an immediate announcement and reconnect attempts. If no interface
  qualifies, both sockets are closed (or never opened) and status is `no_local_network`;
  they are opened when one appears. Bind failure → status `port_in_use` naming the port;
  no retry until restart; UI keeps working.
- **Rationale**: Binding the wildcard address once satisfies "exactly one listener" across
  several interfaces and survives address changes without rebinding; filtering by local and
  peer address enforces the interface scope.
- **Alternatives**: one socket per interface address (rejected: violates "exactly one", and
  broadcast reception fails on address-bound UDP sockets on Linux); `SO_BINDTODEVICE`
  (rejected: only for the single-interface case, adds privilege and platform differences);
  netlink change notifications (rejected: hand-built netlink messages; 30 s polling is
  within budget).

## R9. Address policy

- **Decision**: `device-link::policy::is_lan_peer(Ipv4Addr)` = 10/8, 172.16/12, 192.168/16,
  169.254/16, excluding network and broadcast addresses of in-use subnets and 0.0.0.0 /
  255.255.255.255 as peers. Applied before any processing of datagrams, accepted
  connections and outbound dials (manual addresses included). Addresses are IPv4 literals
  only; no DNS (FR-012). For automated tests a `testkit`-only policy additionally permits
  127.0.0.0/8; it is not compiled in release builds.

## R10. Concurrency model, timers and resource budget

- **Decision**: Blocking `std::net` with threads (same style as 002; no async runtime).
  - Threads: `net-accept` (blocking accept), `net-discovery` (recv with timeout until the
    next 30 s tick: announcements, interface re-scan, nearby expiry, dial scheduling), one
    thread per connection (handshake, pairing or channel), one joiner thread per pairing
    attempt. Stacks 128 KiB. Bounds: 16 unauthenticated connections (excess accepted and
    closed at once, counted `overflow`), 32 channels (= pin limit), 1 pairing exchange.
    Worst case ≈ 51 threads ≈ 6.4 MiB locked stacks; idle with 5 peers ≈ 7 threads.
  - Channel timers: send `Keepalive` if nothing sent for 60 s; close if nothing received for
    150 s (peer shown offline < 3 min, SC-005). Dial backoff for unreachable pins: 30 s,
    doubling to 300 s, reset by an announcement from that peer.
    **Amended by 009 (pending 009 implementation)**: an announcement no longer resets it, and may only wake the dial
    to the last known address no sooner than the minimum backoff; 009 research R6.
  - Duplicate channels (FR-029): both sides may dial; after authentication both keep the
    channel whose dialer has the smaller device ID and close the other.
    **Amended by 009 (pending 009 implementation)**: a higher channel version wins first; 009 research R10.
  - Revocation: registry removes and persists the pin, then `shutdown(Both)` on the stored
    stream clone, closing within 1 s (SC-005).
  - Stop: listener and sockets shut down via `rustix::net::shutdown`; threads joined.
- **Resource budget** (SC-007, FR-039): idle CPU = event-driven only: ≤ 1 discovery wake
  per 30 s plus ≤ 2 keepalive wakes per 60 s per peer (≤ 1 per 30 s average). RAM added
  < 10 MB: stacks above, ≤ 1 KiB frame buffer and ~1 KiB snow state per connection, 64
  nearby × ~64 B, 32 pins × ~200 B. All memory stays under the 002 `mlockall`; the 256 MiB
  `RLIMIT_MEMLOCK` requirement is unchanged. Battery (for 007): no busy polling, no wake
  without a timer or packet, no announcements without pins or an active code (FR-013a);
  intervals are fields of a `Timing` struct so 007 can lengthen them within spec bounds.
- **Alternatives**: single `epoll` loop (rejected now: more state-machine code for a ≤ 51
  connection bound; revisit if 004 needs it); `tokio` (rejected: large runtime, against the
  002 dependency stance).

## R11. Storage of device key and peer registry

- **Decision**: In `$XDG_CONFIG_HOME/passwsync/` (0700), both 0600, written with the 002
  atomic writer (temp file 0600, fsync, rename, fsync dir), checked with the 002 owner and
  permission check.
  - `device-key`: `passwsync-device-key-v1\n<64 hex private key>\n`. Created at every start
    when missing (US1, even with networking off); the private key is then wiped from memory
    if networking is off (FR-007). Exists but unreadable, malformed or permissive →
    status `identity_unusable`, networking off, never overwritten (FR-005).
  - `peers`: header `passwsync-peers-v1`, then ≤ 32 lines
    `<pk hex64> <paired unix> <last_seen unix|-> <last addr a.b.c.d:port|-> <name hex>`;
    device ID is recomputed from the key. Strict parser; any error → `peers_unusable`,
    networking off, file untouched (FR-035). Saved on pin, revoke, name update, and
    last-seen at channel close / stop (not on every keepalive, to avoid disk wakes).
  - Not encrypted: per spec Assumptions, owner-only permissions (same trust level as
    Syncthing's key); the wallet master password is the only person secret.
- **Rationale**: Reuses proven 002 helpers; text format is auditable and strict.
- **Alternatives**: storing in the wallet data dir (rejected: identity is not wallet data);
  postcard binary (rejected: text is easier to inspect and the format is tiny).

## R12. Configuration

- **Decision**: Extend the 002 config grammar: a value is a decimal integer, the bare words
  `on`/`off`, or a double-quoted string without escapes. New keys:
  `network = off|on` (default `off`), `peer_port = 27472`, `discovery_port = 27473`,
  `device_name = "…"` (1–64 Unicode scalar values, no control chars or `"`),
  `network_interface = "…"` (1–15 chars `[A-Za-z0-9._-]`). Errors exit 2 as in 002.
  The UI shows these read-only (FR-008).

## R13. Integration with passwsyncd and the HTTP API

- **Decision**: Start-up adds, after binding the UI listener: load/create device key → if
  `network = on`: load peers, scan interfaces, bind TCP and UDP, start network threads.
  Networking problems never stop the service; they set a status shown in the UI.
  New `/api/*` routes (contracts/http-api-network.md) go through the unchanged 002 guard
  pipeline (peer UID, Host, session, CSRF on every call, Origin on POST, CSP, headers).
  `GET /api/network` is a background poll (5 s; 1 s during pairing). State-changing:
  `POST /api/pairing/start|cancel|accept|reject|join`, `POST /api/devices/{id}/revoke`,
  `POST /api/network/warnings/clear`. None needs a wallet unlock (FR-037) and none resets
  wallet idle timers. The QR is generated server-side with `qrcodegen` and returned as an
  SVG path string; the UI builds the `<svg>` with DOM APIs (CSP-compatible, no external
  resource, FR-038). Log gains a closed set of network events (contracts/host-runtime-
  network.md) and aggregated drop counters.

## R14. Secret hygiene

- **Decision**: Device private key, pairing code, SPAKE2 output (copied from the returned
  `Vec` into `Zeroizing<[u8;32]>`, source zeroized) live in `Zeroizing` buffers. `snow`
  copies keys into internal state without zeroize on drop: accepted residual risk,
  mitigated by the 002 `mlockall` (no swap), non-dumpable process and disabled core dumps;
  revisit in 008. Device names are sent only inside Noise-encrypted payloads (SC-006).

## R15. Testing strategy (TDD)

- **Decision**:
  - `device-link` unit tests, no sockets: in-memory runs of the pairing and channel state
    machines: success; wrong code; expired/reused code; MITM relay with its own keys and a
    guessed code; QR ID mismatch; self and already-paired refusal; limit; replayed,
    tampered, reordered, dropped and cross-connection frames; dedupe rule; FR-013a announce
    gating; nearby bounds/expiry; code rate limit; file codecs (round trip, every
    corruption class); `snow` handshakes checked against a fixed-key expected transcript.
  - `device-link-net` integration tests on loopback with the `testkit` policy: real TCP/UDP
    pairing and channel between two `Link`s, unauthenticated-connection bound, timeouts,
    oversized frames, flood test (SC-008).
  - `passwsyncd` tests: config keys, start-up statuses (identity unusable, port in use, no
    local network via fake interface source), HTTP routes with all 002 guards, socket
    inventory from `/proc/self/fd` + `/proc/net/{tcp,udp}` (SC-002), log/capture scan for
    names, codes and keys (SC-006); `#[ignore]` SC-007 resource test.
  - Manual two-host scenarios (or two Linux network namespaces) in quickstart.md.

## R16. Dependency review (new direct dependencies)

Checked 2026-10-23 in a scratch project depending on the real `passwsyncd` crate plus the
candidates, with the repository `deny.toml`: `cargo deny check` → advisories ok, bans ok,
licenses ok, sources ok; `cargo audit` (1351 advisories) → no vulnerabilities, only the
already-accepted RUSTSEC-2023-0089 (001). No `deny.toml` change needed.

| Crate | Version | Used by | Purpose | License | Notes |
|-------|---------|---------|---------|---------|-------|
| `snow` | 0.10.0, `default-features = false`, features `use-chacha20poly1305`, `use-blake2`, `use-curve25519`, `use-getrandom` | device-link | Noise XX / XXpsk2 | Apache-2.0/MIT | De-facto Rust Noise (libp2p); passes the official cacophony vectors; README: no formal audit. The `std` feature is deliberately NOT enabled: it activates `ring` as a side effect. |
| `spake2` | 0.4.0 | device-link | PAKE | MIT/Apache-2.0 | RustCrypto PAKEs; `forbid(unsafe_code)`; on audited `curve25519-dalek`; used by magic-wormhole.rs; README: no third-party audit |
| `curve25519-dalek` | 4.1.x | device-link | derive X25519 public key | BSD-3-Clause | already transitive via snow/spake2; audited (Quarkslab 2019) |
| `sha2` | 0.10.x | device-link | device ID hash | MIT/Apache-2.0 | already transitive |
| `if-addrs` | 0.15.0, feature `link-local` | device-link-net | interface addresses/netmask/broadcast | MIT/BSD-3-Clause | only `libc` on Linux; wraps `getifaddrs` (also on Android) |
| `qrcodegen` | 1.8.0 | passwsyncd | QR matrix | MIT | Nayuki, zero deps, `forbid(unsafe_code)` |

New crates in the lock file (Linux): `snow`, `spake2`, `chacha20poly1305`, `chacha20`,
`poly1305`, `curve25519-dalek`, `curve25519-dalek-derive`, `sha2`, `hkdf`, `hmac`,
`getrandom` 0.3 (snow; 0.2 remains via `rand_core` 0.6 — duplicate warning only),
`if-addrs`, `qrcodegen`. Already present: `blake2`, `subtle`, `zeroize`, `rand_core`, `libc`.

Accepted risk: neither `snow` nor `spake2` has a formal third-party audit; no audited Rust
alternative of equal size exists (rustls is audited but much larger, see R2). Mitigations:
exact version pins, known-answer tests in our suite, defence in depth (person compares
fingerprints and must accept on A), protocol fuzzing and re-review scheduled in 008.

**Status (implementation, 2026-10-23)**: mitigations in place and verifiable —
(1) exact pins `snow = "=0.10.0"`, `spake2 = "=0.4.0"` in the workspace `Cargo.toml`
(T001); (2) known-answer tests in `crates/device-link/tests/known_answer.rs`: SPAKE2 messages
and key with fixed seeds, a fixed-key `Noise_XXpsk2` transcript digest, and the official
cacophony vector for `Noise_XX_25519_ChaChaPoly_BLAKE2s` (T037); (3) fingerprint display plus
human acceptance on the initiator before any pin (T038, T057, `pairing_success.rs`,
`ui_static.rs`); (4) `cargo deny check` and `cargo audit` clean except the accepted
RUSTSEC-2023-0089, `snow` built without `ring` (T005, T092); (5) protocol fuzzing and an
independent re-review are deferred to feature 008. No `deny.toml` change was needed.
Lock-file check after implementation: the new crates match the R16 list plus
`fiat-crypto` (formally verified field arithmetic used by `curve25519-dalek` 4 on 64-bit
targets) and `r-efi`, `wasip2`, `wit-bindgen` (target-specific dependencies of
`getrandom` 0.3 that are recorded in `Cargo.lock` but not compiled on Linux); all pass
`cargo deny check` (licenses, bans, sources, advisories).

## Implementation notes (deviations recorded during /speckit-implement)

- R8: when every in-use interface disappears at run time, the node keeps its two sockets
  bound but closes all channels, stops announcing and refuses accepted connections (the
  local address no longer belongs to an in-use interface); channels come back on the next
  re-scan. Simpler than closing and re-binding, and no traffic reaches a non-LAN address.
  At start-up `no_local_network` opens nothing and is retried on every 15 s service tick.
- R13: a request without a session cookie is answered `401 unauthorized`, the unchanged
  002 behaviour (tasks.md T025 said 403).
- Shutdown logs `network off` once the network is closed, so the log shows the contract
  order (network first, then wallets locked).
- The QR text uses the first in-use interface address with `peer_port`.
