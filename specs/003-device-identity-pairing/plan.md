# Implementation Plan: Device Identity and Pairing

**Branch**: `feat/003-device-identity-pairing` | **Date**: 2026-10-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-device-identity-pairing/spec.md`

## Summary

Give each `passwsyncd` installation an X25519 device identity (SHA-256 device ID, 80-bit
base32 fingerprint), opt-in LAN networking (off by default), Syncthing-style UDP broadcast
discovery, pairing by an 8-digit one-time code (SPAKE2 output used as the PSK of
`Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s`, SPAKE2 transcript in the prologue, person accepts
on the initiator, two-phase pin commit), and a mutually authenticated forward-secret channel
(`Noise_XX_25519_ChaChaPoly_BLAKE2s` over length-framed TCP) restricted to pinned peers,
with revocation. Protocol and trust logic go into a new I/O-free crate `device-link`;
sockets, threads and interface enumeration into a new adapter crate `device-link-net`
(reused by 007); `passwsyncd` adds config keys, owner-only `device-key`/`peers` files,
HTTP routes behind the unchanged 002 guards, a Devices view with a server-generated QR, and
closed-set log events. No wallet data crosses the network.

## Technical Context

**Language/Version**: Rust stable, edition 2024, MSRV 1.85 (workspace)

**Primary Dependencies**: new: `snow` 0.10.0 (no default features; chacha20poly1305,
blake2, curve25519, getrandom), `spake2` 0.4.0, `curve25519-dalek` 4.1, `sha2` 0.10,
`if-addrs` 0.15 (`link-local`), `qrcodegen` 1.8; reused: `zeroize`, `rand_core` 0.6,
`rustix`, `serde_json` (research R16)

**Storage**: `$XDG_CONFIG_HOME/passwsync/device-key` and `…/peers`, 0600, atomic writes
(R11)

**Testing**: `cargo test`; sans-IO state-machine tests with fakes in `device-link`; loopback
socket tests in `device-link-net` under a `testkit` address policy; raw-HTTP tests in
`passwsyncd`; `#[ignore]` resource/flood tests; manual two-host/netns scenarios (R15)

**Target Platform**: Linux desktop (002 service); core and net adapter reusable on Android
(007)

**Project Type**: Library crates (core + network adapter) integrated into the existing local
web service

**Performance Goals**: nearby ≤ 60 s; offline detection ≤ 3 min; revoke closes channel ≤ 1 s;
UI responsive ≤ 1 s under 10 000 packets/min flood (SC-005, SC-008)

**Constraints**: networking off by default; IPv4 private/link-local only; no DNS/internet;
≤ 16 unauthenticated connections, ≤ 32 pins, ≤ 64 nearby, frames ≤ 1024 B, 10 s step
timeouts; idle < 10 MB added RAM, < 1 % CPU, ≤ 1 wake per 30 s per peer; all memory under
002 `mlockall`; `unsafe_code` forbidden

**Scale/Scope**: ≤ 32 paired devices per installation, one LAN

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | Vetted crypto, no custom primitives, no plaintext secrets on network/logs | PASS — spec mandates vetted AKE + PAKE | PASS — Noise XX / XXpsk2 via `snow`, SPAKE2 via `spake2`; composition only through Noise's standard PSK + prologue (R2, R4); names only inside Noise; closed log set; secrets in `Zeroizing` under `mlockall` (R14) |
| I. (P2P E2E) | E2E + mutual auth | PASS | PASS with one recorded exception (Complexity Tracking): discovery datagrams and the plaintext Hello/SPAKE2 pairing frames; the channel and all wallet-bearing traffic are Noise-encrypted, both statics proven, pins required, forward secrecy, replay/tamper close (R2) |
| II. Simplicity | Simplest equal option | PASS | PASS — one Noise suite, blocking std threads like 002, broadcast instead of mDNS, text files, tiny fixed codecs; extra crates justified below |
| III. TDD | Tests first, fakes | PASS | PASS — every rule testable in-memory (R15) |
| IV. Hexagonal | Core free of infra | PASS | PASS — `device-link` has ports `PeerStore`, `MonoClock`, `WallClock`, injected RNG; sockets/files/HTTP are adapters; `device-link-net → device-link`, `passwsyncd → both` |
| V. Resource Efficiency | Bounded, measured | PASS | PASS — explicit budget and bounds (R10), SC-007 test |
| VI. Decentralization | No central server | PASS | PASS — LAN broadcast + manual address; no relay |
| Workflow | Minimal, reviewed deps | PASS | PASS — `cargo deny` + `cargo audit` clean on the candidate set; unaudited `snow`/`spake2` risk recorded with mitigations (R16) |
| Roadmap globals | Offline except device sync, no accounts, master password only secret | PASS | PASS — opt-in networking; device key is machine secret, never typed; no wallet data in 003 |

Gates pass. Deviations are recorded in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/003-device-identity-pairing/
├── plan.md              # This file
├── research.md          # Phase 0 (R1–R16)
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1 validation guide
├── contracts/
│   ├── peer-protocol.md          # discovery datagram, framing, pairing + channel messages
│   ├── http-api-network.md       # new /api routes and UI view
│   └── host-runtime-network.md   # socket re-scope, files, config keys, start-up, log
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks; not created here)
```

### Source Code (repository root)

```text
crates/
├── device-link/                 # NEW core (no I/O)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── identity.rs          # DeviceKey, DeviceId, Fingerprint, base32
│   │   ├── name.rs              # DeviceName
│   │   ├── code.rs              # PairingCode, rate limiter
│   │   ├── policy.rs            # LAN address policy (+ testkit loopback)
│   │   ├── discovery.rs         # datagram codec, NearbyList
│   │   ├── wire.rs              # Hello, frame limits, payload codec
│   │   ├── pairing.rs           # SPAKE2 + Noise XXpsk2 initiator/joiner state machines
│   │   ├── channel.rs           # Noise XX handshake + transport wrapper
│   │   ├── registry.rs          # PeerPin, PeerRegistry, statuses, warnings
│   │   ├── link.rs              # Link: decisions (announce, dial, accept, dedupe, revoke)
│   │   ├── files.rs             # device-key / peers text codecs
│   │   ├── ports.rs             # PeerStore, MonoClock, WallClock (+ fakes, testkit)
│   │   └── error.rs
│   └── tests/
├── device-link-net/             # NEW adapter (std::net, if-addrs)
│   ├── src/ { lib.rs, interfaces.rs, framed.rs, listener.rs, discovery.rs, dialer.rs, conn.rs }
│   └── tests/                   # loopback pairing/channel/flood
├── passwsyncd/                  # EXISTING: config.rs (+keys, grammar), paths.rs (+files),
│   │                            # net_store.rs (PeerStore over files), app.rs (start-up),
│   │                            # http/api_network.rs, qr.rs, log.rs (+events)
│   └── ui/                      # app.js/app.css/index.html: Devices view
├── wallet-service/              # unchanged
├── vault-core/                  # unchanged
└── vault-storage-file/          # unchanged
```

**Structure Decision**: Add `crates/device-link` and `crates/device-link-net` to workspace
`members` (workspace lints apply, `unsafe_code = "forbid"`). Dependencies point inward:
`passwsyncd → device-link-net → device-link`; `passwsyncd → device-link`. Neither new crate
depends on `wallet-service` or `vault-core`.

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Two new crates (core + net adapter) | Hexagonal boundary keeps protocol/trust logic free of sockets; net adapter is reused by Android 007 without desktop HTTP/hardening | Modules inside `passwsyncd` cannot be reused by 007 and cannot stop core code importing `std::net` |
| PAKE (`spake2`) in addition to Noise | FR-020: a low-entropy code needs a PAKE; as a bare Noise PSK it is brute-forceable offline by an active attacker | Code-as-PSK is insecure; CPace has no maintained crate; OPAQUE is the wrong (augmented) shape |
| Dependencies without formal audit (`snow`, `spake2`) | No audited Rust Noise or balanced-PAKE implementation of comparable size exists; both are mainstream, on audited primitives, `cargo deny`/`audit` clean | `rustls` (audited) needs a far larger tree plus custom raw-key verification and PAKE binding; hand-rolled crypto is prohibited. Mitigations: exact pins, known-answer tests, fingerprint display + human accept, fuzzing in 008 |
| `if-addrs` (wraps `getifaddrs` via libc) | Interface addresses/netmasks for scope filtering and directed broadcast, on Linux and Android, without `unsafe` in our code | `/proc` parsing is unavailable on recent Android; hand-built netlink is more code to audit |
| `qrcodegen` | FR-038 requires a QR generated locally | Writing a QR encoder ourselves is more code; external JS libs or services are forbidden |
| Plaintext discovery datagrams and pairing Hello/SPAKE2 frames (Constitution I: all P2P communication E2E) | Discovery must run before any shared secret exists; it carries only the device ID (public-key derived, no secret, no name). SPAKE2 messages are PAKE-protected and reveal nothing usable without the code. Channel, pairing Noise messages and all payloads are encrypted | Encrypting discovery needs a pre-shared key, i.e. an extra secret outside the roadmap's only-secret rule; Syncthing uses the same cleartext local discovery |
| Config grammar gains `on`/`off` and quoted strings | `device_name` and `network_interface` are strings; `network` is a switch | Integer-coded switches/names are error-prone; a full TOML crate is heavier |
| Duplicate `getrandom` (0.2 and 0.3) | `snow` 0.10 uses getrandom 0.3 while the rand_core 0.6 tree uses 0.2 | Downgrading to `snow` 0.9 trades a duplicate warning for an older line; warning only, revisit in 008 |
| `snow` keeps key copies without zeroize | Library limitation | Accepted residual risk under `mlockall`, non-dumpable process, core dumps off (R14) |
