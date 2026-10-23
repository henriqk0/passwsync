# Research: Vault Core (001)

All Technical Context unknowns are resolved below. Format per item: Decision / Rationale /
Alternatives considered.

## R1. Language, edition, toolchain

- **Decision**: Rust, edition 2024, MSRV 1.85 (stable). Cargo workspace.
- **Rationale**: Mandated by the product brief; memory safety without GC fits Principles I and
  V; edition 2024 is the current stable edition.
- **Alternatives**: Edition 2021 (no benefit for a new project).

## R2. Crate layout (hexagonal boundary)

- **Decision**: Two crates in one workspace:
  - `vault-core`: domain + crypto + file-format codec + `VaultStorage` port + in-memory fake.
    No filesystem, network, or OS-specific I/O apart from the OS random source and clock.
    Neither crate uses the network (FR-032): the product is offline, and only the later sync
    feature will add a network adapter in its own crate.
  - `vault-storage-file`: file adapter implementing `VaultStorage`; depends on `vault-core`.
- **Rationale**: Principle IV requires dependencies pointing inward; a crate boundary makes
  "core does not import infrastructure" a compile-time guarantee rather than a convention.
  The in-memory fake lives in the core because it is pure and needed by the core's own tests.
- **Alternatives**: Single crate with an `adapters` module (simpler, but the boundary is only
  enforced by review); three or more crates (separate crypto/format crates) rejected as
  speculative structure (Principle II).

## R3. Key derivation

- **Decision**: Argon2id via RustCrypto `argon2` (0.5.x). Output 32 bytes used directly as the
  AES-256-GCM key. Defaults: memory 64 MiB, iterations 12, parallelism 1 (iterations tuned from the initial 3 after
  measurement, see below). Accepted range at
  unlock and creation: memory 19 MiB–1 GiB, iterations 2–100, parallelism 1–16; salt 32 bytes
  from the OS CSPRNG.
- **Rationale**: Defaults exceed OWASP minimum (19 MiB, t=2, p=1) and match RFC 9106's
  64 MiB/t=3 second recommendation as a floor; parallelism 1 keeps behavior identical on single-core
  Android background execution. 64 MiB transient memory is acceptable for low-RAM targets and
  is released (and zeroized by the library) right after derivation. Bounds stop a malicious
  header from forcing excessive memory/time (resource-exhaustion) or trivially weak params.
  Tests use the minimum accepted parameters (fast enough, no insecure bypass exists).
- **Alternatives**: scrypt (older, less tunable); KeePassXC's AES-KDF (legacy); a test-only
  weak-parameter escape hatch (rejected: risk of shipping it).

### R3 tuning note (measured during implementation)

SC-003 requires at least 0.3 s per guess on the reference laptop. Measured on a Ryzen 5 PRO
4650U in release mode: 64 MiB with t=3 unlocks in about 107 ms (too cheap), t=9 in about 298 ms,
t=12 in about 0.4 s. Default raised to t=12; memory stays at 64 MiB so RAM use is unchanged
(Principle V). Android timing must still be confirmed (< 4 s, task T048).

## R4. Encryption and integrity

- **Decision**: AES-256-GCM via RustCrypto `aes-gcm` (0.10.x), random 96-bit nonce per save,
  full serialized header passed as associated data (AAD). Ciphertext + 16-byte tag form the
  body.
- **Rationale**: Mandated by constitution; AEAD gives confidentiality and integrity in one
  vetted primitive. Binding the header as AAD means any header byte change fails
  authentication (FR-021). Random nonces are safe: saves per key are far below the 2^32 limit.
  A single AEAD failure path produces the single generic error (FR-003).
- **Alternatives**: XChaCha20-Poly1305 (fine, but not the mandated cipher); separate HMAC
  over the header as KeePassXC KDBX4 does (redundant with AAD; more code).

## R5. Key lifetime and salt reuse

- **Decision**: On create/unlock the master password is normalized, used once for Argon2id,
  then wiped. The derived 32-byte key is kept in a zeroize-on-drop buffer while the vault is
  unlocked so saves do not re-run the KDF. Salt and KDF params stay the same across saves
  until the master password changes (new random salt then). The nonce is fresh on every save.
- **Rationale**: Re-deriving per save would cost ~0.5–2 s per save. Keeping a 32-byte key is
  a smaller secret footprint than keeping the password. Spec FR-004/FR-005a/FR-006 are
  satisfied. The key is never serialized (no `Serialize`, no accessor returning its bytes
  outside the crate), so it cannot be persisted; it is wiped on `lock`, on drop (process exit),
  or when the host's auto-lock timer calls `lock`. This matches the operating model: unlock
  once per device restart per wallet, nothing secret on disk.
- **Shared wallets**: Opening a wallet received from another device needs only its bytes and
  its master password; salt and KDF parameters come from the header, and there is no
  device-bound or person-bound key material (FR-005b). No account, login, or identity exists.
- **Alternatives**: Keep password and re-derive (slower, keeps the more reusable secret);
  KeePassXC master-seed layer (extra complexity, no benefit for a single-file format here).

## R6. Plaintext payload serialization

- **Decision**: `serde` + `postcard` (1.x) to serialize the payload into a zeroize-on-drop
  buffer before encryption; decryption output also goes into a zeroize-on-drop buffer.
- **Rationale**: postcard has a documented stable wire format, is compact (low RAM), has no
  std requirement, and is widely used. Hand-written TLV would add code to audit (Principle II).
- **Alternatives**: bincode (wire format less formally specified); JSON/CBOR (larger, more
  allocations); protobuf (codegen, heavier).

## R7. Zeroization of secrets

- **Decision**: `zeroize` (1.x, `derive` feature). `MasterPassword` and `VaultKey` wrap
  `Zeroizing` buffers; `Entry` derives `ZeroizeOnDrop` for all text fields (not just
  password/notes, which costs little and avoids misclassification). Temporaries such as NFC
  normalization output, lowercase copies made during search, serialization buffers, and
  decrypted plaintext are wrapped in `Zeroizing`. `Debug` for secret-bearing types is
  hand-written to print `[REDACTED]`. Error types never carry field values.
- **Rationale**: Principle I/V and FR-024/FR-025. `zeroize` is the de-facto vetted crate
  (RustCrypto). Wrapping temporaries closes the common leak via intermediate copies.
- **Known limitation**: Rust may leave copies when a `String`/`Vec` reallocates while growing;
  mitigated by pre-sizing buffers (`with_capacity`) and replacing (not appending to) fields on
  edit. Process-level protections (`mlock`/`mlockall`, disabling core dumps, Android
  `FLAG_SECURE`) are host concerns and are deferred to the service/Android features, where the
  process is owned; recorded in plan Constitution Check.
- **Alternatives**: `secrecy` crate (extra wrapper type over `zeroize`, little added value);
  per-page `mlock` via `memsec` (not portable to all Android configurations; premature here).

## R8. Identifiers and randomness

- **Decision**: Wallet and entry identifiers are 16 random bytes from the OS CSPRNG
  (`getrandom` 0.2/0.3 through `rand_core::OsRng`), shown as lowercase hex. Device
  identifiers are caller-supplied opaque strings (1–64 bytes UTF-8).
- **Rationale**: 128-bit random IDs make collisions across devices negligible without
  coordination (needed for P2P). Avoids a `uuid` dependency (Principle II, minimal deps).
- **Alternatives**: UUIDv4/v7 crate (adds dependency for formatting only); sequential IDs
  (collide across devices).

## R9. Sync-ready metadata (version vectors)

- **Decision**: Each entry stores `version: BTreeMap<DeviceId, u64>`; creation sets
  `{device: 1}`; every edit/delete increments the acting device's counter. A pure function
  compares two vectors → `Equal | Newer | Older | Concurrent`. `BTreeMap` gives deterministic
  ordering and serialization.
- **Rationale**: Clarification Q2; the minimum structure that can detect concurrent edits
  (Principle VI "never silently overwritten"). Vector size is bounded by the number of devices
  that ever edited that entry (small).
- **Alternatives**: single revision counter + device (cannot detect all concurrent edits);
  hybrid logical clocks (ordering, not concurrency detection); CRDT per field (over-scoped).

## R10. Time source

- **Decision**: A `Clock` port (`now() -> Timestamp` as UTC Unix seconds, `i64`), with
  `SystemClock` (uses `std::time::SystemTime`) and `FixedClock` for tests, both in the core.
- **Rationale**: Deterministic tests of timestamps (TDD) without a time library dependency.
- **Alternatives**: `chrono`/`time` crates (unneeded for seconds-since-epoch); passing `now`
  to every call (noisier API).

## R11. Master password normalization

- **Decision**: Unicode NFC via `unicode-normalization` (0.1.x); length counted in Unicode
  scalar values after normalization; minimum 12.
- **Rationale**: Same visual password must unlock on Linux and Android (different input
  methods may produce different compositions). Clarification Q3.
- **Alternatives**: NFKC (changes visually distinct characters, can reduce entropy); no
  normalization (cross-device unlock failures).

## R12. File adapter atomicity and permissions

- **Decision**: Write ciphertext to a temp file in the same directory (`.<name>.tmp-<random>`),
  `sync_all`, then `rename` over the target, then fsync the directory (Unix). Create files
  with mode `0600` on Unix. On failure, delete the temp file. Load reads the whole file
  (wallets are small) and maps `ErrorKind::NotFound` to `StorageError::NotFound`.
- **Rationale**: FR-028/SC-008; rename is atomic on POSIX filesystems including Android's.
  Only ciphertext ever touches the temp file (FR-030). Uses std only (no extra deps).
- **Alternatives**: `tempfile`/`atomicwrites` crates (extra deps for ~30 lines of logic);
  in-place overwrite (not crash-safe); keeping `.bak` copies (out of scope).

## R13. Search and list

- **Decision**: Linear scan over live entries; case-insensitive substring match using Unicode
  lowercase of query and fields (temporaries zeroized); password excluded. List/search return
  borrowed references sorted by lowercase title, then by id for determinism.
- **Rationale**: 10,000 entries scan well under 100 ms (SC-004) with no index to keep in sync
  or in memory (Principles II, V).
- **Alternatives**: in-memory index/trie (memory and complexity without need).

## R14. Testing strategy

- **Decision**: `cargo test` only. Unit tests inside modules; integration tests in
  `crates/*/tests/`. A reusable storage contract test suite is exported by `vault-core`
  behind a `testkit` cargo feature and run against both adapters (SC-007). Exhaustive
  single-byte mutation test over a small saved wallet (SC-002). Plaintext-marker leak tests
  over stored bytes and `Debug`/`Display` outputs (SC-006). Performance and memory checks
  (SC-003/004/005) are `#[ignore]` tests run in release mode; memory uses a counting global
  allocator in a dedicated test binary.
- **Rationale**: Principle III with no extra test frameworks (Principle II).
- **Alternatives**: `proptest` (useful later; not needed for the listed scenarios);
  `criterion` (heavier than needed for threshold checks).

## R15. Dependency vetting summary

| Crate | Purpose | Notes |
|-------|---------|-------|
| `argon2` | KDF | RustCrypto, audited family, pure Rust |
| `aes-gcm` | AEAD | RustCrypto, NCC-audited (2020) |
| `zeroize` | memory wiping | RustCrypto |
| `rand_core` (+ `getrandom`) | OS CSPRNG | RustCrypto |
| `serde`, `postcard` | payload codec | widely used, stable wire format |
| `unicode-normalization` | NFC | unicode-rs |
| `thiserror` | error derive | compile-time only; optional, chosen for readable errors |

All dependencies are pure Rust and build for `x86_64-unknown-linux-gnu` and Android targets.
`cargo audit` and `cargo deny` are recommended in CI (enforced in a later feature).

## Dependency review (T002, 2026-10-23)

Pinned by `Cargo.lock` (resolved with MSRV 1.85): `argon2` 0.5.3, `aes-gcm` 0.10.3,
`zeroize` 1.9.1, `rand_core` 0.6.4 (+ `getrandom` 0.2.17), `serde` 1.0.229, `postcard` 1.1.3,
`unicode-normalization` 0.1.26, `thiserror` 2.0.21.

- Licenses: all dependencies are MIT and/or Apache-2.0 (RustCrypto, serde, postcard,
  unicode-rs, thiserror), compatible with this repository's MPL-2.0 license.
- Maintenance: all are actively maintained, widely used crates; RustCrypto crates are
  pure Rust. Newer majors exist (`argon2` 0.6, `aes-gcm` 0.11, `rand_core` 0.10); 0.5/0.10/0.6
  were kept because they are the mature, documented releases this design was specified against.
  Revisit during the hardening feature.
- Networking: `cargo tree --workspace` lists no networking crates (FR-032).
- RustSec advisories (re-run 2026-10-23 with `cargo audit` 0.22.2 and `cargo deny` 0.20.2,
  1351 advisories, 58 crates): **no vulnerabilities**. One informational "unmaintained" notice,
  RUSTSEC-2023-0089 (`atomic-polyfill`, via `postcard` → `heapless` 0.7). It is a no-std
  atomics shim inactive on x86_64 and aarch64 and has no known vulnerability; `postcard` 1.x
  does not offer a way to drop it. Accepted and recorded in `deny.toml` with the reason;
  revisit when `postcard` upgrades `heapless`. Licenses and sources checks pass.
  `cargo deny check` is the command for CI (hardening feature).
