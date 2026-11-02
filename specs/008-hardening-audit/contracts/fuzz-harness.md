# Contract: Fuzz Harness

**Covers**: FR-001..FR-017, FR-037, FR-038, SC-001..SC-004 | Research R1-R12, R21

## Layout

```text
crates/hardening/                 # workspace member, publish = false, lints = workspace (unsafe forbidden)
├── Cargo.toml                    # [dependencies] EMPTY; [dev-dependencies] product crates with "testkit"
├── src/lib.rs                    # pub mod rng, mutate, oracle, runner, report; DEFAULT_SEED
├── src/{rng,mutate,oracle,runner,report}.rs   # + unit tests for each
└── tests/
    ├── targets/mod.rs            # shared: one module per target, each exposes `pub fn target() -> Target`
    ├── targets/handshake.rs      # shared transcript recorder for pairing_* and channel_* (reached as `super::handshake`)
    ├── targets/<target>.rs       # seeds(), one(), oracles; also included by fuzz/ via #[path]
    ├── fuzz_<target>.rs          # exactly one #[test] fn fuzz_<target>() { runner::run(targets::<t>::target()) }
    ├── budgets.rs                # deterministic budget assertions (contracts/benchmarks.md)
    ├── release_isolation.rs      # FR-038 tree check helper used by the gate (optional; gate may call cargo directly)
    └── leakage.rs                # report lines never contain the planted marker (research R9)
fuzz/                             # optional cargo-fuzz workspace, never built by any gate (R12)
```

`vault-core` gains in its existing `testkit` module only: `decode_payload`, `encode_payload`,
`parse_header`, `header_bytes` (research R7). `open_with_key` is split into decrypt +
`decode_plaintext` with no behaviour change, so the testkit entry runs the production decoder.

## Runner behaviour

1. Read `FuzzConfig` from the environment (data-model §1). Invalid value: test fails with the
   variable name.
2. Start the watchdog thread; run every seed once unmutated (warm-up and round-trip baseline);
   record `baseline = VmSize` from `/proc/self/status` (unreadable: fail).
3. For `iter in 0..iterations` (or only `only`): build the input from `Rng::for_iteration`;
   if `trace`, print `FUZZ-TRACE target=<t> iteration=<i>`; run `one()` under `catch_unwind`;
   measure elapsed; read `VmPeak`; classify.
4. Stop at the **first** failure: print the failure line and panic the test (non-zero exit).
5. On success print the report lines and assert coverage (`accepted >= 1`, `rejected >= 1`).

## Output lines (stdout, with `--nocapture`)

```text
FUZZ target=<name> seed=0x<16 hex> inputs=<n> accepted=<n> rejected=<n> [derived=<n>] result=PASS
FUZZ-TIME target=<name> elapsed_ms=<n> max_input_us=<n> peak_over_baseline_kib=<n>
FUZZ-FAIL target=<name> seed=0x<16 hex> iteration=<n> kind=<Kind> detail="<text>" input=hex:<hex>|text:"<escaped>"
```

`FUZZ` lines are deterministic for a given seed and code (SC-002); `FUZZ-TIME` lines are not.
Reproduce a failure: `PASSWSYNC_FUZZ_SEED=0x... PASSWSYNC_FUZZ_ONLY=<iteration> cargo test
--release -p hardening --test fuzz_<target> -- --nocapture`.

## Oracles applied to every input (FR-005)

| Oracle | Rule |
|--------|------|
| Panic | `catch_unwind` returns `Err` -> `Panic` |
| Time | elapsed > `time_limit` -> `TimeOverrun`; > 5x -> watchdog `Hang` + `exit(101)` |
| Allocation | `VmPeak - baseline > alloc_bound + 4 MiB` -> `AllocBound` |
| Error kind | a rejection whose kind is not in the target's closed list -> `UnknownError` |
| Value bounds | accepted value outside its documented limits -> `ValueBound` |

## Targets (SC-001: all 17 must exist and pass)

`min` = minimum executed inputs. `RT` = round-trip oracle: **S** strict `encode(decode(x)) == x`
for every accepted input; **P** FR-006 as written (seeds byte-identical; accepted mutants
re-encode to bytes that decode equal); `-` none (state oracle instead).

| # | Target | Entry (existing unless noted) | Seeds from | min | alloc bound | RT | Target-specific oracle |
|---|--------|-------------------------------|------------|-----|-------------|----|------------------------|
| 1 | `wallet_header` | `vault_core::peek_kdf_config`, `peek_format_version`; `testkit::parse_header` (new) | v1 and v2 wallets at MINIMUM and DEFAULT, header with each KDF param at range edges ±1; file lengths 78 and 79 B (hand-assembled) | 10,000 | 64 MiB (file cap; no copy expected) | S (header 63 B) | errors only `MalformedFile`, `UnsupportedVersion`, `UnsupportedKdf`, `KdfParamsOutOfRange`; length < 79 or > 64 MiB always `MalformedFile`; no key derivation reachable |
| 2 | `wallet_payload` | `vault_core::testkit::decode_payload(version, plaintext)` (new) | `encode_payload` of wallets with 0, 1, 50 entries, tombstones, histories, max-length (1 MiB) field and a 1 MiB+1 field (hand-assembled), v1 payloads | 10,000 | 64 MiB + 1 MiB x nesting depth | P | only `InvalidPasswordOrCorrupted`; accepted: unique ids, every text field ≤ 1 MiB, versions within state, no trailing bytes |
| 3 | `wallet_unlock` | `Vault::unlock` with the correct password | sealed v1/v2 wallets at `KdfConfig::MINIMUM` | 64 derived | 64 MiB + KDF memory | - | every input whose salt, nonce, ciphertext or tag differs from its seed -> exactly `InvalidPasswordOrCorrupted`; inputs rejected by the #1 header checks -> that check's error kind, never derived; KDF-parameter bytes -> #1 checks only, never derived (R8); no content returned in any case (FR-012) |
| 4 | `frame` | `device_link::wire::{decode_frame, frame_len, encode_frame}` | frames of body 1, 512, 1023, 1024 B and 1025 B (1025 hand-assembled: the encoder refuses it); concatenated frames | 10,000 | 4 KiB | S | accepted body length in 1..=1024; consumed = 2 + len; `Ok(None)` only when bytes < header or body incomplete |
| 5 | `hello` | `parse_hello`, `parse_hello_versioned` | every valid (version, kind) Hello | 10,000 | 4 KiB | S (`hello_versioned`) | accepted only the 4 documented 6-byte values; `parse_hello` accepts only v1 |
| 6 | `channel_payload` | `wire::Payload::{decode, decode_v2, decode_v3}`; `Channel::seal_any` -> peer `Channel::open` (real testkit pair) | every payload type of v1/v2/v3 encoded by `Payload::encode` | 10,000 | 8 KiB | S | v1 decoder rejects 0x20/0x21/0x30/0x31; v2 rejects 0x30/0x31; `open` of a mutated plaintext ends in a value or `ChannelError`, channel then closed or usable per 003 rules, never a panic |
| 7 | `discovery` | `discovery::decode_announce` | `encode_announce` with ports 1024, 65535, own id | 10,000 | 4 KiB | S | accepted only 39 B, right magic, port ≥ 1024, id ≠ own |
| 8 | `pairing_initiator` | `PairingInitiator::on_frame` fed a recorded genuine joiner transcript with one message mutated | live testkit pairing run (SPAKE2 + Noise) | 10,000 | 1 MiB | - | mutated attempt ends failed or rejected; registry gains no pin; no session; code consumed per 003 rules |
| 9 | `pairing_joiner` | `PairingJoiner::on_frame` (same method, other side) | same | 10,000 | 1 MiB | - | same as #8 |
| 10 | `channel_responder` | `ChannelResponder::on_frame` fed a recorded dialer transcript, one message mutated | testkit paired devices | 10,000 | 1 MiB | - | ends in `ChannelError` (protocol); no `Channel` returned for a mutated handshake message; peer store unchanged |
| 11 | `channel_dialer` | `ChannelDialer::on_frame` | same | 10,000 | 1 MiB | - | same as #10 |
| 12 | `sync_ctl` | `wallet_sync::codec::decode` | `encode` of every `Ctl` type incl. 0, 512 and 513 tags (513 hand-assembled), CopyStart at 78, 79 and 64 MiB and 64 MiB+1 (hand-assembled) | 10,000 | 64 KiB | S | accepted: ≤ 512 tags/matches, CopyStart size in 79..=64 MiB, ≤ 24 KiB input |
| 13 | `sync_reassembly` | `codec::Reassembler::push` over `codec::fragment` output, with `Rechunk`, reorder, duplicate, drop of `more=false` | fragmented messages of 24 KiB, 24 KiB+1 (hand-assembled) and small messages; fragment payloads of 999, 1000 and 1001 B | 10,000 | 64 KiB | - | buffer never > 24 KiB; completed messages equal the original concatenation when fragments were not mutated; oversize resets and errors |
| 14 | `sync_copy` | sync `Engine` receive side (testkit fakes) fed a recorded copy transfer with one `CopyStart`/`CopyData`/`CopyEnd`/`CopyAbort` mutated | testkit two-engine copy of a small and a 1 MiB wallet | 10,000 | 2 MiB (2 transfers x 1 MiB, 004 FR-029) | - | sizes outside 79..64 MiB rejected before any buffering; held transfer buffer ≤ 1 MiB each, ≤ 2 transfers; mutated copy never adopted unless it authenticates as a wallet (hash check) |
| 15 | `share_msg` | `wallet_sync::share::codec::ShareMsg::decode` | `encode` of every share type, every abort reason, seconds_left 0 and 300 | 10,000 | 8 KiB | S | unknown type/reason, wrong length, trailing bytes, seconds_left > 300 rejected |
| 16 | `http_request` | `passwsyncd::http::request::read_request` over an in-memory chunked reader, then `http::guard::admit` with a testkit `AppState` holding one live session | GET/POST/PUT/DELETE API requests with valid Host, Origin, cookie, CSRF; launch, static, index; bodies 0 and 8 KiB; head at 16 KiB-1, 16 KiB and 16 KiB+1 bytes, 48 and 49 headers | 10,000 | 8 MiB + 16 KiB | - | an accepted request: head ≤ 16 KiB, ≤ 48 headers, body ≤ 8 MiB and = Content-Length, no `Transfer-Encoding` in raw head (independent reference scan), exactly one numeric `Content-Length` (duplicate or non-numeric -> rejected), no bare LF, UTF-8 target, duplicate Host/Origin/cookie/CSRF -> `None`; `admit` returning `Api` for a non-GET implies exact Host, exact Origin, valid session and matching CSRF, else `GuardBypass` |
| 17 | `ffi_args` | `passwsyncd::qr::parse_share_text`; `passwsync_ffi` `join_pairing(peer_id, code)` and `redeem_invitation(sender_id, code)` on a testkit core with networking off | valid share text, peer ids, codes | 10,000 | 1 MiB | S (share text) | malformed ids/codes -> `CoreError` kinds only; no state change; share text > its max length rejected |

Bounded edges (spec Edge Cases): every seed family with a documented bound includes the at-bound,
one-below and one-above cases as explicit seeds. Over-bound seeds that the encoder refuses are
assembled byte-wise from the documented layout (their `fields` still declare the length field). A
bound with no encoder-producible over-bound case is also covered by the `LengthField` mutator with
`bound+1`.

## Determinism and budget (FR-003, FR-004, SC-002)

- Same seed, same code: identical `FUZZ` lines (the gate compares two runs only in the
  quickstart check H-2; the gate itself runs once).
- Whole fuzz step < 300 s on the development host in release profile; the gate times it.

## Test-only and release isolation (FR-001, FR-038)

- `hardening` has no normal dependencies; no product crate depends on it.
- New vault-core entry points exist only under `#[cfg(feature = "testkit")]`.
- Gate step `release-isolation`: `cargo tree` for `passwsyncd` and `passwsync-ffi` (normal +
  build edges, all targets) shows no `testkit` feature and no `hardening` package; release
  builds (`-p passwsyncd --bin passwsyncd`, `-p passwsync-ffi`) contain no `testkit::` or
  `hardening` symbol (`nm -C`).

## Regression tests (FR-017, SC-004)

`crates/<owner>/tests/regress_008.rs`, one `#[test] fn f_nnn_<name>()` per finding, input as a
literal, asserting the rejection (or bound) the fix introduces. Observed failing before the
fix (its red run output is recorded in the PR description and threat-model §9). Allowed fixes: reject invalid input, tighten a bound. Never change a valid encoding; the
round-trip oracle on encoder seeds must stay green.

## Optional cargo-fuzz (FR-009)

`fuzz/Cargo.toml` (own `[workspace]`, root `exclude` lists `fuzz`), `fuzz/fuzz_targets/<t>.rs`:

```rust
#![no_main]
#[path = "../../crates/hardening/tests/targets/mod.rs"] mod targets;
libfuzzer_sys::fuzz_target!(|data: &[u8]| { let _ = targets::<t>::one_bytes(data); });
```

The whole `targets/` tree is included once, so shared helpers resolve: target files reach them as
`super::handshake`, which resolves identically in the in-tree test binary (`mod targets;`) and in
the fuzz wrapper. `one_bytes` maps raw bytes to the target input and panics on any oracle
violation, so libFuzzer records it. Not built, no lock committed, outside `cargo deny`/`cargo audit` scope; README
states it is unverified and must pass both before first use.
