# Research: Hardening Audit

**Feature**: 008-hardening-audit | **Date**: 2026-10-30 | **Plan**: [plan.md](plan.md)

Non-interactive planning: every open point is resolved with the most secure option, then the
simplest. Facts about the host were read on 2026-10-30: rustc/cargo 1.99.1 (Arch Linux
package, not rustup; `rust-toolchain.toml` says `stable` and is ignored by the system
toolchain), cargo-deny 0.20.2, cargo-audit 0.22.2 (in `~/.cargo/bin`), Python 3.14.8, Docker
present but no Arch Linux image cached, cargo-audit advisory DB at `~/.cargo/advisory-db`
(last commit 2026-10-24), no `proptest`, `arbitrary`, `quickcheck` or `libfuzzer-sys` in the
crate cache, remote `github.com/henriqk0/passwsync` (public: the 006 PKGBUILD downloads its
release archive anonymously).

## R1. Fuzzer placement: a dependency-free in-tree crate, targets as integration tests

**Decision**: A new workspace member `crates/hardening` (`publish = false`, workspace lints so
`unsafe_code = "forbid"`). Its `[dependencies]` section is **empty**: the library holds only
the std-only engine (PRNG, mutators, runner, oracles, report). Every product crate is a
`[dev-dependency]` with its `testkit` feature. Fuzz targets are integration tests
`crates/hardening/tests/fuzz_<target>.rs` (one `#[test]` per binary), sharing target code in
`crates/hardening/tests/targets/<target>.rs`. No product crate depends on `hardening`.

**Rationale**:
- Dev-dependency features are not unified into normal builds (resolver 3), so `testkit` never
  reaches `cargo build --release -p passwsyncd` (PKGBUILD) or `-p passwsync-ffi`
  (`android/build-rust.sh`), even if `hardening` is a workspace member. A normal dependency on
  product crates with `testkit` would leak `testkit` into any `cargo build --workspace
  --release`; dev-dependencies avoid that by construction.
- One binary per target gives each target its own process: the allocation oracle (R4) and the
  hang watchdog (R5) then observe only that target.
- One package makes the fuzz gate one command (`cargo test -p hardening --test 'fuzz_*'`).

**Lockfile effect**: Cargo records every workspace member in `Cargo.lock`, so the lockfile
gains exactly one `[[package]]` entry for the path package `hardening` (no source, no
dependencies). No third-party package is added. This is recorded as a plan amendment to SC-012
and FR-037 ("zero third-party lockfile entries") in [plan.md](plan.md).

**Alternatives considered**:
- Targets spread over owner crates' `tests/` with the engine copied or `#[path]`-included:
  no lockfile change, but duplicated or path-hacked engine code, 14 scattered binaries, and the
  FFI target would need a crate that dev-depends on both `passwsyncd` and `passwsync-ffi`
  (none does). Rejected for simplicity.
- `proptest` / `arbitrary` / `bolero`: not cached, not in the lock, need network and a
  security review for test-only value (spec clarification). Rejected.
- Engine inside `vault-core` `testkit`: wrong layer (the core would host HTTP and network
  fuzzing helpers). Rejected (Principle IV).

## R2. Deterministic PRNG and reproducibility

**Decision**: SplitMix64 (about 10 lines, std-only) seeds a per-iteration generator:
`rng(iter) = SplitMix64(seed ^ fnv1a64(target_name) ^ iter.wrapping_mul(0x9E37_79B9_7F4A_7C15))`.
Every iteration is reproducible on its own without replaying earlier ones. Default seed
`0x5057_5359_4E43_0008` is a constant in `crates/hardening/src/lib.rs`.
Environment settings (read once per target; malformed values fail the test, never fall back
silently):

| Variable | Meaning | Default |
|----------|---------|---------|
| `PASSWSYNC_FUZZ_SEED` | seed, decimal or `0x` hex | the constant above |
| `PASSWSYNC_FUZZ_ITERS` | inputs per target (cannot go below the target minimum) | the target minimum |
| `PASSWSYNC_FUZZ_ONLY` | run exactly one iteration number (reproduction) | unset |
| `PASSWSYNC_FUZZ_TRACE` | `1`: print `target iteration` before each input (for aborts) | unset |

**Rationale**: no dependency, trivially auditable, independent iterations make "re-run with
seed and iteration" exact (FR-003, FR-007). Not cryptographic, and it does not need to be.

**Alternatives**: xorshift/xoshiro (equivalent, slightly longer), `rand` with a seeded RNG
(`rand` is not a workspace dependency; `rand_core` is, but brings no seeded generator).

## R3. Mutation set and seed corpus

**Decision**: Seeds are produced at test time by the project's own encoders (spec
clarification). Each seed is `Seed { bytes, fields: Vec<Field> }` where a `Field` describes a
length or count field the encoder wrote (`offset`, `width` 1/2/4 or `Varint`, endianness,
documented `bound`). Mutators (FR-002), chosen uniformly per step, 1 to 4 steps per input:

| Mutator | Effect |
|---------|--------|
| `BitFlip` | flip one bit |
| `BoundaryByte` | replace a byte with 0x00, 0x01, 0x7F, 0x80 or 0xFF |
| `Insert` | insert 1-16 random or boundary bytes |
| `Delete` | delete a range of 1-16 bytes |
| `Truncate` | cut to a length; one deterministic sweep per seed covers every length up to `min(len, 256)` |
| `Duplicate` | copy a range to another offset |
| `Splice` | prefix of seed A + suffix of seed B |
| `LengthField` | overwrite a declared field with 0, bound-1, bound, bound+1, max of its width |
| `VarintBoundary` | insert or replace a postcard varint at any offset with 0, 127, 128, 2^32-1, 2^64-1, or an overlong 10-byte form |

Input sizes are capped per target (cap documented in contracts/fuzz-harness.md) so the
mutator itself never builds inputs larger than the parser's own bound + 1 KiB, except the
explicit "one above the bound" seeds.

**Rationale**: covers the spec's mutation list with targeted pressure on length fields, which is
where allocation and bounds bugs live. Postcard has no fixed offsets, hence `VarintBoundary`.

**Alternatives**: coverage-guided fuzzing (needs `libfuzzer-sys` + nightly: optional R12 only),
grammar generators (more code, little extra value for fixed-layout codecs).

## R4. Allocation-bound oracle without `unsafe`

**Decision**: Measure address-space growth through `/proc/self/status` (`VmPeak`, `VmSize`),
std-only. Per target process: warm up (one seed run, watchdog thread started) then record
`baseline = VmSize`; after each input read `VmPeak`; the input that first makes
`VmPeak - baseline > bound + 4 MiB` is an allocation-bound violation. `VmPeak` counts
allocations even if their pages are never touched (calloc/mmap), so "allocate the announced
length" bugs are visible even when nothing is written. Complemented by structural oracles that
need no measurement: every accepted value must respect its documented limits (e.g. at most
512 tags, at most 1 MiB text fields, reassembled message at most 24 KiB, HTTP body at most
8 MiB) and returned buffers are checked with `len()`/`capacity()`.

Resolution is 4 MiB, which catches the dangerous class (multi-MiB to GiB allocations from
attacker-announced lengths). Sub-MiB bounds are enforced by the structural oracles. If
`/proc/self/status` is unreadable the target fails (fail closed); host and CI are Linux.

**Rationale**: A counting `#[global_allocator]` needs `unsafe impl GlobalAlloc`, which
FR-001/FR-037 forbid. `RLIMIT_DATA` in a child process works but needs re-exec plumbing and
turns violations into aborts that lose the report. Reading `/proc` per input costs about 20 µs.

**Alternatives**: counting allocator (unsafe: rejected), `RLIMIT_AS`/`RLIMIT_DATA` child
processes (more machinery, worse reports), RSS sampling (misses untouched allocations).

## R5. Panic and time oracles, hang handling

**Decision**: Each input runs inside `std::panic::catch_unwind(AssertUnwindSafe(..))` with a
quiet panic hook installed for the target (the hook stores the message; nothing secret is
printed because inputs are synthetic, R9). Elapsed time is measured with `Instant`; above the
per-input limit (1 s, 10 s for full unlock) the input is a time overrun. A watchdog thread
holds an `AtomicU64` with the current iteration; if one input runs longer than 5x its limit
(a hang) it prints the failure line for that iteration and calls `std::process::exit(101)`.

**Rationale**: std-only; threads cannot be killed, so a process exit is the only safe way to
end a hang and still report. HTTP inputs come from an in-memory reader that returns EOF at the
end, so the reader never blocks.

## R6. Round-trip oracles (FR-006)

**Decision**:
- Fixed-layout codecs designed to be canonical (frame, Hello, discovery announce, channel
  payloads v1/v2/v3, sync control messages, share messages, wallet header): **strict**
  oracle `encode(decode(x)) == x` for every accepted input, including mutated ones. This is
  stronger than FR-006's second clause and catches trailing-byte and alias acceptance.
- Postcard wallet payload: FR-006 as written: encoder-produced seeds round-trip
  byte-identically; accepted mutated payloads re-encode to bytes that decode to an equal value
  (postcard may accept a non-minimal varint; acceptance of such an alias is recorded as a
  review item, not a defect, because the payload is authenticated).
- No encoder exists for HTTP requests, handshake transcripts, reassembly sequences and copy
  chunks: these targets use state oracles instead (contracts/fuzz-harness.md).

If a fixed-layout codec turns out to be non-canonical on purpose (a finding), the strict check
is relaxed for that target only, with a recorded reason, after the threat model lists it.

## R7. Test-only entry points

**Decision**: Add to `vault-core` `testkit` (already `#[cfg(feature = "testkit")]`, absent
from release builds):
- `testkit::decode_payload(version: u16, plaintext: &[u8]) -> Result<PayloadSummary, VaultError>`:
  runs exactly the post-decryption path of `open_with_key` (take_from_bytes, trailing check,
  `validate`/`convert`) on caller-provided plaintext.
- `testkit::encode_payload(summary) -> Vec<u8>` and `testkit::header_bytes(..)` /
  `testkit::parse_header(..)`: re-encoders for the round-trip oracle.

`open_with_key` is split into `decrypt` + `decode_plaintext(version, &[u8])` (a pure
refactor, no behaviour change) so the testkit entry calls the same function production calls.
Every other target uses public APIs that already exist (`device_link::wire::*`,
`discovery::decode_announce`, `PairingJoiner`/`PairingInitiator`/`ChannelDialer`/
`ChannelResponder::on_frame`, `Channel::seal_any`/`open`, `wallet_sync::codec::{decode,
Reassembler}`, `wallet_sync::share::codec::ShareMsg::decode`,
`passwsyncd::http::request::read_request`, `passwsyncd::http::guard::admit`,
`passwsyncd::qr::parse_share_text`) plus existing `testkit` fakes.

**Release absence (FR-038)**: verified in the gate by (1) `cargo tree --locked --offline
-e features,normal,build -p passwsyncd` and `-p passwsync-ffi` (target all) showing no
`testkit` feature on any package, and (2) building both release artifacts exactly as the
PKGBUILD and `android/build-rust.sh` do and checking with `nm -C` that no symbol path contains
`testkit::` or `hardening`. (1) is the authoritative proof; (2) is defence in depth.

## R8. Expensive key derivation in the unlock target

**Decision**: The full-unlock target derives keys only for inputs whose header parses to
exactly `KdfConfig::MINIMUM` (19,456 KiB, 2 iterations, 1 lane). Mutations that change KDF
bytes are checked by the FR-010 header checks only (expected: rejected, or accepted as a header
and never derived, so never counted in `derived`). At least 64 derived inputs are
required; the generator keeps producing inputs until 64 derivations ran (bounded by 4,096
attempts, else the target fails). Seeds: v1 and v2 wallets sealed with the test password at
`MINIMUM`. Oracle: `Vault::unlock` with the correct password returns
`InvalidPasswordOrCorrupted` for every input that differs from its seed in salt, nonce,
ciphertext or tag, and returns no content (FR-012). The maximum accepted cost (128 MiB
service cap) is measured once by the benchmark (R13), never fuzzed.

## R9. No secrets or leak markers in fuzz output (FR-038 vs FR-007)

**Decision**: Fuzz seeds use a fixed synthetic password (`"fuzz-only-password"`) and filler
strings drawn from `"fz"` patterns. They never use the leak marker strings that the 001-007
leakage scans search for, so printing a failing input as hex (FR-007) prints nothing those
scans treat as secret. The wallet payload and unlock targets print ciphertext or synthetic
plaintext only. The hardening crate's own leakage test runs a target with a planted marker in
a scratch seed and checks that the target's report lines do not contain it.

## R10. Fuzz gate time budget

**Decision**: The fuzz step runs in the release profile (`cargo test --release -p hardening
--test 'fuzz_*'`). Own crates otherwise compile at opt-level 0 (only dependencies are
optimised in dev), and the handshake targets (SPAKE2 + Noise per input) are the cost driver.
Estimated: parsers < 1 s each at 10,000 inputs; pairing and channel handshake targets 10-40 s
each; full unlock 64 x 50-100 ms. The gate measures the step's wall time and fails it above
300 s (FR-004, SC-002). If the estimate is wrong, the mitigation is to replay recorded
handshake prefixes so only the mutated message onward is recomputed; the minimum count does not
change.

`--test 'fuzz_*'` uses Cargo's glob target selection; if the installed Cargo rejects the glob,
the gate lists the fuzz targets explicitly (the list lives in one array in `scripts/gate.sh`,
checked against `crates/hardening/tests/fuzz_*.rs` by the gate itself so no target is
forgotten).

## R11. Defect-injection check (SC-003)

**Decision**: `scripts/inject_defects.sh` copies the working tree (without `target/`) into a
temporary directory, applies one patch from `scripts/defects/*.patch` at a time, and runs
only the matching fuzz target with a separate `CARGO_TARGET_DIR`. Expected: each run fails.
Patches (5): remove the wallet header length check; remove the frame length range check;
remove the `MAX_TAGS` check in sync `decode`; remove the trailing-bytes check in
`ShareMsg::decode`; remove the `Transfer-Encoding` rejection in `read_request`. Manual [H]
command (slow: rebuilds), recorded in quickstart; not part of the gate.

## R12. Optional cargo-fuzz target

**Decision**: `fuzz/` at the repository root, its own workspace (`[workspace]` in
`fuzz/Cargo.toml`) and listed in the root `exclude` (`["tools/uniffi-bindgen", "fuzz"]`). It
depends on `libfuzzer-sys` (version recorded but **unverified**: not cached), on `hardening`
by path, and on the product crates with `testkit`. Each `fuzz_targets/<target>.rs` includes
`crates/hardening/tests/targets/<target>.rs` with `#[path]` and calls the same `one(data)`
entry the in-tree runner calls. No `Cargo.lock` is committed for it (cannot be generated
offline); `fuzz/README` says it is unbuilt, nightly-only, and must pass `cargo deny`/`cargo
audit` before anyone runs it. No gate builds it; the unsafe-scope scan covers its sources.

## R13. Benchmarks: deterministic assertions vs measured report

**Decision**:
- **Deterministic** budgets (bytes, counts, wake-ups over simulated time, buffer and
  concurrency bounds, parser bound constants) are ordinary tests. Existing ones stay where
  they are (e.g. `passwsyncd/tests/resources_sync.rs::idle_sync_costs_less_than_1_kib_per_peer_per_hour`,
  `device-link-net/tests/resources.rs::wakes_are_counted`); gaps are filled in
  `crates/hardening/tests/budgets.rs`. They run in the gate and in CI (FR-020).
- **Measured** budgets (wall time, CPU share, peak memory) reuse the existing `#[ignore]`d
  release measurement tests (`vault-core/tests/perf.rs`, `passwsyncd/tests/perf_memory.rs`,
  `sync_perf.rs`, `resources_sync.rs`, `resources_network.rs`) plus new ones for what is
  missing (unlock at the 128 MiB service cap, per-guess time, median and worst over repeated
  unlocks). Each prints one `BUDGET` line (contracts/benchmarks.md) before asserting.
  `scripts/bench.sh` runs them with `--ignored --nocapture` in release, collects the `BUDGET`
  lines (a test that fails its assertion still printed its line; a missing line is reported as
  `NO-DATA`), prepends the machine block and writes `target/bench/report.txt`. It exits 0 when
  the report is complete, regardless of verdicts; 1 only if the harness itself breaks. Never
  run in CI (spec Session Q4).
- Peak memory per scenario uses the existing `/proc/self/clear_refs` ("5") + `VmHWM` method;
  CPU share uses `/proc/self/stat` utime+stime over wall time. Std-only.

**Alternatives**: criterion (not in lock), a new bench binary re-implementing the scenarios
(duplicates sync/loopback code that already exists in tests).

## R14. Threat-model structure check

**Decision**: `docs/threat-model.md` follows a fixed Markdown structure
(contracts/threat-model-structure.md). `scripts/check_threat_model.py` (Python 3 stdlib, as in
007) parses headings and pipe tables and enforces the rules. Earlier specs do not mark residual
risks uniformly, so a committed list `scripts/threat_model_required.tsv` names each required
register entry (`RR-id`, source file, an anchor phrase that must still occur in that source
file). The checker fails if a required id is missing from the register, if its Source cell does
not name the listed file, or if the anchor phrase vanished from the source (stale list). Ignored
advisories are read from `deny.toml` and `tools/uniffi-bindgen/deny.toml` with `tomllib` and must
each appear in the register. Negative tests (`scripts/tests/test_check_threat_model.py`,
`unittest`) mutate a valid fixture once per rule and expect rejection.

## R15. CI design: no third-party actions, one pinned image, dated package snapshot

**Decision**:
- GitHub Actions workflow `.github/workflows/ci.yml`; triggers `push`, `pull_request`,
  `workflow_dispatch`, `schedule` (weekly, `17 4 * * 1`). Top-level
  `permissions: contents: read` only. No `secrets.*`, no `github.token`, no `environment:`.
- **No `uses:` at all.** Checkout is three `git` commands in a `run:` step with an anonymous
  fetch of `$GITHUB_SHA` from `$GITHUB_SERVER_URL/$GITHUB_REPOSITORY` (public repository), so
  no credential is ever written to disk (stronger than `persist-credentials: false`) and no
  action needs a commit pin. Nothing to update except the image and snapshot.
- All three jobs (`gate`, `android`, `packaging`) run in one container
  `archlinux@sha256:<digest>` with pacman pointed at a **dated Arch Linux Archive snapshot**
  (`https://archive.archlinux.org/repos/YYYY/MM/DD/$repo/os/$arch`), so every system package
  (rust, git, python, libxml2, base-devel, namcap, ...) is pinned by date, and the toolchain is
  the same Arch `rust` package the host uses. `cargo-deny@0.20.2` and `cargo-audit@0.22.2`
  (host versions) are installed with `cargo install --locked`. No rustup, no `curl | sh`.
- **Digest resolution**: this host cannot resolve the image digest or check a snapshot date
  (no network, image not cached), and inventing a digest is not acceptable. The workflow
  therefore carries the all-zero sentinel `sha256:000...000` and the date `UNRESOLVED` until a
  maintainer fills them (quickstart CI-0). The policy check accepts a real 64-hex digest or the
  sentinel, never a tag; it reports the sentinel as `PENDING [CI]` and the step still PASSes on
  the host. A first CI step refuses to run with the sentinel (fail closed: the job can never
  fall back to an unpinned image).
- `makepkg` refuses root, so the packaging job creates an unprivileged `builder` user inside
  the container and runs `packaging/verify.sh --fetch` then `packaging/verify.sh` as it.
- No cache action, no artifact upload, no comment, no release. Logs only.
- Job time limits: gate 60 min, android 60 min, packaging 45 min.

**Rationale**: fewer third-party components (zero actions) is both more secure and simpler;
one image + one snapshot date is the smallest pin set; Arch matches the host toolchain.

**Alternatives**: `actions/checkout` pinned by SHA (a third-party JS action, and the SHA cannot
be verified offline), ubuntu runner with apt packages (apt versions not pinnable by one value,
toolchain differs from host), `dtolnay/rust-toolchain` (another action).

**Residual (threat model, B-11)**: the hosted runner VM image (`ubuntu-24.04` label) is not
pinnable; the container isolates build steps from most of it.

## R16. Workflow-policy check

**Decision**: `scripts/check_workflow.py` (stdlib) reads a **restricted YAML subset**
(block mappings and sequences, plain or quoted scalars, `|` block scalars). Anchors, aliases,
tags, flow collections and multiple documents are rejected (fail closed), so the checker never
has to understand YAML it did not anticipate. Rules W1-W14 are in contracts/ci-workflow.md.
Negative tests write one bad copy per rule (secret reference, `write` permission,
`pull_request_target`, unpinned `uses:`, tag-only image, checkout with credentials, push / tag
/ release / upload / cache-save / comment / deploy step, missing timeout, unpinned
`cargo install`, non-archive pacman mirror, missing verify script call) and expect rejection.

## R17. Gate script

**Decision**: `scripts/gate.sh` (bash, same conventions as `packaging/verify.sh` and
`android/verify.sh`: one result line per step, exit 0 / 1 / 2 / 64). Default is offline
(`--frozen --offline`, `cargo audit --no-fetch`, `cargo deny --offline`). `--fetch` (CI, or a
maintainer refreshing the host) runs `cargo fetch --locked` and updates both advisory DBs, then
exits. The audit ignore list is **derived from `deny.toml`** (and
`tools/uniffi-bindgen/deny.toml` for its lock) at run time, so both tools use one list by
construction (FR-036). Steps and output format are in contracts/gate-script.md.

## R18. Advisory policy in deny.toml

**Decision**: `deny.toml` `[advisories]` gains `yanked = "deny"` and explicit
`unmaintained = "all"`, `unsound = "all"` (cargo-deny's v2 default for `yanked` is a warning).
`cargo audit` runs with `--deny warnings`, which fails on unmaintained, unsound and yanked
notices. The existing ignore `RUSTSEC-2023-0089` (postcard -> heapless 0.7 -> atomic-polyfill)
and the bindgen-only `RUSTSEC-2026-0374` stay, each with reason, and each gets a register row.
`[bans] multiple-versions` stays `warn` (spec Session Q5); the gate prints the duplicate count
from `cargo tree --duplicates`.

## R19. Gate negative checks (SC-009)

**Decision**: Fast self-tests in the gate's `policy` step use fixtures under
`scripts/tests/fixtures/`: a lock file listing a crate version with a known advisory for
`cargo audit --file` (reads only the lock); a two-package path workspace with a crate named in
the `[bans] deny` list and a disallowed license for `cargo deny check bans licenses` (path
packages need no network). Unknown registry or git sources cannot be resolved offline: the
policy step instead asserts `deny.toml` keeps `unknown-registry = "deny"` and
`unknown-git = "deny"`. The format, lint and failing-test cases are checked once by hand in a
scratch copy (quickstart H-6), and by a step-runner self-test hook (`PASSWSYNC_GATE_SELFTEST`)
that makes a synthetic step fail so the exit code and step naming paths are tested without
breaking the tree.

## R20. Review items to examine first (not yet findings)

Spotted while reading code for this plan; each is checked by the fuzz targets and becomes a
finding (regression test + fix, or open register entry) only if an oracle fails or review
confirms it:

1. `read_body` allocates the announced `Content-Length` (≤ 8 MiB) before the bytes arrive: a
   slow sender holds 8 MiB per connection. Within the 002 bound; the threat model records the
   per-connection worst case next to the server's connection limit.
2. Serde's `Vec` visitor pre-allocates `min(announced, 1 MiB / size_of::<T>())` per collection
   while decoding postcard: peak is about 1 MiB per nesting level before the decode fails.
   The payload target measures it.
3. Postcard may accept non-minimal varints inside the authenticated payload (R6): not a
   format change; recorded if observed.
4. `Reassembler` keeps at most 24 KiB; check that a `CopyData` during reassembly and repeated
   `more = true` fragments are rejected exactly as 004 specifies.

## R21. Regression tests for findings (FR-017, SC-004)

**Decision**: each finding gets id `F-NNN`. The reproducer goes, as a hex or escaped-text
literal, into `crates/<owner>/tests/regress_008.rs` as `fn f_nnn_<short_name>()`, written
**failing** first (Red; the red output is recorded in the PR description), then the minimal fix that only rejects invalid input or tightens a
bound (Green). The fix must keep every encoder-produced seed accepted (the round-trip oracle
re-runs). A finding whose fix would change a valid encoding is not fixed: it gets an open row
(severity, owner) in the threat model's findings table.
