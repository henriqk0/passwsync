# Implementation Plan: Hardening Audit

**Branch**: `feat/008-hardening-audit` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/008-hardening-audit/spec.md`

## Summary

Cross-cutting assurance for 001-007 with no new product behaviour, format, protocol,
cryptography or third-party dependency:

1. **In-tree fuzzer** (`crates/hardening`, no normal dependencies, unsafe forbidden): a seeded,
   deterministic, std-only mutation engine (SplitMix64, 9 mutators plus re-chunking) and
   17 targets as integration tests, one process each, covering every parser that reads
   untrusted bytes: wallet header, payload (through a new `vault-core` `testkit` entry), full
   unlock at the minimum KDF, frames, Hello, channel payloads, discovery, both pairing sides,
   both channel-handshake sides, sync control, reassembly, copy transfer, share messages, the
   loopback HTTP reader + guard, and the FFI/share-text inputs. Oracles: panic, per-input
   time, address-space growth from `/proc/self/status`, value bounds, closed error kinds,
   round trip (strict for fixed-layout codecs), and state oracles for handshakes and the guard.
   Gate budget: ≥ 10,000 inputs per target (64 derived unlocks), < 5 min total.
2. **Findings -> regression tests** test-first in `crates/<owner>/tests/regress_008.rs`; fixes
   only reject invalid input or tighten bounds; anything else is an open threat-model finding.
3. **Budgets**: deterministic ones (bytes, wake-ups, buffer and concurrency bounds, parser
   constants) are tests that gate; measured ones (time, CPU, memory) print `BUDGET` lines from
   the existing and new `#[ignore]`d release tests, collected by `scripts/bench.sh` (which also runs the three deterministic BUDGET files without `--ignored`) into a report
   with machine details. Never gates, never in CI.
4. **Threat model** `docs/threat-model.md`: assets, actors, 11 trust boundaries with all six
   STRIDE categories, residual-risk register (19 required entries from 002-008 and the advisory
   ignores), audit findings, checked by `scripts/check_threat_model.py` with negative tests.
5. **CI**: `.github/workflows/ci.yml` with no `uses:` at all, `contents: read` only, no
   secrets, push/PR/dispatch/weekly; three jobs (`gate`, `android`, `packaging`) in one
   digest-pinned Arch container with pacman on a dated Arch Linux Archive snapshot; checkout by
   anonymous `git fetch` of `$GITHUB_SHA`. `scripts/check_workflow.py` enforces 14 rules.
   The image digest and snapshot date need network to resolve and are left as fail-closed
   sentinels for the maintainer (quickstart CI-0).
6. **One gate script** `scripts/gate.sh` (11 steps, offline, same on host and CI).
7. **Optional cargo-fuzz** `fuzz/`, its own workspace, excluded, never built, unverified.

## Technical Context

**Language/Version**: Rust 1.99.1 on the host (Arch package; edition 2024, MSRV 1.85); Bash;
Python 3 stdlib (3.11+ for `tomllib`; host 3.14.8)

**Primary Dependencies**: none new. `crates/hardening` has an empty `[dependencies]`;
dev-dependencies are workspace crates with their existing `testkit` features. Tools already on
the host: cargo-deny 0.20.2, cargo-audit 0.22.2, `nm`. Optional `fuzz/`: `libfuzzer-sys`
(outside the workspace, unverified, never built)

**Storage**: none. Tests and benchmarks use temporary directories only; the benchmark report goes
to `target/bench/report.txt`

**Testing**: `cargo test` (engine unit tests, 17 fuzz targets, budget tests, leakage test,
regression tests), Python `unittest` for both checkers (one negative fixture per rule), gate
self-test hook, defect-injection script (manual [H])

**Target Platform**: Linux x86_64 host; GitHub-hosted `ubuntu-24.04` runner with an Arch Linux
container [CI]; reference laptop [M]; reference Android phone [D]

**Project Type**: test/assurance tooling + documentation + CI configuration for an existing
Rust workspace

**Performance Goals**: fuzz step < 300 s on the dev host (release profile); each parser input
< 1 s, unlock input < 10 s

**Constraints**: no `unsafe` (allocation measurement via `/proc`, not a custom allocator); no
third-party crate; offline by default; test-only entry points absent from release builds;
no secrets or leak markers in any output; CI read-only, no secrets, everything pinned

**Scale/Scope**: 17 fuzz targets, ~170k inputs per gate run; 23 budgets (20 host, 3 device);
11 trust boundaries x 6 STRIDE; 19 required register entries; 11 gate steps; 14 workflow rules;
13 threat-model rules

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | No plaintext leaks, vetted crypto only, no weakening | PASS: no product behaviour change; fixes may only reject or bound | PASS: no new crypto; fuzz seeds synthetic, no leak markers in output (R9); test entry points only under `testkit`, absence proven in release graphs and binaries (R7); CI has no secrets, no write permission, no third-party actions, pinned image + dated packages, fail-closed sentinels (R15); advisory kinds all fail (R18) |
| II. Simplicity | Simplest equal option | PASS | PASS: std-only engine (~one module per concern), no fuzzing framework, one gate script, stdlib Python checkers like 007, reuse of existing measurement tests, zero actions in CI. Deviations in Complexity Tracking |
| III. TDD | Tests first; every bug fix starts with a reproducing test | PASS | PASS: engine unit tests before engine code; each checker rule has a failing negative fixture first; every finding gets a red regression test before its fix (R21, SC-004); the gate and checkers are themselves tested (R19) |
| IV. Hexagonal | Core free of infrastructure | PASS | PASS: the only core change is a pure split of `open_with_key` plus `testkit` functions; the harness depends on crates, never the reverse |
| V. Resource Efficiency | Measured, bounded | PASS | PASS: this feature measures the 001-004/007 budgets; allocation oracle per input; deterministic budgets gate |
| VI. Decentralization | P2P, no server | PASS | PASS: CI is a development service only; no product network change |
| Workflow | Minimal, vetted deps | PASS | PASS: zero third-party additions; `deny.toml` tightened (`yanked = "deny"`) |
| Roadmap globals | Never commit, never push; offline | PASS | PASS: workflow file is added but not pushed; gate is offline |

No violation. Plan amendments and justified complexity are listed below.

## Project Structure

### Documentation (this feature)

```text
specs/008-hardening-audit/
├── plan.md              # This file
├── research.md          # Phase 0 (R1-R21)
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1: H-1..H-14, CI-0..CI-3, M-1, D-1..D-4
├── contracts/
│   ├── fuzz-harness.md            # engine, runner, output lines, 17 targets and their oracles
│   ├── benchmarks.md              # budget table B-01..B-23, BUDGET line, scripts/bench.sh
│   ├── threat-model-structure.md  # document skeleton, tables, required risks, TM1-TM13
│   ├── ci-workflow.md             # workflow shape, pins, W1-W14
│   └── gate-script.md             # scripts/gate.sh CLI, 11 steps, output, exit codes
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks; not created here)
```

### Source Code (repository root)

```text
Cargo.toml                          # members += "crates/hardening"; exclude = ["tools/uniffi-bindgen", "fuzz"]
Cargo.lock                          # + path package `hardening` only (amendment A1)
deny.toml                           # [advisories] yanked = "deny", unmaintained = "all", unsound = "all"
crates/
├── hardening/                      # NEW: publish = false, lints = workspace, [dependencies] empty
│   ├── src/ lib.rs rng.rs mutate.rs oracle.rs runner.rs report.rs
│   └── tests/ targets/{mod,handshake,wallet_header,wallet_payload,wallet_unlock,frame,hello,channel_payload,
│              discovery,pairing_initiator,pairing_joiner,channel_responder,channel_dialer,sync_ctl,
│              sync_reassembly,sync_copy,share_msg,http_request,ffi_args}.rs
│              fuzz_<target>.rs x 17   budgets.rs   leakage.rs
├── vault-core/src/format.rs        # split open_with_key -> decrypt + decode_plaintext (no behaviour change)
├── vault-core/src/testkit.rs       # + decode_payload, encode_payload, parse_header, header_bytes
├── vault-core/tests/perf.rs        # + unlock_default_median_and_worst, time_per_guess, unlock_at_service_cap; BUDGET lines
├── passwsyncd/tests/{perf_memory,sync_perf,resources_sync,resources_network}.rs   # + BUDGET lines only
├── passwsync-ffi/tests/unsafe_scope.rs   # scan widened to src, tests, benches of every crate + fuzz/
└── <owner>/tests/regress_008.rs    # only if findings exist (F-nnn), plus the minimal fix in <owner>/src
fuzz/                               # NEW optional: Cargo.toml ([workspace]), README, fuzz_targets/<target>.rs
docs/threat-model.md                # NEW
scripts/                            # NEW
├── gate.sh  bench.sh  inject_defects.sh
├── check_workflow.py  check_threat_model.py  threat_model_required.tsv
├── defects/{wallet_header,frame,sync_ctl,share_msg,http_request}.patch
└── tests/ test_check_workflow.py test_check_threat_model.py test_gate_selftest.py
           fixtures/{advisory.lock, deny-ws/ (path crates: banned name, GPL license), threat-model/ ...}
.github/workflows/ci.yml            # NEW (not pushed by this feature)
```

**Structure Decision**: one new workspace member with no normal dependencies holds the engine;
targets and budget tests are its integration tests, reaching product crates only through
dev-dependencies (research R1), so `testkit` cannot reach release builds. Scripts and checkers
live in a new top-level `scripts/` next to the existing `android/verify.sh` and
`packaging/verify.sh`. The threat model is a single document in `docs/`.

## Design Decisions (summary; details in research.md)

1. **Engine**: SplitMix64 per iteration, `Seed{bytes, fields}` from real encoders, 9 mutators +
   re-chunking, stop at first failure with a pasteable reproducer (R2, R3).
2. **Oracles without unsafe**: `catch_unwind`, `Instant` + watchdog `exit(101)` for hangs,
   `VmPeak` growth over baseline (4 MiB resolution) plus structural value bounds (R4, R5).
3. **Round trip**: strict `encode(decode(x)) == x` for fixed-layout codecs, FR-006 form for
   postcard, state oracles where no encoder exists (R6).
4. **Unlock**: derivation only at `KdfConfig::MINIMUM`; KDF-byte mutations go to the header
   oracle; 64 derived inputs minimum (R8).
5. **Release isolation**: `cargo tree` feature graph + `nm` on release artifacts built exactly
   like PKGBUILD and `build-rust.sh` (R7).
6. **Budgets**: deterministic assert and gate; measured print `BUDGET` lines; `bench.sh` collects
   and never fails on verdicts (R13).
7. **Threat model**: fixed skeleton, pipe tables, TSV of required risks with anchor phrases so
   the list cannot silently go stale; advisory ignores cross-checked (R14).
8. **CI**: zero actions, anonymous git checkout, one Arch image + one ALA date, exact
   cargo-deny/audit versions, fail-closed sentinels until a maintainer pins (R15, R16).
9. **Gate**: one bash script, 11 steps, ignore list derived from `deny.toml` for both tools,
   fixtures prove advisory/ban/license failures offline (R17-R19).

## Plan amendments to the spec

- **A1 (SC-012, FR-037)**: "zero entries to the workspace lockfile" is read as "zero
  third-party entries". Cargo records every workspace member, so `Cargo.lock` gains one
  `[[package]]` for the in-tree path package `hardening` (no source, no dependencies, not used
  by any product crate). Strict zero would force the engine to be copied or `#[path]`-included
  across several product crates' tests (research R1). Recorded in spec.md under
  "Plan amendments 2026-10-30" at task time.
- **A2 (FR-033, FR-035)**: the container digest and the Arch Linux Archive date cannot be
  resolved offline. The workflow ships with fail-closed sentinels (all-zero digest,
  `UNRESOLVED` date) that the policy check reports as `PENDING [CI]`; CI cannot run until a
  maintainer pins both (quickstart CI-0). No value is invented.
- **A3 (FR-006)**: fixed-layout codecs get the stricter canonical oracle
  `encode(decode(x)) == x` for every accepted input; postcard keeps the FR-006 wording (R6).

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Fuzz step exceeds 5 min (handshake targets do curve operations per input) | Release profile; gate measures; fallback replays recorded handshake prefixes so only the mutated suffix is recomputed (R10) |
| `VmPeak` noise from glibc arenas hides or fakes a violation | One process per target, warm-up before baseline, 4 MiB slack; structural bounds cover sub-MiB limits (R4) |
| Cargo rejects `--test 'fuzz_*'` glob | Explicit target array in `gate.sh`, checked against the directory listing (R10) |
| Arch package snapshot lacks a tool `packaging/verify.sh` needs, or `makepkg` as root | Package list fixed at task time from 006 contracts/verify.md; unprivileged `builder` user (R15) |
| Anonymous checkout fails if the repository becomes private | Recorded in the threat model (B-11); switching to `actions/checkout` pinned by SHA with `persist-credentials: false` is the documented fallback, still allowed by W5/W7 |
| A finding needs a format change | Not fixed: open row in §9 with severity and owner (FR-017) |
| Host advisory DB older than CI's | Gate prints DB dates; CI may fail first (spec Edge Cases) |
| Fixture for advisory check depends on a specific advisory staying in the DB | Pick a long-standing advisory (withdrawn ones excluded); checker verifies the fixture still triggers, else the `policy` step fails with a clear message |

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| New workspace member `crates/hardening` (amendment A1) | One home for a std-only engine and 17 targets that span every crate, including `passwsyncd` and `passwsync-ffi` together | Copying the engine into several crates duplicates it; `#[path]` includes across crates are fragile; no existing crate dev-depends on both hosts |
| One test binary per fuzz target (17 binaries) | Process isolation for the `/proc`-based allocation oracle and the hang watchdog | One binary with threads mixes allocations of parallel targets and makes `exit(101)` kill unrelated targets |
| `/proc/self/status` allocation oracle (Linux-only) | FR-005 needs an allocation bound and FR-001/FR-037 forbid `unsafe` (a counting allocator) | Counting allocator needs `unsafe impl GlobalAlloc`; rlimit child processes lose reports |
| Restricted-YAML workflow checker | No YAML parser in the Python stdlib and no new dependency allowed | PyYAML is not stdlib; regex over arbitrary YAML would not fail closed |
| Fail-closed pin sentinels in the committed workflow (amendment A2) | Digests cannot be resolved offline and must not be invented | Tag references violate FR-033; omitting the container drops the Arch packaging gate (FR-035) |
| Python 3 for the two checkers | Same choice and conventions as 007 `android/policy/`; `tomllib` reads `deny.toml` | Bash cannot parse tables and TOML reliably; Rust checkers would mix document policy into the cargo test suite |
