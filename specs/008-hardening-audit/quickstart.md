# Quickstart: Hardening Audit Validation

**Feature**: 008-hardening-audit | **Plan**: [plan.md](plan.md)

Run from the repository root on the Linux development host, offline. Tags: [H] host, [CI]
hosted runner, [M] reference laptop, [D] reference phone. Pending items stay `pending` until a
maintainer runs them.

## Prerequisites [H]

- Cached toolchain (`rustc 1.99.1`), crates (`cargo fetch --locked` done earlier), `cargo-deny
  0.20.2`, `cargo-audit 0.22.2`, their advisory DBs, `python3` (stdlib), `nm` (binutils).
- Optional for H-9/H-10: the tools `android/verify.sh` and `packaging/verify.sh` already need.

## Host checks

| # | Check | Command | Expected |
|---|-------|---------|----------|
| H-1 | Whole gate | `scripts/gate.sh` | 11 step lines, `result PASS`, exit 0 (SC-009); workflow pins reported `PENDING [CI]` until CI-0 |
| H-2 | Fuzz determinism | run `cargo test --frozen --offline --release -p hardening --test 'fuzz_*' -- --nocapture` twice, `grep '^FUZZ '` each output, sort, `diff` | identical (SC-002); every target `inputs ≥ 10000` (`wallet_unlock` `derived ≥ 64`), `accepted ≥ 1`, `rejected ≥ 1` (SC-001) |
| H-3 | Fuzz time | `fuzz` step time in H-1 output | < 300 s (FR-004) |
| H-4 | Reproduction | pick any target; `PASSWSYNC_FUZZ_SEED=0x1234 PASSWSYNC_FUZZ_ONLY=42 PASSWSYNC_FUZZ_TRACE=1 cargo test ... --test fuzz_<t> -- --nocapture` | runs exactly iteration 42; a malformed `PASSWSYNC_FUZZ_SEED=zz` fails naming the variable |
| H-5 | Defect injection | `scripts/inject_defects.sh` | 5 of 5 injected defects (wallet, frame, sync, share, HTTP) detected by their fuzz target (SC-003) |
| H-6 | Gate catches breakage | in a scratch copy (`cp -a` without `target/`): add a mis-indented line; add an unused variable; add `assert!(false)` to a test; run `scripts/gate.sh` each time | exit 1 naming `fmt`, `clippy`, `test` respectively (SC-009); advisory/ban/license cases are covered by the `policy` step fixtures |
| H-7 | Workflow policy | `python3 scripts/check_workflow.py` and `python3 -m unittest scripts.tests.test_check_workflow` | PASS on the real file; every negative fixture rejected with its rule id (SC-010) |
| H-8 | Threat model | `python3 scripts/check_threat_model.py` and its unittest | PASS; every TM rule rejects its fixture (SC-008) |
| H-9 | Android gate | `android/verify.sh` | exit 0, ktlint may be SKIPPED (US5.1, SC-012) |
| H-10 | Packaging gate | `packaging/verify.sh` | exit 0 where its tools exist; otherwise exit 2 recorded as pending as in 006 |
| H-11 | Release isolation | part of H-1 (`release-isolation`) | no `testkit` feature or `hardening` package in the release graphs, no symbols (FR-038) |
| H-12 | No new deps / unsafe | `git diff main -- Cargo.lock` | only the `hardening` path package entry (plan amendment A1); `unsafe-scope` step PASS (SC-012) |
| H-13 | Regression tests | for each `F-nnn` Fixed in the threat model: the red run output recorded in the PR description shows the test failing before the fix; test passes now | SC-004 |
| H-14 | Benchmark report | `scripts/bench.sh` | exit 0; `target/bench/report.txt` has machine block, `reference=no`, a row for each B-01..B-20 with value and verdict, no `NO-DATA` (SC-005); output contains no credential text |

## Host results (recorded 2026-11-02, Linux x86_64 dev host, rustc 1.99.1)

| # | Result |
|---|--------|
| H-1 | PASS: `scripts/gate.sh` 11 PASS, exit 0 (fuzz 17 targets, 160,084 inputs, 57 s); workflow pins PENDING [CI] |
| H-2 | PASS: two runs of the 16 US1 targets gave identical sorted `FUZZ` lines (2026-11-02), 150,000+ inputs; `ffi_args` added after (17 targets) |
| H-3 | PASS: fuzz wall time about 45 s for 16 targets (limit 300 s) |
| H-4 | PASS: `PASSWSYNC_FUZZ_SEED=0x1234 PASSWSYNC_FUZZ_ONLY=42 PASSWSYNC_FUZZ_TRACE=1` ran exactly iteration 42; `PASSWSYNC_FUZZ_SEED=zz` failed naming the variable |
| H-5 | PASS: `scripts/inject_defects.sh` 5 of 5 detected (86 s) |
| H-6 | PASS: scratch copy with a mis-formatted line, an unused variable and a failing assertion: gate exit 1 naming `fmt`, `clippy` and `test` |
| H-7 | PASS: real workflow PASS with 2 `PENDING [CI]` lines; every negative fixture rejected |
| H-8 | PASS: `docs/threat-model.md` PASS; TM1-TM13 negative fixtures rejected |
| H-9 | PASS: `android/verify.sh` RESULT 0, every step PASS, ktlint SKIPPED (lock-diff list updated to the one new package `hardening 0.1.0`) |
| H-10 | pending/FAIL (exit 1): `no-config-writes` (006 FR-027 scope: no crates/ diff vs main) fails on any feature branch changing crates; build steps need `packaging/verify.sh --fetch` (cache predates 007 uniffi; no network); namcap missing |
| H-11 | part of H-1 (`release-isolation`) |
| H-12 | PASS: `Cargo.lock` gains only the path package `hardening`; unsafe scan widened and PASS |
| H-13 | PASS: F-001 regression test observed failing before the fix (PR description) |
| H-14 | PASS: `scripts/bench.sh` exit 0, `reference=no`, B-01..B-20 all with value and verdict, no NO-DATA, no credential text |

## CI checks (pending until a maintainer runs them)

| # | Check | Steps | Expected |
|---|-------|-------|----------|
| CI-0 | Resolve pins (networked, maintainer) | `docker pull archlinux:base` on a trusted machine; `docker inspect --format '{{index .RepoDigests 0}}' archlinux:base`; choose the matching date on `archive.archlinux.org/repos/`; write both into `.github/workflows/ci.yml`; run H-7 | policy PASS with no `PENDING` line |
| CI-1 | Real run | push the branch (maintainer; this feature never pushes) | jobs `gate`, `android`, `packaging` pass (SC-011, FR-035) |
| CI-2 | Fork PR | open a PR from a fork | runs with read-only token, no secrets; nothing published |
| CI-3 | Weekly run | wait for the schedule or dispatch manually | same result; a new advisory fails `audit` |

Record: date, commit, run URL, result.

Status 2026-11-02: CI-0..CI-3 **pending**. This host has no network and no Arch image, so the
image digest (`archlinux@sha256:000...000`) and `ARCH_SNAPSHOT: "UNRESOLVED"` stay fail-closed
sentinels (amendment A2); nothing was pushed.

## Manual reference hardware

| # | Where | Steps | Expected | Result |
|---|-------|-------|----------|--------|
| M-1 | reference laptop (001 SC-003) | `PASSWSYNC_REFERENCE_DEVICE=laptop scripts/bench.sh` | B-01/B-02 < 2 s, B-03 ≥ 0.3 s, every measured budget PASS (SC-006) | pending (no reference laptop on this host) |
| D-1 | reference phone (007) | unlock with default KDF, 5 times | < 3 s each (007 SC-005, B-21) | pending (no reference phone) |
| D-2 | reference phone | 1,000-credential wallet unlocked; `dumpsys meminfo` | < 128 MiB (007 SC-011, B-22) | pending (no reference phone) |
| D-3 | reference phone | 24 h idle with 2 paired devices; `dumpsys jobscheduler` | 007 SC-008 wake-up limits (B-23) | pending (no reference phone) |
| D-4 | reference phone | 24 h idle battery stats | 007 SC-009 < 1 % per day (B-23) | pending (no reference phone) |
