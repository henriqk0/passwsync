# Contract: Budgets and Benchmarks

**Covers**: FR-018..FR-022, SC-005..SC-007 | Research R13

## Two classes, two commands

| Class | Command | Fails the gate | Runs in CI |
|-------|---------|----------------|------------|
| deterministic | part of `cargo test` (gate steps `test` and `budgets`) | yes | yes |
| measured | `scripts/bench.sh` (release, `--ignored --nocapture`) | never | never |
| device | manual checklist in quickstart (D-1..D-4) | n/a | n/a |

## Budget table

`check` names the test that asserts (deterministic) or measures (measured). "new" means added
by this feature; others exist and gain only a `BUDGET` print line.

| Id | Budget | Limit | Source | Class | Check |
|----|--------|-------|--------|-------|-------|
| B-01 | unlock time, default KDF, median of 9 | < 2 s | 001 SC-003 | measured | `vault-core/tests/perf.rs` (new fn `unlock_default_median_and_worst`) |
| B-02 | unlock time, default KDF, worst of 9 | < 2 s | 001 SC-003 | measured | same |
| B-03 | time per guess (wrong password), default KDF | ≥ 0.3 s | 001 SC-003 | measured | same file, new fn `time_per_guess` |
| B-04 | unlock at the service KDF cap (131,072 KiB) | info (no budget) | 008 FR-018 | measured | same file, new fn `unlock_at_service_cap` |
| B-05 | list 10,000 credentials | < 100 ms | 001 SC-004 | measured | `vault-core/tests/perf.rs` (existing) |
| B-06 | search 10,000 credentials | < 100 ms | 001 SC-004 | measured | same (existing) |
| B-07 | peak memory unlocked, 10,000 credentials | < 64 MB | 001 SC-005 | measured | `vault-core/tests/perf.rs` (existing, VmHWM) |
| B-08 | idle service memory | < 50 MB | 002 SC-008 | measured | `passwsyncd/tests/perf_memory.rs` (existing) |
| B-09 | idle service: no busy polling (wake-ups over simulated idle) | 0 periodic wake-ups beyond the documented timers | 002 SC-008 | deterministic | `hardening/tests/budgets.rs` (new; prints the B-09 BUDGET line, may call an existing sweeper test helper, no duplicate assertion) |
| B-10 | networking idle extra memory, 5 peers | < 10 MB | 003 SC-007 | measured | `passwsyncd/tests/resources_network.rs` (existing) |
| B-11 | networking idle CPU | < 1 % | 003 SC-007 | measured | same |
| B-12 | wake-ups per peer | ≤ 1 per 30 s | 003 SC-007 | deterministic | `device-link-net/tests/resources.rs::wakes_are_counted` (existing) |
| B-13 | idle sync traffic, 5 peers x 10 wallets, 1 simulated hour | < 1 KiB per peer, identical across runs | 004 SC-006 | deterministic | `passwsyncd/tests/resources_sync.rs::idle_sync_costs_less_than_1_kib_per_peer_per_hour` (existing; second run equality added) |
| B-14 | idle sync CPU | < 1 % | 004 SC-006 | measured | `resources_sync.rs` (existing ignored) |
| B-15 | idle sync memory | < 8 MiB | 004 SC-006 | measured | same |
| B-16 | sync of 10,000-credential wallet differing by one, duration | < 10 s | 004 SC-008 | measured | `passwsyncd/tests/sync_perf.rs` (existing) |
| B-17 | same, peak additional memory | < 64 MB | 004 SC-008 | measured | same |
| B-18 | transfer buffer per transfer | ≤ 1 MiB | 004 FR-029 | deterministic | `hardening/tests/budgets.rs` (new, via sync engine + fuzz target #14 oracle) |
| B-19 | concurrent transfers | ≤ 2 | 004 FR-029 | deterministic | `hardening/tests/budgets.rs` (new) |
| B-20 | parser bounds: frame 1024, fragment 1000, ctl 24 KiB, tags 512, HTTP head 16 KiB / 48 headers, body 8 MiB, wallet 79 B..64 MiB, text 1 MiB, KDF cap 131,072 KiB | equal to the documented constants | 001-004, 007 | deterministic | `hardening/tests/budgets.rs` (new: asserts each public constant equals the spec value) |
| B-21 | phone unlock, default KDF | < 3 s | 007 SC-005 | device | quickstart D-1 |
| B-22 | phone memory, 1,000 credentials unlocked | < 128 MiB | 007 SC-011 | device | quickstart D-2 |
| B-23 | phone background wake-ups / battery | 007 SC-008, SC-009 limits | 007 | device | quickstart D-3, D-4 |

SC-005: the report has a value and verdict (or `NO-DATA` -> treated as incomplete) for every
B-01..B-20; every deterministic budget passes in the gate.

## BUDGET line

```text
BUDGET id=B-nn value=<number> unit=<ms|s|B|KiB|MB|MiB|%|count> limit=<number> cmp=<lt|le|ge|eq|info> source=<NNN-SC-xxx|NNN-FR-xxx> class=<deterministic|measured> verdict=<PASS|OVER|INFO>
```

Printed by the test before any assertion. Values are numbers only; no names, passwords or
credential text on the line or anywhere in benchmark output (FR-038). Benchmarks use only
`tempfile`-style directories under `std::env::temp_dir()` created by the existing test
helpers and removed afterwards.

## scripts/bench.sh

```text
usage: scripts/bench.sh            # run every measured budget, write target/bench/report.txt
env:   PASSWSYNC_REFERENCE_DEVICE=laptop   # mark the run as the reference device (default: no)
exit:  0 report complete (any verdicts); 1 build or harness error; 2 some budget NO-DATA; 64 usage
```

Steps: `cargo test --frozen --offline --release` for each listed measurement test with
`-- --ignored --nocapture --test-threads=1`; the deterministic BUDGET files `hardening/tests/budgets.rs`, `device-link-net/tests/resources.rs` and `passwsyncd/tests/resources_sync.rs` run the same way without `--ignored`, so B-09, B-12, B-13, B-18, B-19 and B-20 also get rows; capture stdout, extract `BUDGET` lines (a failing
assertion does not lose the line), write the machine block (data-model §3) and one row per
budget, print the report. The script never runs in the gate or in CI.

## Reference hardware

The binding verdicts are the manual runs: quickstart M-1 (reference laptop, 001 SC-003) and
D-1..D-4 (reference phone). Until run, quickstart records them as `pending`.
