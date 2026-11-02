# Data Model: Hardening Audit

**Feature**: 008-hardening-audit | **Date**: 2026-10-30 | **Plan**: [plan.md](plan.md)

This feature adds no product data, file format or wire message. The entities below are
test-side and document-side structures. Rust types live in `crates/hardening/src/` (std only);
document structures live in `docs/threat-model.md` and the checker inputs.

## 1. Fuzz engine (crates/hardening/src)

### FuzzConfig
| Field | Type | Rule |
|-------|------|------|
| `seed` | `u64` | default `0x5057_5359_4E43_0008`; env `PASSWSYNC_FUZZ_SEED` (decimal or `0x` hex); malformed value fails the test |
| `iterations` | `u64` | `max(target.min_inputs, env PASSWSYNC_FUZZ_ITERS)` (env can raise it, never lower it) |
| `only` | `Option<u64>` | env `PASSWSYNC_FUZZ_ONLY`; runs exactly that iteration |
| `trace` | `bool` | env `PASSWSYNC_FUZZ_TRACE=1` |

### Rng
SplitMix64 state `u64`. `Rng::for_iteration(seed, target_name, iter)` (research R2). Pure,
deterministic across platforms (wrapping integer ops only).

### Seed
| Field | Type | Rule |
|-------|------|------|
| `label` | `&'static str` | e.g. `"ctl:tags-512"`; printed in failures |
| `bytes` | `Vec<u8>` | produced by the project's own encoder at test time, never a committed blob |
| `fields` | `Vec<Field>` | length/count fields the encoder wrote |
| `chunks` | `Option<Vec<usize>>` | stream targets only (HTTP, reassembly): delivery split points |

### Field
`{ offset: usize, width: Width (U8 | U16Be | U16Le | U32Be | U32Le | Varint), bound: u64 }`.
`LengthField` mutation writes one of `0, bound-1, bound, bound+1, max(width)`.

### Mutation (enum)
`BitFlip`, `BoundaryByte`, `Insert`, `Delete`, `Truncate`, `Duplicate`, `Splice`,
`LengthField`, `VarintBoundary`, plus `Rechunk` for stream targets (new random split points).
An input = seed index + 1-4 mutations, all drawn from the iteration's `Rng`. Iterations
`0..n_seeds` run every seed unmutated (round-trip baseline and coverage of "accepted").

### Target (trait-like struct of fns)
| Field | Meaning |
|-------|---------|
| `name` | stable id, e.g. `sync_ctl` (contracts/fuzz-harness.md table) |
| `min_inputs` | 10,000 (64 derived inputs for `wallet_unlock`) |
| `time_limit` | 1 s per input (10 s for `wallet_unlock`) |
| `alloc_bound` | bytes; the parser's documented bound (oracle adds 4 MiB slack, research R4) |
| `input_cap` | largest mutated input the generator builds |
| `seeds()` | `Vec<Seed>` from encoders |
| `one(&[u8] or &Input) -> Verdict` | runs the parser and the target's oracles; the same fn the optional cargo-fuzz target calls |

### Verdict
`Accepted` | `Rejected(kind: &'static str)` | `Violation(Failure)`. `kind` must be one of the
target's documented error kinds (closed list per target).

### Failure
| Field | Type |
|-------|------|
| `target` | `&'static str` |
| `seed` | `u64` |
| `iteration` | `u64` |
| `kind` | `Panic` \| `TimeOverrun` \| `Hang` \| `AllocBound` \| `ValueBound` \| `UnknownError` \| `RoundTrip` \| `StateLeak` (handshake left pin/session/partial state) \| `GuardBypass` (HTTP) \| `NotGeneric` (unlock error not the generic one) \| `Coverage` |
| `detail` | short text (panic message or the violated rule); never secret by construction (research R9) |
| `input` | `Vec<u8>`, printed `hex:` (binary targets) or `text:"..."` with `\r \n \t \\ \" \xNN` escapes (HTTP, share text) |

### TargetReport
| Field | Deterministic | Meaning |
|-------|---------------|---------|
| `inputs`, `accepted`, `rejected`, `derived` (unlock only) | yes | counts |
| `result` | yes | `PASS` / `FAIL` |
| `max_input_us`, `peak_over_baseline_kib`, `elapsed_ms` | no | printed on a separate `FUZZ-TIME` line |

Coverage rule (FR-008): `accepted >= 1 && rejected >= 1`, else `Failure{kind: Coverage}`.

## 2. Findings

### Finding (`F-NNN`)
| Field | Rule |
|-------|------|
| `id` | `F-001`... in order found |
| `target` | fuzz target name or `review` / `benchmark` |
| `seed`, `iteration` | when found by the fuzzer |
| `reproducer` | minimal input literal (hex or escaped text) |
| `kind` | a `Failure.kind` or `Review` |
| `severity` | High / Medium / Low (threat-model scale) |
| `status` | `Fixed` (with regression test path `crates/<owner>/tests/regress_008.rs::f_nnn_*`) or `Open` (with owner and why not fixable here: valid encoding would change) |

State transitions: `Reported -> RedTest -> Fixed` (test failed before the fix, passes after),
or `Reported -> Open` (recorded in the threat model; no code change). No other transition.

## 3. Budgets and benchmark report

### Budget
| Field | Rule |
|-------|------|
| `id` | `B-01`... (contracts/benchmarks.md table) |
| `name` | short |
| `limit`, `unit`, `cmp` | e.g. `2000 ms lt`, `0.3 s ge`, `1024 B lt` |
| `source` | spec reference, e.g. `001 SC-003` |
| `class` | `deterministic` (asserted, gates) \| `measured` (reported) \| `device` (manual, pending) |
| `check` | test path that asserts or measures it |

### BudgetLine (stdout of a measurement or assertion test)
`BUDGET id=B-nn value=<number> unit=<ms|s|B|KiB|MB|MiB|%|count> limit=<number> cmp=<lt|le|ge|eq|info> source=<NNN-SC-xxx|NNN-FR-xxx> class=<deterministic|measured> verdict=<PASS|OVER|INFO>`
(the exact grammar is in contracts/benchmarks.md). One line per budget value; no other free text on the line; never contains wallet data.

### BenchmarkReport (`target/bench/report.txt`)
| Section | Content |
|---------|---------|
| machine | CPU model, logical cores, MemTotal, kernel, `rustc -V`, profile `release`, `reference=<no|laptop>` (env `PASSWSYNC_REFERENCE_DEVICE`, default `no`), date UTC |
| rows | one per budget: id, name, value, limit, source, class, verdict (`NO-DATA` if a test printed no line) |
| footer | `informational: timing verdicts are binding only on reference hardware` when `reference=no` |

## 4. Threat model (docs/threat-model.md)

Structure and parsing rules: [contracts/threat-model-structure.md](contracts/threat-model-structure.md).

### Asset (`A-nn`)
name, where it lives, protection summary. Required set (FR-023): master passwords, derived
keys, decrypted credentials, wallet files, device private keys, pins, pairing codes, invite
codes, session token, sync records.

### Actor (`X-nn`)
name, capability, in or out of the attacker model. Required set (FR-023): remote LAN attacker,
malicious paired device, other local OS user, malicious web page, same-user malware, thief of a
powered-off device, compromised dependency or build input, CI contributor from a fork.

### TrustBoundary (`B-01`..`B-11`)
| Field | Rule |
|-------|------|
| `id`, `name` | fixed list (contracts/threat-model-structure.md) |
| `crosses` | from-trust -> to-trust |
| `threats` | table rows; every STRIDE category S, T, R, I, D, E present at least once |

### Threat (row `T-<boundary>-<n>`)
| Field | Rule |
|-------|------|
| `stride` | one of `S T R I D E` |
| `threat` | text |
| `mitigation` | text, or `N/A: <one-line reason>` |
| `reference` | at least one of: `NNN FR-xxx`, `NNN SC-xxx`, test path `crates/.../tests/x.rs` (optionally `::fn`), script path, `RR-nn`, `F-NNN` |
| `status` | `Mitigated` \| `Residual (RR-nn)` \| `N/A` |

### ResidualRisk (`RR-nn`)
| Field | Rule |
|-------|------|
| `risk` | text |
| `source` | spec/plan/research path (+ section) or `deny.toml` for advisory ignores |
| `rationale` | text |
| `severity` | exactly `High`, `Medium` or `Low` |
| `owner` | `maintainer` or a named role |
| `closing condition` | text |
| `status` | `Accepted` \| `Pending approval` \| `Open` |

State: `Open -> Accepted` only by a maintainer decision recorded in the document; `Pending
approval` items (the 007 Constitution I exception and the other 007 PENDING APPROVAL rows) stay
pending: this feature never moves them to `Accepted` (FR-027).

### RequiredRisk (scripts/threat_model_required.tsv)
Tab-separated: `rr_id`, `source_path`, `anchor_phrase`. The checker requires each `rr_id` in
the register, its source cell to contain `source_path`, and `anchor_phrase` to occur in that file.

## 5. Gate and workflow

### GateStep
| Field | Rule |
|-------|------|
| `name` | fixed list (contracts/gate-script.md) |
| `command` | fixed |
| `result` | `PASS` \| `FAIL` \| `MISSING` \| `SKIP` |
| `detail` | one line |
| `where` | `[H]` host and `[CI]` (the same script) |

Exit: 0 all PASS; 1 any FAIL; 2 any MISSING with no FAIL; 64 usage.

### WorkflowPolicyRule (`W1`..`W14`)
id, description, check, negative fixture. See [contracts/ci-workflow.md](contracts/ci-workflow.md).

### Pin
| Field | Rule |
|-------|------|
| `kind` | `image` \| `snapshot` \| `tool` |
| `value` | image `archlinux@sha256:<64 hex>` (sentinel all-zero = PENDING); snapshot `YYYY/MM/DD` (`UNRESOLVED` = PENDING); tool `name@X.Y.Z` |
| `state` | `Resolved` \| `Pending [CI]` |
