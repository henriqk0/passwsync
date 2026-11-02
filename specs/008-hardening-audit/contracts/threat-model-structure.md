# Contract: Threat Model Structure

**Covers**: FR-023..FR-029, FR-036, SC-008 | Research R14

`docs/threat-model.md` is one living, system-wide document. `scripts/check_threat_model.py`
(Python 3 stdlib: `re`, `tomllib`, `pathlib`) enforces this contract; its negative tests are
`scripts/tests/test_check_threat_model.py`.

## Document skeleton (headings are exact; order is fixed)

```text
# Threat Model
## 1. Scope and method                  # system parts, STRIDE, how to update, verification tags
## 2. Severity scale                    # defines exactly High, Medium, Low from impact x likelihood
## 3. Assets                            # table: | Id | Asset | Where | Protection |
## 4. Actors                            # table: | Id | Actor | Capability | In model |
## 5. Data flows and trust boundaries   # text diagram + table: | Id | Boundary | Crosses |
## 6. Threats by boundary
### B-01 Wallet at rest
### B-02 Process memory and OS
### B-03 Loopback HTTP service and browser
### B-04 LAN discovery
### B-05 Pairing
### B-06 Paired channel
### B-07 Wallet sync
### B-08 Sharing
### B-09 Android app and platform
### B-10 Packaging and service manager
### B-11 Build, dependency and CI supply chain
## 7. Out-of-model inputs               # same-user local files not fuzzed, with rationale
## 8. Residual-risk register
## 9. Audit findings
## 10. Change log
```

## Tables

Pipe tables, one header row, one separator row. Cells must not be empty.

**Assets** must include rows whose Asset cell matches (case-insensitive substring): master
password, derived key, decrypted credential, wallet file, device private key, pin, pairing code,
invite code, session token, sync record.

**Actors** must include: remote LAN attacker, malicious paired device, other local OS user,
malicious web page, same-user malware, thief of a powered-off device, compromised dependency,
CI contributor from a fork.

**Boundary threat table** (under each `### B-nn`):

```text
| Id | STRIDE | Threat | Mitigation | Reference | Status |
```

- `Id`: `T-Bnn-<n>`, unique.
- `STRIDE`: exactly one of `S`, `T`, `R`, `I`, `D`, `E`. Each boundary has all six.
- `Mitigation`: text, or `N/A: <reason>` (reason non-empty).
- `Reference`: at least one token matching
  `\b\d{3} (FR|SC)-\d{3}[a-z]?\b` | `crates/[\w-]+/tests/[\w/]+\.rs(::\w+)?` |
  `(scripts|android|packaging)/[\w/.-]+` | `RR-\d{2}` | `F-\d{3}` | `R\d+` with a spec number
  (`007 R6`). Referenced repository paths must exist.
- `Status`: `Mitigated` | `Residual (RR-nn)` (that RR id must exist in §8) | `N/A` (requires
  `N/A:` mitigation).

**Residual-risk register** (§8):

```text
| Id | Risk | Source | Rationale | Severity | Owner | Closing condition | Status |
```

- `Id`: `RR-nn`, unique. `Severity`: exactly `High`, `Medium` or `Low`.
- `Source`: a repository path (`specs/00N-.../{spec,plan,research}.md` with optional section,
  or `deny.toml`, `tools/uniffi-bindgen/deny.toml`); the file must exist.
- `Status`: `Accepted` | `Pending approval` | `Open`.
- Every advisory id in `[advisories] ignore` of `deny.toml` and `tools/uniffi-bindgen/deny.toml`
  appears in some row's Risk or Source cell (FR-036).
- Items marked PENDING APPROVAL in 007 (Constitution I exception for non-secret records, JVM
  copies of secrets, Constitution III exception for Kotlin) have `Pending approval`, never
  `Accepted` (FR-027). The checker enforces this for the required ids flagged `pending` in the
  required list.

**Audit findings** (§9):

```text
| Id | Target | Finding | Severity | Status | Test or owner |
```

- `Status`: `Fixed` (then `Test or owner` names `crates/<c>/tests/regress_008.rs::f_nnn_*`,
  which must exist) or `Open` (then names an owner and severity is set). An empty audit is
  written as a single row `| F-000 | - | none found | Low | Fixed | n/a |`, accepted only with
  id `F-000`.

## Required register entries (scripts/threat_model_required.tsv)

Initial list (tasks may add rows; removing one needs a change-log entry):

| RR id | Source file | Anchor phrase (must occur in source) | Flag |
|-------|-------------|--------------------------------------|------|
| RR-01 | specs/003-device-identity-pairing/research.md | `without zeroize` | |
| RR-02 | specs/003-device-identity-pairing/spec.md | `protected by owner-only file permissions` | |
| RR-03 | specs/003-device-identity-pairing/spec.md | `reveal a stable device ID to anyone on the same LAN` | |
| RR-04 | specs/004-wallet-sync-protocol/plan.md | `undetected restore` | |
| RR-05 | specs/004-wallet-sync-protocol/plan.md | `No MAC on the sync record` | |
| RR-06 | specs/005-wallet-sharing/plan.md | `Duplicate detection limited` | |
| RR-07 | specs/005-wallet-sharing/plan.md | `can invalidate an invitation` | |
| RR-08 | specs/005-wallet-sharing/plan.md | `an already delivered copy cannot be withdrawn` | |
| RR-09 | specs/002-local-service-web-ui/spec.md | `clearing cannot be guaranteed` | |
| RR-10 | specs/006-aur-packaging-service/plan.md | `Accepted residuals` | |
| RR-11 | specs/007-android-app/plan.md | `JVM copies of secrets` | pending |
| RR-12 | specs/007-android-app/spec.md | `Screen-reader access` | |
| RR-13 | specs/007-android-app/plan.md | `memory locked full/secrets-only with status` | |
| RR-14 | specs/007-android-app/plan.md | `non-secret records stored in plaintext` | pending |
| RR-15 | specs/007-android-app/plan.md | `Constitution III exception` | pending |
| RR-16 | deny.toml | `RUSTSEC-2023-0089` | |
| RR-17 | tools/uniffi-bindgen/deny.toml | `RUSTSEC-2026-0374` | |
| RR-18 | specs/008-hardening-audit/research.md | `runner VM image` | |
| RR-19 | specs/008-hardening-audit/research.md | `duplicate count` | |

Every anchor above was checked by exact-string search against its source on 2026-10-30 and is
copied verbatim into `scripts/threat_model_required.tsv`; the checker then keeps it from going
stale. Row RR-02 names `spec.md` (the owner-only permission sentence is not in `research.md`).

## Checker rules (each has a negative test)

| Rule | Fails when |
|------|------------|
| TM1 | a required heading is missing, renamed or out of order |
| TM2 | a boundary B-01..B-11 is missing or a different boundary heading is present |
| TM3 | a boundary lacks any STRIDE letter |
| TM4 | a threat row has an empty cell, bad id, duplicate id or bad STRIDE value |
| TM5 | a mitigation has no valid reference, or `N/A` without reason |
| TM6 | a referenced repository path does not exist |
| TM7 | `Residual (RR-nn)` names an unknown RR id |
| TM8 | a register row lacks source, owner, closing condition, or severity not in {High, Medium, Low} |
| TM9 | a required RR id is missing, its source cell lacks the listed file, or the anchor phrase is gone from that file |
| TM10 | a `pending` required RR id has status other than `Pending approval` |
| TM11 | an ignored advisory id from either deny.toml is absent from the register |
| TM12 | a finding row is `Fixed` without an existing regression test path, or `Open` without owner |
| TM13 | a required asset or actor is missing |

CLI: `python3 scripts/check_threat_model.py [docs/threat-model.md]`; prints `PASS` or one
`FAIL TMn: <detail>` line per violation; exit 0 / 1; 64 on usage error.
