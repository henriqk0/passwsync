# Threat Model

Minimal valid fixture for scripts/tests/test_check_threat_model.py (not the real model).

## 1. Scope and method

STRIDE per boundary; tags [H] [CI] [M] [D].

## 2. Severity scale

High, Medium, Low.

## 3. Assets

| Id | Asset | Where | Protection |
|----|-------|-------|------------|
| A-01 | Master password | memory | 001 FR-001 |
| A-02 | Derived key | memory | 001 FR-001 |
| A-03 | Decrypted credential | memory | 001 FR-001 |
| A-04 | Wallet file | memory | 001 FR-001 |
| A-05 | Device private key | memory | 001 FR-001 |
| A-06 | Pin | memory | 001 FR-001 |
| A-07 | Pairing code | memory | 001 FR-001 |
| A-08 | Invite code | memory | 001 FR-001 |
| A-09 | Session token | memory | 001 FR-001 |
| A-10 | Sync record | memory | 001 FR-001 |

## 4. Actors

| Id | Actor | Capability | In model |
|----|-------|------------|----------|
| X-01 | Remote LAN attacker | network | yes |
| X-02 | Malicious paired device | network | yes |
| X-03 | Other local OS user | network | yes |
| X-04 | Malicious web page | network | yes |
| X-05 | Same-user malware | network | yes |
| X-06 | Thief of a powered-off device | network | yes |
| X-07 | Compromised dependency or build input | network | yes |
| X-08 | CI contributor from a fork | network | yes |

## 5. Data flows and trust boundaries

| Id | Boundary | Crosses |
|----|----------|---------|
| B-01 | Wallet at rest | outside -> inside |
| B-02 | Process memory and OS | outside -> inside |
| B-03 | Loopback HTTP service and browser | outside -> inside |
| B-04 | LAN discovery | outside -> inside |
| B-05 | Pairing | outside -> inside |
| B-06 | Paired channel | outside -> inside |
| B-07 | Wallet sync | outside -> inside |
| B-08 | Sharing | outside -> inside |
| B-09 | Android app and platform | outside -> inside |
| B-10 | Packaging and service manager | outside -> inside |
| B-11 | Build, dependency and CI supply chain | outside -> inside |

## 6. Threats by boundary

### B-01 Wallet at rest

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B01-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B01-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B01-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B01-4 | I | disclosure | accepted | RR-01 | Residual (RR-01) |
| T-B01-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B01-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-02 Process memory and OS

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B02-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B02-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B02-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B02-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B02-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B02-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-03 Loopback HTTP service and browser

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B03-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B03-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B03-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B03-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B03-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B03-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-04 LAN discovery

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B04-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B04-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B04-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B04-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B04-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B04-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-05 Pairing

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B05-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B05-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B05-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B05-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B05-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B05-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-06 Paired channel

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B06-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B06-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B06-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B06-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B06-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B06-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-07 Wallet sync

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B07-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B07-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B07-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B07-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B07-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B07-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-08 Sharing

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B08-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B08-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B08-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B08-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B08-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B08-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-09 Android app and platform

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B09-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B09-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B09-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B09-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B09-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B09-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-10 Packaging and service manager

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B10-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B10-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B10-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B10-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B10-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B10-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

### B-11 Build, dependency and CI supply chain

| Id | STRIDE | Threat | Mitigation | Reference | Status |
|----|--------|--------|------------|-----------|--------|
| T-B11-1 | S | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B11-2 | T | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B11-3 | R | repudiation | N/A: single-user tool | 002 FR-001 | N/A |
| T-B11-4 | I | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B11-5 | D | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |
| T-B11-6 | E | threat | checked | crates/vault-core/tests/tamper.rs, scripts/gate.sh | Mitigated |

## 7. Out-of-model inputs

Same-user files.

## 8. Residual-risk register

| Id | Risk | Source | Rationale | Severity | Owner | Closing condition | Status |
|----|------|--------|-----------|----------|-------|-------------------|--------|
| RR-01 | risk | specs/003-device-identity-pairing/research.md | reason | Low | maintainer | when fixed | Accepted |
| RR-02 | risk | specs/003-device-identity-pairing/spec.md | reason | Low | maintainer | when fixed | Accepted |
| RR-03 | risk | specs/003-device-identity-pairing/spec.md | reason | Low | maintainer | when fixed | Accepted |
| RR-04 | risk | specs/004-wallet-sync-protocol/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-05 | risk | specs/004-wallet-sync-protocol/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-06 | risk | specs/005-wallet-sharing/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-07 | risk | specs/005-wallet-sharing/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-08 | risk | specs/005-wallet-sharing/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-09 | risk | specs/002-local-service-web-ui/spec.md | reason | Low | maintainer | when fixed | Accepted |
| RR-10 | risk | specs/006-aur-packaging-service/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-11 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Pending approval |
| RR-12 | risk | specs/007-android-app/spec.md | reason | Low | maintainer | when fixed | Accepted |
| RR-13 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Accepted |
| RR-14 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Pending approval |
| RR-15 | risk | specs/007-android-app/plan.md | reason | Low | maintainer | when fixed | Pending approval |
| RR-16 | RUSTSEC-2023-0089 | deny.toml | reason | Low | maintainer | when fixed | Accepted |
| RR-17 | RUSTSEC-2026-0374 | tools/uniffi-bindgen/deny.toml | reason | Low | maintainer | when fixed | Accepted |
| RR-18 | risk | specs/008-hardening-audit/research.md | reason | Low | maintainer | when fixed | Accepted |
| RR-19 | risk | specs/008-hardening-audit/research.md | reason | Low | maintainer | when fixed | Accepted |

## 9. Audit findings

| Id | Target | Finding | Severity | Status | Test or owner |
|----|--------|---------|----------|--------|---------------|
| F-001 | http_request | bare LF | Low | Fixed | crates/hardening/tests/regress_008.rs::f_001_bare_lf_in_the_request_head_is_rejected |
| F-002 | wallet_payload | alias | Low | Open | vault-core maintainer |

## 10. Change log

- 2026-10-30: fixture.
