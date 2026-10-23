<!--
Sync Impact Report
- Version change: (unfilled template) → 1.0.0
- Modified principles: none renamed (initial ratification)
- Added principles: I. Security-First; II. Simplicity & Occam's Razor; III. Test-Driven
  Development; IV. Hexagonal Architecture; V. Resource Efficiency; VI. Scalability &
  Decentralization
- Added sections: Technical Constraints & References; Development Workflow & Quality Gates;
  Governance
- Removed sections: none
- Deferred items: none
- Templates reviewed: no template files modified (per command scope)
-->

# P2P Password Manager Constitution

## Core Principles

### I. Security-First (NON-NEGOTIABLE)

Security takes precedence over every other trade-off, including simplicity, performance, and
convenience.

- All data at rest MUST be encrypted with state-of-the-art, industry-standard algorithms
  (e.g., AES-256-GCM for encryption, Argon2id for key derivation).
- Zero-knowledge architecture: plain-text credentials MUST NEVER reach the network or
  unencrypted storage (including logs, swap-prone buffers, and temp files).
- All peer-to-peer communication and synchronization MUST be end-to-end encrypted and
  mutually authenticated.
- Cryptography MUST use vetted libraries; custom cryptographic primitives are prohibited.

Rationale: a password manager that leaks secrets has no value; a single breach is unrecoverable.

### II. Simplicity & Occam's Razor

Given two valid options with equal functionality, security, and performance, the simpler MUST
be chosen.

- Over-engineering, speculative abstractions, and premature optimization are prohibited.
- Code MUST be clean, readable, and maintainable.
- Any added complexity MUST be justified in the plan or PR by a concrete requirement.

Rationale: small, auditable code is easier to secure and maintain.

### III. Test-Driven Development (NON-NEGOTIABLE)

TDD is mandatory for all features and bug fixes.

- Workflow is Red-Green-Refactor: write a failing test, write the minimum code to pass it,
  then refactor with tests green.
- Every bug fix MUST begin with a test that reproduces the bug.
- High coverage is required across unit, integration, and synchronization scenarios
  (including multi-device, network partition, and conflict cases).

Rationale: tests are the safety net for cryptographic and sync correctness.

### IV. Hexagonal Architecture (Ports and Adapters)

The core domain logic MUST be isolated from external concerns: databases, UI, network
protocols, disk I/O, and P2P sync engines.

- Dependencies MUST point inward; the core MUST NOT import infrastructure code.
- External interactions MUST go through ports (interfaces) implemented by adapters.
- The core MUST be testable with in-memory fakes of all ports.

Rationale: isolation keeps the core testable and lets infrastructure be swapped safely.

### V. Resource Efficiency (Low RAM Consumption)

The application MUST run efficiently on constrained environments and as a background
desktop/mobile process.

- Memory allocations MUST be managed deliberately; leaks are defects.
- Unnecessary allocations and garbage-collection pressure MUST be avoided; large data SHOULD
  be streamed rather than fully loaded.
- Memory-sensitive changes SHOULD include a measurement or benchmark.
- Secret material MUST be held in memory only as long as needed and wiped when released,
  where the platform allows.

Rationale: always-on background operation requires a small, predictable footprint.

### VI. Scalability & Decentralization

The system MUST be peer-to-peer; no central server or cloud relay may be required for basic
operation or synchronization.

- The system MUST handle a variable number of connected devices.
- Network partitions MUST be tolerated, with eventual consistency on reconnection.
- Conflicts over shared encrypted storage files MUST be resolved deterministically without
  data loss (conflicting versions are preserved, never silently overwritten).

Rationale: users own their data and sync without depending on third-party infrastructure.

## Technical Constraints & References

- Syncthing (https://github.com/syncthing/syncthing) is the reference for decentralized device
  discovery, secure peer-to-peer block exchange, eventual consistency, and conflict handling.
- KeePassXC (https://github.com/keepassxreboot/keepassxc) is the reference for secure local
  database structure, cryptographic primitives, master key protection, and password manager
  best practices.
- References are inspiration, not mandates; where they conflict with the Core Principles, the
  Core Principles prevail.
- Technology stack choices are deferred to feature plans and MUST comply with all principles.

## Development Workflow & Quality Gates

- Tests MUST exist and fail before implementation begins (Principle III).
- A change MUST NOT merge with failing tests or without tests covering new behavior.
- Reviews MUST verify: no plaintext secrets outside protected memory, domain isolation from
  adapters, and justified complexity.
- Dependencies MUST be minimal, vetted, and security-reviewed before being added.

## Governance

This constitution supersedes all other practices. Where principles conflict, precedence is:
Security-First, then the remaining principles in the order listed.

- **Amendments**: proposed via a documented change stating rationale and impact, approved by
  the project maintainers, with a migration plan for affected code and artifacts.
- **Versioning**: semantic versioning. MAJOR for backward-incompatible principle removals or
  redefinitions; MINOR for new principles/sections or materially expanded guidance; PATCH for
  clarifications and wording fixes.
- **Compliance**: every plan, PR, and review MUST verify compliance with this constitution;
  violations MUST be fixed or explicitly justified and recorded.

**Version**: 1.0.0 | **Ratified**: 2026-10-23 | **Last Amended**: 2026-10-23
