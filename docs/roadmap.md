# Roadmap: P2P Password Manager

Governed by `.specify/memory/constitution.md` (Security-First, Simplicity, TDD, Hexagonal,
Low RAM, Decentralization). Features are specified and built one at a time, in order.

## Global rules (apply to every feature)

- Rust. The core is `crates/vault-core` (done in 001); new work adds crates that depend on it
  through ports and adapters, never the other way round.
- The app runs 100% **offline**. The network is used only by the device-sync features
  (003-005). There are **no accounts, no email, no login**.
- The only secret that protects a wallet is its **master password**, needed only to unlock a
  created or shared wallet, **once per device restart per wallet**. The derived key stays in
  memory only and is never persisted or sent. A shared wallet opens with the same master
  password. (Device pairing adds a one-time, short-lived pairing code; it protects the pairing
  handshake only and never a wallet.)
- Future runtime: a service installed via AUR, reached in a browser on localhost, and an
  Android app running in the background. Devices sync after some time, using very little CPU,
  RAM and battery (Syncthing-like: LAN discovery, block exchange, eventual consistency).
- Host executables (002 first, then 007) MUST lock memory against swap, disable core dumps
  and enforce auto-lock (obligation FR-025a from feature 001).
- Sync MUST resist rollback (an attacker restoring an older valid wallet file) and replay.
- Non-interactive: when a Spec Kit step would ask a question, choose the most secure and
  simplest answer consistent with the constitution and record it. Never commit; never push.

## Features

| # | Name | Scope |
|---|------|-------|
| 001 | vault-core | DONE. Encrypted wallet, credentials, storage port, file adapter. |
| 002 | local-service-web-ui | Daemon on 127.0.0.1 with a browser UI: create wallet with a master password, list wallets, unlock (once per restart), credential CRUD and search, copy to clipboard with auto-clear, auto-lock. Loopback only, Host/Origin checks against DNS rebinding, CSRF, per-run session token, strict CSP, no external assets. Implements the FR-025a host obligations. |
| 003 | device-identity-pairing | Per-device keypair, LAN discovery, pairing by short code or QR, mutually authenticated encrypted channel, key pinning, revocation. |
| 004 | wallet-sync-protocol | DONE (implemented, manual two-host scenarios pending). Version/block exchange between paired devices using the version vectors from 001, eventual consistency, conflict handling that preserves both versions, rollback and replay protection, low-resource scheduling. |
| 005 | wallet-sharing | DONE (implemented, manual two-host scenarios pending). Share a wallet with another device on the same network (invite code, QR, manual address). The wallet stays encrypted; the master password is never sent. Consent, expiry, scoped invitations. |
| 006 | aur-packaging-service | PKGBUILD and a hardened systemd user unit for the 002 service; reproducible build. |
| 007 | android-app | Rust core via UniFFI, background sync service, same flows, battery-aware, Keystore/screen-capture protections. |
| 008 | hardening-audit | Fuzzing of the file format and protocol, benchmarks, threat-model review, CI with cargo audit/deny. |
