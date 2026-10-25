# Quickstart: validating wallet sharing (005)

Validation guide only; formats live in [contracts/](contracts/), entities in
[data-model.md](data-model.md), rationale in [research.md](research.md).

## Prerequisites

- Rust stable ≥ 1.85, Linux; features 001–004 built (`cargo build --workspace`).
- Two service instances A and B (a third, C, for scope tests) with separate
  `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_RUNTIME_DIR` (two hosts, or network namespaces as in the
  003 quickstart), `network = on`, all paired with each other (003).
- `cargo deny check` and `cargo audit` pass with an unchanged `Cargo.lock` crate set.

## Automated checks

```sh
cargo test -p wallet-sync           # share codec, proof binding, invitation/redemption state machines, received rules
cargo test -p wallet-service        # adopt_received, already_present, lock observer
cargo test -p device-link -p device-link-net   # v3/v2/v1 negotiation, share frames refused < v3, ensure_channel
cargo test -p passwsyncd            # HTTP routes and guards, two/three-service share, marker scan, fault injection
cargo test --workspace -- --ignored # SC-006 (10 000 credentials < 10 s), SC-007 (idle cost)
cargo clippy --workspace --all-targets -- -D warnings
```

## Manual scenarios

1. **Share (Story 1)**: on A unlock "Personal", Share → choose B → code, QR, countdown shown. On B,
   Devices → "Receive a wallet" → choose A → enter the code. A shows B's name and fingerprint →
   Accept. B lists a received wallet from A; Open with a local name and the master password →
   same credentials as on A. Time from "Share" to open < 2 min (SC-001).
2. **Manual address / QR id (FR-011, FR-012)**: repeat entering A's `address:port` instead of
   choosing A; then send `POST /api/receive` with A's address and C's device id → `id_mismatch`,
   nothing sent.
3. **Leak check (SC-002)**: capture traffic (`tcpdump`) during scenario 1 and search for the code
   digits, the wallet name, a credential title and the master password: zero hits; after the
   6-byte Hello only Noise ciphertext. Check `received/*.meta` and the log: no code, no wallet
   name.
4. **Sync afterwards (Story 2)**: edit on A → visible on B ≤ 60 s; edit on B → on A. Before opening
   on B, edits on A do not create anything under B's `sync/`.
5. **Scope (Story 3)**: new invitation for B; on C enter the right code → refused on C, A shows
   "refused (not recipient)", invitation gone. Wrong code on B → invalidated. Wait 5 min → expired.
   Re-enter a used code → refused ("already used"). Restart A during an invitation → B's redeem
   gets `invalid`. Revoke B on A, then B redeems → never past the handshake.
6. **Consent and cancel (Story 4)**: cancel on A before and during the wait; Reject on A; cancel
   the wait on B; Discard a received wallet on B → in each case nothing in B's `wallets/`, no file
   left in `received/` except as listed. Lock the wallet on A while B waits → B shows "invitation
   cancelled by sender". Cancel after completion → explanation about revoke + password change.
7. **Cannot open (Story 5)**: wrong password → generic error, stays listed; corrupt the received
   `.pwsw` → generic error, Discard works; share a wallet B already holds → "already present",
   no second wallet.
8. **Retention and cleanup**: set B's clock or the test wall clock 24 h ahead → received wallet
   deleted with a notice; kill B during a transfer → at restart no `.part` remains.
9. **Eligibility and limits**: share a wallet flagged `possible_rollback` or still format v1 →
   `not_eligible`; create 6 invitations within 10 minutes → `429`; fill B with 8 received wallets
   → `received_limit`.
10. **Older peer (FR-024)**: run B on the 004 build → A shows "this device does not support
    sharing", 004 sync with B keeps working.

Expected: no crash, no wallet created without the master password on the receiving device, no
plaintext on the wire or in files, every refusal shown on both devices and logged by fingerprint.
