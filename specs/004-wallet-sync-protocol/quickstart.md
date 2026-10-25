# Quickstart: validating wallet sync (004)

Validation guide only; formats live in [contracts/](contracts/), entities in
[data-model.md](data-model.md).

## Prerequisites

- Rust stable ≥ 1.85, Linux; features 001–003 built (`cargo build --workspace`).
- Two service instances with separate `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_RUNTIME_DIR`
  (two hosts, or two network namespaces as in the 003 quickstart), `network = on`, paired.
- `cargo deny check` and `cargo audit` pass (no new crates in the tree).

## Automated checks

```sh
cargo test -p vault-core            # v1→v2 read, v2 round-trip, merge properties, resolution
cargo test -p wallet-sync           # rounds, tags, marks, journal crash points, scheduler, 5-device sim
cargo test -p device-link -p device-link-net   # v2/v1 negotiation, sync frames, size limits
cargo test -p passwsyncd            # HTTP routes, plaintext-marker scan, crash injection
cargo test --workspace -- --ignored # resource tests (SC-006, SC-008)
cargo clippy --workspace --all-targets -- -D warnings
```

## Manual scenarios (two instances A and B)

1. **Basic sync (Story 1)**: copy a wallet file (v2, or v1 then unlock once with networking on)
   from A's `wallets/` to B's; unlock on both; add/edit/delete on A → visible on B ≤ 60 s;
   B's record shows the same state; `/api/state` shows `in_sync` on both.
2. **Leak check (SC-005, R2)**: `strings`/hexdump of the wallet file shows no wallet id or device
   ids; capture traffic (`tcpdump`) and confirm only Noise ciphertext after the 6-byte Hello.
3. **Conflict (Story 2)**: stop networking on B, edit the same credential on both (and an
   edit/delete pair), re-enable → both show the same conflict with both versions and the same
   current version; resolve on A ("keep both") → cleared on B.
4. **Locked receiver (Story 3)**: lock on B, edit on A → B gets `pending-<A>`, its wallet file
   digest is unchanged, state `changes_waiting`; unlock B → merged ≤ 10 s, pending removed.
5. **Rollback (Story 4)**: stop B, replace B's wallet file with an older copy, start B →
   `possible_rollback`, not offered; unlock → stays flagged until A's copy merges it back above
   the mark. Make A offer an older copy (restore A's file and record) → B shows "older state
   offered" for A and A heals after merging B's copy.
6. **Recovery**: corrupt B's record → sync disabled for that wallet with a message; unlock and
   "reset sync state" → syncing resumes.
7. **Sync now / backoff (Story 5)**: press "Sync now" twice quickly → one round in the log;
   kill A's network → B's retries back off (30 s, 60 s, …, ≤ 1 h).
8. **Legacy peer (FR-004)**: run B on the 003 build → A logs `sync peer legacy`, channel stays up,
   no sync traffic.

Expected: no crash, no data lost, all warnings visible until dismissed.
