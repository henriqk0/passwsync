# Data Model: Wallet Sync Protocol (004)

Rationale for every rule: [research.md](research.md). Wire and file layouts:
[contracts/](contracts/).

## vault-core (domain)

### StateVector

- Sorted map `DeviceId → u64`; 0..=256 entries (empty = no change yet); counters ≥ 1; canonical encoding = postcard
  `Vec<(String, u64)>` sorted by device id (same rules as 001 `VersionVector`).
- Operations: `bump(me)` (checked `+1`), `join(a, b)` (component-wise max), `dominates(a, b)`
  (`a ≥ b` in every component, missing = 0), `compare` → `Equal | Newer | Older | Concurrent`.
- Invariant: for every version `v` of every entry, `v.version ≤ state` component-wise.

### Version (one version of an entry)

| Field | Type | Rule |
|-------|------|------|
| modified_at | Timestamp (i64) | informational, tie-breaker only |
| last_modified_by | DeviceId | ≤ 64 bytes |
| version | VersionVector | 001 rules |
| state | `Live{title, username, password, url, notes}` \| `Deleted{deleted_at}` | 001 field rules |

`content_hash` = SHA-256 of the postcard encoding of the Version (identity of a version).

### Entry (v2)

| Field | Type | Rule |
|-------|------|------|
| id | EntryId | unique per wallet |
| created_at | Timestamp | |
| current | Version | shown in list/search |
| conflicts | Vec<Version> | 0..=15; together with `current` pairwise not dominated, no duplicate `content_hash`, ordered by the FR-014 order (current first) |

`is_conflicted() = !conflicts.is_empty()`. The 001 accessors (`title`, `version`, …) read
`current`. List/search include conflicted entries with a `conflicted` flag.

### Wallet payload (v2)

`wallet_id`, `created_at`, `state: StateVector`, `password_epoch: VersionVector` (may be empty),
`entries: Vec<Entry>`. Header (KDF, salt, nonce) as v1 with `format_version = 2`.

### OpenedCopy

Authenticated contents of a received copy (wallet id, state, password epoch, entries, and the
copy's KDF config/salt/key in a zeroizing holder). Produced only by `Vault::open_copy_own_key`
or `open_copy_with_password`; dropped (zeroized) after merge.

### MergeReport

`{ changed: bool, conflicts_added: u32, conflicts_cleared: u32, merge_change: bool,
password_adopted: bool, self_rollback_recovered: bool }`. Errors: `WalletMismatch`,
`TooManyConflicts`, `PasswordConflict` (concurrent epochs), `JumpTooLarge`,
`TooManyDevices`.

### Conflict resolution

`Resolution = Keep(index) | KeepBoth`; `index` addresses `[current, conflicts…]`.
State transition: `Conflicted(n ≥ 2 versions) → Resolved(1 version, new dominating version
vector)`; KeepBoth also creates `live_versions - 1` new entries.

### SaveMeta (storage port)

`{ wallet_id, state }` passed to `VaultStorage::store_versioned` (default impl ignores it).

## wallet-sync (domain)

### SyncRecord (one per wallet held and unlocked at least once on this device)

| Field | Meaning | Written when |
|-------|---------|--------------|
| wallet_id | 16 bytes | record creation |
| wallet_name | local file name | creation; updated if the service renames |
| digest | SHA-256 of the wallet file last saved/verified by this service | journaled save, unlock verification |
| state | authenticated StateVector of that file | same |
| prepared | `None` \| `{digest, state, peer_mark_updates, consumed_pending}` | journal step 1 |
| mark | high-water mark (StateVector) | `join(mark, state)` on each committed save; reset by accept-older / reset |
| flags | `possible_rollback` (with reason `state` or `digest`), `disabled(reason)` | checks (R10); a digest mismatch sets `possible_rollback` with reason `digest` until unlock authenticates the file (FR-012, FR-021) |
| peers | map `PeerId([u8;32]) → PeerSyncState` | |
| pending | map `PeerId → PendingCopy` (≤ 1 per peer) | receipt, merge, discard |
| warnings | list of `SyncWarning` (bounded 64, oldest dropped after dismissal only) | events |

Validation: parse rejects unknown lines, bad hex, unsorted vectors, > 256 devices, > 32 peers,
checksum mismatch → record `Corrupted` → wallet sync `disabled(corrupted_record)`.

### PeerSyncState (per wallet × peer)

`peer_mark: Option<StateVector>` (newest authenticated state received from that peer),
`last_round_at: Option<unix>`, `last_outcome: ok | failed(class) | older_state_offered |
invalid_copy`, `position: in_sync | behind | ahead | diverged | unknown | offline | older_state_offered | error` (same closed set as contracts/http-api-sync.md; `offline` and `error` are derived from the last round outcome).
Deleted on revocation of the peer (with its pending copy).

### PendingCopy

`{ peer, claimed_state, size, received_at, status }`, status:
`waiting | cannot_open | password_conflict | too_many_conflicts`. File
`pending-<peer hex>`. Replaced by a newer copy from the same peer; deleted when merged,
discarded, dominated by local state, or the peer is revoked.

### SyncWarning (closed set)

`possible_rollback{wallet}`, `older_state_offered{wallet, peer}`, `invalid_copy{wallet, peer}`,
`cannot_open{wallet, peer}`, `self_rollback_recovered{wallet, peer}`,
`password_adopted{wallet, peer}`, `record_corrupted{wallet}`, `duplicate_wallet_id{wallet}`.
Dismissal removes the warning only; never changes marks or data (FR-036).

### Round (per peer, in memory)

`Idle → Tagging(round) → Summarizing → Transferring → Closing → Idle`; any timeout (30 s
without progress), protocol error or channel loss → `Failed` (backoff). Holds:
`round: u32`, `role`, `session: [u8;32]`, `tags: Vec<(tag, wallet_id)>` (initiator side),
`matches: Vec<(idx, wallet_id)>`, outstanding `Want` (≤ 1 per direction), reassembly buffer
(≤ 24 KiB), current incoming transfer `{idx, size, received}`.

### Wallet sync state (UI, derived)

Priority order (first that applies): `sync_off` (networking off) → `disabled(reason)` →
`possible_rollback` → `conflicts(n)` → `changes_waiting` (pending while locked) →
`syncing` → `sync_error` (last round failed) → `not_synced` (no peer holds it / never unlocked
here / v1 file) → `in_sync`. Plus `last_synced_at`. `sync_off`, `disabled(reason)` and
`not_synced(reason)` are the closed set shared with the spec (US5, scenario 1) and
contracts/http-api-sync.md.

### Scheduler (per peer)

`next_safety_at`, `backoff: {failures, until}`, `dirty_since: Option<mono>` (quiet period),
`sync_now: bool`, `legacy_until: Option<mono>` (v1-only peer).
**Amended by 009 (pending 009 implementation)**: no version memory outlives a channel; 009 research R1.

## device-link (additive)

- `HelloVersion = V1 | V2`; channel prologue per version.
- `Payload::SyncCtl { more: bool, fragment: Vec<u8> }` (type 0x20),
  `Payload::CopyData { bytes }` (type 0x21); valid only when `Channel::sync_enabled()`.
- `Channel::session_hash() -> [u8; 32]`.

## Relationships

`SyncRecord 1 — 1 wallet file (by digest)`, `SyncRecord 1 — 0..32 PeerSyncState`,
`SyncRecord 1 — 0..32 PendingCopy`, `PeerSyncState n — 1 PeerPin (003)`;
`Entry 1 — 1..16 Version`.
