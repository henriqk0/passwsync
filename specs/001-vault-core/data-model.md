# Data Model: Vault Core (001)

Types are described at the domain level; exact Rust signatures are in
[contracts/vault-core-api.md](contracts/vault-core-api.md). Byte layout is in
[contracts/file-format.md](contracts/file-format.md).

There are no user, account, email, or login entities: the product is offline and
identity-free. The only secret is each wallet's master password (FR-005a, FR-033).

## Value types

| Type | Representation | Validation / rules |
|------|----------------|--------------------|
| `WalletId` | 16 random bytes, hex display | Generated once at wallet creation; immutable (FR-014) |
| `EntryId` | 16 random bytes, hex display | Generated at entry creation; immutable (FR-008) |
| `DeviceId` | UTF-8 string, 1–64 bytes | Supplied by caller; stored as-is (FR-016); empty or >64 bytes rejected. Opaque change-tracking tag only — not a person identity, not secret, never used to authenticate (FR-033) |
| `Timestamp` | `i64` Unix seconds, UTC | From the `Clock` port (FR-009) |
| `MasterPassword` | zeroizing string | NFC-normalized; ≥12 Unicode scalar values (FR-002); wiped after key derivation |
| `VaultKey` | 32 bytes, zeroize-on-drop | Argon2id output; lives in memory only while the vault is unlocked; never serialized or persisted (FR-005, FR-005a, FR-024) |
| `KdfParams` | `{ memory_kib: u32, iterations: u32, parallelism: u32, salt: [u8; 32] }` | memory 19 456–1 048 576 KiB; iterations 2–100; parallelism 1–16 (FR-019) |
| `VersionVector` | ordered map `DeviceId → u64` | Counters ≥1; only the acting device's counter changes, by +1 per change (FR-015) |
| `VersionOrdering` | `Equal \| Newer \| Older \| Concurrent` | Result of comparing two `VersionVector`s (FR-016a) |

### VersionVector comparison

For vectors `a` and `b` (missing device = 0):

- `Equal` if every counter matches.
- `Newer` if `a[d] >= b[d]` for all `d` and `a != b`.
- `Older` if `b` is `Newer` than `a`.
- `Concurrent` otherwise.

## Entities

### Entry (credential)

| Field | Type | Rules |
|-------|------|-------|
| `id` | `EntryId` | Immutable |
| `created_at` | `Timestamp` | Immutable |
| `modified_at` | `Timestamp` | Updated on every edit and on delete |
| `last_modified_by` | `DeviceId` | Updated on every change |
| `version` | `VersionVector` | See rules above |
| `state` | `Live(EntryFields)` or `Deleted { deleted_at }` | Deleted is terminal in this feature |

### EntryFields (secret-bearing; whole struct zeroized on drop)

| Field | Type | Rules |
|-------|------|-------|
| `title` | string | Required, non-empty after trimming whitespace (FR-007) |
| `username` | string | Optional (empty string = absent) |
| `password` | string | Optional; secret; never searched (FR-013); redacted in `Debug` |
| `url` | string | Optional; free text, not validated |
| `notes` | string | Optional; secret; redacted in `Debug` |

Each text field is limited to 1 MiB to bound memory (oversize → validation error).

### Tombstone

An `Entry` whose `state` is `Deleted { deleted_at }`. On delete the `EntryFields` are dropped
(and therefore zeroized); `id`, `created_at`, `version`, `last_modified_by`, `modified_at` are
retained (FR-011).

### Vault (unlocked wallet)

| Field | Type | Rules |
|-------|------|-------|
| `wallet_id` | `WalletId` | Immutable |
| `created_at` | `Timestamp` | Immutable |
| `kdf` | `KdfParams` | Replaced (new salt) on master-password change (FR-006) |
| `key` | `VaultKey` | Never serialized |
| `entries` | list of `Entry` (live and tombstones) | Unique `id`s |

Serialized payload (encrypted body) = `{ wallet_id, created_at, entries }`. The KDF params
live in the plaintext header (authenticated as AAD), not in the payload.

### Encrypted wallet (locked)

Opaque bytes: `header || ciphertext || tag`. See the file-format contract.

## State transitions

```text
                 create(password, device, clock)
   (nothing) ───────────────────────────────────▶ Unlocked Vault
                                                   │   ▲
                        seal() → bytes ───────────┘   │ unlock(bytes, password)
                                                       │
   Encrypted bytes (storage) ◀── save(storage) ───────┘
   Unlocked Vault ── lock()/drop ──▶ (nothing in memory; key + entries zeroized)
   (host auto-lock timeout and process exit both end in lock()/drop)
```

Entry lifecycle:

```text
 add ──▶ Live ──edit──▶ Live (version[device] += 1, modified_at, last_modified_by)
           │
           └─delete──▶ Deleted (fields zeroized; version[device] += 1)   [terminal]
 edit/delete on Deleted or unknown id ──▶ EntryNotFound, no change
```

## Validation errors (domain)

`PasswordTooShort`, `EmptyTitle`, `FieldTooLarge`, `InvalidDeviceId`, `EntryNotFound`.
Unlock/format errors are listed in the file-format contract.
