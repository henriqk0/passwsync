# Contract: Encrypted Wallet File Format, version 2

Extends [001 file-format.md](../../001-vault-core/contracts/file-format.md). Rationale:
[research.md](../research.md) R2–R6. All integers little-endian.

## Header

Identical to version 1 (63 bytes, same fields, ranges and AAD use) except
`format_version = 2`. **No wallet id, state vector or any other sync metadata is stored in
plaintext** (R2). Total size ≥ 79 bytes and ≤ 64 MiB.

## Payload (plaintext, postcard-encoded, AES-256-GCM with header as AAD)

```text
PayloadV2 { wallet_id: [u8;16], created_at: i64,
            state: Vec<(String, u64)>          /* sorted, unique, 0..=256, counters ≥ 1 */,
            password_epoch: Vec<(String, u64)> /* sorted, unique, may be empty */,
            entries: Vec<EntryV2> }
EntryV2   { id: [u8;16], created_at: i64, current: Version,
            conflicts: Vec<Version> /* 0..=15 */ }
Version   { modified_at: i64, last_modified_by: String,
            version: Vec<(String, u64)> /* 001 rules */, state: EntryState /* 001 */ }
```

Decoding additionally rejects (→ `InvalidPasswordOrCorrupted`): state vector > 256
devices, unsorted/duplicate/zero; > 15 conflicts; two versions of one entry with equal
content hash; a version strictly dominated by another version of the same entry; versions not in
canonical order; any entry version component greater than `state`; all 001 payload rules.

## Parse order

As version 1; step 3 becomes: `format_version ∉ {1, 2}` → `UnsupportedVersion(v)`. Step 6
decodes the v1 or v2 payload according to the version.

## Reading version 1

Each v1 entry → `EntryV2{current: Version from the v1 fields, conflicts: []}`;
`password_epoch = []`; `state[d] = Σ_entries version[d]` (exact count of d's changes). Writers always
write version 2; a v1 file is rewritten on its next save (and at unlock when networking is on
with ≥ 1 paired peer, research R3).

## Versioning rules

Unchanged from v1: any further change needs a new version; readers reject unknown versions.
