# Contract: additive changes to `vault-core` (from feature 002)

Additive only; no existing signature or behavior from
[`specs/001-vault-core/contracts/vault-core-api.md`](../../001-vault-core/contracts/vault-core-api.md)
changes. That contract MUST be updated in the same change that implements these items.
Rationale: [research.md](../research.md) R4, R16.

## Header inspection without a password

```rust
/// Parses only the authenticated-later header fields needed to budget memory before
/// unlocking. Runs the same parse steps as `unlock` up to KDF parameter validation
/// (length bounds, magic, version, kdf_id, KDF ranges) and returns the KDF parameters.
/// Never touches the password, key, or ciphertext; values are untrusted until `unlock`
/// authenticates the header as AAD.
pub fn peek_kdf_config(bytes: &[u8]) -> Result<KdfConfig, VaultError>;
// Errors: MalformedFile, UnsupportedVersion(_), UnsupportedKdf, KdfParamsOutOfRange,
//         WalletTooLarge — identical to what `unlock` would return for the same bytes.
```

Used by the service to refuse wallets whose KDF memory exceeds its locked-memory budget
(131 072 KiB) before running Argon2.

## Save-or-rollback mutations

```rust
impl Vault {
    pub fn add_entry_saved(&mut self, fields: EntryFields, storage: &mut dyn VaultStorage)
        -> Result<EntryId, VaultError>;
    pub fn update_entry_saved(&mut self, id: EntryId, fields: EntryFields,
                              storage: &mut dyn VaultStorage) -> Result<(), VaultError>;
    pub fn delete_entry_saved(&mut self, id: EntryId, storage: &mut dyn VaultStorage)
        -> Result<(), VaultError>;
}
```

Behavioral rules:

- Validation errors are returned before anything changes (as the unsaved variants).
- On success the vault equals the result of the unsaved variant followed by `save`.
- If `save` fails, the affected record is restored exactly (fields, timestamps,
  `last_modified_by`, version vector; for add the new id is removed entirely, leaving no
  tombstone) and the storage error is returned. The temporary copy of the previous record is
  zeroized on drop.
- Contract tests: a failing `VaultStorage` fake (`testkit::FailingStorage`) proves the vault
  compares equal (via `all_records`) before and after a failed mutation for each of the three
  operations.

## Additions from feature 004 (wallet sync)

- `merge_saved`, `merge_choosing_password_saved`, `resolve_saved` and
  `change_master_password_saved` follow the same save-or-rollback rule: on a save failure the
  vault is exactly as before.
- `wallet-service` adds `merge_copy`, `sync_facts`, `conflict_count`, `conflicts`,
  `conflict_versions`, `conflict_field`, `resolve_conflict`, `change_password`,
  `open_pending_with_password`, `choose_password`, the `PendingCopies` port
  (`list`, `load`, `check`, `outcome`, `unlocked`, `upgraded`) with `Service::set_pending_copies`;
  `unlock` merges pending copies before returning (one save). `EntrySummary` gains
  `conflicted`. New `ServiceError` codes: `entry_conflicted`, `cannot_open_copy`,
  `invalid_copy`, `too_many_conflicts`, `password_conflict`, `not_conflicted`,
  `invalid_version`. Merges and copy key derivations are serialized with the KDF gate and
  never touch the idle timer.
