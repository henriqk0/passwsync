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
