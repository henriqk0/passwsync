# Contract: additive API for sync (vault-core, wallet-service, device-link)

Additive only; existing signatures and behaviour from 001–003 are unchanged unless stated.
The 001 `vault-core-api.md` and 002 `vault-core-additions.md` contracts MUST be updated in the
change that implements these items. Rationale: [research.md](../research.md) R1, R3–R6, R12, R13.

## vault-core

```rust
pub struct StateVector(/* sorted DeviceId -> u64 */);
impl StateVector {
    pub fn get(&self, d: &DeviceId) -> u64;
    pub fn dominates(&self, other: &Self) -> bool;        // self ≥ other component-wise
    pub fn join(&self, other: &Self) -> Self;
    pub fn compare(&self, other: &Self) -> VersionOrdering;
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)>;
}

pub struct SaveMeta<'a> { pub wallet_id: WalletId, pub state: &'a StateVector }

pub trait VaultStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError>;
    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError>;
    /// NEW, default = `self.store(bytes)`. `Vault::save` calls this.
    fn store_versioned(&mut self, bytes: &[u8], meta: &SaveMeta<'_>) -> Result<(), StorageError> {
        self.store(bytes)
    }
}

impl Vault {
    pub fn state(&self) -> &StateVector;
    pub fn format_version_loaded(&self) -> u16;                 // 1 or 2
    pub fn conflicted(&self) -> Vec<&Entry>;
    pub fn versions(&self, id: EntryId) -> Option<&[Version]>; // [current, conflicts…]

    /// Opens a copy encrypted with this vault's current KDF config and salt (no KDF run).
    pub fn open_copy_own_key(&self, bytes: &[u8]) -> Result<OpenedCopy, VaultError>;
    /// Opens a copy with a password (runs Argon2id once); password wiped on return.
    pub fn open_copy_with_password(bytes: &[u8], password: MasterPassword)
        -> Result<OpenedCopy, VaultError>;
    pub fn needs_password(&self, bytes: &[u8]) -> Result<bool, VaultError>; // header differs

    /// Deterministic join (research R5, R6). On error nothing changes.
    pub fn merge(&mut self, copy: OpenedCopy) -> Result<MergeReport, MergeError>;
    /// Concurrent password epochs: merge keeping `keep`'s key, epoch = join + increment(me).
    pub fn merge_choosing_password(&mut self, copy: OpenedCopy, keep: PasswordChoice)
        -> Result<MergeReport, MergeError>;

    pub fn resolve(&mut self, id: EntryId, how: Resolution) -> Result<Vec<EntryId>, VaultError>;
    pub fn resolve_saved(&mut self, id: EntryId, how: Resolution,
                         storage: &mut dyn VaultStorage) -> Result<Vec<EntryId>, VaultError>;
}

impl OpenedCopy { pub fn wallet_id(&self) -> WalletId; pub fn state(&self) -> &StateVector; }
```

Rules: `merge` and `resolve_saved` follow the 002 save-or-rollback rule (on save failure the
vault is exactly as before). `OpenedCopy` holds key material in zeroizing storage, has no
`Clone`/`Serialize`, and its `Debug` shows only the wallet id and state. Errors are generic for
authentication (`InvalidPasswordOrCorrupted`).

## wallet-service

```rust
pub trait PendingCopies: Send + Sync {            // port, implemented in passwsyncd
    fn list(&self, wallet: &WalletName) -> Vec<PendingRef>;  // peer, claimed state, size
    fn load(&self, wallet: &WalletName, peer: &PeerRef) -> Result<Vec<u8>, StorageError>;
    fn outcome(&self, wallet: &WalletName, peer: &PeerRef, outcome: PendingOutcome);
}

impl Service {
    /// Unchanged signature; after a successful unlock merges pending copies (one at a time,
    /// password-derived keys under the KDF lock), saves once, then wipes the password.
    pub fn unlock(&self, name: &WalletName, password: MasterPassword) -> Result<UnlockOutcome, ServiceError>;
    /// Background: never touches the idle timer. Locked → Err(Locked) (caller keeps pending).
    pub fn merge_copy(&self, name: &WalletName, bytes: &[u8], check: &dyn Fn(&CopyFacts) -> CopyVerdict)
        -> Result<MergeReport, ServiceError>;
    pub fn open_pending_with_password(&self, name: &WalletName, peer: &PeerRef, password: MasterPassword)
        -> Result<MergeReport, ServiceError>;
    pub fn resolve_conflict(&self, name: &WalletName, id: EntryId, how: Resolution) -> Result<Vec<EntryId>, ServiceError>;
    pub fn sync_facts(&self, name: &WalletName) -> Option<(WalletId, StateVector)>; // unlocked only
}
```

`CopyFacts` = authenticated `{wallet_id, state, password_epoch_relation}`; the sync layer's
`check` enforces requested id, claimed state, peer mark and jump bound before the merge.

## device-link / device-link-net

```rust
pub enum HelloVersion { V1, V2 }
impl Channel { pub fn session_hash(&self) -> [u8; 32]; pub fn sync_enabled(&self) -> bool;
               pub fn seal_sync(&mut self, p: &Payload) -> Result<Vec<u8>, ChannelError>; }
pub trait SyncFrameSink: Send + Sync {             // device-link-net
    fn channel_up(&self, peer: DeviceId, conn: u64, session: [u8; 32], dialer: bool);
    fn frame(&self, peer: DeviceId, conn: u64, payload: Payload);   // SyncCtl / CopyData
    fn channel_down(&self, peer: DeviceId, conn: u64);
}
impl Node { pub fn send_sync(&self, peer: &DeviceId, conn: u64, payload: &Payload) -> Result<(), SendError>; }
```

`send_sync` holds the channel mutex across seal and write and updates the keepalive clock.
