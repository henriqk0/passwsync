# Contract: `vault-core` public library API

This is the interface contract consumed by later features (service, Android, sync). Signatures
are normative in shape; minor naming adjustments during TDD are allowed if this document is
updated in the same change. No implementation bodies are given here.

Operating-model constraints on this API: fully offline (no networking in either crate);
no account, email, login, or identity types; the master password is the only secret and is
consumed by `create`/`unlock`/`open`/`change_master_password`; the derived key is internal,
memory-only, and never exposed, serialized, or persisted.

## Crate `vault-core`

### Secrets and identifiers

```rust
pub struct MasterPassword(/* Zeroizing<String> */);
impl MasterPassword {
    /// NFC-normalizes; never fails (length is checked where policy applies).
    pub fn new(s: String) -> Self;          // takes ownership; caller's buffer is moved, not copied
}
// Debug prints "MasterPassword([REDACTED])". No Display, no Clone, no Serialize.

pub struct WalletId([u8; 16]);   // Copy, Eq, Ord, Hash, Display (hex)
pub struct EntryId([u8; 16]);    // Copy, Eq, Ord, Hash, Display (hex), FromStr (hex)
pub struct DeviceId(String);     // Clone, Eq, Ord; DeviceId::new(s) -> Result<_, VaultError>
pub type Timestamp = i64;        // Unix seconds, UTC
```

### Clock port

```rust
pub trait Clock: Send + Sync { fn now(&self) -> Timestamp; }
pub struct SystemClock;                 // std::time::SystemTime
pub struct FixedClock(/* AtomicI64 */); // tests: new(t), set(t), advance(secs)
```

### Entries

```rust
pub struct EntryFields { pub title: String, pub username: String, pub password: String,
                         pub url: String, pub notes: String }
// ZeroizeOnDrop; Debug redacts password and notes; Default.

pub struct Entry { /* private */ }
impl Entry {
    pub fn id(&self) -> EntryId;
    pub fn created_at(&self) -> Timestamp;
    pub fn modified_at(&self) -> Timestamp;
    pub fn last_modified_by(&self) -> &DeviceId;
    pub fn version(&self) -> &VersionVector;
    pub fn fields(&self) -> Option<&EntryFields>;   // None for tombstones
    pub fn deleted_at(&self) -> Option<Timestamp>;  // Some for tombstones
    pub fn is_deleted(&self) -> bool;
}

pub struct VersionVector { /* BTreeMap<DeviceId, u64> */ }
impl VersionVector {
    pub fn get(&self, device: &DeviceId) -> u64;    // 0 if absent
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)>;
    pub fn compare(&self, other: &VersionVector) -> VersionOrdering;
}
pub enum VersionOrdering { Equal, Newer, Older, Concurrent }
```

### KDF configuration

```rust
pub struct KdfConfig { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 }
impl KdfConfig {
    pub const DEFAULT: KdfConfig;   // 65_536 KiB, 12, 1  (tuned for SC-003)
    pub const MINIMUM: KdfConfig;   // 19_456 KiB, 2, 1   (used by tests)
}
```

### Vault (unlocked wallet)

```rust
pub struct Vault { /* private: id, created_at, kdf, key, entries, device, clock */ }

impl Vault {
    pub fn create(password: MasterPassword, kdf: KdfConfig, device: DeviceId,
                  clock: Box<dyn Clock>) -> Result<Vault, VaultError>;
    pub fn unlock(bytes: &[u8], password: MasterPassword, device: DeviceId,
                  clock: Box<dyn Clock>) -> Result<Vault, VaultError>;
    pub fn open(storage: &dyn VaultStorage, password: MasterPassword, device: DeviceId,
                clock: Box<dyn Clock>) -> Result<Vault, VaultError>;   // load + unlock

    pub fn seal(&self) -> Result<Vec<u8>, VaultError>;            // fresh nonce each call
    pub fn save(&self, storage: &mut dyn VaultStorage) -> Result<(), VaultError>;
    pub fn lock(self);                                             // consumes; zeroizes all
    pub fn change_master_password(&mut self, new: MasterPassword) -> Result<(), VaultError>;

    pub fn wallet_id(&self) -> WalletId;
    pub fn created_at(&self) -> Timestamp;
    pub fn kdf_config(&self) -> KdfConfig;

    pub fn add_entry(&mut self, fields: EntryFields) -> Result<EntryId, VaultError>;
    pub fn update_entry(&mut self, id: EntryId, fields: EntryFields) -> Result<(), VaultError>;
    pub fn delete_entry(&mut self, id: EntryId) -> Result<(), VaultError>;

    pub fn get(&self, id: EntryId) -> Option<&Entry>;              // live entries only
    pub fn list(&self) -> Vec<&Entry>;                             // live, sorted by title (ci), then id
    pub fn search(&self, query: &str) -> Vec<&Entry>;              // ci substring: title/username/url/notes
    pub fn all_records(&self) -> impl Iterator<Item = &Entry>;     // live + tombstones, for sync
}
// Vault implements Drop (zeroizes key and entries) and a redacting Debug.
```

Behavioral rules:

- `update_entry` replaces all five fields at once (whole-value replacement avoids in-place
  growth reallocations that could leave secret copies).
- `add_entry`/`update_entry` validate title non-empty (after trim) and each field ≤ 1 MiB.
- Every successful mutation sets `modified_at = clock.now()`, `last_modified_by = device`,
  `version[device] += 1` (creation sets `version = {device: 1}`).
- Mutations on unknown ids or tombstones return `EntryNotFound` and change nothing.
- `change_master_password` checks the 12-character minimum, generates a new salt, keeps the
  current `KdfConfig`, derives the new key, and wipes the old one. The stored file changes only
  on the next `save`.
- `unlock`/`open` need only the wallet bytes and its master password; the `device` argument
  is an opaque change-tracking tag, so a wallet from another device opens identically
  (FR-005b). After unlock, `save` never asks for the password again (FR-005a).
- Auto-lock: the host application enforces timeouts by calling `lock` (or dropping the
  `Vault`); the core has no timer.
- A locked wallet is represented only by bytes; there is no "locked `Vault`" value, so
  operations on a locked wallet are unrepresentable.

### Errors

```rust
pub enum VaultError {
    // validation
    PasswordTooShort, EmptyTitle, FieldTooLarge, InvalidDeviceId, EntryNotFound,
    // unlock / format (see file-format.md parse order)
    MalformedFile, UnsupportedVersion(u16), UnsupportedKdf, KdfParamsOutOfRange,
    InvalidPasswordOrCorrupted,
    // infrastructure
    WalletTooLarge, Storage(StorageError), Rng,
}
```

`Display` messages are fixed strings; no variant carries secret or plaintext data.

## Storage port (in `vault-core`)

```rust
pub trait VaultStorage {
    /// Returns the complete encrypted wallet bytes.
    fn load(&self) -> Result<Vec<u8>, StorageError>;
    /// Atomically replaces the stored bytes. Receives only ciphertext.
    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError>;
}

pub enum StorageError { NotFound, Io(std::io::Error) }

pub struct MemoryStorage { /* Option<Vec<u8>> */ }   // new(), Default; load before store → NotFound
```

An adapter instance is bound to one wallet location (file path for the file adapter).

### Contract test kit (feature `testkit`)

```rust
pub mod testkit {
    /// Runs the shared storage behavior suite; `make` returns a fresh, empty storage.
    pub fn storage_contract<S: VaultStorage>(make: impl Fn() -> S);
}
```

Cases: load-before-store → `NotFound`; store then load returns identical bytes; second store
replaces first; empty and 1 MiB payloads round-trip.

## Crate `vault-storage-file`

```rust
pub struct FileStorage { /* path */ }
impl FileStorage { pub fn new(path: impl Into<PathBuf>) -> Self; }
impl VaultStorage for FileStorage { /* atomic temp-file + fsync + rename; 0600 on Unix */ }
```

Additional file-adapter guarantees (tested in this crate): interrupted store (temp written,
rename not performed) leaves the old file intact; temp files are removed on error; created file
mode is `0600` on Unix; missing parent directory → `Io`, missing file → `NotFound`.
