use std::fmt;

use zeroize::Zeroizing;

use crate::entry::EntryState;
use crate::format::{self, PayloadRef};
use crate::kdf::{derive_key, random_salt};
use crate::{
    Clock, DeviceId, Entry, EntryFields, EntryId, KdfConfig, MasterPassword, StateVector,
    Timestamp, VaultError, VaultKey, VaultStorage, VersionVector, WalletId,
};

const MIN_PASSWORD_CHARS: usize = 12;

fn check_password_length(password: &MasterPassword) -> Result<(), VaultError> {
    if password.char_count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::PasswordTooShort);
    }
    Ok(())
}

/// An unlocked wallet. The key lives in memory only and is wiped when the vault is dropped.
/// A locked wallet is just bytes, so operating on one cannot be expressed.
pub struct Vault {
    pub(crate) wallet_id: WalletId,
    pub(crate) created_at: Timestamp,
    pub(crate) kdf: KdfConfig,
    pub(crate) salt: [u8; 32],
    pub(crate) key: VaultKey,
    pub(crate) entries: Vec<Entry>,
    /// 004: one change counter per device (encrypted payload only, research R2, R4).
    pub(crate) state: StateVector,
    /// 004: password-change epoch (FR-022), empty until the first change.
    pub(crate) password_epoch: VersionVector,
    /// Format version of the bytes this vault was opened from (1 or 2); 2 for new wallets.
    pub(crate) format_loaded: u16,
    pub(crate) device: DeviceId,
    pub(crate) clock: Box<dyn Clock>,
}

impl Vault {
    pub fn create(
        password: MasterPassword,
        kdf: KdfConfig,
        device: DeviceId,
        clock: Box<dyn Clock>,
    ) -> Result<Self, VaultError> {
        kdf.validate()?;
        check_password_length(&password)?;
        let salt = random_salt()?;
        let key = derive_key(&password, &kdf, &salt)?;
        drop(password);
        Ok(Self {
            wallet_id: WalletId::generate()?,
            created_at: clock.now(),
            kdf,
            salt,
            key,
            entries: Vec::new(),
            state: StateVector::new(),
            password_epoch: VersionVector::empty(),
            format_loaded: format::FORMAT_VERSION,
            device,
            clock,
        })
    }

    /// Opens wallet bytes with the wallet's master password alone. `device` is only a
    /// change-tracking tag, so a wallet created on another device opens identically.
    pub fn unlock(
        bytes: &[u8],
        password: MasterPassword,
        device: DeviceId,
        clock: Box<dyn Clock>,
    ) -> Result<Self, VaultError> {
        let (header, key, payload) = format::open(bytes, &password)?;
        drop(password);
        Ok(Self {
            wallet_id: payload.wallet_id,
            created_at: payload.created_at,
            kdf: header.kdf,
            salt: header.salt,
            key,
            entries: payload.entries,
            state: payload.state,
            password_epoch: payload.password_epoch,
            format_loaded: payload.format,
            device,
            clock,
        })
    }

    /// Loads the wallet from `storage` and unlocks it.
    pub fn open(
        storage: &dyn VaultStorage,
        password: MasterPassword,
        device: DeviceId,
        clock: Box<dyn Clock>,
    ) -> Result<Self, VaultError> {
        let bytes = storage.load()?;
        Self::unlock(&bytes, password, device, clock)
    }

    /// Encrypts the wallet (always format version 2) with a fresh nonce. Needs no password:
    /// the key is already held.
    pub fn seal(&self) -> Result<Vec<u8>, VaultError> {
        let payload = PayloadRef {
            wallet_id: self.wallet_id,
            created_at: self.created_at,
            state: &self.state,
            password_epoch: &self.password_epoch,
            entries: &self.entries,
        };
        format::seal(&self.key, self.kdf, &self.salt, &payload)
    }

    /// Seals and stores through [`VaultStorage::store_versioned`] with the wallet id and the
    /// state of the bytes being written (004, research R12).
    pub fn save(&self, storage: &mut dyn VaultStorage) -> Result<(), VaultError> {
        let bytes = self.seal()?;
        let meta = crate::SaveMeta {
            wallet_id: self.wallet_id,
            state: &self.state,
        };
        Ok(storage.store_versioned(&bytes, &meta)?)
    }

    /// Wipes the key and every entry from memory.
    pub fn lock(self) {}

    /// New salt and key, same cost parameters. The file changes on the next `save`. Counts
    /// as a change and moves the password-change epoch (FR-022).
    pub fn change_master_password(&mut self, new: MasterPassword) -> Result<(), VaultError> {
        check_password_length(&new)?;
        let state = self.bumped_state()?;
        let salt = random_salt()?;
        let key = derive_key(&new, &self.kdf, &salt)?;
        drop(new);
        self.salt = salt;
        self.key = key;
        self.state = state;
        self.password_epoch.increment(&self.device);
        Ok(())
    }

    /// [`change_master_password`](Self::change_master_password) then save; on a save
    /// failure the previous key, salt, state and epoch are put back.
    pub fn change_master_password_saved(
        &mut self,
        new: MasterPassword,
        storage: &mut dyn VaultStorage,
    ) -> Result<(), VaultError> {
        check_password_length(&new)?;
        let state = self.bumped_state()?;
        let salt = random_salt()?;
        let key = derive_key(&new, &self.kdf, &salt)?;
        drop(new);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        let old_key = std::mem::replace(&mut self.key, key);
        let old_state = std::mem::replace(&mut self.state, state);
        let old_epoch = self.password_epoch.clone();
        self.password_epoch.increment(&self.device);
        if let Err(error) = self.save(storage) {
            self.salt = old_salt;
            self.key = old_key;
            self.state = old_state;
            self.password_epoch = old_epoch;
            return Err(error);
        }
        Ok(())
    }

    pub fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    pub fn kdf_config(&self) -> KdfConfig {
        self.kdf
    }

    /// The wallet state vector (004): every change this copy contains.
    pub fn state(&self) -> &StateVector {
        &self.state
    }

    /// The password-change epoch (FR-022).
    pub fn password_epoch(&self) -> &VersionVector {
        &self.password_epoch
    }

    /// 1 if this vault was read from a version 1 file (rewritten as 2 on the next save).
    pub fn format_version_loaded(&self) -> u16 {
        self.format_loaded
    }

    /// The device this vault records changes for.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// `state` with this device's counter moved by one (the vault is not changed).
    pub(crate) fn bumped_state(&self) -> Result<StateVector, VaultError> {
        let mut state = self.state.clone();
        state.bump(&self.device)?;
        Ok(state)
    }

    pub fn add_entry(&mut self, fields: EntryFields) -> Result<EntryId, VaultError> {
        let entry = Entry::new_live(fields, &self.device, self.clock.now())?;
        let state = self.bumped_state()?;
        let id = entry.id();
        self.entries.push(entry);
        self.state = state;
        Ok(id)
    }

    pub fn update_entry(&mut self, id: EntryId, fields: EntryFields) -> Result<(), VaultError> {
        let now = self.clock.now();
        let state = self.bumped_state()?;
        let entry = Self::live_entry_mut(&mut self.entries, id)?;
        entry.replace_fields(fields, &self.device, now)?;
        self.state = state;
        Ok(())
    }

    /// Leaves a tombstone so a later sync can pass the deletion on.
    pub fn delete_entry(&mut self, id: EntryId) -> Result<(), VaultError> {
        let now = self.clock.now();
        let state = self.bumped_state()?;
        Self::live_entry_mut(&mut self.entries, id)?.mark_deleted(&self.device, now);
        self.state = state;
        Ok(())
    }

    /// Adds an entry and saves; if the save fails the entry is removed again (no tombstone)
    /// and the storage error is returned.
    pub fn add_entry_saved(
        &mut self,
        fields: EntryFields,
        storage: &mut dyn VaultStorage,
    ) -> Result<EntryId, VaultError> {
        let entry = Entry::new_live(fields, &self.device, self.clock.now())?;
        let state = self.bumped_state()?;
        let id = entry.id();
        self.entries.push(entry);
        let previous = std::mem::replace(&mut self.state, state);
        if let Err(error) = self.save(storage) {
            self.entries.pop();
            self.state = previous;
            return Err(error);
        }
        Ok(id)
    }

    /// Replaces an entry's fields and saves; if the save fails the previous record (fields,
    /// timestamps, device, version vector) is put back exactly.
    pub fn update_entry_saved(
        &mut self,
        id: EntryId,
        fields: EntryFields,
        storage: &mut dyn VaultStorage,
    ) -> Result<(), VaultError> {
        fields.validate()?;
        self.replace_saved(id, EntryState::Live(fields), storage)
    }

    /// Deletes an entry (tombstone) and saves; if the save fails the live record is put back
    /// exactly.
    pub fn delete_entry_saved(
        &mut self,
        id: EntryId,
        storage: &mut dyn VaultStorage,
    ) -> Result<(), VaultError> {
        let now = self.clock.now();
        self.replace_saved(id, EntryState::Deleted { deleted_at: now }, storage)
    }

    /// Swaps the live record `id` for its successor in `state`, saves, and swaps the old
    /// record back on failure. The old record is moved aside, never copied; whichever record
    /// is dropped wipes its fields.
    fn replace_saved(
        &mut self,
        id: EntryId,
        state: EntryState,
        storage: &mut dyn VaultStorage,
    ) -> Result<(), VaultError> {
        let now = self.clock.now();
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id() == id && !entry.is_deleted())
            .ok_or(VaultError::EntryNotFound)?;
        if self.entries[index].is_conflicted() {
            return Err(VaultError::EntryConflicted);
        }
        let wallet_state = self.bumped_state()?;
        let next = self.entries[index].successor(state, &self.device, now);
        let previous = std::mem::replace(&mut self.entries[index], next);
        let previous_state = std::mem::replace(&mut self.state, wallet_state);
        if let Err(error) = self.save(storage) {
            self.entries[index] = previous;
            self.state = previous_state;
            return Err(error);
        }
        Ok(())
    }

    /// A live entry that may be edited: conflicted entries must be resolved first, so an
    /// edit never silently supersedes a concurrent version (FR-014, FR-016).
    fn live_entry_mut(entries: &mut [Entry], id: EntryId) -> Result<&mut Entry, VaultError> {
        let entry = entries
            .iter_mut()
            .find(|entry| entry.id() == id && !entry.is_deleted())
            .ok_or(VaultError::EntryNotFound)?;
        if entry.is_conflicted() {
            return Err(VaultError::EntryConflicted);
        }
        Ok(entry)
    }

    /// Live entries sorted by title (case-insensitive), then id.
    pub fn list(&self) -> Vec<&Entry> {
        let mut live: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| !entry.is_deleted())
            .collect();
        live.sort_by_cached_key(|entry| {
            (entry.fields().map(|f| f.title.to_lowercase()), entry.id())
        });
        live
    }

    /// Case-insensitive substring match over title, username, URL and notes (never the
    /// password). An empty query lists everything.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query = Zeroizing::new(query.to_lowercase());
        let matches = |text: &str| Zeroizing::new(text.to_lowercase()).contains(query.as_str());
        let mut found = self.list();
        found.retain(|entry| {
            entry.fields().is_some_and(|f| {
                [&f.title, &f.username, &f.url, &f.notes]
                    .into_iter()
                    .any(|text| matches(text))
            })
        });
        found
    }

    /// Live entries and tombstones, for sync.
    pub fn all_records(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Live entries only.
    pub fn get(&self, id: EntryId) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.id() == id && !entry.is_deleted())
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("wallet_id", &self.wallet_id)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedClock;

    // Compiles only if `T` does NOT implement `serde::Serialize` (ambiguity trick).
    macro_rules! assert_not_serialize {
        ($t:ty) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + serde::Serialize> AmbiguousIfImpl<u8> for T {}
            let _ = <$t as AmbiguousIfImpl<_>>::check;
        }};
    }

    #[test]
    fn key_and_vault_are_not_serializable() {
        assert_not_serialize!(Vault);
        assert_not_serialize!(crate::VaultKey);
    }

    #[test]
    fn key_and_password_never_appear_in_sealed_bytes() {
        let password_text = "a-very-distinctive-master-password";
        let vault = Vault::create(
            MasterPassword::new(password_text.to_string()),
            KdfConfig::MINIMUM,
            DeviceId::new("laptop").unwrap(),
            Box::new(FixedClock::new(0)),
        )
        .unwrap();
        let sealed = vault.seal().unwrap();
        assert!(!contains(&sealed, vault.key.as_bytes()));
        assert!(!contains(&sealed, password_text.as_bytes()));

        let unlocked = Vault::unlock(
            &sealed,
            MasterPassword::new(password_text.to_string()),
            DeviceId::new("phone").unwrap(),
            Box::new(FixedClock::new(0)),
        )
        .unwrap();
        let resealed = unlocked.seal().unwrap();
        assert!(!contains(&resealed, unlocked.key.as_bytes()));
        assert!(!contains(&resealed, password_text.as_bytes()));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
