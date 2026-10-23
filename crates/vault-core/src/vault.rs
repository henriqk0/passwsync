use std::fmt;

use zeroize::Zeroizing;

use crate::format::{self, PayloadRef};
use crate::kdf::{derive_key, random_salt};
use crate::{
    Clock, DeviceId, Entry, EntryFields, EntryId, KdfConfig, MasterPassword, Timestamp, VaultError,
    VaultKey, VaultStorage, WalletId,
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
    wallet_id: WalletId,
    created_at: Timestamp,
    kdf: KdfConfig,
    salt: [u8; 32],
    key: VaultKey,
    entries: Vec<Entry>,
    device: DeviceId,
    clock: Box<dyn Clock>,
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

    /// Encrypts the wallet with a fresh nonce. Needs no password: the key is already held.
    pub fn seal(&self) -> Result<Vec<u8>, VaultError> {
        let payload = PayloadRef {
            wallet_id: self.wallet_id,
            created_at: self.created_at,
            entries: &self.entries,
        };
        format::seal(&self.key, self.kdf, &self.salt, &payload)
    }

    pub fn save(&self, storage: &mut dyn VaultStorage) -> Result<(), VaultError> {
        Ok(storage.store(&self.seal()?)?)
    }

    /// Wipes the key and every entry from memory.
    pub fn lock(self) {}

    /// New salt and key, same cost parameters. The file changes on the next `save`.
    pub fn change_master_password(&mut self, new: MasterPassword) -> Result<(), VaultError> {
        check_password_length(&new)?;
        let salt = random_salt()?;
        let key = derive_key(&new, &self.kdf, &salt)?;
        drop(new);
        self.salt = salt;
        self.key = key;
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

    pub fn add_entry(&mut self, fields: EntryFields) -> Result<EntryId, VaultError> {
        let entry = Entry::new_live(fields, &self.device, self.clock.now())?;
        let id = entry.id();
        self.entries.push(entry);
        Ok(id)
    }

    pub fn update_entry(&mut self, id: EntryId, fields: EntryFields) -> Result<(), VaultError> {
        let now = self.clock.now();
        let entry = Self::live_entry_mut(&mut self.entries, id)?;
        entry.replace_fields(fields, &self.device, now)
    }

    /// Leaves a tombstone so a later sync can pass the deletion on.
    pub fn delete_entry(&mut self, id: EntryId) -> Result<(), VaultError> {
        let now = self.clock.now();
        Self::live_entry_mut(&mut self.entries, id)?.mark_deleted(&self.device, now);
        Ok(())
    }

    fn live_entry_mut(entries: &mut [Entry], id: EntryId) -> Result<&mut Entry, VaultError> {
        entries
            .iter_mut()
            .find(|entry| entry.id() == id && !entry.is_deleted())
            .ok_or(VaultError::EntryNotFound)
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
