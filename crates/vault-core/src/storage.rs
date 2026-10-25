use crate::{StateVector, StorageError, WalletId};

/// What a save is writing, for adapters that journal saves (004, research R12): the
/// wallet id and state vector of the (encrypted) bytes, which they cannot decrypt.
#[derive(Clone, Copy, Debug)]
pub struct SaveMeta<'a> {
    pub wallet_id: WalletId,
    pub state: &'a StateVector,
}

/// Port to wherever the encrypted wallet bytes live. Receives only ciphertext.
pub trait VaultStorage {
    /// Returns the complete encrypted wallet bytes.
    fn load(&self) -> Result<Vec<u8>, StorageError>;
    /// Atomically replaces the stored bytes.
    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError>;
    /// Called by [`Vault::save`](crate::Vault::save). Default: [`store`](Self::store), so
    /// 001 adapters work unchanged.
    fn store_versioned(&mut self, bytes: &[u8], meta: &SaveMeta<'_>) -> Result<(), StorageError> {
        let _ = meta;
        self.store(bytes)
    }
}

/// In-memory fake of the storage port.
#[derive(Default)]
pub struct MemoryStorage(Option<Vec<u8>>);

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VaultStorage for MemoryStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        self.0.clone().ok_or(StorageError::NotFound)
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_before_store_is_not_found() {
        assert!(matches!(
            MemoryStorage::new().load(),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn store_then_load_returns_same_bytes() {
        let mut storage = MemoryStorage::new();
        storage.store(b"abc").unwrap();
        assert_eq!(storage.load().unwrap(), b"abc");
    }

    #[test]
    fn second_store_replaces_first() {
        let mut storage = MemoryStorage::new();
        storage.store(b"first").unwrap();
        storage.store(b"second").unwrap();
        assert_eq!(storage.load().unwrap(), b"second");
    }
}
