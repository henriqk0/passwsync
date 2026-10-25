use vault_core::MemoryStorage;
use vault_core::testkit::storage_contract;

#[test]
fn memory_storage_satisfies_the_contract() {
    storage_contract(MemoryStorage::new);
}

// --- 004 T016: `store_versioned` (research R12) ---

use std::sync::{Arc, Mutex};

use vault_core::{
    DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, SaveMeta, StateVector,
    StorageError, Vault, VaultStorage, WalletId,
};

/// A 001-style adapter: implements only `load` and `store`.
#[derive(Default)]
struct PlainAdapter(Option<Vec<u8>>);

impl VaultStorage for PlainAdapter {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        self.0.clone().ok_or(StorageError::NotFound)
    }
    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
}

/// Records the metadata of every versioned store.
#[derive(Default)]
struct Recording {
    bytes: Option<Vec<u8>>,
    seen: Arc<Mutex<Vec<(WalletId, StateVector)>>>,
}

impl VaultStorage for Recording {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        self.bytes.clone().ok_or(StorageError::NotFound)
    }
    fn store(&mut self, _: &[u8]) -> Result<(), StorageError> {
        panic!("Vault::save must call store_versioned");
    }
    fn store_versioned(&mut self, bytes: &[u8], meta: &SaveMeta<'_>) -> Result<(), StorageError> {
        self.seen
            .lock()
            .unwrap()
            .push((meta.wallet_id, meta.state.clone()));
        self.bytes = Some(bytes.to_vec());
        Ok(())
    }
}

fn vault() -> Vault {
    Vault::create(
        MasterPassword::new("correct horse battery".into()),
        KdfConfig::MINIMUM,
        DeviceId::new("laptop").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap()
}

#[test]
fn default_store_versioned_delegates_to_store() {
    let mut adapter = PlainAdapter::default();
    let state = StateVector::new();
    let meta = SaveMeta {
        wallet_id: WalletId::from_bytes([1; 16]),
        state: &state,
    };
    adapter.store_versioned(b"abc", &meta).unwrap();
    assert_eq!(adapter.load().unwrap(), b"abc");
    // And a 001 adapter still saves a vault.
    let v = vault();
    v.save(&mut adapter).unwrap();
    assert!(adapter.load().unwrap().len() > 79);
}

#[test]
fn save_passes_wallet_id_and_state_of_the_written_bytes() {
    let mut storage = Recording::default();
    let seen = Arc::clone(&storage.seen);
    let mut v = vault();
    v.add_entry_saved(
        {
            let mut f = EntryFields::default();
            f.title = "x".into();
            f
        },
        &mut storage,
    )
    .unwrap();
    let recorded = seen.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, v.wallet_id());
    assert_eq!(&recorded[0].1, v.state());
    assert_eq!(recorded[0].1.get(&DeviceId::new("laptop").unwrap()), 1);
}
