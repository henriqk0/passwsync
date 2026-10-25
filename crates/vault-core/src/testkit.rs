//! Behavior suite every [`VaultStorage`] adapter must pass. Enabled by the `testkit` feature.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{MemoryStorage, StorageError, VaultStorage};

/// In-memory storage whose `store` fails on demand (loads keep working). Lets hosts prove
/// that a failed save leaves both memory and the stored bytes unchanged.
#[derive(Default)]
pub struct FailingStorage {
    inner: MemoryStorage,
    failing: Arc<AtomicBool>,
}

impl FailingStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps a shared switch, so a test keeps control after the storage is moved away.
    pub fn with_switch(failing: Arc<AtomicBool>) -> Self {
        Self {
            inner: MemoryStorage::new(),
            failing,
        }
    }

    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    pub fn switch(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.failing)
    }
}

impl VaultStorage for FailingStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        self.inner.load()
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected save failure",
            )));
        }
        self.inner.store(bytes)
    }
}

/// Runs the shared storage behavior suite. `make` returns a fresh, empty storage.
pub fn storage_contract<S: VaultStorage>(make: impl Fn() -> S) {
    load_before_store_is_not_found(make());
    store_then_load_is_identical(make());
    second_store_replaces_first(make());
    empty_and_large_payloads_round_trip(make());
}

fn load_before_store_is_not_found<S: VaultStorage>(storage: S) {
    assert!(matches!(storage.load(), Err(StorageError::NotFound)));
}

fn store_then_load_is_identical<S: VaultStorage>(mut storage: S) {
    let bytes: Vec<u8> = (0..=255).collect();
    storage.store(&bytes).unwrap();
    assert_eq!(storage.load().unwrap(), bytes);
}

fn second_store_replaces_first<S: VaultStorage>(mut storage: S) {
    storage.store(b"first, and longer").unwrap();
    storage.store(b"second").unwrap();
    assert_eq!(storage.load().unwrap(), b"second");
}

fn empty_and_large_payloads_round_trip<S: VaultStorage>(mut storage: S) {
    storage.store(&[]).unwrap();
    assert!(storage.load().unwrap().is_empty());
    let large = vec![0xA5u8; 1024 * 1024];
    storage.store(&large).unwrap();
    assert_eq!(storage.load().unwrap(), large);
}

/// Encrypts arbitrary payload bytes under `password` as a wallet file of format `version`
/// (fresh salt and nonce). Lets tests craft authenticated files that a writer never
/// produces, valid or not.
pub fn seal_payload(
    password: &str,
    kdf: crate::KdfConfig,
    version: u16,
    plaintext: &[u8],
) -> Vec<u8> {
    let salt = crate::kdf::random_salt().expect("random salt");
    let key = crate::kdf::derive_key(
        &crate::MasterPassword::new(password.to_string()),
        &kdf,
        &salt,
    )
    .expect("key derivation");
    crate::format::seal_plaintext(
        &key,
        version,
        kdf,
        &salt,
        zeroize::Zeroizing::new(plaintext.to_vec()),
    )
    .expect("seal")
}

/// A second in-memory holder of the same wallet: same key, entries and state, another
/// device id and a fixed clock at `now`. No key derivation (fast property tests).
pub fn fork(vault: &crate::Vault, device: &str, now: crate::Timestamp) -> crate::Vault {
    crate::Vault {
        wallet_id: vault.wallet_id,
        created_at: vault.created_at,
        kdf: vault.kdf,
        salt: vault.salt,
        key: crate::VaultKey::from_bytes(*vault.key.as_bytes()),
        entries: vault.entries.iter().map(crate::Entry::duplicate).collect(),
        state: vault.state.clone(),
        password_epoch: vault.password_epoch.clone(),
        format_loaded: vault.format_loaded,
        device: crate::DeviceId::new(device).expect("device id"),
        clock: Box::new(crate::FixedClock::new(now)),
    }
}

/// The vault as a received copy would open, without encrypting it.
pub fn copy_of(vault: &crate::Vault) -> crate::OpenedCopy {
    crate::OpenedCopy {
        wallet_id: vault.wallet_id,
        created_at: vault.created_at,
        state: vault.state.clone(),
        password_epoch: vault.password_epoch.clone(),
        entries: vault.entries.iter().map(crate::Entry::duplicate).collect(),
        kdf: vault.kdf,
        salt: vault.salt,
        key: crate::VaultKey::from_bytes(*vault.key.as_bytes()),
    }
}

/// A copy of `vault` whose state claims `counter` changes by `device` (entries unchanged).
pub fn with_state_counter(vault: &crate::Vault, device: &str, counter: u64) -> crate::OpenedCopy {
    let mut copy = copy_of(vault);
    let device = crate::DeviceId::new(device).expect("device id");
    let mut pairs: Vec<(crate::DeviceId, u64)> =
        copy.state.iter().map(|(d, c)| (d.clone(), c)).collect();
    match pairs.iter_mut().find(|(d, _)| *d == device) {
        Some(slot) => slot.1 = counter,
        None => {
            pairs.push((device, counter));
            pairs.sort();
        }
    }
    copy.state = crate::StateVector::from_pairs(pairs).expect("state");
    copy
}
