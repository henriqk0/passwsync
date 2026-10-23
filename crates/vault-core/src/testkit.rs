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
