//! Behavior suite every [`VaultStorage`] adapter must pass. Enabled by the `testkit` feature.

use crate::{StorageError, VaultStorage};

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
