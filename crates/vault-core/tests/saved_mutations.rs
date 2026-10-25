//! Save-or-rollback mutations (feature 002, contracts/vault-core-additions.md).

use vault_core::testkit::FailingStorage;
use vault_core::{StorageError, VaultStorage};

#[test]
fn failing_storage_stores_and_loads_like_memory_storage_when_not_failing() {
    let mut storage = FailingStorage::new();
    assert!(matches!(storage.load(), Err(StorageError::NotFound)));
    storage.store(b"one").unwrap();
    assert_eq!(storage.load().unwrap(), b"one");
}

#[test]
fn failing_storage_fails_store_on_demand_and_keeps_old_bytes() {
    let mut storage = FailingStorage::new();
    storage.store(b"old").unwrap();
    storage.set_failing(true);
    assert!(matches!(storage.store(b"new"), Err(StorageError::Io(_))));
    assert_eq!(storage.load().unwrap(), b"old");
    storage.set_failing(false);
    storage.store(b"new").unwrap();
    assert_eq!(storage.load().unwrap(), b"new");
}

#[test]
fn failing_storage_switch_is_shared() {
    let mut storage = FailingStorage::new();
    let switch = storage.switch();
    switch.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(storage.store(b"x").is_err());
}

mod saved {
    use std::sync::Arc;

    use vault_core::testkit::FailingStorage;
    use vault_core::{
        Clock, DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword,
        MemoryStorage, Timestamp, Vault, VaultError, VaultStorage, VersionVector,
    };

    const PASSWORD: &str = "correct horse battery";

    struct SharedClock(Arc<FixedClock>);

    impl Clock for SharedClock {
        fn now(&self) -> Timestamp {
            self.0.now()
        }
    }

    type Snapshot = (
        EntryId,
        Timestamp,
        Timestamp,
        DeviceId,
        VersionVector,
        Option<(String, String, String, String, String)>,
        Option<Timestamp>,
    );

    fn snapshot(vault: &Vault) -> Vec<Snapshot> {
        vault
            .all_records()
            .map(|e| {
                (
                    e.id(),
                    e.created_at(),
                    e.modified_at(),
                    e.last_modified_by().clone(),
                    e.version().clone(),
                    e.fields().map(|f| {
                        (
                            f.title.clone(),
                            f.username.clone(),
                            f.password.clone(),
                            f.url.clone(),
                            f.notes.clone(),
                        )
                    }),
                    e.deleted_at(),
                )
            })
            .collect()
    }

    fn setup() -> (Vault, Arc<FixedClock>) {
        let time = Arc::new(FixedClock::new(1_000));
        let vault = Vault::create(
            MasterPassword::new(PASSWORD.into()),
            KdfConfig::MINIMUM,
            DeviceId::new("laptop").unwrap(),
            Box::new(SharedClock(time.clone())),
        )
        .unwrap();
        (vault, time)
    }

    fn fields(title: &str, password: &str) -> EntryFields {
        EntryFields {
            title: title.into(),
            username: "me".into(),
            password: password.into(),
            url: "https://example.com".into(),
            notes: "n".into(),
        }
    }

    fn reopen(storage: &dyn VaultStorage) -> Vault {
        Vault::open(
            storage,
            MasterPassword::new(PASSWORD.into()),
            DeviceId::new("laptop").unwrap(),
            Box::new(FixedClock::new(0)),
        )
        .unwrap()
    }

    #[test]
    fn add_saved_equals_add_then_save() {
        let (mut vault, _) = setup();
        let mut storage = MemoryStorage::new();
        let id = vault
            .add_entry_saved(fields("GitHub", "pw1"), &mut storage)
            .unwrap();
        assert_eq!(vault.get(id).unwrap().fields().unwrap().title, "GitHub");
        assert_eq!(snapshot(&reopen(&storage)), snapshot(&vault));
    }

    #[test]
    fn update_saved_equals_update_then_save() {
        let (mut vault, time) = setup();
        let mut storage = MemoryStorage::new();
        let id = vault
            .add_entry_saved(fields("GitHub", "pw1"), &mut storage)
            .unwrap();
        time.advance(10);
        vault
            .update_entry_saved(id, fields("GitHub2", "pw2"), &mut storage)
            .unwrap();
        let entry = vault.get(id).unwrap();
        assert_eq!(entry.fields().unwrap().title, "GitHub2");
        assert_eq!(entry.modified_at(), 1_010);
        assert_eq!(snapshot(&reopen(&storage)), snapshot(&vault));
    }

    #[test]
    fn delete_saved_equals_delete_then_save() {
        let (mut vault, _) = setup();
        let mut storage = MemoryStorage::new();
        let id = vault
            .add_entry_saved(fields("GitHub", "pw1"), &mut storage)
            .unwrap();
        vault.delete_entry_saved(id, &mut storage).unwrap();
        assert!(vault.get(id).is_none());
        assert_eq!(vault.all_records().count(), 1, "tombstone kept for sync");
        assert_eq!(snapshot(&reopen(&storage)), snapshot(&vault));
    }

    #[test]
    fn validation_errors_change_nothing_and_do_not_save() {
        let (mut vault, _) = setup();
        let mut storage = MemoryStorage::new();
        let id = vault
            .add_entry_saved(fields("GitHub", "pw1"), &mut storage)
            .unwrap();
        let saved = storage.load().unwrap();
        let before = snapshot(&vault);
        assert!(matches!(
            vault.add_entry_saved(fields(" ", "x"), &mut storage),
            Err(VaultError::EmptyTitle)
        ));
        assert!(matches!(
            vault.update_entry_saved(id, fields("", "x"), &mut storage),
            Err(VaultError::EmptyTitle)
        ));
        let missing = EntryId::from_bytes([9; 16]);
        assert!(matches!(
            vault.update_entry_saved(missing, fields("t", "x"), &mut storage),
            Err(VaultError::EntryNotFound)
        ));
        assert!(matches!(
            vault.delete_entry_saved(missing, &mut storage),
            Err(VaultError::EntryNotFound)
        ));
        assert_eq!(snapshot(&vault), before);
        assert_eq!(storage.load().unwrap(), saved);
    }

    fn with_one_entry() -> (Vault, Arc<FixedClock>, FailingStorage, EntryId) {
        let (mut vault, time) = setup();
        let mut storage = FailingStorage::new();
        let id = vault
            .add_entry_saved(fields("GitHub", "pw1"), &mut storage)
            .unwrap();
        time.advance(60);
        storage.set_failing(true);
        (vault, time, storage, id)
    }

    #[test]
    fn failed_save_of_add_restores_everything_without_tombstone() {
        let (mut vault, _, mut storage, _) = with_one_entry();
        let before = snapshot(&vault);
        let saved = storage.load().unwrap();
        let result = vault.add_entry_saved(fields("GitLab", "pw2"), &mut storage);
        assert!(matches!(result, Err(VaultError::Storage(_))));
        assert_eq!(snapshot(&vault), before);
        assert_eq!(storage.load().unwrap(), saved);
    }

    #[test]
    fn failed_save_of_update_restores_the_exact_record() {
        let (mut vault, _, mut storage, id) = with_one_entry();
        let before = snapshot(&vault);
        let result = vault.update_entry_saved(id, fields("Changed", "pw2"), &mut storage);
        assert!(matches!(result, Err(VaultError::Storage(_))));
        assert_eq!(snapshot(&vault), before);
    }

    #[test]
    fn failed_save_of_delete_restores_the_live_record() {
        let (mut vault, _, mut storage, id) = with_one_entry();
        let before = snapshot(&vault);
        let result = vault.delete_entry_saved(id, &mut storage);
        assert!(matches!(result, Err(VaultError::Storage(_))));
        assert_eq!(snapshot(&vault), before);
        assert!(vault.get(id).is_some());
    }

    #[test]
    fn record_order_is_preserved_after_a_failed_update() {
        let (mut vault, _, mut storage, id) = with_one_entry();
        storage.set_failing(false);
        vault
            .add_entry_saved(fields("Second", "p"), &mut storage)
            .unwrap();
        storage.set_failing(true);
        let before = snapshot(&vault);
        let _ = vault.update_entry_saved(id, fields("Changed", "pw2"), &mut storage);
        let _ = vault.delete_entry_saved(id, &mut storage);
        assert_eq!(snapshot(&vault), before);
    }

    // --- 004 T015: saved mutations bump the state and roll it back on failure ---

    #[test]
    fn saved_mutations_bump_the_state_once_each() {
        let (mut vault, _, mut storage, id) = with_one_entry();
        storage.set_failing(false);
        let me = DeviceId::new("laptop").unwrap();
        assert_eq!(vault.state().get(&me), 1);
        vault
            .update_entry_saved(id, fields("Changed", "pw2"), &mut storage)
            .unwrap();
        assert_eq!(vault.state().get(&me), 2);
        vault.delete_entry_saved(id, &mut storage).unwrap();
        assert_eq!(vault.state().get(&me), 3);
        assert_eq!(reopen(&storage).state(), vault.state());
    }

    #[test]
    fn failed_saves_restore_the_state() {
        let (mut vault, _, mut storage, id) = with_one_entry();
        let before = vault.state().clone();
        assert!(
            vault
                .add_entry_saved(fields("x", "p"), &mut storage)
                .is_err()
        );
        assert!(
            vault
                .update_entry_saved(id, fields("y", "p"), &mut storage)
                .is_err()
        );
        assert!(vault.delete_entry_saved(id, &mut storage).is_err());
        assert_eq!(vault.state(), &before);
    }

    // --- 004 T026: a saved merge rolls back on storage failure ---

    #[test]
    fn failed_save_of_a_merge_leaves_the_vault_exactly_as_before() {
        let (mut vault, time, mut storage, id) = with_one_entry();
        storage.set_failing(false);
        let mut other = vault_core::testkit::fork(&vault, "phone", 5_000);
        other.update_entry(id, fields("From phone", "pw9")).unwrap();
        other.add_entry(fields("New on phone", "p")).unwrap();
        time.advance(1);
        storage.set_failing(true);
        let before = snapshot(&vault);
        let state = vault.state().clone();
        let saved = storage.load().unwrap();
        let result = vault.merge_saved(vault_core::testkit::copy_of(&other), &mut storage);
        assert!(matches!(result, Err(vault_core::MergeError::Save(_))));
        assert_eq!(snapshot(&vault), before);
        assert_eq!(vault.state(), &state);
        assert_eq!(storage.load().unwrap(), saved);
        // Once storage works the same merge applies and is saved.
        storage.set_failing(false);
        let report = vault
            .merge_saved(vault_core::testkit::copy_of(&other), &mut storage)
            .unwrap();
        assert!(report.changed);
        assert_eq!(reopen(&storage).state(), vault.state());
        assert_eq!(vault.get(id).unwrap().fields().unwrap().title, "From phone");
    }

    #[test]
    fn a_merged_copy_is_consumed() {
        // The copy is moved into the merge and dropped (zeroized) whatever the outcome.
        let (mut vault, _, mut storage, _) = with_one_entry();
        storage.set_failing(false);
        let copy = vault_core::testkit::copy_of(&vault);
        let report = vault.merge_saved(copy, &mut storage).unwrap();
        assert!(!report.changed);
    }
}
