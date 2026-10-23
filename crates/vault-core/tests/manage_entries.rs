use std::sync::Arc;

use vault_core::{
    Clock, DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, MemoryStorage,
    Timestamp, Vault, VaultError,
};

const PASSWORD: &str = "correct horse battery";

/// Lets a test keep control of the time after the vault takes ownership of its clock.
struct SharedClock(Arc<FixedClock>);

impl Clock for SharedClock {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

fn pw() -> MasterPassword {
    MasterPassword::new(PASSWORD.to_string())
}

fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn setup() -> (Vault, Arc<FixedClock>) {
    let time = Arc::new(FixedClock::new(1_000));
    let vault = Vault::create(
        pw(),
        KdfConfig::MINIMUM,
        device("laptop"),
        Box::new(SharedClock(time.clone())),
    )
    .unwrap();
    (vault, time)
}

fn fields(title: &str, username: &str, password: &str, url: &str, notes: &str) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: username.into(),
        password: password.into(),
        url: url.into(),
        notes: notes.into(),
    }
}

fn titled(title: &str) -> EntryFields {
    fields(title, "", "", "", "")
}

fn titles(entries: Vec<&vault_core::Entry>) -> Vec<String> {
    entries
        .iter()
        .map(|e| e.fields().unwrap().title.clone())
        .collect()
}

#[test]
fn update_replaces_fields_and_advances_metadata() {
    let (mut vault, time) = setup();
    let id = vault
        .add_entry(fields("Old", "u", "old-pw", "", ""))
        .unwrap();
    time.advance(60);
    vault
        .update_entry(id, fields("New", "u2", "new-pw", "https://x", "n"))
        .unwrap();

    let entry = vault.get(id).unwrap();
    assert_eq!(
        entry.fields(),
        Some(&fields("New", "u2", "new-pw", "https://x", "n"))
    );
    assert_eq!(entry.id(), id);
    assert_eq!(entry.created_at(), 1_000);
    assert_eq!(entry.modified_at(), 1_060);
    assert_eq!(entry.last_modified_by(), &device("laptop"));
    assert_eq!(entry.version().get(&device("laptop")), 2);
}

#[test]
fn delete_leaves_a_tombstone_and_hides_the_entry() {
    let (mut vault, time) = setup();
    let id = vault
        .add_entry(fields("Gone", "user", "pw", "", ""))
        .unwrap();
    time.advance(30);
    vault.delete_entry(id).unwrap();

    assert!(vault.get(id).is_none());
    assert!(vault.list().is_empty());
    assert!(vault.search("gone").is_empty());
    let record = vault.all_records().find(|e| e.id() == id).unwrap();
    assert!(record.is_deleted());
    assert_eq!(record.deleted_at(), Some(1_030));
    assert!(record.fields().is_none());
    assert_eq!(record.modified_at(), 1_030);
    assert_eq!(record.version().get(&device("laptop")), 2);
}

#[test]
fn unknown_or_deleted_ids_are_not_found_and_change_nothing() {
    let (mut vault, _) = setup();
    let id = vault.add_entry(titled("Keep")).unwrap();
    vault.delete_entry(id).unwrap();
    let unknown = EntryId::generate().unwrap();

    for target in [id, unknown] {
        assert!(matches!(
            vault.update_entry(target, titled("x")),
            Err(VaultError::EntryNotFound)
        ));
        assert!(matches!(
            vault.delete_entry(target),
            Err(VaultError::EntryNotFound)
        ));
    }
    let record = vault.all_records().find(|e| e.id() == id).unwrap();
    assert_eq!(
        record.version().get(&device("laptop")),
        2,
        "tombstone untouched"
    );
    assert_eq!(vault.all_records().count(), 1);
}

#[test]
fn invalid_update_changes_nothing() {
    let (mut vault, _) = setup();
    let id = vault.add_entry(titled("Valid")).unwrap();
    assert!(matches!(
        vault.update_entry(id, titled(" ")),
        Err(VaultError::EmptyTitle)
    ));
    let entry = vault.get(id).unwrap();
    assert_eq!(entry.fields().unwrap().title, "Valid");
    assert_eq!(entry.version().get(&device("laptop")), 1);
}

#[test]
fn list_is_sorted_case_insensitively_and_keeps_duplicates() {
    let (mut vault, _) = setup();
    for title in ["GitHub", "gitlab", "Bank", "Bank"] {
        vault.add_entry(titled(title)).unwrap();
    }
    assert_eq!(titles(vault.list()), ["Bank", "Bank", "GitHub", "gitlab"]);
}

#[test]
fn search_matches_title_username_url_and_notes() {
    let (mut vault, _) = setup();
    vault.add_entry(titled("GitHub")).unwrap();
    vault.add_entry(titled("gitlab")).unwrap();
    vault.add_entry(titled("Bank")).unwrap();
    vault
        .add_entry(fields("Mail", "git-user", "", "", ""))
        .unwrap();
    vault
        .add_entry(fields("Site", "", "", "https://GIT.example", ""))
        .unwrap();
    vault
        .add_entry(fields("Memo", "", "", "", "see Git docs"))
        .unwrap();

    assert_eq!(
        titles(vault.search("git")),
        ["GitHub", "gitlab", "Mail", "Memo", "Site"]
    );
    assert_eq!(titles(vault.search("GITLAB")), ["gitlab"]);
    assert!(vault.search("nothing-matches-this").is_empty());
}

#[test]
fn search_never_matches_the_password() {
    let (mut vault, _) = setup();
    vault
        .add_entry(fields("Bank", "", "hunter2-secret", "", ""))
        .unwrap();
    assert!(vault.search("hunter2").is_empty());
}

#[test]
fn search_is_unicode_case_insensitive() {
    let (mut vault, _) = setup();
    vault.add_entry(titled("école")).unwrap();
    assert_eq!(titles(vault.search("ÉCOLE")), ["école"]);
}

#[test]
fn empty_query_equals_list() {
    let (mut vault, _) = setup();
    for title in ["b", "a", "c"] {
        vault.add_entry(titled(title)).unwrap();
    }
    assert_eq!(titles(vault.search("")), titles(vault.list()));
}

#[test]
fn edits_and_tombstones_survive_save_and_open() {
    let (mut vault, time) = setup();
    let edited = vault.add_entry(fields("Before", "", "pw", "", "")).unwrap();
    let deleted = vault.add_entry(titled("Doomed")).unwrap();
    time.advance(10);
    vault
        .update_entry(edited, fields("After", "", "pw2", "", ""))
        .unwrap();
    vault.delete_entry(deleted).unwrap();

    let mut storage = MemoryStorage::new();
    vault.save(&mut storage).unwrap();
    let opened = Vault::open(
        &storage,
        pw(),
        device("laptop"),
        Box::new(FixedClock::new(0)),
    )
    .unwrap();

    assert_eq!(opened.get(edited).unwrap().fields().unwrap().title, "After");
    assert_eq!(
        opened.get(edited).unwrap().version().get(&device("laptop")),
        2
    );
    assert!(opened.get(deleted).is_none());
    let tombstone = opened.all_records().find(|e| e.id() == deleted).unwrap();
    assert_eq!(tombstone.deleted_at(), Some(1_010));
    assert_eq!(opened.all_records().count(), 2);
}
