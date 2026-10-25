//! 004 T069: resolving a conflict (FR-016, FR-017, research R5).

mod support;

use support::PASSWORD;
use vault_core::testkit::{FailingStorage, copy_of, fork};
use vault_core::{
    DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, Resolution, Vault,
    VaultError, VaultStorage, VersionOrdering,
};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn f(title: &str) -> EntryFields {
    let mut fields = EntryFields::default();
    fields.title = title.into();
    fields
}

/// `on_a` holds a conflict on the returned entry: "from a" (t=300) and "from b" (t=400,
/// current).
fn conflicted() -> (Vault, Vault, EntryId) {
    let mut base = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        d("a"),
        Box::new(FixedClock::new(100)),
    )
    .unwrap();
    let id = base.add_entry(f("shared")).unwrap();
    let mut a = fork(&base, "a", 300);
    let mut b = fork(&base, "b", 400);
    a.update_entry(id, f("from a")).unwrap();
    b.update_entry(id, f("from b")).unwrap();
    let mut on_a = fork(&a, "a", 500);
    on_a.merge(copy_of(&b)).unwrap();
    let mut on_b = fork(&b, "b", 500);
    on_b.merge(copy_of(&a)).unwrap();
    (on_a, on_b, id)
}

fn title(v: &Vault, id: EntryId) -> Option<String> {
    v.get(id).and_then(|e| e.fields().map(|x| x.title.clone()))
}

#[test]
fn keep_one_version_dominates_all_and_counts_as_a_change() {
    let (mut v, _, id) = conflicted();
    let versions: Vec<_> = v
        .versions(id)
        .unwrap()
        .iter()
        .map(|x| x.version().clone())
        .collect();
    let before = v.state().clone();
    let created = v.resolve(id, Resolution::Keep(1)).unwrap();
    assert!(created.is_empty());
    let entry = v.get(id).unwrap();
    assert!(!entry.is_conflicted());
    assert_eq!(entry.fields().unwrap().title, "from a");
    assert_eq!(entry.last_modified_by(), &d("a"));
    assert_eq!(entry.modified_at(), 500);
    for old in &versions {
        assert_eq!(entry.version().compare(old), VersionOrdering::Newer);
    }
    assert_eq!(v.state().get(&d("a")), before.get(&d("a")) + 1);
}

#[test]
fn keep_both_creates_a_new_entry_for_each_other_live_version() {
    let (mut v, _, id) = conflicted();
    let created = v.resolve(id, Resolution::KeepBoth).unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(title(&v, id).unwrap(), "from b");
    assert_eq!(title(&v, created[0]).unwrap(), "from a");
    assert!(v.conflicted().is_empty());
    assert_eq!(v.get(created[0]).unwrap().version().get(&d("a")), 1);
}

#[test]
fn a_tombstone_version_can_be_kept_or_resolved_away() {
    let mut base = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        d("a"),
        Box::new(FixedClock::new(100)),
    )
    .unwrap();
    let id = base.add_entry(f("shared")).unwrap();
    let mut a = fork(&base, "a", 300);
    let mut b = fork(&base, "b", 400);
    a.update_entry(id, f("edited")).unwrap();
    b.delete_entry(id).unwrap();
    let mut v = fork(&a, "a", 500);
    v.merge(copy_of(&b)).unwrap();
    let mut keep_delete = fork(&v, "a", 600);
    keep_delete.resolve(id, Resolution::Keep(1)).unwrap();
    assert!(
        keep_delete.get(id).is_none(),
        "deleted after keeping the tombstone"
    );
    let mut keep_both = fork(&v, "a", 600);
    assert!(
        keep_both
            .resolve(id, Resolution::KeepBoth)
            .unwrap()
            .is_empty()
    );
    assert_eq!(title(&keep_both, id).unwrap(), "edited");
}

#[test]
fn errors_change_nothing() {
    let (mut v, _, id) = conflicted();
    let plain = v.add_entry(f("plain")).unwrap();
    assert!(matches!(
        v.resolve(plain, Resolution::Keep(0)),
        Err(VaultError::NotConflicted)
    ));
    assert!(matches!(
        v.resolve(id, Resolution::Keep(2)),
        Err(VaultError::InvalidVersionIndex)
    ));
    assert!(matches!(
        v.resolve(EntryId::from_bytes([9; 16]), Resolution::Keep(0)),
        Err(VaultError::EntryNotFound)
    ));
    assert_eq!(v.versions(id).unwrap().len(), 2);
}

#[test]
fn a_resolution_propagates_and_clears_the_conflict_on_the_peer() {
    let (mut on_a, mut on_b, id) = conflicted();
    on_a.resolve(id, Resolution::Keep(1)).unwrap();
    let report = on_b.merge(copy_of(&on_a)).unwrap();
    assert_eq!(report.conflicts_cleared, 1);
    assert_eq!(title(&on_b, id).unwrap(), "from a");
    assert_eq!(on_b.versions(id).unwrap().len(), 1);
}

#[test]
fn different_resolutions_on_two_devices_produce_a_new_conflict() {
    let (mut on_a, mut on_b, id) = conflicted();
    on_a.resolve(id, Resolution::Keep(0)).unwrap();
    on_b.resolve(id, Resolution::Keep(1)).unwrap();
    on_a.merge(copy_of(&on_b)).unwrap();
    assert!(
        on_a.get(id).unwrap().is_conflicted(),
        "neither result is lost"
    );
}

#[test]
fn resolve_saved_rolls_back_on_storage_failure() {
    let (mut v, _, id) = conflicted();
    let mut storage = FailingStorage::new();
    v.save(&mut storage).unwrap();
    let saved = storage.load().unwrap();
    storage.set_failing(true);
    let state = v.state().clone();
    assert!(
        v.resolve_saved(id, Resolution::KeepBoth, &mut storage)
            .is_err()
    );
    assert_eq!(v.versions(id).unwrap().len(), 2);
    assert_eq!(v.state(), &state);
    assert_eq!(v.all_records().count(), 1);
    assert_eq!(storage.load().unwrap(), saved);
    storage.set_failing(false);
    let created = v
        .resolve_saved(id, Resolution::KeepBoth, &mut storage)
        .unwrap();
    assert_eq!(created.len(), 1);
}
