//! 004 T020: example-based merge rules (research R5, FR-013 to FR-017).

mod support;

use support::*;
use vault_core::testkit::{copy_of, fork};
use vault_core::{
    DeviceId, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, MergeError, Vault,
};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn f(title: &str) -> EntryFields {
    let mut fields = EntryFields::default();
    fields.title = title.into();
    fields.password = format!("{title}-pw");
    fields
}

fn base() -> (Vault, EntryId) {
    let mut v = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        d("a"),
        Box::new(FixedClock::new(100)),
    )
    .unwrap();
    let id = v.add_entry(f("shared")).unwrap();
    (v, id)
}

fn title_of(v: &Vault, id: EntryId) -> Option<String> {
    v.all_records()
        .find(|e| e.id() == id)
        .and_then(|e| e.fields().map(|x| x.title.clone()))
}

fn versions_of(v: &Vault, id: EntryId) -> usize {
    v.versions(id).map_or(0, <[_]>::len)
}

#[test]
fn equal_copies_change_nothing() {
    let (a, id) = base();
    let mut b = fork(&a, "b", 100);
    let report = b.merge(copy_of(&a)).unwrap();
    assert!(!report.changed);
    assert_eq!(report.conflicts_added, 0);
    assert!(!report.merge_change);
    assert_eq!(title_of(&b, id).unwrap(), "shared");
    assert_eq!(b.state(), a.state());
}

#[test]
fn newer_version_wins_and_older_is_ignored() {
    let (a, id) = base();
    let mut b = fork(&a, "b", 200);
    b.update_entry(id, f("edited on b")).unwrap();
    let mut a2 = fork(&a, "a", 200);
    let report = a2.merge(copy_of(&b)).unwrap();
    assert!(report.changed);
    assert_eq!(report.conflicts_added, 0);
    assert_eq!(title_of(&a2, id).unwrap(), "edited on b");
    assert_eq!(versions_of(&a2, id), 1);
    assert_eq!(a2.state(), b.state());
    // The older copy changes nothing on b.
    let report = b.merge(copy_of(&a)).unwrap();
    assert!(!report.changed);
    assert_eq!(title_of(&b, id).unwrap(), "edited on b");
}

#[test]
fn concurrent_edits_keep_both_with_a_deterministic_current() {
    let (a0, id) = base();
    let mut a = fork(&a0, "a", 300);
    let mut b = fork(&a0, "b", 400);
    a.update_entry(id, f("from a")).unwrap();
    b.update_entry(id, f("from b")).unwrap();
    let mut on_a = fork(&a, "a", 500);
    let mut on_b = fork(&b, "b", 500);
    let ra = on_a.merge(copy_of(&b)).unwrap();
    let rb = on_b.merge(copy_of(&a)).unwrap();
    assert_eq!(ra.conflicts_added, 1);
    assert_eq!(rb.conflicts_added, 1);
    for v in [&on_a, &on_b] {
        let entry = v.all_records().find(|e| e.id() == id).unwrap();
        assert!(entry.is_conflicted());
        // Later modification first: b edited at 400.
        assert_eq!(entry.fields().unwrap().title, "from b");
        assert_eq!(entry.conflicts()[0].fields().unwrap().title, "from a");
    }
    assert_eq!(on_a.state(), on_b.state());
    assert!(on_a.conflicted().iter().any(|e| e.id() == id));
}

#[test]
fn edit_versus_delete_keeps_the_live_version_current() {
    let (a0, id) = base();
    let mut a = fork(&a0, "a", 300);
    let mut b = fork(&a0, "b", 900);
    a.update_entry(id, f("still here")).unwrap();
    b.delete_entry(id).unwrap(); // later, but a tombstone
    let mut on_b = fork(&b, "b", 1000);
    on_b.merge(copy_of(&a)).unwrap();
    let entry = on_b.all_records().find(|e| e.id() == id).unwrap();
    assert!(entry.is_conflicted());
    assert!(!entry.is_deleted(), "live precedes tombstone");
    assert_eq!(entry.fields().unwrap().title, "still here");
    assert!(entry.conflicts()[0].is_deleted());
    assert!(on_b.get(id).is_some(), "never silently deleted");
}

#[test]
fn a_tombstone_beats_an_older_live_version() {
    let (a0, id) = base();
    let mut b = fork(&a0, "b", 300);
    b.delete_entry(id).unwrap();
    let mut a = fork(&a0, "a", 300);
    a.merge(copy_of(&b)).unwrap();
    assert!(a.get(id).is_none());
    assert_eq!(versions_of(&a, id), 1);
    let entry = a.all_records().find(|e| e.id() == id).unwrap();
    assert!(entry.is_deleted());
}

#[test]
fn entries_on_one_side_only_are_taken() {
    let (a0, _) = base();
    let mut a = fork(&a0, "a", 300);
    let mut b = fork(&a0, "b", 300);
    let only_a = a.add_entry(f("only a")).unwrap();
    let only_b = b.add_entry(f("only b")).unwrap();
    a.merge(copy_of(&b)).unwrap();
    assert_eq!(title_of(&a, only_a).unwrap(), "only a");
    assert_eq!(title_of(&a, only_b).unwrap(), "only b");
    assert_eq!(a.state().get(&d("a")), 2);
    assert_eq!(a.state().get(&d("b")), 1);
}

#[test]
fn equal_vectors_with_different_content_are_kept_and_force_a_merge_change() {
    // Counter reuse (R5): the same entry vector on both sides with different content.
    let (a0, id) = base();
    let mut x = fork(&a0, "a", 300);
    let mut y = fork(&a0, "a", 300); // same device id: an undetected restore
    x.update_entry(id, f("x")).unwrap();
    y.update_entry(id, f("y")).unwrap();
    assert_eq!(x.state(), y.state());
    let before = x.state().clone();
    let report = x.merge(copy_of(&y)).unwrap();
    assert_eq!(versions_of(&x, id), 2, "both kept");
    assert!(report.merge_change);
    assert!(
        x.state().dominates(&before) && x.state() != &before,
        "merging device bumped"
    );
}

#[test]
fn wallet_mismatch_changes_nothing() {
    let (a, _) = base();
    let (other, _) = base();
    let mut b = fork(&a, "b", 1);
    let before = b.state().clone();
    assert!(matches!(
        b.merge(copy_of(&other)),
        Err(MergeError::WalletMismatch)
    ));
    assert_eq!(b.state(), &before);
}

#[test]
fn more_than_16_versions_fail_without_change() {
    let (a0, id) = base();
    let mut merged = fork(&a0, "x", 1);
    let mut devices = Vec::new();
    for i in 0..17 {
        let mut v = fork(&a0, &format!("d{i:02}"), 10 + i);
        v.update_entry(id, f(&format!("v{i}"))).unwrap();
        devices.push(v);
    }
    for v in &devices[..16] {
        merged.merge(copy_of(v)).unwrap();
    }
    assert_eq!(versions_of(&merged, id), 16);
    let before = merged.state().clone();
    assert!(matches!(
        merged.merge(copy_of(&devices[16])),
        Err(MergeError::TooManyConflicts)
    ));
    assert_eq!(merged.state(), &before);
    assert_eq!(versions_of(&merged, id), 16);
}

#[test]
fn a_jump_beyond_2_pow_32_is_refused() {
    let (a0, _) = base();
    let mut b = fork(&a0, "b", 1);
    let big = vault_core::testkit::with_state_counter(&a0, "a", (1u64 << 32) + 2);
    assert!(matches!(b.merge(big), Err(MergeError::JumpTooLarge)));
    let ok = vault_core::testkit::with_state_counter(&a0, "a", (1u64 << 32) + 1);
    assert!(b.merge(ok).is_ok(), "exactly local + 2^32 is accepted");
}

#[test]
fn a_join_beyond_256_devices_is_refused() {
    let (a0, _) = base();
    let mut left = fork(&a0, "x", 1);
    let mut right = fork(&a0, "y", 1);
    for i in 0..128 {
        let mut l = fork(&left, &format!("l{i:03}"), 1);
        l.add_entry(f("l")).unwrap();
        left = l;
        let mut r = fork(&right, &format!("r{i:03}"), 1);
        r.add_entry(f("r")).unwrap();
        right = r;
    }
    assert_eq!(left.state().len(), 129); // "a" + 128
    let before = left.state().clone();
    assert!(matches!(
        left.merge(copy_of(&right)),
        Err(MergeError::TooManyDevices)
    ));
    assert_eq!(left.state(), &before);
}

#[test]
fn self_rollback_is_reported_when_a_copy_knows_more_of_my_changes() {
    let (a0, id) = base();
    let mut later = fork(&a0, "a", 200);
    later.update_entry(id, f("lost on restore")).unwrap();
    let mut restored = fork(&a0, "a", 300);
    let report = restored.merge(copy_of(&later)).unwrap();
    assert!(report.self_rollback_recovered);
    assert_eq!(title_of(&restored, id).unwrap(), "lost on restore");
}
