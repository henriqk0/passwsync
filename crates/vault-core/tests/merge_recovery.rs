//! 004 T100: recovering after a whole-installation restore (research R10).

mod support;

use support::PASSWORD;
use vault_core::testkit::{copy_of, fork};
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

fn d(n: &str) -> DeviceId {
    DeviceId::new(n).unwrap()
}

fn f(t: &str) -> EntryFields {
    let mut x = EntryFields::default();
    x.title = t.into();
    x
}

fn base() -> Vault {
    let mut v = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        d("me"),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    v.add_entry(f("one")).unwrap();
    v
}

#[test]
fn a_peer_holding_my_lost_changes_brings_them_back_and_my_counter_moves_past_them() {
    let backup = base();
    // Before the restore this device made more changes, which reached the peer.
    let mut before_restore = fork(&backup, "me", 10);
    for i in 0..3 {
        before_restore.add_entry(f(&format!("lost {i}"))).unwrap();
    }
    let peer = fork(&before_restore, "peer", 20);
    // The installation is restored: the device is back at the backup.
    let mut restored = fork(&backup, "me", 30);
    let report = restored.merge(copy_of(&peer)).unwrap();
    assert!(report.self_rollback_recovered);
    assert_eq!(restored.all_records().count(), 4, "lost changes recovered");
    assert_eq!(restored.state().get(&d("me")), peer.state().get(&d("me")));
    restored.add_entry(f("after recovery")).unwrap();
    assert!(
        restored.state().get(&d("me")) > peer.state().get(&d("me")),
        "counter moves past"
    );
    // The peer takes the new change without conflict.
    let mut peer2 = fork(&peer, "peer", 40);
    let r = peer2.merge(copy_of(&restored)).unwrap();
    assert_eq!(r.conflicts_added, 0);
    assert_eq!(peer2.all_records().count(), 5);
}

#[test]
fn counter_reuse_never_silently_drops_a_version() {
    let backup = base();
    let id = backup.list()[0].id();
    let mut before_restore = fork(&backup, "me", 10);
    before_restore
        .update_entry(id, f("edit before restore"))
        .unwrap();
    let peer = fork(&before_restore, "peer", 20);
    let mut restored = fork(&backup, "me", 30);
    // The same counter is used again for different content.
    restored.update_entry(id, f("edit after restore")).unwrap();
    assert_eq!(
        restored.get(id).unwrap().version(),
        peer.get(id).unwrap().version()
    );
    let report = restored.merge(copy_of(&peer)).unwrap();
    let versions = restored.versions(id).unwrap();
    assert_eq!(versions.len(), 2, "both kept as a conflict");
    assert!(
        report.merge_change,
        "the merging device records a merge change"
    );
    assert!(restored.state().get(&d("me")) > peer.state().get(&d("me")));
}
