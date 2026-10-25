//! 004 T096 (US4, FR-019, SC-004): replayed rounds, stale tags and restored devices.

mod support;

use support::sim::*;
use support::*;
use vault_core::testkit::fork;
use wallet_sync::codec::Ctl;
use wallet_sync::ports::SyncStore;
use wallet_sync::record::{Position, WarningKind};
use wallet_sync::round::SyncEvent;
use wallet_sync::tags::{tag, tag_matches};

#[test]
fn a_round_replayed_on_a_new_session_matches_nothing() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    connect(&mut a, &mut b, [1; 32]);
    a.engine.start_round(b.id);
    let old = pump(&mut a, &mut b);
    let old_tags = old.a_to_b[0].clone();
    let _ = b.store.delete_pending(&wid(1), &a.id);
    // A new channel (fresh Noise session); the old Tags are injected again.
    b.engine.channel_down(a.id, CONN);
    b.engine.channel_up(a.id, CONN, [2; 32], false);
    let Ctl::Tags { entries, .. } = old_tags else {
        panic!()
    };
    inject(&mut b, a.id, &Ctl::Tags { round: 1, entries });
    let answer = drain_ctl(&mut b, a.id);
    match &answer[0] {
        Ctl::Matches { entries, .. } => assert!(entries.is_empty(), "session-bound tags"),
        other => panic!("{other:?}"),
    }
    assert!(!answer.iter().any(|c| matches!(c, Ctl::Summary { .. })));
}

#[test]
fn a_stale_tag_from_another_session_never_matches() {
    let t = tag(&wid(1), &[1; 32], 3, 0);
    assert!(tag_matches(&wid(1), &[1; 32], 3, 0, &t));
    assert!(!tag_matches(&wid(1), &[2; 32], 3, 0, &t));
}

#[test]
fn a_device_restored_with_its_record_is_caught_by_its_peers_marks() {
    let mut sim = Sim::new(2, 11);
    let id = sim.devices[0].vault.list()[0].id();
    // A's state before the newer edits (its "backup").
    let backup_vault = fork(&sim.devices[0].vault, "dev1", 50);
    let backup_record = sim.devices[0].record();
    let backup_file = sim.devices[0].source.get(NAME).unwrap();
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("newer on A")).is_ok());
    sim.connect(0, 1);
    sim.start_round(0, 1);
    sim.settle();
    assert_eq!(
        sim.devices[1]
            .vault
            .get(id)
            .unwrap()
            .fields()
            .unwrap()
            .title,
        "newer on A"
    );
    // A's whole installation (wallet file and record) is restored from the backup.
    sim.disconnect(0, 1);
    sim.devices[0].vault = backup_vault;
    sim.devices[0].source.set(NAME, backup_file);
    let wallet = sim.devices[0].wallet();
    sim.devices[0]
        .store
        .update(&wallet, &mut |_| Some(backup_record.clone()))
        .unwrap();
    sim.connect(0, 1);
    sim.start_round(0, 1);
    sim.settle();
    let b = &sim.devices[1];
    let rec = b.record();
    // (The position is in sync again once A healed in the same settle; the warning stays.)
    let _ = Position::OlderStateOffered;
    assert!(
        rec.warnings
            .iter()
            .any(|w| w.kind == WarningKind::OlderStateOffered)
    );
    assert!(
        b.events
            .iter()
            .any(|e| matches!(e, SyncEvent::OlderStateOffered { .. }))
    );
    assert_eq!(
        b.vault.get(id).unwrap().fields().unwrap().title,
        "newer on A",
        "nothing moved backwards on B"
    );
    // A heals: it receives B's copy and merges it.
    sim.start_round(1, 0);
    sim.settle();
    assert_eq!(
        sim.devices[0]
            .vault
            .get(id)
            .unwrap()
            .fields()
            .unwrap()
            .title,
        "newer on A"
    );
}
