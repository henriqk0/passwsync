//! 004 T081, T141 (US3): a locked device stores received copies as ciphertext only.

mod support;

use support::sim::*;
use support::*;
use wallet_sync::ports::{MergeOutcome, StoreError, SyncStore};
use wallet_sync::record::{Outcome, PendingStatus, Position};
use wallet_sync::round::{RoundClass, SyncEvent};
use wallet_sync::testkit::Step;

const S: [u8; 32] = [8; 32];

/// a (older, "locked": merges report Locked) and b (newer).
fn pair_locked() -> (Device, Device) {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    connect(&mut a, &mut b, S);
    (a, b)
}

fn finish_merges_locked(a: &mut Device) {
    for request in a.engine.take_merge_requests() {
        a.engine.merge_finished(&request, MergeOutcome::Locked);
    }
}

#[test]
fn a_locked_device_keeps_the_copy_as_ciphertext_without_touching_its_wallet() {
    let (mut a, mut b) = pair_locked();
    let file_before = a.source.get("W").unwrap();
    let digest_before = record(&a, wid(1)).digest;
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    assert_eq!(
        a.store.read_pending(&wid(1), &b.id).unwrap(),
        b.source.get("W").unwrap()
    );
    let rec = record(&a, wid(1));
    assert_eq!(rec.pending[&b.id].status, PendingStatus::Waiting);
    assert_eq!(rec.digest, digest_before, "record digest unchanged");
    assert_eq!(
        a.source.get("W").unwrap(),
        file_before,
        "wallet file unchanged"
    );
}

#[test]
fn a_newer_copy_from_the_same_peer_replaces_the_older_one() {
    let (mut a, mut b) = pair_locked();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    // b changes again.
    let newer = file_bytes(3, 300);
    b.source.set("W", newer.clone());
    b.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.digest = wallet_sync::record::sha256(&newer);
            r.state = sv(&[("x", 3)]);
            Some(r)
        })
        .unwrap();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    assert_eq!(
        a.store.pending_peers(&wid(1)).unwrap(),
        vec![b.id],
        "one per peer"
    );
    assert_eq!(a.store.read_pending(&wid(1), &b.id).unwrap(), newer);
    assert_eq!(record(&a, wid(1)).pending[&b.id].claimed, sv(&[("x", 3)]));
}

#[test]
fn a_stored_copy_is_not_requested_again() {
    let (mut a, mut b) = pair_locked();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    assert!(
        !Transcript::ctypes(&t.a_to_b).contains(&"Want"),
        "the pending copy covers it"
    );
}

#[test]
fn a_pending_copy_dominated_by_the_local_state_is_deleted() {
    let (mut a, mut b) = pair_locked();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    // a's own state moves past the copy (e.g. merged from elsewhere and saved).
    a.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.state = sv(&[("x", 5)]);
            Some(r)
        })
        .unwrap();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    assert!(a.store.pending_peers(&wid(1)).unwrap().is_empty());
    assert!(record(&a, wid(1)).pending.is_empty());
}

#[test]
fn revoking_the_sender_deletes_its_pending_copies() {
    let (mut a, mut b) = pair_locked();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    finish_merges_locked(&mut a);
    a.engine.revoke_peer(b.id);
    assert!(a.store.pending_peers(&wid(1)).unwrap().is_empty());
    let rec = record(&a, wid(1));
    assert!(rec.pending.is_empty() && !rec.peers.contains_key(&b.id));
}

#[test]
fn a_locked_intermediary_never_forwards_a_pending_copy() {
    let mut sim = Sim::new(3, 9);
    let id = sim.devices[0].vault.list()[0].id();
    sim.devices[1].locked = true;
    let t = sim.tick();
    sim.devices[0].edit(t, |v| v.update_entry(id, fields("from A")).is_ok());
    sim.connect(0, 1);
    sim.start_round(0, 1);
    sim.settle();
    assert_eq!(
        sim.devices[1]
            .store
            .pending_peers(&sim.devices[1].wallet())
            .unwrap()
            .len(),
        1
    );
    // B (locked) syncs with C: C only ever receives B's own (older) file.
    sim.connect(1, 2);
    sim.start_round(1, 2);
    sim.settle();
    sim.start_round(2, 1);
    sim.settle();
    let c = &sim.devices[2];
    assert!(
        c.store.pending_peers(&c.wallet()).unwrap().is_empty(),
        "nothing newer to get"
    );
    assert_eq!(
        c.vault.get(id).unwrap().fields().unwrap().title,
        "alpha",
        "A's change did not travel through a locked B"
    );
}

// --- T141: storage full while receiving ---

#[test]
fn storage_full_keeps_nothing_and_fails_the_round() {
    for step in [Step::IncomingAppend, Step::IncomingFinish] {
        let (mut a, mut b) = pair_locked();
        let file_before = a.source.get("W").unwrap();
        let record_before = record(&a, wid(1));
        a.store.fail_once(step, StoreError::NoSpace);
        a.engine.start_round(b.id);
        pump(&mut a, &mut b);
        assert!(
            a.store.pending_peers(&wid(1)).unwrap().is_empty(),
            "{step:?}"
        );
        assert_eq!(a.store.partial_count(), 0, "{step:?}");
        assert_eq!(a.source.get("W").unwrap(), file_before);
        let rec = record(&a, wid(1));
        assert_eq!(rec.pending, record_before.pending);
        assert_eq!(rec.digest, record_before.digest);
        let peer = &rec.peers[&b.id];
        assert_eq!(peer.last_outcome, Outcome::Failed, "sync_error");
        assert_eq!(peer.position, Position::Error);
        assert!(
            events(&mut a).iter().any(|e| matches!(
                e,
                SyncEvent::RoundEnded {
                    class: RoundClass::Failed,
                    ..
                }
            )),
            "a failed round backs off"
        );
    }
}

// --- T098 (sync side): an invalid copy is deleted with a warning naming only the peer ---

#[test]
fn an_invalid_copy_is_deleted_with_a_warning() {
    let (mut a, mut b) = pair_locked();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    for request in a.engine.take_merge_requests() {
        a.engine.merge_finished(&request, MergeOutcome::Invalid);
    }
    assert!(a.store.pending_peers(&wid(1)).unwrap().is_empty());
    let rec = record(&a, wid(1));
    assert!(rec.pending.is_empty());
    let warning = rec
        .warnings
        .iter()
        .find(|w| w.kind == wallet_sync::record::WarningKind::InvalidCopy)
        .unwrap();
    assert_eq!(warning.peer, Some(b.id));
    assert_eq!(rec.peers[&b.id].last_outcome, Outcome::InvalidCopy);
    assert!(
        events(&mut a)
            .iter()
            .any(|e| matches!(e, SyncEvent::InvalidCopy { name, .. } if name == "W"))
    );
}
