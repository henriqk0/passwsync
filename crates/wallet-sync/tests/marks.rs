//! 004 T094 (US4): high-water marks, peer marks and possible-rollback flags (FR-021,
//! FR-021a, research R10).

mod support;

use support::*;
use wallet_sync::codec::Ctl;
use wallet_sync::decide::jump_too_large;
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{FileCheck, SyncRecord, WarningKind};
use wallet_sync::round::SyncEvent;

fn rec() -> SyncRecord {
    SyncRecord::new(wid(1), "W".into(), [1; 32], sv(&[("a", 2)]))
}

#[test]
fn each_committed_save_joins_the_mark_and_flags_a_state_below_it() {
    let mut r = rec();
    r.committed([2; 32], &sv(&[("a", 3)]));
    assert_eq!(r.mark, sv(&[("a", 3)]));
    assert!(!r.flags.possible_rollback());
    // A save of an older state (e.g. after a restore) keeps the mark and flags it.
    r.committed([3; 32], &sv(&[("a", 1), ("b", 1)]));
    assert_eq!(r.mark, sv(&[("a", 3), ("b", 1)]));
    assert!(r.flags.rollback_state);
    // The flag persists until a later state reaches the mark.
    r.committed([4; 32], &sv(&[("a", 2), ("b", 1)]));
    assert!(r.flags.rollback_state);
    r.committed([5; 32], &sv(&[("a", 3), ("b", 2)]));
    assert!(
        !r.flags.rollback_state,
        "a merge brought the state above the mark"
    );
    assert_eq!(r.digest, [5; 32]);
}

#[test]
fn a_file_changed_outside_the_service_is_flagged_until_an_unlock_authenticates_it() {
    let mut r = rec();
    assert_eq!(r.check_file(Some([1; 32])), FileCheck::Unchanged);
    assert_eq!(r.check_file(Some([9; 32])), FileCheck::Changed);
    assert!(r.flags.rollback_digest);
    // Still flagged on the next check, even if the bytes come back.
    assert_eq!(r.check_file(Some([1; 32])), FileCheck::Unchanged);
    assert!(
        r.flags.rollback_digest,
        "only an unlock clears the digest flag"
    );
    // The unlock authenticates the file: a newer state clears everything.
    r.authenticated([9; 32], &sv(&[("a", 4)]));
    assert!(!r.flags.possible_rollback());
    assert_eq!(r.mark, sv(&[("a", 4)]));
    assert_eq!(r.check_file(None), FileCheck::Missing);
}

#[test]
fn an_authenticated_state_below_the_mark_stays_flagged() {
    let mut r = rec();
    r.check_file(Some([9; 32]));
    r.authenticated([9; 32], &sv(&[("a", 1)]));
    assert!(!r.flags.rollback_digest);
    assert!(r.flags.rollback_state, "older than the high-water mark");
    assert_eq!(r.mark, sv(&[("a", 2)]), "the mark never goes down");
    assert_eq!(
        r.state,
        sv(&[("a", 1)]),
        "the record describes the real file"
    );
}

#[test]
fn peer_marks_rise_only_with_authenticated_states() {
    let mut r = rec();
    let p = PeerId([7; 32]);
    r.raise_peer_mark(p, &sv(&[("a", 2)]));
    r.raise_peer_mark(p, &sv(&[("a", 1)]));
    assert_eq!(
        r.peers[&p].peer_mark,
        Some(sv(&[("a", 2)])),
        "never lowered"
    );
    r.raise_peer_mark(p, &sv(&[("b", 1)]));
    assert_eq!(r.peers[&p].peer_mark, Some(sv(&[("a", 2), ("b", 1)])));
}

#[test]
fn a_flagged_wallet_is_summarized_with_no_offer_and_still_receives() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 5)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 3)]), 2);
    a.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.flags.rollback_state = true;
            Some(r)
        })
        .unwrap();
    connect(&mut b, &mut a, [1; 32]);
    b.engine.start_round(a.id);
    let t = pump(&mut b, &mut a);
    assert!(
        t.b_to_a
            .iter()
            .any(|c| matches!(c, Ctl::Summary { no_offer: true, .. }))
    );
    assert!(
        !Transcript::ctypes(&t.a_to_b).contains(&"Want"),
        "b never asks a flagged copy"
    );
}

#[test]
fn a_file_digest_mismatch_at_round_time_flags_and_logs() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 5)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 3)]), 2);
    a.source.set("W", file_bytes(77, 200)); // replaced while the service was away
    connect(&mut a, &mut b, [1; 32]);
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    let r = record(&a, wid(1));
    assert!(r.flags.rollback_digest);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.kind == WarningKind::PossibleRollback)
    );
    assert!(
        events(&mut a)
            .iter()
            .any(|e| matches!(e, SyncEvent::PossibleRollback { .. }))
    );
    assert!(
        b.store.pending_peers(&wid(1)).unwrap().is_empty(),
        "not offered"
    );
}

#[test]
fn the_jump_bound_is_2_pow_32_over_local_or_peer_mark() {
    let local = sv(&[("a", 1)]);
    assert!(!jump_too_large(&sv(&[("a", 1 + (1 << 32))]), &local, None));
    assert!(jump_too_large(&sv(&[("a", 2 + (1 << 32))]), &local, None));
}
