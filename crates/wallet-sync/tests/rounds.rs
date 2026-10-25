//! 004 T048, T140: the per-peer round state machine (contracts/sync-protocol.md "Round").

mod support;

use support::*;
use wallet_sync::codec::{Ctl, encode, fragment};
use wallet_sync::record::Position;
use wallet_sync::round::{EngineConfig, Frame, RoundClass, SyncEvent};

const SESSION: [u8; 32] = [0x42; 32];

fn ended(events: &[SyncEvent]) -> Vec<RoundClass> {
    events
        .iter()
        .filter_map(|e| match e {
            SyncEvent::RoundEnded { class, .. } => Some(*class),
            _ => None,
        })
        .collect()
}

#[test]
fn in_sync_wallets_exchange_only_tags_matches_and_done() {
    let (mut a, mut b) = (device(1), device(2));
    let state = sv(&[("x", 3)]);
    add_wallet(&a, wid(1), "Personal", state.clone(), 1);
    add_wallet(&b, wid(1), "Mine", state.clone(), 1);
    connect(&mut a, &mut b, SESSION);
    assert!(a.engine.start_round(b.id));
    let t = pump(&mut a, &mut b);
    assert_eq!(Transcript::ctypes(&t.a_to_b), ["Tags", "Done"]);
    assert_eq!(Transcript::ctypes(&t.b_to_a), ["Matches", "Done"]);
    assert_eq!(t.data_bytes, 0, "no wallet data (FR-029b)");
    match &t.b_to_a[0] {
        Ctl::Matches { entries, .. } => assert_eq!(entries, &[(0, true)]),
        other => panic!("{other:?}"),
    }
    assert_eq!(ended(&events(&mut a)), [RoundClass::Ok]);
    assert_eq!(ended(&events(&mut b)), [RoundClass::Ok]);
    let peer = record(&a, wid(1)).peers[&b.id].clone();
    assert_eq!(peer.position, Position::InSync);
    assert!(peer.last_round_at.is_some());
}

#[test]
fn a_newer_side_is_wanted_and_its_copy_stored_as_pending() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "Personal", sv(&[("x", 3)]), 1);
    add_wallet(&b, wid(1), "Personal", sv(&[("x", 5)]), 2);
    connect(&mut a, &mut b, SESSION);
    assert!(a.engine.start_round(b.id));
    let t = pump(&mut a, &mut b);
    assert_eq!(
        Transcript::ctypes(&t.a_to_b),
        ["Tags", "Summary", "Want", "Done"]
    );
    assert_eq!(
        Transcript::ctypes(&t.b_to_a),
        // b has nothing to want and nothing to serve yet: its Done may precede a's Want.
        ["Matches", "Summary", "Done", "CopyStart", "CopyEnd"]
    );
    assert_eq!(t.data_bytes, 200);
    assert_eq!(
        a.store.read_pending(&wid(1), &b.id).unwrap(),
        b.source.get("Personal").unwrap()
    );
    let rec = record(&a, wid(1));
    assert_eq!(rec.pending[&b.id].claimed, sv(&[("x", 5)]));
    assert_eq!(rec.peers[&b.id].position, Position::Behind);
    assert_eq!(record(&b, wid(1)).peers[&a.id].position, Position::Ahead);
    let ev = events(&mut a);
    assert!(
        ev.iter()
            .any(|e| matches!(e, SyncEvent::PendingStored { peer, .. } if *peer == b.id))
    );
    assert_eq!(a.engine.take_merge_requests().len(), 1);
    assert!(b.store.pending_peers(&wid(1)).unwrap().is_empty());
}

#[test]
fn concurrent_states_are_exchanged_both_ways() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 3), ("y", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2), ("z", 1)]), 2);
    connect(&mut a, &mut b, SESSION);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    assert!(Transcript::ctypes(&t.a_to_b).contains(&"Want"));
    assert!(Transcript::ctypes(&t.b_to_a).contains(&"Want"));
    assert!(a.store.read_pending(&wid(1), &b.id).is_ok());
    assert!(b.store.read_pending(&wid(1), &a.id).is_ok());
    assert_eq!(record(&a, wid(1)).peers[&b.id].position, Position::Diverged);
}

#[test]
fn simultaneous_tags_let_the_dialers_round_win() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 1)]), 1);
    connect(&mut a, &mut b, SESSION); // a dialed
    assert!(a.engine.start_round(b.id));
    assert!(b.engine.start_round(a.id));
    let t = pump(&mut a, &mut b);
    // b discarded its own round and answered a's.
    assert_eq!(Transcript::ctypes(&t.b_to_a)[1..], ["Matches", "Done"]);
    assert_eq!(ended(&events(&mut a)), [RoundClass::Ok]);
    assert_eq!(ended(&events(&mut b)), [RoundClass::Ok]);
}

#[test]
fn one_round_per_peer_and_busy_for_a_second_one() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    connect(&mut a, &mut b, SESSION);
    assert!(a.engine.start_round(b.id));
    assert!(!a.engine.start_round(b.id), "already running");
    // Deliver Tags and Matches only, so a's round is past tagging.
    for f in a.engine.poll_outgoing(b.id, 64) {
        b.engine.on_frame(a.id, CONN, f);
    }
    for f in b.engine.poll_outgoing(a.id, 64) {
        a.engine.on_frame(b.id, CONN, f);
    }
    // A second Tags from b (with a higher round number) gets Busy.
    let tags = encode(&Ctl::Tags {
        round: 9,
        entries: vec![],
    });
    for (more, frag) in fragment(&tags) {
        a.engine.on_frame(
            b.id,
            CONN,
            Frame::Ctl {
                more,
                fragment: frag,
            },
        );
    }
    let out = a.engine.poll_outgoing(b.id, 64);
    let mut saw_busy = false;
    let mut r = wallet_sync::codec::Reassembler::default();
    for f in out {
        if let Frame::Ctl { more, fragment } = f {
            if let Ok(Some(m)) = r.push(more, &fragment) {
                saw_busy |= matches!(wallet_sync::codec::decode(&m), Ok(Ctl::Busy { round: 9 }));
            }
        }
    }
    assert!(saw_busy);
}

#[test]
fn wallets_the_other_side_lacks_are_never_named_or_created() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "Shared", sv(&[("x", 1)]), 1);
    add_wallet(&a, wid(2), "Only-on-A", sv(&[("x", 9)]), 3);
    add_wallet(&b, wid(1), "Shared", sv(&[("x", 1)]), 1);
    connect(&mut a, &mut b, SESSION);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    match &t.b_to_a[0] {
        Ctl::Matches { entries, .. } => assert_eq!(entries.len(), 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        b.store.load(&wid(2)).unwrap(),
        None,
        "never created (FR-002)"
    );
    assert!(b.store.pending_peers(&wid(2)).unwrap().is_empty());
    assert!(b.source.get("Only-on-A").is_none());
    for id in [wid(1), wid(2)] {
        assert!(
            !t.raw.windows(16).any(|w| w == id.as_bytes()),
            "wallet id on the wire"
        );
    }
    for name in ["Shared", "Only-on-A"] {
        assert!(!t.raw.windows(name.len()).any(|w| w == name.as_bytes()));
    }
    // The same in the other direction (b initiates).
    b.engine.start_round(a.id);
    let t = pump(&mut a, &mut b);
    match &t.a_to_b[0] {
        Ctl::Matches { entries, .. } => assert_eq!(entries.len(), 1),
        other => panic!("{other:?}"),
    }
}

#[test]
fn done_is_exchanged_and_both_sides_record_the_round() {
    let (mut a, mut b) = (device(1), device(2));
    connect(&mut a, &mut b, SESSION);
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(7), "Other", sv(&[("y", 1)]), 2);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    assert_eq!(Transcript::ctypes(&t.a_to_b), ["Tags", "Done"]);
    assert_eq!(Transcript::ctypes(&t.b_to_a), ["Matches", "Done"]);
    assert_eq!(ended(&events(&mut a)), [RoundClass::Ok]);
    assert_eq!(ended(&events(&mut b)), [RoundClass::Ok]);
    assert!(!a.engine.round_running(b.id));
}

#[test]
fn a_device_without_wallets_starts_no_round() {
    let (mut a, mut b) = (device(1), device(2));
    connect(&mut a, &mut b, SESSION);
    assert!(!a.engine.start_round(b.id));
    assert!(pump(&mut a, &mut b).raw.is_empty());
}

// --- T140: rotating summary window (FR-005, FR-029) ---

#[test]
fn the_window_rotates_so_every_wallet_is_summarized_within_ceil_n_over_512_rounds() {
    let (mut a, mut b) = (device(1), device(2));
    let n = 600u16;
    for i in 0..n {
        add_wallet(&a, wid(i), &format!("w{i}"), sv(&[("x", 1)]), 1);
        add_wallet(&b, wid(i), &format!("w{i}"), sv(&[("x", 1)]), 1);
    }
    connect(&mut a, &mut b, SESSION);
    assert!(a.engine.start_round(b.id));
    let t = pump(&mut a, &mut b);
    match &t.a_to_b[0] {
        Ctl::Tags { entries, .. } => assert_eq!(entries.len(), 512),
        other => panic!("{other:?}"),
    }
    let seen_on_b = |b: &Device| {
        (0..n)
            .filter(|i| record(b, wid(*i)).peers.contains_key(&PEER_A))
            .count()
    };
    assert_eq!(seen_on_b(&b), 512, "only the window was named");
    assert!(a.engine.start_round(b.id));
    pump(&mut a, &mut b);
    assert_eq!(seen_on_b(&b), 600, "ceil(600 / 512) = 2 rounds cover all");
    let _ = EngineConfig::default();
}

const PEER_A: wallet_sync::ports::PeerId = wallet_sync::ports::PeerId([1; 32]);

#[test]
fn a_refused_peer_still_receives_our_copy() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 5), ("y", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2), ("z", 1)]), 2);
    // a saw a newer state from b before (b was restored from an old backup since).
    a.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.peer_mut(PeerId([2; 32])).peer_mark = Some(sv(&[("x", 4)]));
            Some(r)
        })
        .unwrap();
    connect(&mut a, &mut b, SESSION);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    assert!(
        !Transcript::ctypes(&t.a_to_b).contains(&"Want"),
        "older state not wanted"
    );
    assert!(
        b.store.read_pending(&wid(1), &a.id).is_ok(),
        "b still gets a's copy"
    );
    let rec = record(&a, wid(1));
    assert_eq!(rec.peers[&b.id].position, Position::OlderStateOffered);
    assert!(
        events(&mut a)
            .iter()
            .any(|e| matches!(e, SyncEvent::OlderStateOffered { .. }))
    );
}

use wallet_sync::ports::{PeerId, SyncStore};

// --- T113: round timeout and outcome classes ---

#[test]
fn thirty_seconds_without_progress_fail_the_round_and_delete_the_partial() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    let big = file_bytes(4, 10_000);
    b.source.set("W", big.clone());
    b.store
        .update(&wid(1), &mut |_| {
            Some(wallet_sync::record::SyncRecord::new(
                wid(1),
                "W".into(),
                wallet_sync::record::sha256(&big),
                sv(&[("x", 2)]),
            ))
        })
        .unwrap();
    connect(&mut a, &mut b, SESSION);
    a.engine.start_round(b.id);
    for _ in 0..10 {
        for f in a.engine.poll_outgoing(b.id, 64) {
            b.engine.on_frame(a.id, CONN, f);
        }
        for f in b.engine.poll_outgoing(a.id, 2) {
            a.engine.on_frame(b.id, CONN, f);
        }
        if a.store.partial_count() > 0 {
            break;
        }
    }
    assert_eq!(a.store.partial_count(), 1);
    advance(&a, std::time::Duration::from_secs(29));
    a.engine.tick();
    assert!(a.engine.round_running(b.id), "not yet");
    advance(&a, std::time::Duration::from_secs(1));
    a.engine.tick();
    assert!(!a.engine.round_running(b.id));
    assert_eq!(a.store.partial_count(), 0, "partial deleted");
    assert_eq!(ended(&events(&mut a)), [RoundClass::Timeout]);
    let peer = record(&a, wid(1)).peers[&b.id].clone();
    assert_eq!(peer.last_outcome, wallet_sync::record::Outcome::Failed);
    assert_eq!(peer.position, Position::Error);
}

#[test]
fn a_round_reports_its_traffic_and_class() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    connect(&mut a, &mut b, SESSION);
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    let ev = events(&mut a);
    let (sent, received) = ev
        .iter()
        .find_map(|e| match e {
            SyncEvent::RoundEnded {
                class: RoundClass::Ok,
                sent,
                received,
                ..
            } => Some((*sent, *received)),
            _ => None,
        })
        .unwrap();
    assert!(sent > 0 && received > 200, "{sent} {received}");
}
