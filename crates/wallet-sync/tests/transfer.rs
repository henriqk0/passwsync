//! 004 T051: copy transfers (contracts/sync-protocol.md steps 4-5, "Accepting a copy").

mod support;

use support::*;
use wallet_sync::codec::{AbortReason, Ctl, RefuseReason};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::round::{EngineConfig, Frame, SyncEvent};

const S: [u8; 32] = [3; 32];

/// a (older) and b (newer) hold the same wallet; returns the pair connected (a dialed).
fn older_newer(len: usize) -> (Device, Device) {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    let bytes = file_bytes(7, len);
    b.source.set("W", bytes.clone());
    b.store
        .update(&wid(1), &mut |_| {
            Some(wallet_sync::record::SyncRecord::new(
                wid(1),
                "W".into(),
                wallet_sync::record::sha256(&bytes),
                sv(&[("x", 2)]),
            ))
        })
        .unwrap();
    connect(&mut a, &mut b, S);
    (a, b)
}

/// Runs a's round up to b's `CopyStart` (inclusive) and returns the round number.
fn until_copy_start(a: &mut Device, b: &mut Device) -> u32 {
    assert!(a.engine.start_round(b.id));
    let mut number = 0;
    for _ in 0..20 {
        for f in a.engine.poll_outgoing(b.id, 64) {
            b.engine.on_frame(a.id, CONN, f);
        }
        let mut started = false;
        let frames = b.engine.poll_outgoing(a.id, 1);
        for f in frames {
            if let Frame::Ctl {
                more: false,
                fragment,
            } = &f
            {
                if fragment[0] == 0x06 {
                    number = u32::from_be_bytes(fragment[1..5].try_into().unwrap());
                    started = true;
                }
            }
            a.engine.on_frame(b.id, CONN, f);
        }
        if started {
            return number;
        }
    }
    panic!("no CopyStart");
}

#[test]
fn a_copy_streams_to_a_partial_file_then_becomes_pending_at_exact_size() {
    let (mut a, mut b) = older_newer(5_000);
    until_copy_start(&mut a, &mut b);
    // One data frame: the partial exists, no pending yet.
    let f = b.engine.poll_outgoing(a.id, 1);
    assert!(matches!(f[0], Frame::Data(ref d) if d.len() == 1000));
    a.engine.on_frame(b.id, CONN, f.into_iter().next().unwrap());
    assert!(a.store.has_partial(&wid(1), &b.id));
    assert!(a.store.read_pending(&wid(1), &b.id).is_err());
    pump(&mut a, &mut b);
    assert!(!a.store.has_partial(&wid(1), &b.id));
    assert_eq!(
        a.store.read_pending(&wid(1), &b.id).unwrap(),
        b.source.get("W").unwrap()
    );
}

#[test]
fn chunks_are_at_most_1000_bytes() {
    let (mut a, mut b) = older_newer(2_500);
    a.engine.start_round(b.id);
    let mut sizes = Vec::new();
    for _ in 0..50 {
        for f in a.engine.poll_outgoing(b.id, 64) {
            b.engine.on_frame(a.id, CONN, f);
        }
        let frames = b.engine.poll_outgoing(a.id, 64);
        if frames.is_empty() {
            break;
        }
        for f in frames {
            if let Frame::Data(d) = &f {
                sizes.push(d.len());
            }
            a.engine.on_frame(b.id, CONN, f);
        }
    }
    assert_eq!(sizes, [1000, 1000, 500]);
}

#[test]
fn a_short_copy_end_is_a_protocol_error_and_the_partial_is_deleted() {
    let (mut a, mut b) = older_newer(5_000);
    let round = until_copy_start(&mut a, &mut b);
    let f = b.engine.poll_outgoing(a.id, 1);
    a.engine.on_frame(b.id, CONN, f.into_iter().next().unwrap());
    inject(&mut a, b.id, &Ctl::CopyEnd { round, idx: 0 });
    assert!(closed(&events(&mut a)));
    assert!(!a.store.has_partial(&wid(1), &b.id));
    assert!(a.store.read_pending(&wid(1), &b.id).is_err());
}

#[test]
fn an_overrun_beyond_the_announced_size_is_a_protocol_error() {
    let (mut a, mut b) = older_newer(100);
    until_copy_start(&mut a, &mut b);
    a.engine.on_frame(b.id, CONN, Frame::Data(vec![0; 101]));
    assert!(closed(&events(&mut a)));
    assert_eq!(a.store.partial_count(), 0);
}

#[test]
fn data_outside_a_transfer_is_a_protocol_error() {
    let (mut a, b) = older_newer(100);
    a.engine.start_round(b.id);
    a.engine.on_frame(b.id, CONN, Frame::Data(vec![1, 2, 3]));
    assert!(closed(&events(&mut a)));
}

#[test]
fn a_file_changed_while_streaming_is_aborted_as_changed() {
    let (mut a, mut b) = older_newer(3_000);
    b.source.change_on_open("W", file_bytes(9, 3_000));
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    assert!(t.b_to_a.iter().any(|c| matches!(
        c,
        Ctl::CopyAbort {
            reason: AbortReason::Changed,
            ..
        }
    )));
    assert!(a.store.read_pending(&wid(1), &b.id).is_err());
    assert_eq!(a.store.partial_count(), 0);
}

/// a tags; b (the server here) answers; then a's Summary and Want are injected into b.
/// Returns what b answers to the Want.
fn want_answer(b: &mut Device, a: &mut Device, before_want: impl FnOnce(&mut Device)) -> Vec<Ctl> {
    assert!(a.engine.start_round(b.id));
    for f in a.engine.poll_outgoing(b.id, 64) {
        b.engine.on_frame(a.id, CONN, f);
    }
    let answer = drain_ctl(b, a.id);
    let round = answer[0].round();
    before_want(b);
    inject(
        b,
        a.id,
        &Ctl::Summary {
            round,
            idx: 0,
            no_offer: false,
            state: sv(&[("x", 1)]),
        },
    );
    let _ = drain_ctl(b, a.id);
    inject(b, a.id, &Ctl::Want { round, idx: 0 });
    drain_ctl(b, a.id)
}

fn refused(answer: &[Ctl], reason: RefuseReason) -> bool {
    answer
        .iter()
        .any(|c| matches!(c, Ctl::Refuse { reason: r, .. } if *r == reason))
}

#[test]
fn a_flagged_wallet_is_not_offerable() {
    let (mut a, mut b) = older_newer(300);
    b.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.flags.rollback_state = true;
            Some(r)
        })
        .unwrap();
    let answer = want_answer(&mut b, &mut a, |_| {});
    assert!(refused(&answer, RefuseReason::NotOfferable), "{answer:?}");
}

#[test]
fn a_file_changed_since_its_record_is_refused_as_changed() {
    let (mut a, mut b) = older_newer(300);
    let answer = want_answer(&mut b, &mut a, |b| b.source.set("W", file_bytes(8, 300)));
    assert!(refused(&answer, RefuseReason::Changed), "{answer:?}");
}

#[test]
fn no_free_transfer_slot_is_refused_as_busy() {
    let (mut a, b) = older_newer(300);
    let mut zero = device_with(
        2,
        EngineConfig {
            max_transfers: 0,
            ..EngineConfig::default()
        },
    );
    zero.store = b.store.clone();
    zero.source = b.source.clone();
    let mut b = Device {
        engine: wallet_sync::round::Engine::new(
            wallet_sync::round::EngineDeps {
                store: std::sync::Arc::new(b.store.clone()),
                source: std::sync::Arc::new(b.source.clone()),
                mono: b.mono.clone(),
                wall: b.wall.clone(),
                rng: Box::new(TestRng(5)),
            },
            EngineConfig {
                max_transfers: 0,
                ..EngineConfig::default()
            },
        ),
        ..zero
    };
    b.engine.channel_up(a.id, CONN, S, false);
    let answer = want_answer(&mut b, &mut a, |_| {});
    assert!(refused(&answer, RefuseReason::Busy), "{answer:?}");
}

#[test]
fn at_most_two_transfers_service_wide() {
    // One serving device, three wanting peers, rounds interleaved.
    let mut server = device(9);
    let bytes = file_bytes(5, 50_000);
    server.source.set("W", bytes.clone());
    server
        .store
        .update(&wid(1), &mut |_| {
            Some(wallet_sync::record::SyncRecord::new(
                wid(1),
                "W".into(),
                wallet_sync::record::sha256(&bytes),
                sv(&[("x", 9)]),
            ))
        })
        .unwrap();
    let mut clients: Vec<Device> = (1..=3).map(device).collect();
    for c in &mut clients {
        add_wallet(c, wid(1), "W", sv(&[("x", 1)]), 1);
        c.engine.channel_up(server.id, CONN, [c.id.0[0]; 32], true);
        server.engine.channel_up(c.id, CONN, [c.id.0[0]; 32], false);
        assert!(c.engine.start_round(server.id));
    }
    // Deliver every client's Tags and Summaries first, so all Wants arrive together.
    let mut busy = 0;
    let mut max_active = 0;
    for _ in 0..200 {
        let mut moved = false;
        for c in &mut clients {
            for f in c.engine.poll_outgoing(server.id, 64) {
                moved = true;
                server.engine.on_frame(c.id, CONN, f);
            }
        }
        max_active = max_active.max(server.engine.transfers_active());
        for c in &mut clients {
            for f in server.engine.poll_outgoing(c.id, 4) {
                moved = true;
                if let Frame::Ctl {
                    more: false,
                    fragment,
                } = &f
                {
                    if fragment[0] == 0x05 && fragment[7] == 1 {
                        busy += 1;
                    }
                }
                c.engine.on_frame(server.id, CONN, f);
            }
        }
        if !moved {
            break;
        }
    }
    assert!(max_active <= 2, "{max_active} transfers at once");
    assert!(busy >= 1, "the third was refused as busy");
    let got = clients
        .iter()
        .filter(|c| c.store.read_pending(&wid(1), &server.id).is_ok())
        .count();
    assert_eq!(got, 2);
    // A busy refusal is not a failure: the refused client's round ended ok.
    for c in &mut clients {
        let ev = events(c);
        assert!(ev.iter().any(|e| matches!(
            e,
            SyncEvent::RoundEnded {
                class: wallet_sync::round::RoundClass::Ok,
                ..
            }
        )));
    }
}

#[test]
fn only_the_own_stored_file_is_offered_never_a_pending_copy() {
    // b holds a pending copy from a (newer), and its own older file; c wants b's state.
    let (mut b, mut c) = (device(2), device(3));
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    add_wallet(&c, wid(1), "W", sv(&[("x", 1)]), 3);
    b.store
        .put_pending(&wid(1), &PeerId([1; 32]), file_bytes(1, 400));
    connect(&mut c, &mut b, S);
    c.engine.start_round(b.id);
    pump(&mut c, &mut b);
    assert_eq!(
        c.store.read_pending(&wid(1), &b.id).unwrap(),
        b.source.get("W").unwrap(),
        "b's own file, not a's copy (FR-006a)"
    );
}
