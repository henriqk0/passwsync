//! 004 T053: hostile or broken peers at the protocol level. Every violation closes the round
//! with a protocol error, never panics, leaves no transfer slot or partial file behind.

mod support;

use support::*;
use wallet_sync::codec::{Ctl, MAX_CTL};
use wallet_sync::ports::SyncStore;
use wallet_sync::round::{Frame, RoundClass, SyncEvent};

const S: [u8; 32] = [5; 32];

fn pair() -> (Device, Device) {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    add_wallet(&a, wid(2), "V", sv(&[("y", 1)]), 1);
    add_wallet(&b, wid(1), "W", sv(&[("x", 2)]), 2);
    add_wallet(&b, wid(2), "V", sv(&[("y", 1)]), 1);
    connect(&mut a, &mut b, S);
    (a, b)
}

fn assert_protocol_error(dev: &mut Device, peer: wallet_sync::ports::PeerId, case: &str) {
    let ev = events(dev);
    assert!(closed(&ev), "{case}: channel not closed");
    let protocol_end = ev.iter().any(|e| {
        matches!(
            e,
            SyncEvent::RoundEnded {
                class: RoundClass::Protocol,
                ..
            }
        )
    });
    let had_round = ev
        .iter()
        .any(|e| matches!(e, SyncEvent::RoundStarted { .. }));
    assert!(
        protocol_end || !had_round,
        "{case}: round not ended as protocol"
    );
    assert!(
        !dev.engine.round_running(peer),
        "{case}: round left running"
    );
    assert_eq!(
        dev.engine.transfers_active(),
        0,
        "{case}: transfer slot leaked"
    );
    assert_eq!(dev.store.partial_count(), 0, "{case}: partial file left");
    // Further frames on the closed channel are ignored, nothing is sent.
    inject(dev, peer, &Ctl::Done { round: 1 });
    assert!(
        dev.engine.poll_outgoing(peer, 64).is_empty(),
        "{case}: still talking"
    );
}

fn raw(dev: &mut Device, from: wallet_sync::ports::PeerId, bytes: &[u8]) {
    dev.engine.on_frame(
        from,
        CONN,
        Frame::Ctl {
            more: false,
            fragment: bytes.to_vec(),
        },
    );
}

#[test]
fn malformed_messages_of_every_ctype() {
    for ctype in 0x01u8..=0x0A {
        // Tags without its count, others missing their fields (Done/Busy: missing round).
        let body: Vec<u8> = if matches!(ctype, 0x09 | 0x0A) {
            vec![ctype, 0, 0]
        } else {
            vec![ctype, 0, 0, 0, 1, 0xff]
        };
        let (mut a, b) = pair();
        raw(&mut a, b.id, &body);
        assert_protocol_error(&mut a, b.id, &format!("ctype {ctype:#04x}"));
    }
}

#[test]
fn unknown_ctype_and_trailing_bytes() {
    for body in [&[0x0Bu8, 0, 0, 0, 1][..], &[0xEE], &[0x09, 0, 0, 0, 1, 0]] {
        let (mut a, b) = pair();
        raw(&mut a, b.id, body);
        assert_protocol_error(&mut a, b.id, &format!("{body:?}"));
    }
}

#[test]
fn oversized_control_message_and_frames() {
    let (mut a, b) = pair();
    for _ in 0..=MAX_CTL / 1000 {
        a.engine.on_frame(
            b.id,
            CONN,
            Frame::Ctl {
                more: true,
                fragment: vec![0; 1000],
            },
        );
    }
    assert_protocol_error(&mut a, b.id, "> 24 KiB");
    let (mut a, b) = pair();
    a.engine.on_frame(
        b.id,
        CONN,
        Frame::Ctl {
            more: false,
            fragment: vec![0x09; 1001],
        },
    );
    assert_protocol_error(&mut a, b.id, "fragment > 1000");
    let (mut a, mut b) = pair();
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    let _ = events(&mut a);
    a.engine.on_frame(b.id, CONN, Frame::Data(vec![0; 1001]));
    assert_protocol_error(&mut a, b.id, "data frame > 1000 outside a transfer");
}

#[test]
fn an_oversized_data_chunk_inside_a_transfer_is_rejected() {
    let (mut a, mut b) = pair();
    let big = file_bytes(4, 10_000);
    b.source.set("W", big.clone());
    b.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.digest = wallet_sync::record::sha256(&big);
            Some(r)
        })
        .unwrap();
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
    a.engine.on_frame(b.id, CONN, Frame::Data(vec![0; 1001]));
    assert_protocol_error(&mut a, b.id, "data chunk > 1000 within the size");
}

#[test]
fn data_interleaved_into_a_fragmented_control_message() {
    let (mut a, b) = pair();
    a.engine.on_frame(
        b.id,
        CONN,
        Frame::Ctl {
            more: true,
            fragment: vec![0x01],
        },
    );
    a.engine.on_frame(b.id, CONN, Frame::Data(vec![1]));
    assert_protocol_error(&mut a, b.id, "interleaved CopyData");
}

#[test]
fn wrong_state_messages() {
    // Matches / Done / CopyEnd without a round.
    for ctl in [
        Ctl::Matches {
            round: 1,
            entries: vec![],
        },
        Ctl::Done { round: 1 },
        Ctl::CopyEnd { round: 1, idx: 0 },
        Ctl::Want { round: 1, idx: 0 },
    ] {
        let (mut a, b) = pair();
        inject(&mut a, b.id, &ctl);
        assert_protocol_error(&mut a, b.id, &format!("{ctl:?} without a round"));
    }
    // Done before Matches (a initiated; b sends Done instead of Matches).
    let (mut a, b) = pair();
    a.engine.start_round(b.id);
    let round = 1;
    inject(&mut a, b.id, &Ctl::Done { round });
    assert_protocol_error(&mut a, b.id, "Done before Matches");
    // Want before our Summary (b initiates; a is responder and summarized idx 0 only if it
    // differs: here idx of an in-sync wallet is wanted).
    let (mut a, mut b) = pair();
    b.engine.start_round(a.id);
    for f in b.engine.poll_outgoing(a.id, 64) {
        a.engine.on_frame(b.id, CONN, f);
    }
    let answer = drain_ctl(&mut a, b.id);
    let in_sync_idx = match &answer[0] {
        Ctl::Matches { entries, .. } => entries.iter().find(|(_, s)| *s).unwrap().0,
        other => panic!("{other:?}"),
    };
    inject(
        &mut a,
        b.id,
        &Ctl::Want {
            round: answer[0].round(),
            idx: in_sync_idx,
        },
    );
    assert_protocol_error(&mut a, b.id, "Want for an unsummarized wallet");
    // CopyEnd without CopyStart.
    let (mut a, mut b) = pair();
    a.engine.start_round(b.id);
    for f in a.engine.poll_outgoing(b.id, 64) {
        b.engine.on_frame(a.id, CONN, f);
    }
    inject(&mut a, b.id, &Ctl::CopyEnd { round: 1, idx: 0 });
    assert_protocol_error(&mut a, b.id, "CopyEnd without start");
}

#[test]
fn wrong_round_and_idx_out_of_range() {
    let (mut a, b) = pair();
    a.engine.start_round(b.id);
    inject(
        &mut a,
        b.id,
        &Ctl::Matches {
            round: 2,
            entries: vec![],
        },
    );
    assert_protocol_error(&mut a, b.id, "wrong round");
    let (mut a, b) = pair();
    a.engine.start_round(b.id);
    inject(
        &mut a,
        b.id,
        &Ctl::Matches {
            round: 1,
            entries: vec![(99, false)],
        },
    );
    assert_protocol_error(&mut a, b.id, "idx out of range");
    let (mut a, b) = pair();
    a.engine.start_round(b.id);
    inject(
        &mut a,
        b.id,
        &Ctl::Matches {
            round: 1,
            entries: vec![(0, false), (0, true)],
        },
    );
    assert_protocol_error(&mut a, b.id, "duplicate idx");
}

#[test]
fn replayed_old_round_messages() {
    let (mut a, mut b) = pair();
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    let _ = events(&mut a);
    // Round 1 is over; its Matches arrive again.
    inject(&mut a, b.id, &t.b_to_a[0]);
    assert_protocol_error(&mut a, b.id, "replayed Matches");
    // A replayed Tags with an old round number.
    let (mut a, mut b) = pair();
    b.engine.start_round(a.id);
    let t = pump(&mut a, &mut b);
    let _ = events(&mut a);
    inject(&mut a, b.id, &t.b_to_a[0]);
    assert_protocol_error(&mut a, b.id, "replayed Tags");
}

#[test]
fn a_violation_mid_transfer_deletes_the_partial_copy() {
    let (mut a, mut b) = pair();
    // Make b's wallet big so the transfer spans several frames.
    let big = file_bytes(4, 10_000);
    b.source.set("W", big.clone());
    b.store
        .update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.digest = wallet_sync::record::sha256(&big);
            Some(r)
        })
        .unwrap();
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
    assert_eq!(a.store.partial_count(), 1, "transfer under way");
    raw(&mut a, b.id, &[0x42]);
    assert_protocol_error(&mut a, b.id, "garbage mid-transfer");
}
