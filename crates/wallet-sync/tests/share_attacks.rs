//! 005 T057 (US3, FR-013, FR-025): replayed or misbound proofs, `rid` confusion, transfer
//! framing abuse and floods; a channel that is not share-enabled carries nothing.

mod support;

use support::share::*;
use wallet_sync::ports::{PeerId, ReceivedStore};
use wallet_sync::share::ShareEvent;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::proof::redeem_proof;

fn invalid_answer(a: &mut ShareDevice, to: PeerId) -> bool {
    drain_msgs(a, to).iter().any(|m| {
        matches!(
            m,
            ShareMsg::Abort {
                reason: AbortReason::Invalid,
                ..
            }
        )
    })
}

#[test]
fn proofs_bound_to_another_session_rid_or_pair_are_refused() {
    type Case = (&'static str, [u8; 32], PeerId, PeerId, u32, u32);
    let cases: [Case; 4] = [
        (
            "other session",
            [0x11; 32],
            PeerId([1; 32]),
            PeerId([2; 32]),
            5,
            5,
        ),
        ("other rid", SESSION, PeerId([1; 32]), PeerId([2; 32]), 6, 5),
        (
            "other sender",
            SESSION,
            PeerId([9; 32]),
            PeerId([2; 32]),
            5,
            5,
        ),
        (
            "other recipient",
            SESSION,
            PeerId([1; 32]),
            PeerId([9; 32]),
            5,
            5,
        ),
    ];
    for (label, session, sender, recipient, proof_rid, sent_rid) in cases {
        let (mut a, b, _) = invited(500);
        let proof = redeem_proof(CODE, &session, &sender, &recipient, proof_rid);
        a.engine.on_msg(
            b.id,
            CONN,
            ShareMsg::Redeem {
                rid: sent_rid,
                proof,
            },
        );
        assert!(invalid_answer(&mut a, b.id), "{label}");
        let view = a.engine.view().invitation.unwrap();
        assert_eq!(
            (view.state, view.reason),
            ("refused", Some("wrong_code")),
            "{label}"
        );
    }
    // The correctly bound proof works.
    let (mut a, b, _) = invited(500);
    let proof = redeem_proof(CODE, &SESSION, &a.id, &b.id, 5);
    a.engine
        .on_msg(b.id, CONN, ShareMsg::Redeem { rid: 5, proof });
    assert!(matches!(
        drain_msgs(&mut a, b.id)[..],
        [ShareMsg::Pending { rid: 5, .. }]
    ));
}

#[test]
fn late_messages_of_the_last_exchange_are_ignored_other_rids_close() {
    let (mut a, mut b, _, wire) = redeemed(500, CODE);
    let rid = wire.b_to_a[0].rid();
    a.engine.reject().unwrap();
    pump(&mut a, &mut b);
    assert_eq!(b.engine.view().receive.unwrap().state, "failed");
    b.engine.take_events();
    // A late Pending for the finished rid: ignored.
    b.engine.on_msg(
        a.id,
        CONN,
        ShareMsg::Pending {
            rid,
            seconds_left: 10,
        },
    );
    assert!(!closed(&b.engine.take_events()));
    // Any other rid: protocol error.
    b.engine.on_msg(
        a.id,
        CONN,
        ShareMsg::Pending {
            rid: rid ^ 1,
            seconds_left: 10,
        },
    );
    assert!(closed(&b.engine.take_events()));
}

#[test]
fn share_data_outside_a_transfer_is_a_protocol_error() {
    let (_a, mut b, _, _) = redeemed(500, CODE);
    let a_id = PeerId([1; 32]);
    b.engine.on_data(a_id, CONN, &[1, 2, 3]);
    assert!(closed(&b.engine.take_events()));
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("channel_lost")
    );
    assert_eq!(b.received.partial_count(), 0);
}

/// Delivers only A's `Offer` to B.
fn offer_only(a: &mut ShareDevice, b: &mut ShareDevice) {
    match a.engine.poll_outgoing(b.id, 1).pop() {
        Some(wallet_sync::share::OutFrame::Msg(m @ ShareMsg::Offer { .. })) => {
            b.engine.on_msg(a.id, CONN, m)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn more_bytes_than_offered_or_an_early_end_close_and_delete_the_partial() {
    // Too many bytes.
    let (mut a, mut b, _, wire) = redeemed(500, CODE);
    let rid = wire.b_to_a[0].rid();
    a.engine.accept(b.id, &|_| true).unwrap();
    offer_only(&mut a, &mut b);
    b.engine.on_data(a.id, CONN, &[0; 400]);
    assert_eq!(b.received.partial_count(), 1);
    b.engine.on_data(a.id, CONN, &[0; 101]);
    assert!(closed(&b.engine.take_events()));
    assert_eq!(b.received.partial_count(), 0);
    assert!(b.received.list().unwrap().is_empty());

    // End with fewer bytes.
    let (mut a, mut b, _, wire) = redeemed(500, CODE);
    let rid2 = wire.b_to_a[0].rid();
    a.engine.accept(b.id, &|_| true).unwrap();
    offer_only(&mut a, &mut b);
    b.engine.on_data(a.id, CONN, &[0; 499]);
    b.engine.on_msg(a.id, CONN, ShareMsg::End { rid: rid2 });
    assert!(closed(&b.engine.take_events()));
    assert_eq!(b.received.partial_count(), 0);
    assert!(b.received.list().unwrap().is_empty());
    let _ = rid;
}

#[test]
fn a_second_exchange_on_the_same_channel_and_redeem_floods_close() {
    let (mut a, b, _, _) = redeemed(500, CODE);
    a.engine.take_events();
    let proof = redeem_proof(CODE, &SESSION, &a.id, &b.id, 77);
    a.engine
        .on_msg(b.id, CONN, ShareMsg::Redeem { rid: 77, proof });
    let events = a.engine.take_events();
    assert!(closed(&events), "{events:?}");
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("channel_lost")));

    // A flood of Redeems from a third device: the first consumes, the next ones close.
    let (mut a, _b, _) = invited(500);
    let c = PeerId([3; 32]);
    a.engine.channel_up(c, 9, [9; 32], true);
    for rid in 0..100u32 {
        a.engine.on_msg(
            c,
            9,
            ShareMsg::Redeem {
                rid,
                proof: [0; 32],
            },
        );
    }
    let events = a.engine.take_events();
    assert!(closed(&events));
    let refused = events
        .iter()
        .filter(|e| matches!(e, ShareEvent::RedeemRefused { .. }))
        .count();
    assert!(refused <= 8, "bounded work: {refused}");
    assert!(
        drain_msgs(&mut a, c).is_empty(),
        "the closed channel gets nothing more"
    );
}

#[test]
fn share_messages_on_a_channel_without_share_support_are_dropped() {
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    let b = share_device(2);
    a.engine.channel_up(b.id, CONN, SESSION, false);
    a.engine
        .create(invite_wallet("Personal"), b.id, code(CODE))
        .unwrap();
    a.engine.take_events();
    let proof = redeem_proof(CODE, &SESSION, &a.id, &b.id, 1);
    a.engine
        .on_msg(b.id, CONN, ShareMsg::Redeem { rid: 1, proof });
    a.engine.on_data(b.id, CONN, &[1, 2]);
    assert!(a.engine.take_events().is_empty());
    assert!(drain_msgs(&mut a, b.id).is_empty());
    assert_eq!(a.engine.view().invitation.unwrap().state, "active");
}
