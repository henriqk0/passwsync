//! 005 T027: the recipient's exchange (contracts/share-protocol.md "Exchange", "Timeouts",
//! FR-011, FR-013, FR-015).

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::ports::ReceivedStore;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::proof::redeem_proof;
use wallet_sync::share::{OutFrame, RedeemError};

#[test]
fn redeem_sends_a_session_bound_proof_and_never_the_code() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    let view = b.engine.view().receive.unwrap();
    assert_eq!(view.state, "connecting");
    assert_eq!(view.sender, Some(a.id));
    assert!(
        drain_msgs(&mut b, a.id).is_empty(),
        "nothing before the channel"
    );
    b.engine.sender_channel(a.id, CONN);
    let msgs = drain_msgs(&mut b, a.id);
    let [ShareMsg::Redeem { rid, proof }] = msgs[..] else {
        panic!("{msgs:?}")
    };
    assert_eq!(proof, redeem_proof(CODE, &SESSION, &a.id, &b.id, rid));
    assert_eq!(b.engine.view().receive.unwrap().state, "awaiting_sender");
    let text = format!("{:?} {:?}", b.engine.view(), b.engine);
    assert!(!text.contains(CODE));
}

#[test]
fn rids_come_from_the_injected_rng() {
    let mut rids = Vec::new();
    for seed in [2u8, 3] {
        let mut a = share_device(1);
        let mut b = share_device(seed);
        link(&mut a, &mut b, CONN, SESSION);
        b.engine.redeem(Some(a.id), code(CODE)).unwrap();
        b.engine.sender_channel(a.id, CONN);
        rids.push(drain_msgs(&mut b, a.id)[0].rid());
    }
    assert_ne!(rids[0], rids[1]);
}

#[test]
fn the_whole_receive_stores_the_ciphertext_and_answers_stored() {
    let (mut a, mut b, bytes, _) = redeemed(2500, CODE);
    let view = b.engine.view().receive.unwrap();
    assert_eq!(view.state, "awaiting_sender");
    assert_eq!(view.seconds_left, Some(300));
    a.engine.accept(b.id, &|_| true).unwrap();
    // Offer plus one chunk: the partial exists, nothing listed yet.
    for f in a.engine.poll_outgoing(b.id, 2) {
        match f {
            OutFrame::Msg(m) => b.engine.on_msg(a.id, CONN, m),
            OutFrame::Data(d) => b.engine.on_data(a.id, CONN, &d),
        }
    }
    let view = b.engine.view().receive.unwrap();
    assert_eq!(view.state, "receiving");
    assert_eq!(view.progress, Some((1000, 2500)));
    assert_eq!(b.received.partial_count(), 1);
    assert!(b.received.list().unwrap().is_empty());
    pump(&mut a, &mut b);
    let view = b.engine.view().receive.unwrap();
    assert_eq!(view.state, "stored");
    let listed = b.received.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(view.received_id, Some(listed[0].id));
    assert_eq!(listed[0].sender, a.id);
    assert_eq!(listed[0].received_at, T0);
    assert_eq!(listed[0].size, 2500);
    assert_eq!(b.received.read(listed[0].id).unwrap(), bytes);
    assert_eq!(b.received.partial_count(), 0);
}

#[test]
fn the_answer_to_redeem_is_awaited_10_seconds() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.sender_channel(a.id, CONN);
    let rid = drain_msgs(&mut b, a.id)[0].rid();
    advance(&b, Duration::from_millis(9_999));
    b.engine.tick();
    assert_eq!(b.engine.view().receive.unwrap().state, "awaiting_sender");
    advance(&b, Duration::from_millis(1));
    b.engine.tick();
    let view = b.engine.view().receive.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("timeout")));
    assert_eq!(
        drain_msgs(&mut b, a.id),
        vec![ShareMsg::Abort {
            rid,
            reason: AbortReason::RecipientCancelled
        }]
    );
}

#[test]
fn pending_extends_the_wait_to_seconds_left_plus_10() {
    let (_a, mut b, _, _) = redeemed(500, CODE);
    advance(&b, Duration::from_secs(309));
    b.engine.tick();
    assert_eq!(b.engine.view().receive.unwrap().state, "awaiting_sender");
    advance(&b, Duration::from_secs(1));
    b.engine.tick();
    let view = b.engine.view().receive.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("timeout")));
}

#[test]
fn the_channel_is_awaited_at_most_300_seconds() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    advance(&b, Duration::from_secs(299));
    b.engine.tick();
    assert_eq!(b.engine.view().receive.unwrap().state, "connecting");
    advance(&b, Duration::from_secs(1));
    b.engine.tick();
    let view = b.engine.view().receive.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("unreachable")));
}

#[test]
fn one_redemption_at_a_time() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    assert_eq!(
        b.engine.redeem(Some(a.id), code(CODE)),
        Err(RedeemError::Busy)
    );
    b.engine.sender_channel(a.id, CONN);
    assert_eq!(
        b.engine.redeem(Some(a.id), code(CODE)),
        Err(RedeemError::Busy)
    );
}

#[test]
fn an_offer_before_pending_is_a_protocol_error() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.sender_channel(a.id, CONN);
    let rid = drain_msgs(&mut b, a.id)[0].rid();
    b.engine
        .on_msg(a.id, CONN, ShareMsg::Offer { rid, size: 500 });
    assert!(closed(&b.engine.take_events()));
    assert_eq!(b.engine.view().receive.unwrap().state, "failed");
    assert_eq!(b.received.partial_count(), 0);
}

#[test]
fn a_connection_failure_is_reported_with_its_reason() {
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine
        .connect_failed(wallet_sync::share::ReceiveFailure::IdMismatch);
    let view = b.engine.view().receive.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("id_mismatch")));
    // A new redemption may start afterwards.
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
}
