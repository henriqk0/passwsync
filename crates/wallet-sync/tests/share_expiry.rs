//! 005 T055 (US3, FR-005): the 5-minute validity on the sender's clock, checked at every
//! step before `Offer`; a transfer started in time finishes within the 004 bounds.

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::share::AcceptError;
use wallet_sync::share::codec::ShareMsg;

#[test]
fn pending_reports_the_seconds_left_on_the_sender_clock() {
    let (mut a, mut b, _) = invited(500);
    advance(&a, Duration::from_secs(100));
    // The recipient's clocks are irrelevant.
    advance(&b, Duration::from_secs(5_000));
    b.wall.set(T0 + 1_000_000);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.sender_channel(a.id, CONN);
    let wire = pump(&mut a, &mut b);
    assert!(matches!(
        wire.a_to_b[0],
        ShareMsg::Pending {
            seconds_left: 200,
            ..
        }
    ));
}

#[test]
fn a_redeem_just_before_expiry_gets_one_second_and_accept_at_expiry_fails() {
    let (mut a, mut b, _) = invited(500);
    advance(&a, Duration::from_millis(299_500));
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.sender_channel(a.id, CONN);
    let wire = pump(&mut a, &mut b);
    assert!(matches!(
        wire.a_to_b[0],
        ShareMsg::Pending {
            seconds_left: 1,
            ..
        }
    ));
    advance(&a, Duration::from_millis(500));
    assert_eq!(a.engine.accept(b.id, &|_| true), Err(AcceptError::Expired));
    let wire = pump(&mut a, &mut b);
    assert!(
        !wire
            .a_to_b
            .iter()
            .any(|m| matches!(m, ShareMsg::Offer { .. }))
    );
    assert_eq!(
        wire.data_a_to_b, 0,
        "a transfer not started by expiry never starts"
    );
}

#[test]
fn a_transfer_started_before_expiry_finishes_after_it() {
    let (mut a, mut b, bytes, _) = redeemed(3000, CODE);
    advance(&a, Duration::from_secs(299));
    a.engine.accept(b.id, &|_| true).unwrap();
    advance(&a, Duration::from_secs(20));
    a.engine.tick();
    assert_eq!(a.engine.view().invitation.unwrap().state, "transferring");
    pump(&mut a, &mut b);
    assert_eq!(a.engine.view().invitation.unwrap().state, "completed");
    let id = b.received.list().unwrap()[0].id;
    assert_eq!(b.received.read(id).unwrap(), bytes);
}

use wallet_sync::ports::ReceivedStore;

#[test]
fn a_stalled_transfer_fails_after_30_seconds_without_progress() {
    let (mut a, mut b, _, _) = redeemed(3000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    // One frame each way, then silence.
    for f in a.engine.poll_outgoing(b.id, 2) {
        match f {
            wallet_sync::share::OutFrame::Msg(m) => b.engine.on_msg(a.id, CONN, m),
            wallet_sync::share::OutFrame::Data(d) => b.engine.on_data(a.id, CONN, &d),
        }
    }
    advance(&a, Duration::from_secs(29));
    a.engine.tick();
    assert_eq!(a.engine.view().invitation.unwrap().state, "transferring");
    advance(&a, Duration::from_secs(1));
    a.engine.tick();
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("timeout")));
    // The recipient's own bound removes its partial file too.
    advance(&b, Duration::from_secs(30));
    b.engine.tick();
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("timeout"));
    assert_eq!(b.received.partial_count(), 0);
}

#[test]
fn a_transfer_never_lasts_longer_than_15_minutes() {
    let (mut a, mut b, _, _) = redeemed(200_000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    // Steady trickle: progress every 20 s, but the total bound still applies.
    for _ in 0..45 {
        for f in a.engine.poll_outgoing(b.id, 1) {
            match f {
                wallet_sync::share::OutFrame::Msg(m) => b.engine.on_msg(a.id, CONN, m),
                wallet_sync::share::OutFrame::Data(d) => b.engine.on_data(a.id, CONN, &d),
            }
        }
        advance(&a, Duration::from_secs(20));
        a.engine.tick();
    }
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("timeout")));
}
