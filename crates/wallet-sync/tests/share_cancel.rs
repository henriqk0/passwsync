//! 005 T064 (US4, FR-009, FR-014, FR-015, SC-004): either side can stop a share at any point
//! before it completes, leaving nothing on the recipient.

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::ports::ReceivedStore;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{CancelOutcome, OutFrame};

fn aborted(msgs: &[ShareMsg], reason: AbortReason) -> bool {
    msgs.iter()
        .any(|m| matches!(m, ShareMsg::Abort { reason: r, .. } if *r == reason))
}

/// Delivers A's frames to B up to `max` frames (the Offer and some chunks).
fn partial_transfer(a: &mut ShareDevice, b: &mut ShareDevice, max: usize) {
    for f in a.engine.poll_outgoing(b.id, max) {
        match f {
            OutFrame::Msg(m) => b.engine.on_msg(a.id, CONN, m),
            OutFrame::Data(d) => b.engine.on_data(a.id, CONN, &d),
        }
    }
}

#[test]
fn sender_cancel_works_in_every_live_state() {
    // Active.
    let (mut a, _b, _) = invited(500);
    assert_eq!(a.engine.cancel(), CancelOutcome::Cancelled);
    assert_eq!(a.engine.view().invitation.unwrap().state, "cancelled");
    assert_eq!(a.engine.cancel(), CancelOutcome::Nothing);

    // Awaiting acceptance: the recipient is told at once.
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    assert_eq!(a.engine.cancel(), CancelOutcome::Cancelled);
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire.a_to_b, AbortReason::Cancelled));
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("cancelled_by_sender")
    );

    // Transferring: the transfer stops and the partial file is deleted.
    let (mut a, mut b, _, _) = redeemed(5000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    partial_transfer(&mut a, &mut b, 3);
    assert_eq!(b.received.partial_count(), 1);
    assert_eq!(a.engine.cancel(), CancelOutcome::Cancelled);
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire.a_to_b, AbortReason::Cancelled));
    assert_eq!(wire.data_a_to_b, 0, "no more data after the cancel");
    assert_eq!(b.received.partial_count(), 0);
    assert!(b.received.list().unwrap().is_empty());
    assert_eq!(a.slots.active(), 0, "slot released");
}

#[test]
fn after_completion_cancel_reports_already_delivered() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.engine.cancel(), CancelOutcome::AlreadyDelivered);
    assert_eq!(a.engine.view().invitation.unwrap().state, "completed");
    assert_eq!(
        b.received.list().unwrap().len(),
        1,
        "the copy stays delivered"
    );
}

#[test]
fn no_decision_before_expiry_aborts_as_expired() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    advance(&a, Duration::from_secs(300));
    a.engine.tick();
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire.a_to_b, AbortReason::Expired));
}

#[test]
fn the_recipient_can_cancel_at_every_stage() {
    // While connecting: nothing to tell anyone.
    let (a, mut b, _) = invited(500);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.cancel_redemption();
    let view = b.engine.view().receive.unwrap();
    assert_eq!((view.state, view.reason), ("cancelled", None));
    assert!(drain_msgs(&mut b, a.id).is_empty());

    // Waiting for the sender.
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    b.engine.cancel_redemption();
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire.b_to_a, AbortReason::RecipientCancelled));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(
        (view.state, view.reason),
        ("failed", Some("recipient_cancelled"))
    );
    assert_eq!(b.engine.view().receive.unwrap().state, "cancelled");

    // Receiving: the partial file goes.
    let (mut a, mut b, _, _) = redeemed(5000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    partial_transfer(&mut a, &mut b, 3);
    assert_eq!(b.received.partial_count(), 1);
    b.engine.cancel_redemption();
    assert_eq!(b.received.partial_count(), 0);
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire.b_to_a, AbortReason::RecipientCancelled));
    assert_eq!(
        a.engine.view().invitation.unwrap().reason,
        Some("recipient_cancelled")
    );
    assert!(b.received.list().unwrap().is_empty());
}

#[test]
fn channel_loss_deletes_the_partial_and_consumes_the_invitation() {
    let (mut a, mut b, _, _) = redeemed(5000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    partial_transfer(&mut a, &mut b, 3);
    b.engine.channel_down(a.id, CONN);
    a.engine.channel_down(b.id, CONN);
    assert_eq!(b.received.partial_count(), 0);
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("channel_lost")
    );
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("channel_lost")));
    // Single use: a new channel and the same code are refused.
    link(&mut a, &mut b, 2, [2; 32]);
    b.engine.redeem(Some(a.id), code(CODE)).unwrap();
    b.engine.sender_channel(a.id, 2);
    let wire = pump_conn(&mut a, &mut b, 2);
    assert!(aborted(&wire.a_to_b, AbortReason::Invalid));
    assert_eq!(wire.data_a_to_b, 0);
}
