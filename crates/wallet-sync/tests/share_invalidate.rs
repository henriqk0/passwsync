//! 005 T053 (US3, FR-010, SC-003): every way an invitation ends; nothing is ever offered after
//! it, and a late `Redeem` from the recipient learns the precise reason from a code-less
//! tombstone.

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::ports::PeerId;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{CancelOutcome, InvitationEnd, Refusal, ShareEvent};

/// `dev` redeems `typed` towards `a` on a fresh channel `conn`; returns everything A sent.
fn redeem_on(a: &mut ShareDevice, dev: &mut ShareDevice, conn: u64, typed: &str) -> Wire {
    link(a, dev, conn, [conn as u8; 32]);
    dev.engine.redeem(Some(a.id), code(typed)).unwrap();
    dev.engine.sender_channel(a.id, conn);
    pump_conn(a, dev, conn)
}

fn aborted(wire: &Wire, reason: AbortReason) -> bool {
    wire.a_to_b
        .iter()
        .any(|m| matches!(m, ShareMsg::Abort { reason: r, .. } if *r == reason))
}

fn nothing_offered(wire: &Wire) {
    assert!(
        !wire
            .a_to_b
            .iter()
            .any(|m| matches!(m, ShareMsg::Offer { .. } | ShareMsg::End { .. })),
        "{:?}",
        wire.a_to_b
    );
    assert_eq!(wire.data_a_to_b, 0);
}

fn refusals(a: &mut ShareDevice) -> Vec<Refusal> {
    a.engine
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            ShareEvent::RedeemRefused { why, .. } => Some(why),
            _ => None,
        })
        .collect()
}

#[test]
fn a_completed_invitation_answers_used() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    pump(&mut a, &mut b);
    assert_eq!(a.engine.view().invitation.unwrap().state, "completed");
    let wire = redeem_on(&mut a, &mut b, 2, CODE);
    assert!(aborted(&wire, AbortReason::Invalid));
    nothing_offered(&wire);
    assert_eq!(refusals(&mut a), vec![Refusal::Used]);
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("invalid"));
}

#[test]
fn expiry_while_active_and_while_awaiting_acceptance() {
    let (mut a, mut b, _) = invited(500);
    advance(&a, Duration::from_secs(300));
    let wire = redeem_on(&mut a, &mut b, 1, CODE);
    assert!(aborted(&wire, AbortReason::Expired));
    nothing_offered(&wire);
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("expired"));

    let (mut a, mut b, _, _) = redeemed(500, CODE);
    advance(&a, Duration::from_secs(300));
    a.engine.tick();
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire, AbortReason::Expired));
    nothing_offered(&wire);
    assert_eq!(a.engine.view().invitation.unwrap().state, "expired");
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("expired"));
}

#[test]
fn cancel_before_redemption_is_told_to_a_late_redeem() {
    let (mut a, mut b, _) = invited(500);
    assert_eq!(a.engine.cancel(), CancelOutcome::Cancelled);
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("cancelled", Some("by_person")));
    let wire = redeem_on(&mut a, &mut b, 1, CODE);
    assert!(aborted(&wire, AbortReason::Cancelled));
    nothing_offered(&wire);
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("cancelled_by_sender")
    );
}

#[test]
fn reject_ends_the_exchange_and_the_invitation() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine.reject().unwrap();
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire, AbortReason::Rejected));
    nothing_offered(&wire);
    assert_eq!(a.engine.view().invitation.unwrap().state, "rejected");
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("rejected"));
    let wire = redeem_on(&mut a, &mut b, 2, CODE);
    assert!(aborted(&wire, AbortReason::Invalid), "used");
    nothing_offered(&wire);
}

#[test]
fn locking_the_wallet_before_the_transfer_cancels() {
    let (mut a, mut b, _) = invited(500);
    a.engine.wallet_locked("Other");
    assert_eq!(
        a.engine.view().invitation.unwrap().state,
        "active",
        "another wallet"
    );
    a.engine.wallet_locked("Personal");
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(
        (view.state, view.reason),
        ("cancelled", Some("wallet_locked"))
    );
    let wire = redeem_on(&mut a, &mut b, 1, CODE);
    assert!(aborted(&wire, AbortReason::Cancelled));

    // While the recipient waits for acceptance it is told at once.
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine.wallet_locked("Personal");
    let wire = pump(&mut a, &mut b);
    assert!(aborted(&wire, AbortReason::Cancelled));
    nothing_offered(&wire);
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("cancelled_by_sender")
    );
    assert!(a.engine.take_events().iter().any(|e| matches!(
        e,
        ShareEvent::InvitationEnded {
            end: InvitationEnd::Locked
        }
    )));
}

#[test]
fn one_wrong_code_consumes_the_invitation() {
    let (mut a, mut b, _, wire) = redeemed(500, "87654321");
    assert!(aborted(&wire, AbortReason::Invalid));
    nothing_offered(&wire);
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("refused", Some("wrong_code")));
    assert!(view.code.is_none());
    assert_eq!(refusals(&mut a), vec![Refusal::WrongCode]);
    // The right code afterwards is refused too: single attempt.
    let wire = redeem_on(&mut a, &mut b, 2, CODE);
    assert!(aborted(&wire, AbortReason::Invalid));
    nothing_offered(&wire);
    assert_eq!(refusals(&mut a), vec![Refusal::Used]);
}

#[test]
fn another_paired_device_with_the_right_code_is_refused_and_invalidates() {
    let (mut a, mut b, _) = invited(500);
    let mut c = share_device(3);
    let wire = redeem_on(&mut a, &mut c, 7, CODE);
    assert!(aborted(&wire, AbortReason::Invalid));
    nothing_offered(&wire);
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(
        (view.state, view.reason),
        ("refused", Some("not_recipient"))
    );
    assert_eq!(refusals(&mut a), vec![Refusal::NotRecipient]);
    // The real recipient now gets "invalid".
    let wire = redeem_on(&mut a, &mut b, 1, CODE);
    assert!(aborted(&wire, AbortReason::Invalid));
    nothing_offered(&wire);
}

#[test]
fn revoking_the_recipient_cancels() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine.peer_revoked(b.id);
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(
        (view.state, view.reason),
        ("cancelled", Some("recipient_revoked"))
    );
    let wire = pump(&mut a, &mut b);
    nothing_offered(&wire);
    // Revoking someone else changes nothing.
    let (mut a, _b, _) = invited(500);
    a.engine.peer_revoked(PeerId([9; 32]));
    assert_eq!(a.engine.view().invitation.unwrap().state, "active");
}

#[test]
fn a_new_invitation_replaces_the_previous_one() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    a.engine
        .create(invite_wallet("Personal"), b.id, code("11112222"))
        .unwrap();
    let wire = pump(&mut a, &mut b);
    assert!(
        aborted(&wire, AbortReason::Cancelled),
        "the waiting recipient is told"
    );
    nothing_offered(&wire);
    assert!(a.engine.take_events().iter().any(|e| matches!(
        e,
        ShareEvent::InvitationEnded {
            end: InvitationEnd::Replaced
        }
    )));
    assert_eq!(a.engine.view().invitation.unwrap().state, "active");
}

#[test]
fn the_tombstone_lasts_until_the_original_expiry() {
    let (mut a, mut b, _) = invited(500);
    a.engine.cancel();
    advance(&a, Duration::from_secs(299));
    a.engine.tick();
    let wire = redeem_on(&mut a, &mut b, 1, CODE);
    assert!(aborted(&wire, AbortReason::Cancelled));
    advance(&a, Duration::from_secs(1));
    a.engine.tick();
    let wire = redeem_on(&mut a, &mut b, 2, CODE);
    assert!(aborted(&wire, AbortReason::Invalid), "tombstone dropped");
    assert_eq!(refusals(&mut a).last(), Some(&Refusal::NoInvitation));
    // The engine never shows a code or wallet name in its Debug output.
    let text = format!("{:?}", a.engine);
    assert!(!text.contains(CODE) && !text.contains("Personal"));
}
