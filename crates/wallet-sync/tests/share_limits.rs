//! 005 T054 (US3, FR-007, FR-017): one active invitation, 5 per 10 minutes, busy while
//! transferring, no transfer without a free slot, the code dropped after the first `Redeem`.

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{AcceptError, CreateError};

#[test]
fn at_most_one_active_invitation() {
    let (mut a, b, _) = invited(500);
    a.engine
        .create(invite_wallet("Personal"), b.id, code("22223333"))
        .unwrap();
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.state, "active");
    assert_eq!(view.code.as_deref().map(String::as_str), Some("22223333"));
}

#[test]
fn five_creations_per_ten_minutes() {
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    let b = share_device(2);
    for _ in 0..5 {
        a.engine
            .create(invite_wallet("Personal"), b.id, code(CODE))
            .unwrap();
        advance(&a, Duration::from_secs(10));
    }
    assert_eq!(
        a.engine.create(invite_wallet("Personal"), b.id, code(CODE)),
        Err(CreateError::TooMany)
    );
    // Refused attempts do not count; after the window the oldest creation drops out.
    advance(&a, Duration::from_secs(600 - 50));
    a.engine
        .create(invite_wallet("Personal"), b.id, code(CODE))
        .unwrap();
    assert_eq!(
        a.engine.create(invite_wallet("Personal"), b.id, code(CODE)),
        Err(CreateError::TooMany)
    );
}

#[test]
fn creation_while_transferring_is_busy() {
    let (mut a, b, _, _) = redeemed(5000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    assert_eq!(
        a.engine.create(invite_wallet("Personal"), b.id, code(CODE)),
        Err(CreateError::Busy)
    );
    assert_eq!(a.engine.view().invitation.unwrap().state, "transferring");
}

#[test]
fn no_free_slot_at_accept_fails_the_invitation_with_busy() {
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    let _sync_one = a.slots.try_take().unwrap();
    let _sync_two = a.slots.try_take().unwrap();
    assert_eq!(a.engine.accept(b.id, &|_| true), Err(AcceptError::Busy));
    let wire = pump(&mut a, &mut b);
    assert!(wire.a_to_b.iter().any(|m| matches!(
        m,
        ShareMsg::Abort {
            reason: AbortReason::Busy,
            ..
        }
    )));
    assert_eq!(wire.data_a_to_b, 0);
    assert_eq!(b.engine.view().receive.unwrap().reason, Some("busy"));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("busy")));
}

#[test]
fn the_code_is_never_kept_after_the_first_redeem() {
    let (a, _b, _, _) = redeemed(500, CODE);
    assert!(a.engine.view().invitation.unwrap().code.is_none());
    let text = format!("{:?} {:?}", a.engine, a.engine.view());
    assert!(!text.contains(CODE));
}
