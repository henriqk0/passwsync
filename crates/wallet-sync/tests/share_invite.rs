//! 005 T025: invitation creation and eligibility (data-model.md "Invitation", FR-002,
//! FR-004, FR-005, FR-008).

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::ports::SyncStore;
use wallet_sync::share::{CreateError, Ineligible};

#[test]
fn an_eligible_unlocked_wallet_gets_an_active_invitation_for_one_recipient() {
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    let b = share_device(2);
    a.engine
        .create(invite_wallet("Personal"), b.id, code(CODE))
        .unwrap();
    let view = a.engine.view().invitation.expect("invitation");
    assert_eq!(view.state, "active");
    assert_eq!(view.wallet, "Personal");
    assert_eq!(view.recipient, b.id);
    assert_eq!(view.code.as_deref().map(String::as_str), Some(CODE));
    assert_eq!(view.expires_in, 300);
    assert!(view.progress.is_none() && view.reason.is_none());
    advance(&a, Duration::from_secs(100));
    assert_eq!(a.engine.view().invitation.unwrap().expires_in, 200);
}

#[test]
fn the_invitation_expires_exactly_300_seconds_after_creation() {
    let (a, _b, _) = invited(500);
    advance(&a, Duration::from_millis(299_999));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.state, "active");
    assert!(view.code.is_some());
    advance(&a, Duration::from_millis(1));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.state, "expired");
    assert!(view.code.is_none(), "code shown only while active");
    assert_eq!(view.expires_in, 0);
}

fn refused(dev: &mut ShareDevice, wallet: wallet_sync::share::InviteWallet) -> CreateError {
    let err = dev
        .engine
        .create(wallet, wallet_sync::ports::PeerId([2; 32]), code(CODE))
        .unwrap_err();
    assert!(dev.engine.view().invitation.is_none(), "nothing created");
    err
}

#[test]
fn ineligible_wallets_are_refused_with_the_reason() {
    // Format version 1.
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    let mut v1 = invite_wallet("Personal");
    v1.format = 1;
    assert_eq!(
        refused(&mut a, v1),
        CreateError::Ineligible(Ineligible::FormatV1)
    );

    // No sync record.
    let mut a = share_device(1);
    a.source.set("Personal", support::file_bytes(1, 500));
    assert_eq!(
        refused(&mut a, invite_wallet("Personal")),
        CreateError::Ineligible(Ineligible::NoRecord)
    );

    // Possible rollback.
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    a.store
        .update(&wallet_id(1), &mut |r| {
            let mut r = r?;
            r.flags.rollback_state = true;
            Some(r)
        })
        .unwrap();
    assert_eq!(
        refused(&mut a, invite_wallet("Personal")),
        CreateError::Ineligible(Ineligible::PossibleRollback)
    );

    // Disabled (duplicate wallet id or too many conflicts).
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    a.store
        .update(&wallet_id(1), &mut |r| {
            let mut r = r?;
            r.flags.duplicate_wallet_id = true;
            Some(r)
        })
        .unwrap();
    assert_eq!(
        refused(&mut a, invite_wallet("Personal")),
        CreateError::Ineligible(Ineligible::Disabled)
    );

    // The file changed since its record (digest differs).
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    a.source.set("Personal", support::file_bytes(9, 500));
    assert_eq!(
        refused(&mut a, invite_wallet("Personal")),
        CreateError::Ineligible(Ineligible::Changed)
    );

    // The record belongs to another local name.
    let mut a = share_device(1);
    eligible_wallet(&a, "Personal", 500);
    assert_eq!(
        refused(&mut a, invite_wallet("Other")),
        CreateError::Ineligible(Ineligible::NoRecord)
    );
}

#[test]
fn reason_words_match_the_http_contract() {
    for (reason, word) in [
        (Ineligible::FormatV1, "format_v1"),
        (Ineligible::PossibleRollback, "possible_rollback"),
        (Ineligible::Disabled, "disabled"),
        (Ineligible::NoRecord, "no_record"),
        (Ineligible::Changed, "changed"),
    ] {
        assert_eq!(reason.word(), word);
    }
}

#[test]
fn debug_output_never_shows_the_code() {
    let (a, _b, _) = invited(500);
    let view = a.engine.view();
    for text in [format!("{view:?}"), format!("{:?}", a.engine)] {
        assert!(!text.contains(CODE), "{text}");
        assert!(!text.contains("1234"), "{text}");
    }
}
