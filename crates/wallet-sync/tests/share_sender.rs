//! 005 T026: the sender's exchange (contracts/share-protocol.md "Exchange" steps 1-4, FR-014,
//! FR-016, FR-017).

mod support;

use std::time::Duration;

use support::share::*;
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{AcceptError, OutFrame, ShareEvent};

#[test]
fn a_valid_redeem_is_answered_with_pending_and_wipes_the_code() {
    let (a, b, _, wire) = redeemed(2500, CODE);
    assert_eq!(wire.b_to_a.len(), 1);
    let ShareMsg::Redeem { rid, .. } = wire.b_to_a[0] else {
        panic!("{:?}", wire.b_to_a)
    };
    assert_eq!(
        wire.a_to_b,
        vec![ShareMsg::Pending {
            rid,
            seconds_left: 300
        }]
    );
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.state, "awaiting_acceptance");
    assert!(view.code.is_none(), "code wiped after the first Redeem");
    assert_eq!(view.recipient, b.id);
    assert_eq!(wire.data_a_to_b, 0, "nothing sent before acceptance");
}

#[test]
fn accept_streams_the_stored_file_and_completes_on_stored() {
    let (mut a, mut b, bytes, _) = redeemed(2500, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    assert_eq!(a.engine.view().invitation.unwrap().state, "transferring");
    let wire = pump(&mut a, &mut b);
    let rid = wire.a_to_b[0].rid();
    assert_eq!(
        wire.a_to_b,
        vec![ShareMsg::Offer { rid, size: 2500 }, ShareMsg::End { rid }]
    );
    assert_eq!(wire.data_a_to_b, 2500, "exactly size bytes");
    assert_eq!(wire.b_to_a, vec![ShareMsg::Stored { rid }]);
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.state, "completed");
    assert!(view.reason.is_none());
    let stored = b.received.list().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(b.received.read(stored[0].id).unwrap(), bytes);
    let events = a.engine.take_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ShareEvent::TransferCompleted { bytes: 2500, .. }))
    );
}

use wallet_sync::ports::ReceivedStore;

#[test]
fn chunks_are_at_most_1000_bytes_and_progress_is_reported() {
    let (mut a, b, _, _) = redeemed(2500, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    let frames = a.engine.poll_outgoing(b.id, 2);
    assert!(matches!(frames[0], OutFrame::Msg(ShareMsg::Offer { .. })));
    match &frames[1] {
        OutFrame::Data(bytes) => assert_eq!(bytes.len(), 1000),
        other => panic!("{other:?}"),
    }
    let view = a.engine.view().invitation.unwrap();
    assert_eq!(view.progress, Some((1000, 2500)));
    let rest = a.engine.poll_outgoing(b.id, 64);
    let sizes: Vec<usize> = rest
        .iter()
        .filter_map(|f| match f {
            OutFrame::Data(d) => Some(d.len()),
            _ => None,
        })
        .collect();
    assert_eq!(sizes, vec![1000, 500]);
}

#[test]
fn only_ciphertext_and_non_secret_messages_travel() {
    let (mut a, mut b, bytes, mut wire) = redeemed(3000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    let rest = pump(&mut a, &mut b);
    wire.raw.extend_from_slice(&rest.raw);
    let raw = &wire.raw;
    let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(b"Personal"), "no wallet name");
    assert!(!contains(&[1u8; 16]), "no wallet id");
    assert!(!contains(CODE.as_bytes()), "no code");
    // Everything besides the share messages is the stored file itself.
    let msgs: usize = wire
        .a_to_b
        .iter()
        .chain(&wire.b_to_a)
        .chain(&rest.a_to_b)
        .chain(&rest.b_to_a)
        .map(|m| m.encode().len())
        .sum();
    assert_eq!(raw.len(), msgs + bytes.len());
}

#[test]
fn the_snapshot_is_taken_at_the_start_of_the_transfer() {
    let (mut a, mut b, bytes, _) = redeemed(2500, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    // A save after the transfer started renames a new file; the open handle is unaffected.
    a.source.set("Personal", support::file_bytes(0x11, 2600));
    pump(&mut a, &mut b);
    assert_eq!(a.engine.view().invitation.unwrap().state, "completed");
    let id = b.received.list().unwrap()[0].id;
    assert_eq!(b.received.read(id).unwrap(), bytes);
}

#[test]
fn a_file_that_does_not_match_its_record_aborts_as_sender_error() {
    let (mut a, mut b, _, _) = redeemed(2500, CODE);
    a.source
        .change_on_open("Personal", support::file_bytes(0x12, 2500));
    a.engine.accept(b.id, &|_| true).unwrap();
    let wire = pump(&mut a, &mut b);
    let rid = wire.a_to_b[0].rid();
    assert!(wire.a_to_b.contains(&ShareMsg::Abort {
        rid,
        reason: AbortReason::SenderError
    }));
    assert!(!wire.a_to_b.contains(&ShareMsg::End { rid }));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("sender_error")));
    assert!(b.received.list().unwrap().is_empty(), "nothing kept on B");
    assert_eq!(b.received.partial_count(), 0);
}

#[test]
fn accept_rechecks_recipient_expiry_lock_and_slots() {
    let (mut a, b, _, _) = redeemed(500, CODE);
    assert_eq!(
        a.engine
            .accept(wallet_sync::ports::PeerId([9; 32]), &|_| true),
        Err(AcceptError::Mismatch)
    );
    assert_eq!(
        a.engine.view().invitation.unwrap().state,
        "awaiting_acceptance",
        "a mismatch changes nothing"
    );
    assert_eq!(
        a.engine.accept(b.id, &|_| false),
        Err(AcceptError::WalletLocked)
    );
    assert_eq!(a.engine.view().invitation.unwrap().state, "cancelled");

    let (mut a, b, _, _) = redeemed(500, CODE);
    advance(&a, Duration::from_secs(300));
    assert_eq!(a.engine.accept(b.id, &|_| true), Err(AcceptError::Expired));
    assert_eq!(a.engine.view().invitation.unwrap().state, "expired");

    let (mut a, b, _, _) = redeemed(500, CODE);
    let _one = a.slots.try_take().unwrap();
    let _two = a.slots.try_take().unwrap();
    assert_eq!(a.engine.accept(b.id, &|_| true), Err(AcceptError::Busy));
    let view = a.engine.view().invitation.unwrap();
    assert_eq!((view.state, view.reason), ("failed", Some("busy")));

    let mut fresh = share_device(5);
    assert_eq!(
        fresh.engine.accept(b.id, &|_| true),
        Err(AcceptError::NothingPending)
    );
}

#[test]
fn a_transfer_holds_one_shared_slot_until_it_ends() {
    let (mut a, mut b, _, _) = redeemed(5000, CODE);
    a.engine.accept(b.id, &|_| true).unwrap();
    assert_eq!(a.slots.active(), 1);
    pump(&mut a, &mut b);
    assert_eq!(a.slots.active(), 0);
    assert_eq!(b.slots.active(), 0, "the recipient's slot is released too");
}
