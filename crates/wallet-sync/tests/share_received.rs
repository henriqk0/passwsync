//! 005 T065 (US4, FR-018, FR-022, FR-022a, FR-023): received wallets are bounded, can be
//! discarded, expire after 24 hours, go with a revoked sender; notices are bounded.

mod support;

use support::share::*;
use wallet_sync::ports::{PeerId, ReceivedMeta, ReceivedStore};
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{DeleteCause, DiscardError, NoticeKind, RedeemError, ShareEvent};

fn put(dev: &ShareDevice, n: u8, sender: PeerId, received_at: u64) {
    dev.received.put(
        ReceivedMeta {
            id: [n; 16],
            sender,
            received_at,
            size: 100,
        },
        support::file_bytes(n, 100),
    );
}

#[test]
fn at_most_eight_received_wallets() {
    let (a, mut b, _) = invited(500);
    for n in 0..8 {
        put(&b, n, a.id, T0);
    }
    assert_eq!(
        b.engine.redeem(Some(a.id), code(CODE)),
        Err(RedeemError::ReceivedLimit)
    );
    // With room at redemption but full again at the offer: Abort(received_limit).
    let (mut a, mut b, _, _) = redeemed(500, CODE);
    for n in 0..8 {
        put(&b, n, a.id, T0);
    }
    a.engine.accept(b.id, &|_| true).unwrap();
    let wire = pump(&mut a, &mut b);
    assert!(wire.b_to_a.iter().any(|m| matches!(
        m,
        ShareMsg::Abort {
            reason: AbortReason::ReceivedLimit,
            ..
        }
    )));
    assert_eq!(
        b.engine.view().receive.unwrap().reason,
        Some("received_limit")
    );
    assert_eq!(
        a.engine.view().invitation.unwrap().reason,
        Some("received_limit")
    );
    assert_eq!(b.received.list().unwrap().len(), 8);
}

#[test]
fn discard_deletes_the_ciphertext() {
    let mut b = share_device(2);
    let sender = PeerId([1; 32]);
    put(&b, 1, sender, T0);
    assert_eq!(b.engine.discard([1; 16]), Ok(sender));
    assert!(b.received.list().unwrap().is_empty());
    assert_eq!(b.received.read([1; 16]).ok(), None);
    assert_eq!(b.engine.discard([1; 16]), Err(DiscardError::NotFound));
}

#[test]
fn received_wallets_expire_after_24_hours_or_when_dated_in_the_future() {
    let mut b = share_device(2);
    let s1 = PeerId([1; 32]);
    let s2 = PeerId([3; 32]);
    put(&b, 1, s1, T0);
    put(&b, 2, s2, T0 + 301); // more than 5 minutes in the future
    put(&b, 3, s1, T0 + 300); // exactly 5 minutes: kept
    let events = b.engine.tick();
    assert_eq!(
        b.received
            .list()
            .unwrap()
            .iter()
            .map(|m| m.id[0])
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert!(events.contains(&ShareEvent::ReceivedDeleted {
        sender: s2,
        why: DeleteCause::Expired
    }));
    b.wall.set(T0 + 86_399);
    b.engine.tick();
    assert_eq!(b.received.list().unwrap().len(), 2);
    b.wall.set(T0 + 86_400);
    let events = b.engine.tick();
    assert_eq!(
        b.received
            .list()
            .unwrap()
            .iter()
            .map(|m| m.id[0])
            .collect::<Vec<_>>(),
        vec![3]
    );
    assert!(events.contains(&ShareEvent::ReceivedDeleted {
        sender: s1,
        why: DeleteCause::Expired
    }));
    let kinds: Vec<NoticeKind> = b
        .engine
        .view()
        .notices
        .into_iter()
        .map(|n| n.kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            NoticeKind::ReceivedExpired { sender: s2 },
            NoticeKind::ReceivedExpired { sender: s1 }
        ]
    );
}

#[test]
fn a_revoked_sender_takes_its_received_wallets_with_it() {
    let mut b = share_device(2);
    let s1 = PeerId([1; 32]);
    let s2 = PeerId([3; 32]);
    put(&b, 1, s1, T0);
    put(&b, 2, s1, T0);
    put(&b, 3, s2, T0);
    b.engine.peer_revoked(s1);
    assert_eq!(
        b.received
            .list()
            .unwrap()
            .iter()
            .map(|m| m.id[0])
            .collect::<Vec<_>>(),
        vec![3]
    );
    let events = b.engine.take_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                ShareEvent::ReceivedDeleted {
                    why: DeleteCause::Revoked,
                    ..
                }
            ))
            .count(),
        2
    );
    let kinds: Vec<NoticeKind> = b
        .engine
        .view()
        .notices
        .into_iter()
        .map(|n| n.kind)
        .collect();
    assert_eq!(
        kinds,
        vec![NoticeKind::ReceivedDeletedRevoked { sender: s1 }]
    );
}

#[test]
fn notices_are_bounded_and_dismissal_removes_only_the_notice() {
    let mut b = share_device(2);
    let ids: Vec<u64> = (0..20)
        .map(|n| {
            b.engine
                .push_notice(NoticeKind::ReceivedCleaned { count: n })
        })
        .collect();
    let notices = b.engine.view().notices;
    assert_eq!(notices.len(), 16);
    assert_eq!(
        notices[0].kind,
        NoticeKind::ReceivedCleaned { count: 4 },
        "oldest dropped"
    );
    put(&b, 1, PeerId([1; 32]), T0);
    b.engine.dismiss(&[ids[19], ids[4]]);
    let notices = b.engine.view().notices;
    assert_eq!(notices.len(), 14);
    assert!(notices.iter().all(|n| n.id != ids[19] && n.id != ids[4]));
    assert_eq!(b.received.list().unwrap().len(), 1, "data untouched");
}
