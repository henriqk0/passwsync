//! Revocation (US5, FR-033, FR-034): local, saved first, refuses the revoked key, and only a
//! new pairing restores trust.

mod support;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::error::{Error, FailReason};
use device_link::link::{Link, PeerStatus, Refusal, Timing};
use device_link::pairing::InitiatorState;
use support::{Device, NOW_UNIX, Run, code};

fn paired() -> (Device, Device) {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let pin = a.pin_of(&b);
    a.reg.pin(pin).unwrap();
    let pin = b.pin_of(&a);
    b.reg.pin(pin).unwrap();
    (a, b)
}

/// B dials A; returns the error A's responder reported and what B's dialer saw.
fn dial(b: &Device, a: &Device) -> (Option<ChannelError>, Option<ChannelError>) {
    let mut dialer = ChannelDialer::start(&b.key, *a.key.public(), b.name.clone()).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&a.key, a.name.clone(), &out[0]);
    let pinned = |k: &[u8; 32]| a.reg.is_pinned_key(k);
    responder.on_frame(&out[1], &pinned).unwrap();
    dialer.on_frame(&responder.outgoing()[0]).unwrap();
    let a_side = responder.on_frame(&dialer.outgoing()[0], &pinned).err();
    let b_side = dialer.on_frame(&responder.outgoing()[0]).err();
    (a_side, b_side)
}

#[test]
fn revoke_removes_and_saves_the_pin_before_success() {
    let (mut a, b) = paired();
    let mut link = Link::new(a.id(), Timing::default());
    link.connected(&b.id(), b.id());
    let saves = a.store.save_count();
    a.reg.revoke(&b.id()).unwrap();
    link.revoked(b.id());
    assert_eq!(a.store.save_count(), saves + 1);
    assert!(a.store.pins().is_empty());
    assert_eq!(link.status(&b.id()), PeerStatus::Offline);
    assert_eq!(link.channel_dialer(&b.id()), None, "channel forgotten");
}

#[test]
fn a_failed_save_keeps_the_pin_and_the_channel() {
    // `Link::revoke` is the save-then-forget step `Node::revoke` runs (FR-033, T080).
    let (mut a, b) = paired();
    let mut link = Link::new(a.id(), Timing::default());
    link.connected(&b.id(), b.id());
    a.store.fail_saves(true);
    assert_eq!(link.revoke(&mut a.reg, &b.id()), Err(Error::Storage));
    assert!(a.reg.contains(&b.id()), "pin kept");
    assert_eq!(a.store.pins().len(), 1, "nothing saved");
    assert_eq!(link.status(&b.id()), PeerStatus::Connected, "channel kept");
    assert_eq!(link.channel_dialer(&b.id()), Some(b.id()));
    assert_eq!(
        link.refusal_reason(&b.id()),
        Refusal::Unpaired,
        "not marked revoked"
    );
    // Once the save works, the pin goes, the channel is forgotten and the key is refused.
    a.store.fail_saves(false);
    let removed = link.revoke(&mut a.reg, &b.id()).unwrap();
    assert_eq!(removed.id(), b.id());
    assert!(a.store.pins().is_empty());
    assert_eq!(link.status(&b.id()), PeerStatus::Offline);
    assert_eq!(link.channel_dialer(&b.id()), None);
    assert_eq!(link.refusal_reason(&b.id()), Refusal::Revoked);
    assert_eq!(link.revoke(&mut a.reg, &b.id()), Err(Error::NotFound));
}

#[test]
fn the_revoked_key_is_refused_and_the_peer_sees_refused_by_peer() {
    let (mut a, b) = paired();
    let mut link_a = Link::new(a.id(), Timing::default());
    a.reg.revoke(&b.id()).unwrap();
    link_a.revoked(b.id());
    let (a_side, b_side) = dial(&b, &a);
    let Some(ChannelError::Unpaired { presented }) = a_side else {
        panic!("{a_side:?}");
    };
    assert_eq!(link_a.refusal_reason(&presented), Refusal::Revoked);
    assert_eq!(b_side, Some(ChannelError::Refused));
    let mut link_b = Link::new(b.id(), Timing::default());
    link_b.refused_by_peer(&a.id(), std::time::Duration::ZERO);
    assert_eq!(link_b.status(&a.id()), PeerStatus::RefusedByPeer);
    assert!(b.reg.contains(&a.id()), "B keeps its own pin of A (FR-034)");
}

#[test]
fn only_a_new_pairing_with_a_fresh_code_restores_trust() {
    let (mut a, mut b) = paired();
    let mut link_a = Link::new(a.id(), Timing::default());
    a.reg.revoke(&b.id()).unwrap();
    link_a.revoked(b.id());
    // B also revokes A so it may pair again.
    b.reg.revoke(&a.id()).unwrap();
    // Without a code shown, a pairing attempt is refused at once.
    let mut no_code = None;
    let mut refused = Run::start(&b, "00000001", None, 5);
    refused.pump(&mut a, &mut b, &mut no_code);
    assert_eq!(refused.a_reason(), Some(FailReason::RefusedNotPairing));
    assert!(a.reg.is_empty());
    // A fresh code pairs again.
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 6);
    run.pump(&mut a, &mut b, &mut c);
    run.a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX)
        .unwrap();
    let commit = run.a.as_mut().unwrap().outgoing().remove(0);
    run.deliver_to_b(&mut b, commit);
    assert!(matches!(run.a_state(), InitiatorState::Paired(_)));
    link_a.paired(b.id());
    assert_eq!(link_a.refusal_reason(&b.id()), Refusal::Unpaired);
    let (a_side, b_side) = dial(&b, &a);
    assert_eq!((a_side, b_side), (None, None), "trusted again");
}
