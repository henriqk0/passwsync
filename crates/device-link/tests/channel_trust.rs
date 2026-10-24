//! Unpaired, changed and revoked keys are refused; pins never change (FR-028, SC-004).

mod support;

use std::net::SocketAddrV4;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::link::{Link, MAX_WARNINGS, Refusal, Timing, Warning};
use support::Device;
use support::channel::{key, name};

fn addr(last: u8) -> SocketAddrV4 {
    SocketAddrV4::new([192, 168, 1, last].into(), 27472)
}

#[test]
fn a_stranger_is_refused_as_unpaired_and_nothing_changes() {
    let b = Device::new(2, "Phone");
    let stranger = key(9);
    let mut link = Link::new(b.id(), Timing::default());
    let mut dialer = ChannelDialer::start(&stranger, *b.key.public(), name("S")).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&b.key, b.name.clone(), &out[0]);
    let is_pinned = |k: &[u8; 32]| b.reg.is_pinned_key(k);
    responder.on_frame(&out[1], &is_pinned).unwrap();
    dialer.on_frame(&responder.outgoing()[0]).unwrap();
    let error = responder
        .on_frame(&dialer.outgoing()[0], &is_pinned)
        .unwrap_err();
    let ChannelError::Unpaired { presented } = error else {
        panic!("{error:?}");
    };
    assert_eq!(link.refusal_reason(&presented), Refusal::Unpaired);
    assert!(b.reg.is_empty());
    assert!(link.warnings().is_empty(), "no address match, no warning");
    link.clear_warnings();
}

#[test]
fn a_changed_key_at_the_pinned_address_is_refused_with_a_warning() {
    let mut a = Device::new(1, "Laptop");
    let b = Device::new(2, "Phone");
    let mut pin = a.pin_of(&b);
    pin.last_addr = Some(addr(7));
    a.reg.pin(pin).unwrap();
    let impostor = key(3);
    let mut link = Link::new(a.id(), Timing::default());
    // A dials B's last address; the impostor answers there.
    let mut dialer = ChannelDialer::start(&a.key, *b.key.public(), a.name.clone()).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&impostor, name("Phone"), &out[0]);
    responder.on_frame(&out[1], &|_| true).unwrap();
    let error = dialer.on_frame(&responder.outgoing()[0]).unwrap_err();
    let ChannelError::KeyMismatch { presented } = error else {
        panic!("{error:?}");
    };
    link.warn_unpaired_key(addr(7), presented, b.id());
    assert_eq!(
        link.warnings(),
        vec![Warning::UnpairedKeyAtAddress {
            addr: addr(7),
            presented: impostor.id(),
            claimed: b.id(),
        }]
    );
    // The pin is unchanged and cannot be replaced.
    assert_eq!(a.reg.get(&b.id()).unwrap().public, *b.key.public());
    assert!(!a.reg.is_pinned_key(impostor.public()));
    link.clear_warnings();
    assert!(link.warnings().is_empty());
}

#[test]
fn warnings_keep_the_eight_most_recent() {
    let mut link = Link::new(key(1).id(), Timing::default());
    assert_eq!(MAX_WARNINGS, 8);
    for i in 0..10u8 {
        link.warn_unpaired_key(addr(i), key(100 + i).id(), key(50).id());
    }
    let warnings = link.warnings();
    assert_eq!(warnings.len(), 8);
    let Warning::UnpairedKeyAtAddress { addr: first, .. } = &warnings[0];
    assert_eq!(*first, addr(2), "the two oldest were dropped");
}

#[test]
fn a_revoked_key_is_refused_as_revoked_until_paired_again() {
    let mut link = Link::new(key(1).id(), Timing::default());
    let peer = key(2).id();
    link.revoked(peer);
    assert_eq!(link.refusal_reason(&peer), Refusal::Revoked);
    link.paired(peer);
    assert_eq!(link.refusal_reason(&peer), Refusal::Unpaired);
}

#[test]
fn a_responder_with_the_unpaired_dialer_at_a_pinned_address_warns() {
    let mut link = Link::new(key(1).id(), Timing::default());
    let claimed = key(2).id();
    let presented = key(3).id();
    // The listener saw an unpinned key coming from a paired device's last address.
    link.warn_unpaired_key(addr(7), presented, claimed);
    link.warn_unpaired_key(addr(7), presented, claimed);
    assert_eq!(
        link.warnings().len(),
        1,
        "a repeated warning is not duplicated"
    );
}
