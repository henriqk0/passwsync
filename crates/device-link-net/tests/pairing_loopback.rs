//! Full pairing between two nodes over loopback TCP.

mod support;

use std::time::Duration;

use device_link::error::FailReason;
use device_link_net::NetEvent;
use support::{Options, pair, start, wait_for};

#[test]
fn pairing_succeeds_over_tcp() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    assert_eq!(a.store.pins().len(), 1);
    assert_eq!(b.store.pins().len(), 1);
    assert_eq!(b.store.pins()[0].name.as_str(), "Laptop");
    assert_eq!(a.store.pins()[0].name.as_str(), "Phone");
    let pairing = a.node.snapshot().pairing.unwrap();
    assert_eq!(pairing.state, "paired");
    assert!(pairing.code.is_none(), "code gone once used");
    assert!(a.has_event(&NetEvent::PairingSucceeded(b.id)));
    assert!(wait_for(Duration::from_secs(2), || b
        .has_event(&NetEvent::PairingSucceeded(a.id))));
    a.node.stop();
    b.node.stop();
}

#[test]
fn wrong_code_fails_on_both_and_pins_nothing() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    a.node.start_pairing().unwrap();
    let code = a.node.snapshot().pairing.unwrap().code.unwrap();
    // Change the first digit: always a wrong code.
    let first = if code.as_bytes()[0] == b'9' { '0' } else { '9' };
    let wrong = format!("{first}{}", &code[1..]);
    b.node.join(a.addr(), &wrong, None).unwrap();
    assert!(wait_for(Duration::from_secs(5), || b
        .node
        .snapshot()
        .join
        .is_some_and(|j| j.state == "failed")));
    let join = b.node.snapshot().join.unwrap();
    assert_eq!(join.reason, Some(FailReason::WrongCodeOrTampered));
    assert!(wait_for(Duration::from_secs(5), || a
        .node
        .snapshot()
        .pairing
        .is_some_and(|p| p.state == "failed")));
    assert!(
        a.node.snapshot().pairing.unwrap().code.is_none(),
        "code invalidated"
    );
    assert!(a.store.pins().is_empty() && b.store.pins().is_empty());
    assert!(b.has_event(&NetEvent::PairingFailed(FailReason::WrongCodeOrTampered)));
    a.node.stop();
    b.node.stop();
}

#[test]
fn reject_on_a_fails_both() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    a.node.start_pairing().unwrap();
    let code = a.node.snapshot().pairing.unwrap().code.unwrap();
    b.node.join(a.addr(), &code, None).unwrap();
    assert!(wait_for(Duration::from_secs(5), || a
        .node
        .snapshot()
        .pairing
        .is_some_and(|p| p.state == "awaiting_acceptance")));
    let pending = a.node.snapshot().pairing.unwrap();
    let peer = pending.peer.unwrap();
    assert_eq!(peer.id, b.id);
    assert_eq!(peer.name.as_str(), "Phone");
    a.node.reject();
    assert!(wait_for(Duration::from_secs(5), || b
        .node
        .snapshot()
        .join
        .is_some_and(|j| j.state == "failed")));
    assert_eq!(
        b.node.snapshot().join.unwrap().reason,
        Some(FailReason::Rejected)
    );
    assert!(a.store.pins().is_empty() && b.store.pins().is_empty());
    a.node.stop();
    b.node.stop();
}

#[test]
fn joining_an_unreachable_address_reports_unreachable() {
    let b = start(2, "Phone", Options::default());
    let nobody = std::net::SocketAddrV4::new([127, 0, 0, 1].into(), support::free_port());
    b.node.join(nobody, "12345678", None).unwrap();
    assert!(wait_for(Duration::from_secs(5), || b
        .node
        .snapshot()
        .join
        .is_some_and(|j| j.state == "failed")));
    assert_eq!(
        b.node.snapshot().join.unwrap().reason,
        Some(FailReason::Unreachable)
    );
    b.node.stop();
}
