//! Happy pairing path, frames 1-9 of contracts/peer-protocol.md (sans-IO).

mod support;

use device_link::code::CodeState;
use device_link::pairing::{InitiatorState, JoinerState};
use support::{Device, NOW_UNIX, Run, code};

#[test]
fn two_devices_pair_with_acceptance_and_two_phase_commit() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(12_345_678));
    let mut run = Run::start(&b, "12345678", None, 5);
    run.pump(&mut a, &mut b, &mut c);

    // Frames: Hello, SPAKE_B, SPAKE_A, msg1, msg2, msg3, PairPending.
    assert_eq!(run.wire.len(), 7, "frames 1-7 exchanged");
    assert_eq!(run.wire[1].len(), 33);
    assert_eq!(run.wire[2].len(), 33);
    assert_eq!(
        c.as_ref().unwrap().state(run.now),
        CodeState::Consumed,
        "code consumed by the first valid SPAKE_B"
    );
    let InitiatorState::AwaitingAcceptance(peer) = run.a_state() else {
        panic!("A should await acceptance: {:?}", run.a_state());
    };
    assert_eq!(peer.id, b.id());
    assert_eq!(peer.name.as_str(), "Phone");
    let JoinerState::AwaitingAcceptance {
        peer: a_peer,
        seconds_left,
    } = run.b.state()
    else {
        panic!("B should await acceptance: {:?}", run.b.state());
    };
    assert_eq!(a_peer, a.id());
    assert!((290..=300).contains(&seconds_left), "{seconds_left}");
    assert!(
        a.reg.is_empty() && b.reg.is_empty(),
        "nothing pinned before acceptance"
    );
    let timeout = run.b.read_timeout();
    assert_eq!(timeout.as_secs(), u64::from(seconds_left) + 10);

    // The person accepts on A: A saves first, then PairCommit leaves.
    let accepted = run
        .a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX)
        .unwrap();
    assert_eq!(accepted.id, b.id());
    assert_eq!(a.store.save_count(), 1, "A saved before sending PairCommit");
    let commit = run.a.as_mut().unwrap().outgoing();
    assert_eq!(commit.len(), 1);
    assert!(b.store.pins().is_empty());
    run.deliver_to_b(&mut b, commit.into_iter().next().unwrap());
    assert_eq!(b.store.save_count(), 1, "B saved before PairAck");
    let JoinerState::Paired(a_info) = run.b.state() else {
        panic!("B paired: {:?}", run.b.state());
    };
    assert_eq!(a_info.name.as_str(), "Laptop");
    let ack = run.to_a.remove(0);
    run.deliver_to_a(&mut a, c.as_mut(), ack);
    assert!(matches!(run.a_state(), InitiatorState::Paired(_)));
    assert_eq!(c.as_ref().unwrap().state(run.now), CodeState::Accepted);

    // Both hold the other's key; both show the same fingerprints.
    let a_pin = a.reg.get(&b.id()).unwrap();
    assert_eq!(a_pin.public, *b.key.public());
    assert_eq!(a_pin.name.as_str(), "Phone");
    assert_eq!(a_pin.paired_at, NOW_UNIX);
    let b_pin = b.reg.get(&a.id()).unwrap();
    assert_eq!(b_pin.public, *a.key.public());
    assert_eq!(b_pin.name.as_str(), "Laptop");
    assert_eq!(peer.id.fingerprint(), b.id().fingerprint());
    assert_eq!(a_info.id.fingerprint(), a.id().fingerprint());
}

#[test]
fn qr_pairing_with_the_right_expected_id_succeeds() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", Some(a.id()), 5);
    run.pump(&mut a, &mut b, &mut c);
    assert!(matches!(
        run.a_state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
    assert!(matches!(
        run.b.state(),
        JoinerState::AwaitingAcceptance { .. }
    ));
}

#[test]
fn names_never_appear_in_clear_on_the_wire() {
    let mut a = Device::new(1, "LaptopSecretName");
    let mut b = Device::new(2, "PhoneSecretName");
    let mut c = Some(code(7));
    let mut run = Run::start(&b, "00000007", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    run.a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX)
        .unwrap();
    let commit = run.a.as_mut().unwrap().outgoing().remove(0);
    run.deliver_to_b(&mut b, commit);
    let all: Vec<u8> = run.wire.concat();
    for needle in [&b"LaptopSecretName"[..], b"PhoneSecretName", b"00000007"] {
        assert!(!all.windows(needle.len()).any(|w| w == needle));
    }
}
