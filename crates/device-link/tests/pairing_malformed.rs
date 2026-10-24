//! Malformed input never panics, never pins, and ends the exchange (FR-030).

mod support;

use device_link::error::FailReason;
use device_link::pairing::{InitiatorState, JoinerState, PairingInitiator};
use device_link::registry::PeerRegistry;
use device_link::wire::{Payload, RejectReason};
use support::{Device, RawJoiner, Run, code};

const HELLO: &[u8] = b"PWSC\x01\x02";

fn initiator(a: &Device) -> PairingInitiator {
    PairingInitiator::new(&a.key, a.name.clone(), HELLO)
}

fn failed(machine: &PairingInitiator) -> Option<FailReason> {
    match machine.state() {
        InitiatorState::Failed(reason) => Some(reason),
        _ => None,
    }
}

#[test]
fn bad_first_frames_fail_with_protocol_without_consuming_the_code() {
    let a = Device::new(1, "Laptop");
    for body in [
        vec![0u8; 1025],
        vec![],
        vec![0x42; 32],
        vec![0x42; 34],
        vec![0x41; 33], // wrong SPAKE side byte
        vec![0xff; 33],
    ] {
        let mut c = Some(code(1));
        let mut machine = initiator(&a);
        machine.on_frame(&body, c.as_mut(), &a.reg, std::time::Duration::from_secs(1));
        assert_eq!(
            failed(&machine),
            Some(FailReason::Protocol),
            "{} bytes",
            body.len()
        );
        assert!(machine.outgoing().is_empty());
        assert!(a.reg.is_empty());
        assert!(
            c.as_ref()
                .unwrap()
                .is_active(std::time::Duration::from_secs(1)),
            "garbage does not consume the code"
        );
    }
}

fn after_spake(
    a: &Device,
    raw: &mut RawJoiner,
    c: &mut Option<device_link::code::PairingCode>,
) -> (PairingInitiator, Vec<u8>) {
    let mut machine = initiator(a);
    machine.on_frame(
        &raw.spake_b.clone(),
        c.as_mut(),
        &a.reg,
        std::time::Duration::from_secs(1),
    );
    let spake_a = machine.outgoing().remove(0);
    (machine, spake_a)
}

#[test]
fn junk_noise_messages_end_the_exchange() {
    let a = Device::new(1, "Laptop");
    for junk in [vec![0u8; 5], vec![0u8; 32], vec![7u8; 200], vec![0u8; 1025]] {
        let mut c = Some(code(1));
        let mut raw = RawJoiner::new(2, "00000001");
        let (mut machine, _) = after_spake(&a, &mut raw, &mut c);
        machine.on_frame(&junk, c.as_mut(), &a.reg, std::time::Duration::from_secs(1));
        assert!(
            failed(&machine).is_some(),
            "junk msg1 of {} bytes",
            junk.len()
        );
        assert!(a.reg.is_empty());
    }
    // Junk in place of msg3.
    let mut c = Some(code(1));
    let mut raw = RawJoiner::new(2, "00000001");
    let (mut machine, spake_a) = after_spake(&a, &mut raw, &mut c);
    let msg1 = raw.msg1(&spake_a);
    machine.on_frame(&msg1, c.as_mut(), &a.reg, std::time::Duration::from_secs(1));
    let _msg2 = machine.outgoing().remove(0);
    machine.on_frame(
        &[9u8; 96],
        c.as_mut(),
        &a.reg,
        std::time::Duration::from_secs(1),
    );
    assert!(failed(&machine).is_some());
}

fn to_msg3(
    a: &Device,
    payload: &[u8],
) -> (
    PairingInitiator,
    RawJoiner,
    Option<device_link::code::PairingCode>,
) {
    let mut c = Some(code(1));
    let mut raw = RawJoiner::new(2, "00000001");
    let (mut machine, spake_a) = after_spake(a, &mut raw, &mut c);
    let msg1 = raw.msg1(&spake_a);
    machine.on_frame(&msg1, c.as_mut(), &a.reg, std::time::Duration::from_secs(1));
    let msg2 = machine.outgoing().remove(0);
    let msg3 = raw.msg3(&msg2, payload);
    machine.on_frame(&msg3, c.as_mut(), &a.reg, std::time::Duration::from_secs(1));
    (machine, raw, c)
}

#[test]
fn bad_pair_hello_payloads_fail_with_protocol() {
    let a = Device::new(1, "Laptop");
    for payload in [
        &b"\x01\x02AbX"[..], // trailing byte
        b"\x01\x00",         // empty name
        b"\x20\x01A",        // unknown type
        b"\x05",             // valid type, wrong place (PairAck)
        b"\x10\x01A",        // ChannelHello during pairing
        b"",
    ] {
        let (machine, _, _) = to_msg3(&a, payload);
        assert_eq!(failed(&machine), Some(FailReason::Protocol), "{payload:?}");
        assert!(a.reg.is_empty());
    }
    // The valid payload reaches acceptance.
    let (machine, _, _) = to_msg3(&a, b"\x01\x02Ab");
    assert!(matches!(
        machine.state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
}

#[test]
fn out_of_order_and_unexpected_transport_frames_fail() {
    let a = Device::new(1, "Laptop");
    // msg1 sent before SPAKE_B: SPAKE length check fails.
    let mut c = Some(code(1));
    let mut machine = initiator(&a);
    machine.on_frame(
        &[0u8; 32],
        c.as_mut(),
        &a.reg,
        std::time::Duration::from_secs(1),
    );
    assert_eq!(failed(&machine), Some(FailReason::Protocol));

    // After acceptance is pending, B sends a transport frame that is not PairAck.
    let (mut machine, mut raw, mut c) = to_msg3(&a, b"\x01\x02Ab");
    assert_eq!(
        raw.decrypt(&machine.outgoing().remove(0)),
        Some(Payload::PairPending { seconds_left: 299 })
    );
    let junk = raw.encrypt(b"\x13");
    machine.on_frame(&junk, c.as_mut(), &a.reg, std::time::Duration::from_secs(2));
    assert_eq!(failed(&machine), Some(FailReason::Protocol));
    assert!(a.reg.is_empty());
    let _ = &mut c;
}

#[test]
fn joiner_rejects_malformed_frames_from_a() {
    let mut b = Device::new(2, "Phone");
    let mut reg_store = std::mem::replace(
        &mut b.reg,
        PeerRegistry::load([0u8; 32], b.store.clone()).unwrap(),
    );
    for body in [
        vec![0u8; 32],
        vec![0u8; 34],
        vec![0x42; 33],
        vec![0u8; 1025],
        vec![],
    ] {
        let mut run = Run::start(&b, "00000001", None, 5);
        let _ = std::mem::take(&mut run.to_a);
        run.b.on_frame(&body, &mut reg_store, support::NOW_UNIX);
        assert!(
            matches!(run.b.state(), JoinerState::Failed(FailReason::Protocol)),
            "{} bytes: {:?}",
            body.len(),
            run.b.state()
        );
        assert!(run.b.outgoing().is_empty());
    }
    assert!(reg_store.is_empty());
    let _ = RejectReason::Rejected;
}
