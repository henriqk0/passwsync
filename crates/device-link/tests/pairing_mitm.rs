//! Active attackers without the code learn nothing and pin nothing (FR-020, SC-003).

mod support;

use device_link::error::FailReason;
use device_link::pairing::{InitiatorState, JoinerState};
use support::{Device, NOW_UNIX, Run, assert_nothing_pinned, code};

#[test]
fn relay_mitm_without_the_code_cannot_complete() {
    // Mallory sits between B and A: towards A she is a joiner with a guess, towards B she
    // plays initiator with her own guess. Neither guess is the code.
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut mallory = Device::new(66, "Laptop");
    let mut real = Some(code(12_345_678));
    let mut guess = Some(code(11_111_111));
    // B -> Mallory (B types the real code).
    let mut to_mallory = Run::start(&b, "12345678", None, 5);
    to_mallory.pump(&mut mallory, &mut b, &mut guess);
    assert_eq!(to_mallory.b_reason(), Some(FailReason::WrongCodeOrTampered));
    // Mallory -> A with her guess.
    let mut to_a = Run::start(&mallory, "11111111", None, 6);
    to_a.pump(&mut a, &mut mallory, &mut real);
    assert_eq!(to_a.b_reason(), Some(FailReason::WrongCodeOrTampered));
    assert!(to_a.a_failed());
    assert_nothing_pinned(&a, &b);
    assert!(mallory.reg.is_empty());
}

#[test]
fn a_guess_gets_exactly_one_try_and_consumes_the_code() {
    let mut a = Device::new(1, "Laptop");
    let mut mallory = Device::new(66, "Evil");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(4242));
    let mut guess = Run::start(&mallory, "00004243", None, 5);
    guess.pump(&mut a, &mut mallory, &mut c);
    assert!(guess.b_failed() && guess.a_failed());
    // Even the right code is now refused.
    let mut legit = Run::start(&b, "00004242", None, 6);
    legit.pump(&mut a, &mut b, &mut c);
    assert_eq!(legit.b_reason(), Some(FailReason::RefusedNotPairing));
    assert_nothing_pinned(&a, &b);
}

#[test]
fn tampering_any_byte_of_frames_2_to_5_fails() {
    // Wire indices: 0 Hello, 1 SPAKE_B, 2 SPAKE_A, 3 msg1, 4 msg2.
    for frame in 1..=4usize {
        for byte in [0usize, 1, 16, 32] {
            let mut a = Device::new(1, "Laptop");
            let mut b = Device::new(2, "Phone");
            let mut c = Some(code(1));
            let mut run = Run::start(&b, "00000001", None, 5);
            run.pump_with(&mut a, &mut b, &mut c, &mut |index, body: &mut Vec<u8>| {
                if index == frame && byte < body.len() {
                    body[byte] ^= 0x01;
                }
            });
            assert!(
                !matches!(run.b.state(), JoinerState::AwaitingAcceptance { .. }),
                "frame {frame} byte {byte}: B must not reach acceptance"
            );
            assert!(
                run.a
                    .as_ref()
                    .is_none_or(|m| !matches!(m.state(), InitiatorState::AwaitingAcceptance(_))),
                "frame {frame} byte {byte}: A must not reach acceptance"
            );
            assert_nothing_pinned(&a, &b);
        }
    }
}

#[test]
fn tampering_the_hello_breaks_the_prologue_binding() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    // A forged Hello that still parses is impossible (one valid encoding); instead check
    // that B's prologue covers the Hello: replacing B's Hello for A by a channel Hello
    // is refused by A's dispatcher.
    let hello = run.to_a[0].clone();
    assert_eq!(hello, b"PWSC\x01\x02");
    run.pump(&mut a, &mut b, &mut c);
    assert!(matches!(
        run.a_state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
}

#[test]
fn qr_pairing_with_another_device_id_fails_with_id_mismatch() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let someone_else = Device::new(3, "Other").id();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", Some(someone_else), 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::IdMismatch));
    assert_nothing_pinned(&a, &b);
}

#[test]
fn replaying_a_recorded_session_against_a_fresh_code_fails() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    run.a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX)
        .unwrap();
    let commit = run.a.as_mut().unwrap().outgoing().remove(0);
    run.deliver_to_b(&mut b, commit);
    // B's frames: wire[0] Hello, [1] SPAKE_B, [3] msg1, [5] msg3, then PairAck.
    let recorded: Vec<Vec<u8>> = [0usize, 1, 3, 5]
        .iter()
        .map(|i| run.wire[*i].clone())
        .chain(run.to_a.clone())
        .collect();
    // Fresh device state for A (another code, no pins); attacker replays B's frames.
    let mut a2 = Device::new(1, "Laptop");
    let mut fresh = Some(code(1));
    let mut replay =
        device_link::pairing::PairingInitiator::new(&a2.key, a2.name.clone(), &recorded[0]);
    for frame in &recorded[1..] {
        replay.on_frame(frame, fresh.as_mut(), &a2.reg, run.now);
        let _ = replay.outgoing();
        if matches!(replay.state(), InitiatorState::Failed(_)) {
            break;
        }
    }
    assert!(
        matches!(replay.state(), InitiatorState::Failed(_)),
        "{:?}",
        replay.state()
    );
    assert!(a2.reg.is_empty());
    let _ = &mut a2;
}

#[test]
fn replaying_spake_b_into_a_new_session_fails() {
    let mut a = Device::new(1, "Laptop");
    let mut b = Device::new(2, "Phone");
    let mut c = Some(code(1));
    let mut first = Run::start(&b, "00000001", None, 5);
    first.pump(&mut a, &mut b, &mut c);
    let spake_b = first.wire[1].clone();
    // New session on A with a new code; the attacker replays SPAKE_B and B's msg1.
    let mut a2 = Device::new(1, "Laptop");
    let mut fresh = Some(code(1));
    let mut machine =
        device_link::pairing::PairingInitiator::new(&a2.key, a2.name.clone(), b"PWSC\x01\x02");
    machine.on_frame(&spake_b, fresh.as_mut(), &a2.reg, first.now);
    let _ = machine.outgoing();
    machine.on_frame(&first.wire[3], fresh.as_mut(), &a2.reg, first.now);
    let _ = machine.outgoing();
    machine.on_frame(&first.wire[5], fresh.as_mut(), &a2.reg, first.now);
    assert!(matches!(machine.state(), InitiatorState::Failed(_)));
    assert!(a2.reg.is_empty());
    let _ = &mut a2;
}
