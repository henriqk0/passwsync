//! Every pairing failure leaves both registries empty and the code unusable (SC-003).

mod support;

use std::time::Duration;

use device_link::code::CodeState;
use device_link::error::FailReason;
use device_link::pairing::{AcceptError, InitiatorState, PairingSlot, Role};
use device_link::registry::MAX_PINS;
use support::{Device, NOW_UNIX, Run, assert_nothing_pinned, code};

fn devices() -> (Device, Device) {
    (Device::new(1, "Laptop"), Device::new(2, "Phone"))
}

fn assert_code_unusable(c: &Option<device_link::code::PairingCode>, now: Duration) {
    if let Some(c) = c {
        assert_ne!(c.state(now), CodeState::Active, "code must be unusable");
    }
}

#[test]
fn wrong_code_fails_on_both_sides() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(12_345_678));
    let mut run = Run::start(&b, "12345679", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::WrongCodeOrTampered));
    assert_eq!(run.a_reason(), Some(FailReason::WrongCodeOrTampered));
    assert_nothing_pinned(&a, &b);
    assert_code_unusable(&c, run.now);
}

#[test]
fn expired_code_is_refused() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.now = Duration::from_secs(301);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::Expired));
    assert_eq!(run.b_reason(), Some(FailReason::RefusedNotPairing));
    assert_nothing_pinned(&a, &b);
    assert_code_unusable(&c, run.now);
}

#[test]
fn code_cannot_be_reused_after_a_failed_attempt() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut first = Run::start(&b, "00000002", None, 5);
    first.pump(&mut a, &mut b, &mut c);
    assert!(first.b_failed());
    let mut second = Run::start(&b, "00000001", None, 6);
    second.pump(&mut a, &mut b, &mut c);
    assert_eq!(second.b_reason(), Some(FailReason::RefusedNotPairing));
    assert_eq!(second.a_reason(), Some(FailReason::RefusedNotPairing));
    assert_nothing_pinned(&a, &b);
}

#[test]
fn device_without_a_code_refuses_pairing() {
    let (mut a, mut b) = devices();
    let mut c = None;
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::RefusedNotPairing));
    assert_eq!(run.b_reason(), Some(FailReason::RefusedNotPairing));
    assert_nothing_pinned(&a, &b);
}

#[test]
fn second_concurrent_pairing_is_refused() {
    let (mut a, mut b) = devices();
    let mut b2 = Device::new(3, "Tablet");
    let mut c = Some(code(1));
    let mut first = Run::start(&b, "00000001", None, 5);
    first.pump(&mut a, &mut b, &mut c);
    assert!(matches!(
        first.a_state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
    let mut second = Run::start(&b2, "00000001", None, 6);
    second.pump(&mut a, &mut b2, &mut c);
    assert_eq!(second.b_reason(), Some(FailReason::RefusedNotPairing));
    assert!(b2.reg.is_empty());
    // The first exchange is unaffected.
    assert!(matches!(
        first.a_state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
}

#[test]
fn one_exchange_per_device_so_crossed_joins_cannot_both_succeed() {
    let mut slot_a = PairingSlot::default();
    let mut slot_b = PairingSlot::default();
    // Each device starts joining the other (its own outgoing exchange holds its slot).
    assert!(slot_a.try_acquire(Role::Joiner));
    assert!(slot_b.try_acquire(Role::Joiner));
    // Each incoming exchange then finds the slot taken: both refused.
    assert!(!slot_a.try_acquire(Role::Initiator));
    assert!(!slot_b.try_acquire(Role::Initiator));
    assert!(slot_a.is_busy());
    slot_a.release();
    assert!(!slot_a.is_busy());
    assert!(slot_a.try_acquire(Role::Initiator));
    assert_eq!(slot_a.role(), Some(Role::Initiator));
}

#[test]
fn reject_on_a_aborts_both() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    run.a.as_mut().unwrap().reject(c.as_mut());
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::Rejected));
    assert_eq!(run.b_reason(), Some(FailReason::Rejected));
    assert_nothing_pinned(&a, &b);
    assert_code_unusable(&c, run.now);
}

#[test]
fn joiner_closing_before_commit_leaves_nothing() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    run.a.as_mut().unwrap().on_closed(c.as_mut());
    assert_eq!(run.a_reason(), Some(FailReason::Protocol));
    let result = run
        .a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX);
    assert_eq!(result.err(), Some(AcceptError::NothingPending));
    run.b.on_closed();
    assert!(run.b_failed());
    assert_nothing_pinned(&a, &b);
    assert_code_unusable(&c, run.now);
}

#[test]
fn failed_save_on_a_pins_nothing() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    a.store.fail_saves(true);
    let result = run
        .a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), run.now, NOW_UNIX);
    assert_eq!(result.err(), Some(AcceptError::Storage));
    run.pump(&mut a, &mut b, &mut c);
    assert!(run.a_failed() && run.b_failed());
    assert_nothing_pinned(&a, &b);
}

#[test]
fn accept_requires_the_pending_device_id() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    let other = Device::new(9, "Other").id();
    let result = run
        .a
        .as_mut()
        .unwrap()
        .accept(&other, &mut a.reg, c.as_mut(), run.now, NOW_UNIX);
    assert_eq!(result.err(), Some(AcceptError::Mismatch));
    assert!(matches!(
        run.a_state(),
        InitiatorState::AwaitingAcceptance(_)
    ));
    assert!(a.reg.is_empty());
}

#[test]
fn pairing_with_self_is_refused() {
    let mut a = Device::new(1, "Laptop");
    let mut same = Device::new(1, "Laptop");
    let mut c = Some(code(1));
    let mut run = Run::start(&same, "00000001", None, 5);
    run.pump(&mut a, &mut same, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::SelfPair));
    assert_nothing_pinned(&a, &same);
}

#[test]
fn already_paired_is_refused_from_either_side() {
    // B already pins A: B stops at msg2.
    let (mut a, mut b) = devices();
    let pin = b.pin_of(&a);
    b.reg.pin(pin).unwrap();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::AlreadyPaired));
    assert!(a.reg.is_empty());
    assert_eq!(b.reg.len(), 1);

    // A already pins B: A answers PairReject(already_paired).
    let (mut a, mut b) = devices();
    let pin = a.pin_of(&b);
    a.reg.pin(pin).unwrap();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::AlreadyPaired));
    assert_eq!(run.b_reason(), Some(FailReason::AlreadyPaired));
    assert!(b.reg.is_empty());
    assert_eq!(a.reg.len(), 1);
}

fn fill(device: &mut Device) {
    for i in 0..MAX_PINS as u8 {
        let other = Device::new(100 + i, "Filler");
        let pin = device.pin_of(&other);
        device.reg.pin(pin).unwrap();
    }
}

#[test]
fn the_33rd_pin_is_refused_on_either_side() {
    let (mut a, mut b) = devices();
    fill(&mut a);
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::Limit));
    assert_eq!(run.b_reason(), Some(FailReason::Limit));
    assert!(b.reg.is_empty());

    let (mut a, mut b) = devices();
    fill(&mut b);
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::Limit));
    assert!(a.reg.is_empty());
}

#[test]
fn step_timeout_is_ten_seconds_and_fails_cleanly() {
    let (mut a, b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    assert_eq!(run.b.read_timeout(), Duration::from_secs(10));
    // Deliver only the Hello and SPAKE_B; A answers; B never gets it.
    let hello = run.to_a.remove(0);
    run.deliver_to_a(&mut a, c.as_mut(), hello);
    let spake = run.to_a.remove(0);
    run.deliver_to_a(&mut a, c.as_mut(), spake);
    assert_eq!(
        run.a.as_ref().unwrap().read_timeout(),
        Duration::from_secs(10)
    );
    run.b.on_timeout();
    run.a.as_mut().unwrap().on_timeout(c.as_mut());
    assert_eq!(run.b_reason(), Some(FailReason::Timeout));
    assert_eq!(run.a_reason(), Some(FailReason::Timeout));
    assert_nothing_pinned(&a, &b);
    assert_code_unusable(&c, run.now);
}

#[test]
fn acceptance_expires_with_the_code() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    let late = Duration::from_secs(300);
    run.a.as_mut().unwrap().tick(c.as_mut(), late);
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.a_reason(), Some(FailReason::Expired));
    assert_eq!(run.b_reason(), Some(FailReason::Expired));
    let result = run
        .a
        .as_mut()
        .unwrap()
        .accept(&b.id(), &mut a.reg, c.as_mut(), late, NOW_UNIX);
    assert_eq!(result.err(), Some(AcceptError::NothingPending));
    assert_nothing_pinned(&a, &b);
}

#[test]
fn accepting_after_expiry_is_refused_as_expired() {
    let (mut a, mut b) = devices();
    let mut c = Some(code(1));
    let mut run = Run::start(&b, "00000001", None, 5);
    run.pump(&mut a, &mut b, &mut c);
    let result = run.a.as_mut().unwrap().accept(
        &b.id(),
        &mut a.reg,
        c.as_mut(),
        Duration::from_secs(301),
        NOW_UNIX,
    );
    assert_eq!(result.err(), Some(AcceptError::Expired));
    run.pump(&mut a, &mut b, &mut c);
    assert_eq!(run.b_reason(), Some(FailReason::Expired));
    assert_nothing_pinned(&a, &b);
}
