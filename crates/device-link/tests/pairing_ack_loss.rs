//! FR-022b regression: lost final messages never leave a half-pairing on the joiner.

mod support;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::error::FailReason;
use device_link::pairing::{InitiatorState, JoinerState};
use support::{Device, NOW_UNIX, Run, code};

#[test]
fn a_lost_pair_ack_leaves_both_pins_and_a_channel_works_without_re_pairing() {
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
    // The transport drops B's PairAck; A only sees the connection end.
    let ack = run.to_a.remove(0);
    drop(ack);
    run.a.as_mut().unwrap().on_closed(c.as_mut());
    assert!(
        matches!(run.a_state(), InitiatorState::Paired(_)),
        "A keeps its pin"
    );
    assert!(a.reg.contains(&b.id()));
    assert!(matches!(run.b.state(), JoinerState::Paired(_)));
    assert!(b.reg.contains(&a.id()));
    // A later channel attempt from B succeeds without re-pairing.
    let mut dialer = ChannelDialer::start(&b.key, *a.key.public(), b.name.clone()).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&a.key, a.name.clone(), &out[0]);
    let pinned = |k: &[u8; 32]| a.reg.is_pinned_key(k);
    responder.on_frame(&out[1], &pinned).unwrap();
    dialer.on_frame(&responder.outgoing()[0]).unwrap();
    assert!(
        responder
            .on_frame(&dialer.outgoing()[0], &pinned)
            .unwrap()
            .is_some()
    );
    assert!(dialer.on_frame(&responder.outgoing()[0]).unwrap().is_some());
}

#[test]
fn a_lost_pair_commit_leaves_b_without_a_pin_and_a_s_pin_is_harmless() {
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
    // PairCommit is lost; B gives up when the connection ends.
    let _lost = run.a.as_mut().unwrap().outgoing();
    run.b.on_closed();
    assert_eq!(
        run.b_reason(),
        Some(FailReason::Protocol),
        "pairing failed, try again"
    );
    assert!(b.reg.is_empty(), "no half-pairing on B");
    assert!(a.reg.contains(&b.id()), "A's pin stays (harmless)");
    // No channel is possible: A dials B, B (no pin) answers Refused.
    let mut dialer = ChannelDialer::start(&a.key, *b.key.public(), a.name.clone()).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&b.key, b.name.clone(), &out[0]);
    let pinned = |k: &[u8; 32]| b.reg.is_pinned_key(k);
    responder.on_frame(&out[1], &pinned).unwrap();
    dialer.on_frame(&responder.outgoing()[0]).unwrap();
    assert!(matches!(
        responder.on_frame(&dialer.outgoing()[0], &pinned),
        Err(ChannelError::Unpaired { .. })
    ));
    assert_eq!(
        dialer.on_frame(&responder.outgoing()[0]).err(),
        Some(ChannelError::Refused)
    );
}
