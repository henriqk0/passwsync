//! Replay, reorder, tamper, cross-connection and malformed traffic close the channel
//! (FR-027, FR-031, SC-004).

mod support;

use device_link::channel::{ChannelError, ChannelResponder};
use device_link::wire::{CloseReason, Payload, RejectReason};
use support::channel::{connect, key, name};

#[test]
fn a_replayed_message_fails_and_the_channel_is_dead() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    let frame = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert!(ends.responder.open(&frame).is_ok());
    assert_eq!(
        ends.responder.open(&frame).err(),
        Some(ChannelError::Crypto)
    );
    assert!(ends.responder.is_closed());
    let next = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert!(ends.responder.open(&next).is_err(), "closed for good");
}

#[test]
fn reordered_messages_fail() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    let _first = ends.dialer.seal(&Payload::Keepalive).unwrap();
    let second = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert_eq!(
        ends.responder.open(&second).err(),
        Some(ChannelError::Crypto)
    );
}

#[test]
fn any_flipped_bit_fails() {
    let (a, b) = (key(1), key(2));
    for index in [0usize, 1, 5, 16] {
        let mut ends = connect(&a, &b);
        let mut frame = ends.dialer.seal(&Payload::Keepalive).unwrap();
        frame[index] ^= 0x80;
        assert_eq!(
            ends.responder.open(&frame).err(),
            Some(ChannelError::Crypto)
        );
    }
}

#[test]
fn traffic_from_another_connection_does_not_decrypt() {
    let (a, b) = (key(1), key(2));
    let mut one = connect(&a, &b);
    let mut two = connect(&a, &b);
    let frame = one.dialer.seal(&Payload::Keepalive).unwrap();
    assert_eq!(two.responder.open(&frame).err(), Some(ChannelError::Crypto));
}

#[test]
fn msg3_replayed_into_another_connection_is_rejected() {
    let (a, b) = (key(1), key(2));
    let one = connect(&a, &b);
    let two = connect(&a, &b);
    // A responder that answered msg1 of session two receives msg3 of session one.
    let mut responder = ChannelResponder::new(&b, name("Phone"), &two.wire[0]);
    let pinned = *a.public();
    let is_pinned = move |k: &[u8; 32]| *k == pinned;
    responder.on_frame(&two.wire[1], &is_pinned).unwrap();
    let _ = responder.outgoing();
    assert!(responder.on_frame(&one.wire[3], &is_pinned).is_err());
}

#[test]
fn truncated_empty_and_oversized_frames_fail() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    let frame = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert!(ends.responder.open(&frame[..frame.len() - 1]).is_err());
    let mut ends = connect(&a, &b);
    assert!(ends.responder.open(&[]).is_err());
    let mut ends = connect(&a, &b);
    assert_eq!(
        ends.responder.open(&[0u8; 1025]).err(),
        Some(ChannelError::Protocol)
    );
}

#[test]
fn only_maintenance_messages_are_accepted_after_welcome() {
    let (a, b) = (key(1), key(2));
    let ok = [
        Payload::Keepalive,
        Payload::NameUpdate { name: name("X") },
        Payload::Close {
            reason: CloseReason::Shutdown,
        },
    ];
    for payload in ok {
        let mut ends = connect(&a, &b);
        let frame = ends.dialer.seal(&payload).unwrap();
        assert_eq!(ends.responder.open(&frame).unwrap(), payload);
    }
    let refused = [
        Payload::PairAck,
        Payload::PairHello { name: name("X") },
        Payload::PairReject {
            reason: RejectReason::Rejected,
        },
        Payload::ChannelHello { name: name("X") },
        Payload::Welcome { name: name("X") },
        Payload::Refused,
    ];
    for payload in refused {
        let mut ends = connect(&a, &b);
        let frame = ends.dialer.seal_any(&payload.encode()).unwrap();
        assert_eq!(
            ends.responder.open(&frame).err(),
            Some(ChannelError::Protocol),
            "{payload:?}"
        );
        assert!(ends.responder.is_closed());
    }
}

#[test]
fn unknown_types_and_trailing_bytes_fail() {
    let (a, b) = (key(1), key(2));
    for plain in [
        &[0x20u8, 1, b'w'][..], // e.g. a wallet-sync type (FR-031)
        &[0x13, 0x00],
        &[0x15, 1, 0],
        &[0xff],
        &[],
    ] {
        let mut ends = connect(&a, &b);
        let frame = ends.dialer.seal_any(plain).unwrap();
        assert_eq!(
            ends.responder.open(&frame).err(),
            Some(ChannelError::Protocol),
            "{plain:?}"
        );
    }
}
