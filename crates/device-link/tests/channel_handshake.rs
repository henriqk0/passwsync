//! Channel handshake, frames 1-5 of contracts/peer-protocol.md "Channel" (sans-IO).

mod support;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::pairing::{CHANNEL_PROLOGUE, NOISE_CHANNEL};
use device_link::wire::{HelloKind, Payload, hello};
use support::channel::{connect, key, name};

#[test]
fn handshake_authenticates_both_sides_and_exchanges_names() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    assert_eq!(ends.wire.len(), 5);
    assert_eq!(ends.dialer.peer_id(), b.id());
    assert_eq!(ends.dialer.peer_name().as_str(), "Phone");
    assert_eq!(ends.responder.peer_id(), a.id());
    assert_eq!(ends.responder.peer_name().as_str(), "Laptop");
    assert!(ends.dialer.is_dialer() && !ends.responder.is_dialer());
    assert_eq!(ends.dialer.dialer_id(), a.id());
    assert_eq!(ends.responder.dialer_id(), a.id());
    let frame = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert_eq!(ends.responder.open(&frame).unwrap(), Payload::Keepalive);
    let update = Payload::NameUpdate {
        name: name("Phone 2"),
    };
    let frame = ends.responder.seal(&update).unwrap();
    assert_eq!(ends.dialer.open(&frame).unwrap(), update);
    // Names never appear in clear.
    let all = ends.wire.concat();
    for needle in [&b"Laptop"[..], b"Phone"] {
        assert!(!all.windows(needle.len()).any(|w| w == needle));
    }
}

#[test]
fn dialer_refuses_a_responder_whose_key_is_not_the_pin() {
    let (a, b, impostor) = (key(1), key(2), key(3));
    let mut dialer = ChannelDialer::start(&a, *b.public(), name("Laptop")).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&impostor, name("Evil"), &out[0]);
    responder.on_frame(&out[1], &|_| true).unwrap();
    let msg2 = responder.outgoing();
    match dialer.on_frame(&msg2[0]) {
        Err(ChannelError::KeyMismatch { presented }) => assert_eq!(presented, impostor.id()),
        other => panic!("expected key mismatch, got {other:?}"),
    }
    assert!(
        dialer.outgoing().is_empty(),
        "the dialer never reveals its static key"
    );
}

#[test]
fn responder_refuses_an_unpinned_dialer_with_refused() {
    let (stranger, b) = (key(9), key(2));
    let mut dialer = ChannelDialer::start(&stranger, *b.public(), name("Stranger")).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&b, name("Phone"), &out[0]);
    responder.on_frame(&out[1], &|_| false).unwrap();
    let msg2 = responder.outgoing();
    dialer.on_frame(&msg2[0]).unwrap();
    let msg3 = dialer.outgoing();
    match responder.on_frame(&msg3[0], &|_| false) {
        Err(ChannelError::Unpaired { presented }) => assert_eq!(presented, stranger.id()),
        other => panic!("expected unpaired, got {other:?}"),
    }
    let refused = responder.outgoing();
    assert_eq!(refused.len(), 1, "exactly one Refused message");
    assert_eq!(
        dialer.on_frame(&refused[0]).err(),
        Some(ChannelError::Refused)
    );
}

#[test]
fn the_prologue_binds_the_hello() {
    let (a, b) = (key(1), key(2));
    let mut dialer = ChannelDialer::start(&a, *b.public(), name("Laptop")).unwrap();
    let out = dialer.outgoing();
    // The responder believes a different Hello was sent: msg2 no longer verifies.
    let mut responder = ChannelResponder::new(&b, name("Phone"), b"PWSC\x01\x02");
    responder.on_frame(&out[1], &|_| true).unwrap();
    let msg2 = responder.outgoing();
    assert!(dialer.on_frame(&msg2[0]).is_err());
    assert_eq!(CHANNEL_PROLOGUE, b"passwsync-channel-v1");
    assert_eq!(hello(HelloKind::Channel), *b"PWSC\x01\x01");
}

#[test]
fn every_session_uses_fresh_ephemeral_keys() {
    let (a, b) = (key(1), key(2));
    let first = connect(&a, &b);
    let second = connect(&a, &b);
    assert_ne!(
        first.wire[1], second.wire[1],
        "msg1 carries a fresh ephemeral"
    );
    assert_ne!(&first.wire[2][..32], &second.wire[2][..32]);
}

/// Forward secrecy: with both static private keys but without the session's ephemeral
/// private keys, recorded traffic cannot be decrypted.
#[test]
fn recorded_traffic_stays_secret_even_with_both_static_keys() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    let secret = ends
        .dialer
        .seal(&Payload::NameUpdate {
            name: name("Secret"),
        })
        .unwrap();
    let wire = ends.wire.clone();
    let mut buf = [0u8; 1024];
    let prologue = [CHANNEL_PROLOGUE, &wire[0][..]].concat();
    // Attempt 1: replay msg1 into a fresh responder holding B's static key, then read msg3.
    let mut fake_b = snow::Builder::new(NOISE_CHANNEL.parse().unwrap())
        .local_private_key(b.private_bytes())
        .unwrap()
        .prologue(&prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    fake_b.read_message(&wire[1], &mut buf).unwrap();
    let _ = fake_b.write_message(&[], &mut buf).unwrap();
    assert!(fake_b.read_message(&wire[3], &mut buf).is_err());
    // Attempt 2: a fresh initiator with A's static key cannot read the recorded msg2.
    let mut fake_a = snow::Builder::new(NOISE_CHANNEL.parse().unwrap())
        .local_private_key(a.private_bytes())
        .unwrap()
        .prologue(&prologue)
        .unwrap()
        .build_initiator()
        .unwrap();
    let _ = fake_a.write_message(&[], &mut buf).unwrap();
    assert!(fake_a.read_message(&wire[2], &mut buf).is_err());
    // Attempt 3: transport keys of a new session between the same statics do not fit.
    let mut other = connect(&a, &b);
    assert!(other.responder.open(&secret).is_err());
    // The real session still reads it.
    assert_eq!(
        ends.responder.open(&secret).unwrap(),
        Payload::NameUpdate {
            name: name("Secret")
        }
    );
}
