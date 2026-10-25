//! 004 T029: channel protocol v2 negotiation (contracts/sync-protocol.md "Negotiation").

mod support;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::pairing::CHANNEL_PROLOGUE_V2;
use device_link::wire::{
    HelloKind, HelloVersion, Payload, hello, hello_versioned, parse_hello, parse_hello_versioned,
};
use support::channel::{connect, connect_v2, key, name};

#[test]
fn hello_v2_bytes_and_parsing() {
    assert_eq!(
        hello_versioned(HelloKind::Channel, HelloVersion::V2),
        *b"PWSC\x02\x01"
    );
    assert_eq!(
        hello_versioned(HelloKind::Channel, HelloVersion::V1),
        *b"PWSC\x01\x01"
    );
    assert_eq!(
        hello(HelloKind::Pairing),
        *b"PWSC\x01\x02",
        "pairing unchanged"
    );
    assert_eq!(
        parse_hello_versioned(b"PWSC\x02\x01"),
        Ok((HelloKind::Channel, HelloVersion::V2))
    );
    assert_eq!(
        parse_hello_versioned(b"PWSC\x01\x01"),
        Ok((HelloKind::Channel, HelloVersion::V1))
    );
    assert_eq!(
        parse_hello_versioned(b"PWSC\x01\x02"),
        Ok((HelloKind::Pairing, HelloVersion::V1))
    );
    for bad in [
        &b"PWSC\x02\x02"[..],
        // 005 changed this from `PWSC\x03\x01`, which is now the valid channel Hello v3.
        b"PWSC\x04\x01",
        b"PWSC\x02",
        b"PWSC\x02\x01\x00",
    ] {
        assert!(parse_hello_versioned(bad).is_err(), "{bad:?}");
    }
    // The 003 parser keeps rejecting version 2 (a v1 peer closes on it, R7).
    assert!(parse_hello(b"PWSC\x02\x01").is_err());
    assert_eq!(CHANNEL_PROLOGUE_V2, b"passwsync-channel-v2");
}

#[test]
fn a_v2_handshake_gives_a_sync_enabled_channel_on_both_ends() {
    let (a, b) = (key(1), key(2));
    let ends = connect_v2(&a, &b);
    assert!(ends.dialer.sync_enabled());
    assert!(ends.responder.sync_enabled());
    assert_eq!(ends.dialer.session_hash(), ends.responder.session_hash());
}

#[test]
fn a_v1_handshake_with_a_v2_responder_gives_a_channel_without_sync() {
    let (a, b) = (key(1), key(2));
    let ends = connect(&a, &b);
    assert!(!ends.dialer.sync_enabled());
    assert!(!ends.responder.sync_enabled());
    assert_eq!(ends.dialer.session_hash(), ends.responder.session_hash());
}

#[test]
fn session_hash_differs_per_session() {
    let (a, b) = (key(1), key(2));
    let one = connect_v2(&a, &b);
    let two = connect_v2(&a, &b);
    assert_ne!(one.dialer.session_hash(), two.dialer.session_hash());
    assert_ne!(one.dialer.session_hash(), [0u8; 32]);
}

#[test]
fn the_v2_prologue_binds_the_version() {
    let (a, b) = (key(1), key(2));
    let mut dialer =
        ChannelDialer::start_version(&a, *b.public(), name("Laptop"), HelloVersion::V2).unwrap();
    let out = dialer.outgoing();
    // A responder that believes Hello v1 was sent (downgrade attempt).
    let mut responder = ChannelResponder::new(&b, name("Phone"), b"PWSC\x01\x01");
    responder.on_frame(&out[1], &|_| true).unwrap();
    let msg2 = responder.outgoing();
    assert!(dialer.on_frame(&msg2[0]).is_err());
}

#[test]
fn sync_frames_on_a_v1_channel_are_a_protocol_error() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect(&a, &b);
    let ctl = Payload::SyncCtl {
        more: false,
        fragment: vec![1],
    };
    assert_eq!(
        ends.dialer.seal_sync(&ctl).err(),
        Some(ChannelError::Protocol)
    );
    let frame = ends.dialer.seal_any(&ctl.encode()).unwrap();
    assert_eq!(
        ends.responder.open(&frame).err(),
        Some(ChannelError::Protocol)
    );
}

#[test]
fn sync_frames_flow_on_a_v2_channel() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect_v2(&a, &b);
    for payload in [
        Payload::SyncCtl {
            more: true,
            fragment: vec![7; 1000],
        },
        Payload::CopyData {
            bytes: vec![9; 1000],
        },
        Payload::Keepalive,
    ] {
        let frame = if matches!(payload, Payload::Keepalive) {
            ends.responder.seal(&payload).unwrap()
        } else {
            ends.responder.seal_sync(&payload).unwrap()
        };
        assert!(frame.len() <= 1024);
        assert_eq!(ends.dialer.open(&frame).unwrap(), payload);
    }
    // Maintenance messages cannot go through seal_sync, nor sync ones through seal.
    assert!(ends.dialer.seal_sync(&Payload::Keepalive).is_err());
    let mut ends = connect_v2(&a, &b);
    assert!(
        ends.dialer
            .seal(&Payload::CopyData { bytes: vec![1] })
            .is_err()
    );
}
