//! 005 T006: channel protocol v3 (specs/005-wallet-sharing/contracts/share-protocol.md
//! "Negotiation"): prologue binding, share payloads only on v3, v2 unchanged.

mod support;

use device_link::channel::{ChannelDialer, ChannelError, ChannelResponder};
use device_link::wire::{HelloVersion, MAX_FRAME, Payload};
use support::channel::{connect, connect_v2, connect_v3, key, name};

fn share_payloads() -> Vec<Payload> {
    vec![
        Payload::ShareMsg {
            body: vec![0x01; 37],
        },
        Payload::ShareData {
            bytes: vec![0x42; 1000],
        },
    ]
}

#[test]
fn a_v3_handshake_gives_a_share_and_sync_enabled_channel_on_both_ends() {
    let (a, b) = (key(1), key(2));
    let ends = connect_v3(&a, &b);
    for end in [&ends.dialer, &ends.responder] {
        assert!(end.share_enabled());
        assert!(end.sync_enabled(), "v3 = v2 + share");
        assert_eq!(end.version(), HelloVersion::V3);
    }
    assert_eq!(ends.dialer.session_hash(), ends.responder.session_hash());
}

#[test]
fn only_v3_is_share_enabled() {
    let (a, b) = (key(1), key(2));
    let v1 = connect(&a, &b);
    let v2 = connect_v2(&a, &b);
    assert!(!v1.dialer.share_enabled() && !v1.responder.share_enabled());
    assert!(!v2.dialer.share_enabled() && !v2.responder.share_enabled());
    assert!(v2.dialer.sync_enabled(), "v2 behaves as in 004");
    assert_eq!(v2.dialer.version(), HelloVersion::V2);
    assert_eq!(v1.dialer.version(), HelloVersion::V1);
}

#[test]
fn the_v3_prologue_binds_the_version() {
    let (a, b) = (key(1), key(2));
    for claimed in [&b"PWSC\x02\x01"[..], b"PWSC\x01\x01"] {
        let mut dialer =
            ChannelDialer::start_version(&a, *b.public(), name("Laptop"), HelloVersion::V3)
                .unwrap();
        let out = dialer.outgoing();
        assert_eq!(out[0], b"PWSC\x03\x01");
        // A responder that believes a lower Hello was sent (downgrade attempt).
        let mut responder = ChannelResponder::new(&b, name("Phone"), claimed);
        responder.on_frame(&out[1], &|_| true).unwrap();
        let msg2 = responder.outgoing();
        assert!(dialer.on_frame(&msg2[0]).is_err());
    }
    // And the other way: a v2 dialer against a responder that thinks it saw v3.
    let mut dialer =
        ChannelDialer::start_version(&a, *b.public(), name("Laptop"), HelloVersion::V2).unwrap();
    let out = dialer.outgoing();
    let mut responder = ChannelResponder::new(&b, name("Phone"), b"PWSC\x03\x01");
    responder.on_frame(&out[1], &|_| true).unwrap();
    let msg2 = responder.outgoing();
    assert!(dialer.on_frame(&msg2[0]).is_err());
}

#[test]
fn share_payloads_on_v1_or_v2_channels_are_protocol_errors() {
    let (a, b) = (key(1), key(2));
    for payload in share_payloads() {
        for mut ends in [connect(&a, &b), connect_v2(&a, &b)] {
            assert_eq!(
                ends.dialer.seal_sync(&payload).err(),
                Some(ChannelError::Protocol)
            );
            let frame = ends.dialer.seal_any(&payload.encode()).unwrap();
            assert_eq!(
                ends.responder.open(&frame).err(),
                Some(ChannelError::Protocol)
            );
            assert!(ends.responder.is_closed(), "protocol error closes");
        }
    }
}

#[test]
fn a_v3_channel_carries_sync_and_share_payloads() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect_v3(&a, &b);
    let mut all = share_payloads();
    all.push(Payload::SyncCtl {
        more: false,
        fragment: vec![3; 1000],
    });
    all.push(Payload::CopyData {
        bytes: vec![4; 1000],
    });
    for payload in all {
        let frame = ends.responder.seal_sync(&payload).unwrap();
        assert!(frame.len() <= MAX_FRAME, "framing unchanged");
        assert_eq!(ends.dialer.open(&frame).unwrap(), payload);
        let back = ends.dialer.seal_sync(&payload).unwrap();
        assert_eq!(ends.responder.open(&back).unwrap(), payload);
    }
    let keepalive = ends.dialer.seal(&Payload::Keepalive).unwrap();
    assert_eq!(ends.responder.open(&keepalive).unwrap(), Payload::Keepalive);
    // Share payloads cannot use the maintenance path.
    assert!(
        ends.dialer
            .seal(&Payload::ShareMsg { body: vec![1] })
            .is_err()
    );
}

#[test]
fn out_of_bounds_share_payloads_are_refused_on_v3() {
    let (a, b) = (key(1), key(2));
    let mut ends = connect_v3(&a, &b);
    assert!(
        ends.dialer
            .seal_sync(&Payload::ShareMsg { body: vec![] })
            .is_err()
    );
    assert!(
        ends.dialer
            .seal_sync(&Payload::ShareData {
                bytes: vec![0; 1001]
            })
            .is_err()
    );
    let frame = ends.dialer.seal_any(&[0x30]).unwrap();
    assert_eq!(
        ends.responder.open(&frame).err(),
        Some(ChannelError::Protocol)
    );
    let mut ends = connect_v3(&a, &b);
    let frame = ends.dialer.seal_any(&[0x32, 1]).unwrap();
    assert_eq!(
        ends.responder.open(&frame).err(),
        Some(ChannelError::Protocol),
        "unknown type"
    );
}
