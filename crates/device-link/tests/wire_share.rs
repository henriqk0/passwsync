//! 005 T005: channel Hello v3 and the share payloads `ShareMsg` (0x30) and `ShareData` (0x31)
//! (specs/005-wallet-sharing/contracts/share-protocol.md "Negotiation", "New payload types").

use device_link::error::Error;
use device_link::pairing::CHANNEL_PROLOGUE_V3;
use device_link::wire::{
    HelloKind, HelloVersion, Payload, hello, hello_versioned, parse_hello, parse_hello_versioned,
};

#[test]
fn hello_v3_bytes_and_parsing() {
    assert_eq!(
        hello_versioned(HelloKind::Channel, HelloVersion::V3),
        *b"PWSC\x03\x01"
    );
    assert_eq!(
        parse_hello_versioned(b"PWSC\x03\x01"),
        Ok((HelloKind::Channel, HelloVersion::V3))
    );
    // v1 and v2 unchanged, pairing unchanged.
    assert_eq!(
        parse_hello_versioned(b"PWSC\x02\x01"),
        Ok((HelloKind::Channel, HelloVersion::V2))
    );
    assert_eq!(
        parse_hello_versioned(b"PWSC\x01\x01"),
        Ok((HelloKind::Channel, HelloVersion::V1))
    );
    assert_eq!(hello(HelloKind::Pairing), *b"PWSC\x01\x02");
    for bad in [
        &b"PWSC\x03\x02"[..],
        b"PWSC\x04\x01",
        b"PWSC\x03",
        b"PWSC\x03\x01\x00",
        b"PWSC\x00\x01",
    ] {
        assert!(parse_hello_versioned(bad).is_err(), "{bad:?}");
    }
    // The 003 parser stays v1-only.
    assert!(parse_hello(b"PWSC\x03\x01").is_err());
    assert!(parse_hello(b"PWSC\x02\x01").is_err());
    assert_eq!(CHANNEL_PROLOGUE_V3, b"passwsync-channel-v3");
}

#[test]
fn share_payloads_encode_as_documented_and_round_trip() {
    let msg = Payload::ShareMsg {
        body: vec![0x01, 2, 3],
    };
    assert_eq!(msg.encode(), vec![0x30, 0x01, 2, 3]);
    let data = Payload::ShareData {
        bytes: vec![9, 8, 7],
    };
    assert_eq!(data.encode(), vec![0x31, 9, 8, 7]);
    for len in [1usize, 37, 999, 1000] {
        for p in [
            Payload::ShareMsg {
                body: vec![0x5a; len],
            },
            Payload::ShareData {
                bytes: vec![0xa5; len],
            },
        ] {
            assert_eq!(Payload::decode_v3(&p.encode()), Ok(p));
        }
    }
}

#[test]
fn share_payload_bounds_and_unknown_types() {
    assert_eq!(Payload::decode_v3(&[0x30]), Err(Error::Protocol), "empty");
    assert_eq!(Payload::decode_v3(&[0x31]), Err(Error::Protocol), "empty");
    let mut over = vec![0x30];
    over.extend_from_slice(&[0; 1001]);
    assert_eq!(Payload::decode_v3(&over), Err(Error::Protocol));
    let mut over = vec![0x31];
    over.extend_from_slice(&[0; 1001]);
    assert_eq!(Payload::decode_v3(&over), Err(Error::Protocol));
    for bad in [&[0x32u8, 1][..], &[0x2f, 1], &[0xff], &[0x22, 1]] {
        assert_eq!(Payload::decode_v3(bad), Err(Error::Protocol), "{bad:?}");
    }
    // v3 still decodes the v2 and 003 sets.
    assert_eq!(Payload::decode_v3(&[0x13]), Ok(Payload::Keepalive));
    assert_eq!(
        Payload::decode_v3(&[0x21, 1]),
        Ok(Payload::CopyData { bytes: vec![1] })
    );
    // Lower versions reject the share types.
    assert_eq!(Payload::decode_v2(&[0x30, 1]), Err(Error::Protocol));
    assert_eq!(Payload::decode_v2(&[0x31, 1]), Err(Error::Protocol));
    assert_eq!(Payload::decode(&[0x30, 1]), Err(Error::Protocol));
    assert_eq!(Payload::decode(&[0x31, 1]), Err(Error::Protocol));
}
