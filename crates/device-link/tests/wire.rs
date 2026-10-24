use device_link::error::Error;
use device_link::name::DeviceName;
use device_link::wire::{
    CloseReason, HelloKind, MAX_FRAME, Payload, RejectReason, decode_frame, encode_frame,
    frame_len, hello, parse_hello,
};

fn name(text: &str) -> DeviceName {
    DeviceName::parse(text).unwrap()
}

#[test]
fn frames_carry_a_big_endian_length_of_1_to_1024() {
    assert_eq!(MAX_FRAME, 1024);
    assert_eq!(encode_frame(b"abc").unwrap(), b"\x00\x03abc");
    let big = vec![7u8; 1024];
    let framed = encode_frame(&big).unwrap();
    assert_eq!(&framed[..2], &[0x04, 0x00]);
    assert_eq!(encode_frame(&[]).err(), Some(Error::Protocol));
    assert_eq!(encode_frame(&[0u8; 1025]).err(), Some(Error::Protocol));
    assert_eq!(frame_len([0, 1]), Ok(1));
    assert_eq!(frame_len([4, 0]), Ok(1024));
    assert_eq!(frame_len([0, 0]), Err(Error::Protocol));
    assert_eq!(frame_len([4, 1]), Err(Error::Protocol));
    assert_eq!(frame_len([0xff, 0xff]), Err(Error::Protocol));
}

#[test]
fn decode_frame_handles_truncation_and_limits() {
    assert_eq!(decode_frame(b"\x00\x03abcXY"), Ok(Some((&b"abc"[..], 5))));
    assert_eq!(decode_frame(b"\x00\x03ab"), Ok(None), "truncated body");
    assert_eq!(decode_frame(b"\x00"), Ok(None), "truncated header");
    assert_eq!(decode_frame(b"\x00\x00"), Err(Error::Protocol));
    assert_eq!(
        decode_frame(b"\x04\x01"),
        Err(Error::Protocol),
        "1025 rejected before body"
    );
}

#[test]
fn hello_has_magic_version_and_kind() {
    assert_eq!(hello(HelloKind::Channel), *b"PWSC\x01\x01");
    assert_eq!(hello(HelloKind::Pairing), *b"PWSC\x01\x02");
    assert_eq!(parse_hello(b"PWSC\x01\x01"), Ok(HelloKind::Channel));
    assert_eq!(parse_hello(b"PWSC\x01\x02"), Ok(HelloKind::Pairing));
    for bad in [
        &b"PWSD\x01\x01"[..],
        b"PWSC\x02\x01",
        b"PWSC\x01\x03",
        b"PWSC\x01\x00",
        b"PWSC\x01",
        b"PWSC\x01\x01\x00",
        b"",
    ] {
        assert_eq!(parse_hello(bad), Err(Error::Protocol), "{bad:?}");
    }
}

#[test]
fn every_payload_round_trips_with_the_contract_encoding() {
    let cases: Vec<(Payload, Vec<u8>)> = vec![
        (
            Payload::PairHello { name: name("Ab") },
            b"\x01\x02Ab".to_vec(),
        ),
        (
            Payload::PairPending { seconds_left: 287 },
            vec![0x02, 0x01, 0x1f],
        ),
        (
            Payload::PairCommit { name: name("é") },
            vec![0x03, 0x02, 0xc3, 0xa9],
        ),
        (
            Payload::PairReject {
                reason: RejectReason::Rejected,
            },
            vec![0x04, 1],
        ),
        (
            Payload::PairReject {
                reason: RejectReason::Expired,
            },
            vec![0x04, 2],
        ),
        (
            Payload::PairReject {
                reason: RejectReason::SelfPair,
            },
            vec![0x04, 3],
        ),
        (
            Payload::PairReject {
                reason: RejectReason::AlreadyPaired,
            },
            vec![0x04, 4],
        ),
        (
            Payload::PairReject {
                reason: RejectReason::Limit,
            },
            vec![0x04, 5],
        ),
        (Payload::PairAck, vec![0x05]),
        (
            Payload::ChannelHello { name: name("A") },
            b"\x10\x01A".to_vec(),
        ),
        (Payload::Welcome { name: name("B") }, b"\x11\x01B".to_vec()),
        (Payload::Refused, vec![0x12]),
        (Payload::Keepalive, vec![0x13]),
        (
            Payload::NameUpdate { name: name("C") },
            b"\x14\x01C".to_vec(),
        ),
        (
            Payload::Close {
                reason: CloseReason::Shutdown,
            },
            vec![0x15, 1],
        ),
        (
            Payload::Close {
                reason: CloseReason::Duplicate,
            },
            vec![0x15, 2],
        ),
    ];
    for (payload, bytes) in cases {
        assert_eq!(payload.encode(), bytes, "{payload:?}");
        assert_eq!(Payload::decode(&bytes), Ok(payload));
    }
}

#[test]
fn payload_decode_is_strict() {
    let max = "é".repeat(64); // 128 bytes
    let mut ok = vec![0x01, 128];
    ok.extend_from_slice(max.as_bytes());
    assert!(Payload::decode(&ok).is_ok());
    let bad: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x06],
        vec![0x16],
        vec![0x20, 1, b'A'], // e.g. a wallet-sync type
        vec![0x05, 0x00],    // trailing byte
        vec![0x13, 0x00],
        vec![0x01, 0x00],             // empty name
        vec![0x01, 0x03, b'A', b'B'], // length beyond the end
        vec![0x01, 0x01, b'A', b'X'], // trailing
        vec![0x01, 0x01, b'"'],
        vec![0x01, 0x01, b'\n'],
        vec![0x01, 0x02, 0xc3, 0x28], // invalid UTF-8
        vec![0x02, 0x01],             // short u16
        vec![0x04, 0],
        vec![0x04, 6],
        vec![0x15, 0],
        vec![0x15, 3],
    ];
    for bytes in bad {
        assert_eq!(Payload::decode(&bytes), Err(Error::Protocol), "{bytes:?}");
    }
    let mut long = vec![0x01, 65];
    long.extend_from_slice(&[b'x'; 65]);
    assert_eq!(Payload::decode(&long), Err(Error::Protocol), "65 scalars");
}
