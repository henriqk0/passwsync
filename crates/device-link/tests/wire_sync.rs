//! 004 T030: `SyncCtl` (0x20) and `CopyData` (0x21) codecs (contracts/sync-protocol.md).

use device_link::error::Error;
use device_link::wire::Payload;

#[test]
fn sync_payloads_encode_as_documented() {
    let ctl = Payload::SyncCtl {
        more: true,
        fragment: vec![0xAA, 0xBB],
    };
    assert_eq!(ctl.encode(), vec![0x20, 1, 0xAA, 0xBB]);
    let last = Payload::SyncCtl {
        more: false,
        fragment: vec![5],
    };
    assert_eq!(last.encode(), vec![0x20, 0, 5]);
    let data = Payload::CopyData {
        bytes: vec![1, 2, 3],
    };
    assert_eq!(data.encode(), vec![0x21, 1, 2, 3]);
    for p in [ctl, last, data] {
        assert_eq!(Payload::decode_v2(&p.encode()), Ok(p));
    }
}

#[test]
fn bounds_are_1_to_1000_bytes() {
    let at_limit = Payload::SyncCtl {
        more: false,
        fragment: vec![0; 1000],
    };
    assert!(Payload::decode_v2(&at_limit.encode()).is_ok());
    let mut over = vec![0x20, 0];
    over.extend_from_slice(&[0; 1001]);
    assert_eq!(Payload::decode_v2(&over), Err(Error::Protocol));
    assert_eq!(
        Payload::decode_v2(&[0x20, 0]),
        Err(Error::Protocol),
        "empty fragment"
    );
    assert_eq!(Payload::decode_v2(&[0x20]), Err(Error::Protocol));
    assert_eq!(
        Payload::decode_v2(&[0x20, 2, 1]),
        Err(Error::Protocol),
        "bad more"
    );
    assert_eq!(
        Payload::decode_v2(&[0x21]),
        Err(Error::Protocol),
        "empty data"
    );
    let mut data_over = vec![0x21];
    data_over.extend_from_slice(&[0; 1001]);
    assert_eq!(Payload::decode_v2(&data_over), Err(Error::Protocol));
    let mut data_ok = vec![0x21];
    data_ok.extend_from_slice(&[0; 1000]);
    assert!(Payload::decode_v2(&data_ok).is_ok());
}

#[test]
fn v1_decoding_still_rejects_sync_types_and_unknown_types_stay_errors() {
    assert_eq!(Payload::decode(&[0x20, 0, 1]), Err(Error::Protocol));
    assert_eq!(Payload::decode(&[0x21, 1]), Err(Error::Protocol));
    for bad in [&[0x22u8, 1][..], &[0x1f, 1], &[0xff]] {
        assert_eq!(Payload::decode_v2(bad), Err(Error::Protocol), "{bad:?}");
    }
    // The 003 set still decodes under v2 rules.
    assert_eq!(Payload::decode_v2(&[0x13]), Ok(Payload::Keepalive));
}
