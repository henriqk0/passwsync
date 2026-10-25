//! 004 T034: control-message codec and fragmentation (contracts/sync-protocol.md).

use vault_core::{DeviceId, StateVector};
use wallet_sync::codec::{
    AbortReason, Ctl, MAX_CTL, MAX_TAGS, Reassembler, RefuseReason, decode, encode, fragment,
};
use wallet_sync::error::ProtocolError;

fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(
        pairs
            .iter()
            .map(|(d, c)| (DeviceId::new(*d).unwrap(), *c))
            .collect(),
    )
    .unwrap()
}

#[test]
fn every_ctype_has_the_documented_layout() {
    let cases: Vec<(Ctl, Vec<u8>)> = vec![
        (
            Ctl::Tags {
                round: 7,
                entries: vec![([1; 16], [2; 16])],
            },
            [vec![0x01, 0, 0, 0, 7, 0, 1], vec![1; 16], vec![2; 16]].concat(),
        ),
        (
            Ctl::Matches {
                round: 7,
                entries: vec![(3, true), (5, false)],
            },
            vec![0x02, 0, 0, 0, 7, 0, 2, 0, 3, 1, 0, 5, 0],
        ),
        (
            Ctl::Summary {
                round: 1,
                idx: 2,
                no_offer: true,
                state: sv(&[("ab", 3)]),
            },
            vec![
                0x03, 0, 0, 0, 1, 0, 2, 1, 0, 1, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 3,
            ],
        ),
        (Ctl::Want { round: 1, idx: 9 }, vec![0x04, 0, 0, 0, 1, 0, 9]),
        (
            Ctl::Refuse {
                round: 1,
                idx: 9,
                reason: RefuseReason::Changed,
            },
            vec![0x05, 0, 0, 0, 1, 0, 9, 3],
        ),
        (
            Ctl::CopyStart {
                round: 1,
                idx: 9,
                size: 100_000,
            },
            vec![0x06, 0, 0, 0, 1, 0, 9, 0, 1, 0x86, 0xa0],
        ),
        (
            Ctl::CopyEnd { round: 1, idx: 9 },
            vec![0x07, 0, 0, 0, 1, 0, 9],
        ),
        (
            Ctl::CopyAbort {
                round: 1,
                idx: 9,
                reason: AbortReason::Cancelled,
            },
            vec![0x08, 0, 0, 0, 1, 0, 9, 5],
        ),
        (Ctl::Done { round: 2 }, vec![0x09, 0, 0, 0, 2]),
        (Ctl::Busy { round: 2 }, vec![0x0A, 0, 0, 0, 2]),
    ];
    for (ctl, bytes) in cases {
        assert_eq!(encode(&ctl), bytes, "{ctl:?}");
        assert_eq!(decode(&bytes), Ok(ctl));
    }
}

#[test]
fn reasons_are_closed_sets() {
    for (byte, reason) in [
        (1, RefuseReason::Busy),
        (2, RefuseReason::NotOfferable),
        (3, RefuseReason::Changed),
        (4, RefuseReason::Storage),
    ] {
        assert_eq!(
            decode(&[0x05, 0, 0, 0, 1, 0, 0, byte]),
            Ok(Ctl::Refuse {
                round: 1,
                idx: 0,
                reason
            })
        );
    }
    for (byte, reason) in [
        (1, AbortReason::ReadError),
        (2, AbortReason::Changed),
        (3, AbortReason::TooLarge),
        (4, AbortReason::Storage),
        (5, AbortReason::Cancelled),
    ] {
        assert_eq!(
            decode(&[0x08, 0, 0, 0, 1, 0, 0, byte]),
            Ok(Ctl::CopyAbort {
                round: 1,
                idx: 0,
                reason
            })
        );
    }
    for bad in [
        &[0x05u8, 0, 0, 0, 1, 0, 0, 0][..],
        &[0x05, 0, 0, 0, 1, 0, 0, 5],
        &[0x08, 0, 0, 0, 1, 0, 0, 6],
    ] {
        assert_eq!(decode(bad), Err(ProtocolError), "{bad:?}");
    }
}

#[test]
fn ranges_are_enforced() {
    // Tags: at most 512 entries.
    let tags = |n: usize| Ctl::Tags {
        round: 1,
        entries: vec![([0; 16], [0; 16]); n],
    };
    assert_eq!(MAX_TAGS, 512);
    assert!(decode(&encode(&tags(512))).is_ok());
    let mut over = vec![0x01, 0, 0, 0, 1, 0x02, 0x01];
    over.extend(std::iter::repeat_n(0u8, 513 * 32));
    assert_eq!(decode(&over), Err(ProtocolError));
    // Matches: at most 512, in_sync 0/1.
    assert_eq!(
        decode(&[0x02, 0, 0, 0, 1, 0, 1, 0, 0, 2]),
        Err(ProtocolError)
    );
    // CopyStart size 79..=64 MiB.
    for (size, ok) in [
        (78u32, false),
        (79, true),
        (67_108_864, true),
        (67_108_865, false),
    ] {
        let mut bytes = vec![0x06, 0, 0, 0, 1, 0, 0];
        bytes.extend_from_slice(&size.to_be_bytes());
        assert_eq!(decode(&bytes).is_ok(), ok, "size {size}");
    }
    // Summary flags: only bit 0.
    assert_eq!(
        decode(&[0x03, 0, 0, 0, 1, 0, 0, 2, 0, 0]),
        Err(ProtocolError)
    );
}

#[test]
fn state_vector_encoding_rules() {
    let summary = |sv_bytes: &[u8]| {
        let mut bytes = vec![0x03, 0, 0, 0, 1, 0, 0, 0];
        bytes.extend_from_slice(sv_bytes);
        decode(&bytes)
    };
    assert!(summary(&[0, 0]).is_ok(), "empty");
    let entry =
        |id: &[u8], c: u64| [vec![id.len() as u8], id.to_vec(), c.to_be_bytes().to_vec()].concat();
    let unsorted = [vec![0, 2], entry(b"b", 1), entry(b"a", 1)].concat();
    let duplicate = [vec![0, 2], entry(b"a", 1), entry(b"a", 2)].concat();
    let zero = [vec![0, 1], entry(b"a", 0)].concat();
    let empty_id = [vec![0, 1], entry(b"", 1)].concat();
    let long_id = [vec![0, 1], entry(&[b'x'; 65], 1)].concat();
    let bad_utf8 = [vec![0, 1], entry(&[0xff], 1)].concat();
    let mut too_many = vec![0x01, 0x01]; // 257
    for i in 0..257u32 {
        too_many.extend(entry(format!("{i:03}").as_bytes(), 1));
    }
    for (name, bytes) in [
        ("unsorted", unsorted),
        ("duplicate", duplicate),
        ("zero", zero),
        ("empty id", empty_id),
        ("long id", long_id),
        ("bad utf8", bad_utf8),
        ("257 devices", too_many),
    ] {
        assert_eq!(summary(&bytes), Err(ProtocolError), "{name}");
    }
    let max: Vec<(String, u64)> = (0..256).map(|i| (format!("{i:064}"), u64::MAX)).collect();
    let big = StateVector::from_pairs(
        max.iter()
            .map(|(d, c)| (DeviceId::new(d.clone()).unwrap(), *c))
            .collect(),
    )
    .unwrap();
    let largest = encode(&Ctl::Summary {
        round: 1,
        idx: 0,
        no_offer: false,
        state: big,
    });
    assert!(largest.len() <= MAX_CTL, "{} bytes", largest.len());
    assert!(decode(&largest).is_ok());
}

#[test]
fn trailing_truncated_unknown_and_oversized_are_rejected() {
    let done = encode(&Ctl::Done { round: 1 });
    let mut trailing = done.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(ProtocolError));
    for n in 0..done.len() {
        assert_eq!(decode(&done[..n]), Err(ProtocolError));
    }
    for ctype in [0x00u8, 0x0B, 0x20, 0xff] {
        assert_eq!(decode(&[ctype, 0, 0, 0, 1]), Err(ProtocolError));
    }
    assert_eq!(decode(&vec![0x01; MAX_CTL + 1]), Err(ProtocolError));
}

#[test]
fn fragments_are_at_most_1000_bytes_and_reassemble() {
    let msg: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
    let parts = fragment(&msg);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].1.len(), 1000);
    assert!(parts[0].0 && parts[1].0 && !parts[2].0, "more flags");
    let mut r = Reassembler::default();
    assert_eq!(r.push(true, &parts[0].1), Ok(None));
    assert!(r.in_progress());
    assert_eq!(r.push(true, &parts[1].1), Ok(None));
    assert_eq!(r.push(false, &parts[2].1), Ok(Some(msg.clone())));
    assert!(!r.in_progress());
    // A one-fragment message.
    assert_eq!(fragment(&[1, 2, 3]), vec![(false, vec![1, 2, 3])]);
    assert_eq!(r.push(false, &[1, 2, 3]), Ok(Some(vec![1, 2, 3])));
}

#[test]
fn reassembly_beyond_24_kib_is_a_protocol_error() {
    let mut r = Reassembler::default();
    let chunk = vec![0u8; 1000];
    for _ in 0..24 {
        assert_eq!(r.push(true, &chunk), Ok(None));
    }
    assert!(r.push(true, &[0; 577]).is_err(), "24 577 bytes");
    let mut r = Reassembler::default();
    for _ in 0..24 {
        r.push(true, &chunk).unwrap();
    }
    assert_eq!(
        r.push(false, &[0; 576]).map(|m| m.map(|m| m.len())),
        Ok(Some(MAX_CTL))
    );
}

#[test]
fn empty_or_oversized_fragments_are_rejected() {
    let mut r = Reassembler::default();
    assert!(r.push(false, &[]).is_err());
    let mut r = Reassembler::default();
    assert!(r.push(false, &[0; 1001]).is_err());
}
