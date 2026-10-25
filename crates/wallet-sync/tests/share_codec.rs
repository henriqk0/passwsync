//! 005 T015: share message codec (specs/005-wallet-sharing/contracts/share-protocol.md
//! "New payload types").

use wallet_sync::error::ProtocolError;
use wallet_sync::share::codec::{AbortReason, ShareMsg};

const ALL_REASONS: [(AbortReason, u8); 10] = [
    (AbortReason::Invalid, 1),
    (AbortReason::Rejected, 2),
    (AbortReason::Cancelled, 3),
    (AbortReason::Expired, 4),
    (AbortReason::Busy, 5),
    (AbortReason::Storage, 6),
    (AbortReason::TooLarge, 7),
    (AbortReason::SenderError, 8),
    (AbortReason::RecipientCancelled, 9),
    (AbortReason::ReceivedLimit, 10),
];

fn samples() -> Vec<(ShareMsg, Vec<u8>)> {
    let rid = 0x0102_0304u32;
    let mut redeem = vec![0x01, 1, 2, 3, 4];
    redeem.extend_from_slice(&[0xAA; 32]);
    let mut out = vec![
        (
            ShareMsg::Redeem {
                rid,
                proof: [0xAA; 32],
            },
            redeem,
        ),
        (
            ShareMsg::Pending {
                rid,
                seconds_left: 300,
            },
            vec![0x02, 1, 2, 3, 4, 0x01, 0x2C],
        ),
        (
            ShareMsg::Offer { rid, size: 79 },
            vec![0x03, 1, 2, 3, 4, 0, 0, 0, 79],
        ),
        (ShareMsg::End { rid }, vec![0x04, 1, 2, 3, 4]),
        (ShareMsg::Stored { rid }, vec![0x05, 1, 2, 3, 4]),
    ];
    for (reason, code) in ALL_REASONS {
        out.push((
            ShareMsg::Abort { rid, reason },
            vec![0x06, 1, 2, 3, 4, code],
        ));
    }
    out
}

#[test]
fn every_message_round_trips_with_its_exact_layout() {
    for (msg, bytes) in samples() {
        assert_eq!(msg.encode(), bytes, "{msg:?}");
        assert_eq!(ShareMsg::decode(&bytes), Ok(msg.clone()));
        assert_eq!(msg.rid(), 0x0102_0304);
    }
    assert_eq!(
        ShareMsg::Redeem {
            rid: 0,
            proof: [0; 32]
        }
        .encode()
        .len(),
        37
    );
    assert_eq!(AbortReason::from_code(10), Some(AbortReason::ReceivedLimit));
    assert_eq!(AbortReason::ReceivedLimit.code(), 10);
}

#[test]
fn ranges_are_enforced() {
    let pending = |s: u16| {
        let mut b = vec![0x02, 0, 0, 0, 1];
        b.extend_from_slice(&s.to_be_bytes());
        ShareMsg::decode(&b)
    };
    assert!(pending(1).is_ok());
    assert!(pending(300).is_ok());
    assert_eq!(pending(0), Err(ProtocolError));
    assert_eq!(pending(301), Err(ProtocolError));
    let offer = |size: u32| {
        let mut b = vec![0x03, 0, 0, 0, 1];
        b.extend_from_slice(&size.to_be_bytes());
        ShareMsg::decode(&b)
    };
    assert!(offer(79).is_ok());
    assert!(offer(67_108_864).is_ok());
    // Out-of-range sizes decode; the recipient answers them with Abort(too_large)
    // (share-protocol.md "Exchange" step 3; see share_faults.rs).
    assert!(offer(78).is_ok());
    assert!(offer(67_108_865).is_ok());
}

#[test]
fn malformed_bodies_are_protocol_errors() {
    assert_eq!(ShareMsg::decode(&[]), Err(ProtocolError), "empty");
    for stype in [0x00u8, 0x07, 0xff] {
        assert_eq!(ShareMsg::decode(&[stype, 0, 0, 0, 1]), Err(ProtocolError));
    }
    for code in [0u8, 11, 0xff] {
        assert_eq!(
            ShareMsg::decode(&[0x06, 0, 0, 0, 1, code]),
            Err(ProtocolError),
            "unknown reason {code}"
        );
    }
    for (_, bytes) in samples() {
        // One byte short and one trailing byte.
        assert_eq!(
            ShareMsg::decode(&bytes[..bytes.len() - 1]),
            Err(ProtocolError)
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(ShareMsg::decode(&long), Err(ProtocolError));
    }
    let big = vec![0x01; 1001];
    assert_eq!(
        ShareMsg::decode(&big),
        Err(ProtocolError),
        "over 1000 bytes"
    );
}

#[test]
fn debug_omits_proofs_and_rid() {
    let msg = ShareMsg::Redeem {
        rid: 0xDEAD_BEEF,
        proof: [0xAB; 32],
    };
    let text = format!("{msg:?}");
    for needle in ["171", "ab", "AB", "3735928559", "deadbeef", "DEADBEEF"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
    for (msg, _) in samples() {
        let text = format!("{msg:?}");
        assert!(!text.contains("16909060"), "rid in {text}");
        assert!(!text.contains("170"), "proof in {text}");
    }
}
