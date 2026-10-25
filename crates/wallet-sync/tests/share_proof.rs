//! 005 T017: the redemption proof (contracts/share-protocol.md "Redemption proof", R5):
//! HMAC-SHA-256 keyed with the 8 code digits over
//! `"passwsync-share-redeem-v1" || session || sender_id || recipient_id || rid`.
//! Known answers were computed independently (Python `hmac`/`hashlib`).

use wallet_sync::ports::PeerId;
use wallet_sync::share::proof::{redeem_proof, verify_proof};
use zeroize::Zeroizing;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn known_answer_vectors() {
    let one = redeem_proof("12345678", &[1; 32], &PeerId([2; 32]), &PeerId([3; 32]), 7);
    assert_eq!(
        hex(&one),
        "21bab43f44753a1dde7e8d720f61690823727e0c6993f00235a5ae75e139e8f9"
    );
    let mut session = [0u8; 32];
    for (i, b) in session.iter_mut().enumerate() {
        *b = i as u8;
    }
    let two = redeem_proof(
        "00000000",
        &session,
        &PeerId([0xAA; 32]),
        &PeerId([0x55; 32]),
        u32::MAX,
    );
    assert_eq!(
        hex(&two),
        "80bd4d57f19f78c43241d9087a4591407f6819dfc6c449e80d5383dc79db07b8"
    );
}

#[test]
fn every_input_is_bound() {
    let base = || {
        (
            "12345678",
            [1u8; 32],
            PeerId([2; 32]),
            PeerId([3; 32]),
            7u32,
        )
    };
    let (c, s, a, b, r) = base();
    let reference = redeem_proof(c, &s, &a, &b, r);
    assert_ne!(redeem_proof("12345679", &s, &a, &b, r), reference, "code");
    assert_ne!(redeem_proof(c, &[9; 32], &a, &b, r), reference, "session");
    assert_ne!(
        redeem_proof(c, &s, &PeerId([4; 32]), &b, r),
        reference,
        "sender"
    );
    assert_ne!(
        redeem_proof(c, &s, &a, &PeerId([4; 32]), r),
        reference,
        "recipient"
    );
    assert_ne!(redeem_proof(c, &s, &b, &a, r), reference, "roles swapped");
    assert_ne!(redeem_proof(c, &s, &a, &b, 8), reference, "rid");
}

#[test]
fn verification_accepts_only_the_matching_proof() {
    let (s, a, b) = ([1u8; 32], PeerId([2; 32]), PeerId([3; 32]));
    let proof = redeem_proof("12345678", &s, &a, &b, 7);
    assert!(verify_proof("12345678", &s, &a, &b, 7, &proof));
    assert!(!verify_proof("87654321", &s, &a, &b, 7, &proof));
    assert!(!verify_proof("12345678", &s, &a, &b, 8, &proof));
    let mut flipped = proof;
    flipped[31] ^= 1;
    assert!(!verify_proof("12345678", &s, &a, &b, 7, &flipped));
    flipped = proof;
    flipped[0] ^= 0x80;
    assert!(!verify_proof("12345678", &s, &a, &b, 7, &flipped));
}

#[test]
fn verification_is_constant_time_by_construction() {
    // The verifier must use `Mac::verify_slice` (subtle's constant-time compare), never `==`
    // on the tag bytes.
    let source = include_str!("../src/share/proof.rs");
    assert!(source.contains("verify_slice"));
    let code_part = source.split("#[cfg(test)]").next().unwrap();
    assert!(!code_part.contains("== proof"), "no variable-time compare");
    assert!(!code_part.contains("proof =="), "no variable-time compare");
}

#[test]
fn the_code_never_appears_in_the_proof_and_a_zeroizing_code_can_be_used() {
    let code = Zeroizing::new(String::from("31415926"));
    let proof = redeem_proof(&code, &[7; 32], &PeerId([1; 32]), &PeerId([2; 32]), 1);
    let digits = code.as_bytes();
    assert!(!proof.windows(digits.len()).any(|w| w == digits));
    assert!(!hex(&proof).contains("31415926"));
    drop(code); // wiped on drop (Zeroizing)
}
