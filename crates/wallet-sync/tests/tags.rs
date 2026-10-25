//! 004 T036: blinded wallet tags and state digests (research R9).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::codec::encode_state;
use wallet_sync::tags::{digest_matches, state_digest, tag, tag_matches};

const SESSION: [u8; 32] = [0x11; 32];

fn wid(byte: u8) -> WalletId {
    WalletId::from_bytes([byte; 16])
}

fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(
        pairs
            .iter()
            .map(|(d, c)| (DeviceId::new(*d).unwrap(), *c))
            .collect(),
    )
    .unwrap()
}

fn reference(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    full[..16].try_into().unwrap()
}

#[test]
fn tag_is_truncated_hmac_sha256_keyed_by_the_wallet_id() {
    let expected = reference(
        &[7; 16],
        &[
            b"passwsync-sync-tag-v1",
            &SESSION,
            &5u32.to_be_bytes(),
            &[1],
        ],
    );
    assert_eq!(tag(&wid(7), &SESSION, 5, 1), expected);
    // Pinned known answer.
    let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "93e2f8e57b0513a8d3d7f23c15988c7f");
}

#[test]
fn state_digest_covers_the_canonical_state() {
    let state = sv(&[("a", 2), ("b", 1)]);
    let expected = reference(
        &[7; 16],
        &[
            b"passwsync-sync-state-v1",
            &SESSION,
            &5u32.to_be_bytes(),
            &[0],
            &encode_state(&state),
        ],
    );
    assert_eq!(state_digest(&wid(7), &SESSION, 5, 0, &state), expected);
    assert_ne!(
        state_digest(&wid(7), &SESSION, 5, 0, &sv(&[("a", 2), ("b", 2)])),
        expected
    );
}

#[test]
fn session_round_role_and_wallet_separate_tags() {
    let base = tag(&wid(1), &SESSION, 1, 0);
    assert_ne!(base, tag(&wid(1), &[0x12; 32], 1, 0), "session");
    assert_ne!(base, tag(&wid(1), &SESSION, 2, 0), "round");
    assert_ne!(base, tag(&wid(1), &SESSION, 1, 1), "role");
    assert_ne!(base, tag(&wid(2), &SESSION, 1, 0), "wallet");
    let state = sv(&[("a", 1)]);
    let digest = state_digest(&wid(1), &SESSION, 1, 0, &state);
    assert_ne!(digest, state_digest(&wid(1), &SESSION, 1, 1, &state));
    assert_ne!(digest, base, "tag and digest domains differ");
}

#[test]
fn comparisons_go_through_constant_time_verification() {
    let state = sv(&[("a", 1)]);
    let t = tag(&wid(3), &SESSION, 9, 0);
    assert!(tag_matches(&wid(3), &SESSION, 9, 0, &t));
    let mut wrong = t;
    wrong[15] ^= 1;
    assert!(!tag_matches(&wid(3), &SESSION, 9, 0, &wrong));
    let d = state_digest(&wid(3), &SESSION, 9, 0, &state);
    assert!(digest_matches(&wid(3), &SESSION, 9, 0, &state, &d));
    assert!(!digest_matches(
        &wid(3),
        &SESSION,
        9,
        0,
        &sv(&[("a", 2)]),
        &d
    ));
}

#[test]
fn the_wallet_id_never_appears_in_a_tag_or_digest() {
    let id = [0xA5u8; 16];
    let t = tag(&WalletId::from_bytes(id), &SESSION, 1, 0);
    assert_ne!(t, id);
    let d = state_digest(
        &WalletId::from_bytes(id),
        &SESSION,
        1,
        0,
        &StateVector::new(),
    );
    assert_ne!(d, id);
}
