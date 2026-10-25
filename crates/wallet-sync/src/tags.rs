//! Session-blinded wallet tags and state digests (research R9): HMAC-SHA-256 keyed by the
//! 16-byte wallet id (never sent), truncated to 16 bytes, bound to the Noise session hash,
//! the round and the initiator's role. Comparisons use `hmac`'s constant-time verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use vault_core::{StateVector, WalletId};

use crate::codec::encode_state;

type HmacSha256 = Hmac<Sha256>;

const TAG_DOMAIN: &[u8] = b"passwsync-sync-tag-v1";
const STATE_DOMAIN: &[u8] = b"passwsync-sync-state-v1";

fn mac(wallet: &WalletId) -> HmacSha256 {
    // HMAC accepts keys of any length; a 16-byte key cannot fail.
    HmacSha256::new_from_slice(wallet.as_bytes()).unwrap_or_else(|_| unreachable!())
}

fn tag_mac(wallet: &WalletId, session: &[u8; 32], round: u32, role: u8) -> HmacSha256 {
    let mut m = mac(wallet);
    m.update(TAG_DOMAIN);
    m.update(session);
    m.update(&round.to_be_bytes());
    m.update(&[role]);
    m
}

fn digest_mac(
    wallet: &WalletId,
    session: &[u8; 32],
    round: u32,
    role: u8,
    state: &StateVector,
) -> HmacSha256 {
    let mut m = mac(wallet);
    m.update(STATE_DOMAIN);
    m.update(session);
    m.update(&round.to_be_bytes());
    m.update(&[role]);
    m.update(&encode_state(state));
    m
}

fn truncate(m: HmacSha256) -> [u8; 16] {
    let full = m.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// `HMAC(wid, "passwsync-sync-tag-v1" || session || round || role)[0..16]`.
pub fn tag(wallet: &WalletId, session: &[u8; 32], round: u32, role: u8) -> [u8; 16] {
    truncate(tag_mac(wallet, session, round, role))
}

/// `HMAC(wid, "passwsync-sync-state-v1" || session || round || role || sv)[0..16]`.
pub fn state_digest(
    wallet: &WalletId,
    session: &[u8; 32],
    round: u32,
    role: u8,
    state: &StateVector,
) -> [u8; 16] {
    truncate(digest_mac(wallet, session, round, role, state))
}

/// Constant-time check of a received tag against `wallet`.
pub fn tag_matches(
    wallet: &WalletId,
    session: &[u8; 32],
    round: u32,
    role: u8,
    received: &[u8; 16],
) -> bool {
    tag_mac(wallet, session, round, role)
        .verify_truncated_left(received)
        .is_ok()
}

/// Constant-time check of a received state digest against our state.
pub fn digest_matches(
    wallet: &WalletId,
    session: &[u8; 32],
    round: u32,
    role: u8,
    state: &StateVector,
    received: &[u8; 16],
) -> bool {
    digest_mac(wallet, session, round, role, state)
        .verify_truncated_left(received)
        .is_ok()
}
