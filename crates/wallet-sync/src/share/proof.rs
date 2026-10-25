//! Redemption proof (005 contracts/share-protocol.md "Redemption proof", research R5):
//! `HMAC-SHA-256(key = code digits, "passwsync-share-redeem-v1" || session || sender_id ||
//! recipient_id || rid)`. The code itself never crosses the network; the proof is bound to the
//! channel session, both device ids and the exchange id, and is verified in constant time with
//! `Mac::verify_slice`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::ports::PeerId;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN: &[u8] = b"passwsync-share-redeem-v1";

fn proof_mac(
    code: &str,
    session: &[u8; 32],
    sender: &PeerId,
    recipient: &PeerId,
    rid: u32,
) -> HmacSha256 {
    // HMAC accepts keys of any length: this cannot fail.
    let mut m = HmacSha256::new_from_slice(code.as_bytes()).unwrap_or_else(|_| unreachable!());
    m.update(DOMAIN);
    m.update(session);
    m.update(&sender.0);
    m.update(&recipient.0);
    m.update(&rid.to_be_bytes());
    m
}

/// The 32-byte proof the recipient sends in `Redeem`.
pub fn redeem_proof(
    code: &str,
    session: &[u8; 32],
    sender: &PeerId,
    recipient: &PeerId,
    rid: u32,
) -> [u8; 32] {
    proof_mac(code, session, sender, recipient, rid)
        .finalize()
        .into_bytes()
        .into()
}

/// Constant-time check of a received proof against the invitation's code.
pub fn verify_proof(
    code: &str,
    session: &[u8; 32],
    sender: &PeerId,
    recipient: &PeerId,
    rid: u32,
    proof: &[u8; 32],
) -> bool {
    proof_mac(code, session, sender, recipient, rid)
        .verify_slice(proof)
        .is_ok()
}
