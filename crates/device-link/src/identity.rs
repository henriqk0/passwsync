//! Device key (X25519 static), device ID and fingerprint (research R3).

use std::fmt;

use curve25519_dalek::MontgomeryPoint;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

const ID_DOMAIN: &[u8] = b"passwsync-device-id-v1";

/// This installation's long-term X25519 key. Deliberately neither `Debug` nor `Display`;
/// the private half is wiped on drop.
#[derive(ZeroizeOnDrop)]
pub struct DeviceKey {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl DeviceKey {
    /// Derives the public key with the same clamping as the Noise X25519 DH.
    pub fn from_private(private: [u8; 32]) -> Self {
        Self::from_zeroizing(Zeroizing::new(private))
    }

    /// Takes ownership of an already wiped-on-drop buffer.
    pub fn from_zeroizing(private: Zeroizing<[u8; 32]>) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();
        Self { private, public }
    }

    /// A second handle on the same key whose private half is wiped on drop too; no bare
    /// copy of the private bytes is left behind (FR-007).
    pub fn duplicate(&self) -> Self {
        Self {
            private: self.private.clone(),
            public: self.public,
        }
    }

    pub fn generate(rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        let mut private = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(private.as_mut())
            .map_err(|_| Error::Random)?;
        Ok(Self::from_zeroizing(private))
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// For the key file codec and the Noise handshake only.
    pub fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }

    pub fn id(&self) -> DeviceId {
        DeviceId::from_public(&self.public)
    }
}

/// `SHA-256("passwsync-device-id-v1" || public)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub fn from_public(public: &[u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(ID_DOMAIN);
        hash.update(public);
        Self(hash.finalize().into())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Exactly 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        decode_hex32(text).map(Self).ok_or(Error::InvalidDeviceId)
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let encoded = base32(&self.0[..10]);
        let mut text = String::with_capacity(19);
        for (i, chunk) in encoded.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                text.push('-');
            }
            text.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        }
        Fingerprint(text)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.to_hex())
    }
}

/// Display form `XXXX-XXXX-XXXX-XXXX` (80 bits). Never used for trust decisions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn prefix4(&self) -> &str {
        &self.0[..4]
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 4648 base32, uppercase, no padding (input length a multiple of 5).
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Lowercase hex of any even length.
pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

pub(crate) fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}
