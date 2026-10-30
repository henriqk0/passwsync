//! Lowercase hex for tokens and identifiers (no secret-dependent branching on decode input
//! is needed: decoded values are only compared in constant time afterwards).

pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Decodes exactly 64 hex digits into 32 bytes (wiped on drop).
pub fn decode32(text: &str) -> Option<zeroize::Zeroizing<[u8; 32]>> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex of a secret, in a buffer wiped on drop.
pub fn encode_secret(bytes: &[u8]) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(encode(bytes))
}
