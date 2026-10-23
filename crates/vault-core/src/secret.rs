use std::fmt;

use unicode_normalization::{UnicodeNormalization, is_nfc};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The wallet's master password, NFC-normalized so it unlocks on every platform.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterPassword(String);

impl MasterPassword {
    pub fn new(mut password: String) -> Self {
        if is_nfc(&password) {
            // Moved, not copied: a copy would leave the original unwiped.
            return Self(password);
        }
        // Sized for worst-case expansion (NFC of a char is at most about twice its UTF-8
        // length) so the buffer never reallocates and strands an unwiped copy.
        let mut normalized = String::with_capacity(password.len().saturating_mul(3));
        normalized.extend(password.nfc());
        password.zeroize();
        Self(normalized)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn char_count(&self) -> usize {
        self.0.chars().count()
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterPassword([REDACTED])")
    }
}

/// The key derived from the master password. Memory-only: not `Clone`, not `Serialize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn password_is_nfc_normalized() {
        let composed = MasterPassword::new("caf\u{e9}".to_string());
        let decomposed = MasterPassword::new("cafe\u{301}".to_string());
        assert_eq!(composed.as_bytes(), decomposed.as_bytes());
    }

    #[test]
    fn char_count_counts_scalar_values_after_nfc() {
        assert_eq!(
            MasterPassword::new("cafe\u{301}".to_string()).char_count(),
            4
        );
        assert_eq!(MasterPassword::new("abc".to_string()).char_count(), 3);
    }

    #[test]
    fn debug_is_redacted() {
        let password = MasterPassword::new("hunter2hunter2".to_string());
        let key = VaultKey::from_bytes([7; 32]);
        assert_eq!(format!("{password:?}"), "MasterPassword([REDACTED])");
        assert_eq!(format!("{key:?}"), "VaultKey([REDACTED])");
    }

    #[test]
    fn secrets_zeroize_on_drop() {
        assert_zeroize_on_drop::<MasterPassword>();
        assert_zeroize_on_drop::<VaultKey>();
    }

    #[test]
    fn already_normalized_password_is_moved_not_copied() {
        let original = String::from("correct horse battery");
        let address = original.as_ptr();
        let password = MasterPassword::new(original);
        assert_eq!(
            password.as_bytes().as_ptr(),
            address,
            "a copy would leave the original unwiped"
        );
    }

    #[test]
    fn normalization_that_expands_the_text_is_correct() {
        // U+FB2C is excluded from composition, so NFC turns each 3-byte char into 6 bytes.
        let password = MasterPassword::new("\u{fb2c}".repeat(50));
        let expected = "\u{5e9}\u{5bc}\u{5c1}".repeat(50);
        assert_eq!(password.as_bytes(), expected.as_bytes());
        assert_eq!(password.char_count(), 150);
    }
}
