#![forbid(unsafe_code)]
//! Inbound secrets (contracts/ffi-api.md section 2): a `Vec<u8>` from Kotlin becomes a
//! `Zeroizing<String>` in place; every path wipes the bytes.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::CoreError;

/// A secret received as bytes (master password, credential password, typed code).
pub struct SecretInput(Zeroizing<String>);

impl TryFrom<Vec<u8>> for SecretInput {
    type Error = CoreError;

    /// In place: `String::from_utf8` reuses the buffer. Invalid UTF-8 hands the bytes back,
    /// which are wiped right away.
    fn try_from(bytes: Vec<u8>) -> Result<Self, CoreError> {
        match String::from_utf8(bytes) {
            Ok(text) => Ok(Self(Zeroizing::new(text))),
            Err(error) => {
                drop(Zeroizing::new(error.into_bytes()));
                Err(CoreError::InvalidInput)
            }
        }
    }
}

impl SecretInput {
    /// A typed pairing or invite code: ASCII digits, spaces and dashes ignored (003
    /// `normalize_code`); anything else is `InvalidInput`.
    pub fn digits(bytes: Vec<u8>) -> Result<Self, CoreError> {
        let input = Self::try_from(bytes)?;
        let mut out = Zeroizing::new(String::with_capacity(input.0.len()));
        for c in input.0.chars() {
            match c {
                '0'..='9' => out.push(c),
                ' ' | '-' => {}
                _ => return Err(CoreError::InvalidInput),
            }
        }
        Ok(Self(out))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput(..)")
    }
}
