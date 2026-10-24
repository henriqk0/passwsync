//! Human-readable, non-secret device name (FR-006).

use std::fmt;

use crate::error::Error;
use crate::identity::Fingerprint;

pub const MAX_NAME_CHARS: usize = 64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceName(String);

impl DeviceName {
    /// 1-64 Unicode scalar values, no control characters, no `"`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let count = text.chars().count();
        let ok = (1..=MAX_NAME_CHARS).contains(&count)
            && !text.chars().any(|c| c.is_control() || c == '"');
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::InvalidName)
        }
    }

    /// `passwsync device <first 4 fingerprint characters>`.
    pub fn default_for(fingerprint: &Fingerprint) -> Self {
        Self(format!("passwsync device {}", fingerprint.prefix4()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A network interface name: 1-15 of `[A-Za-z0-9._-]` (also the `network_interface` setting).
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let ok = (1..=15).contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
