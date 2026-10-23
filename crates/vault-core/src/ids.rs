use std::fmt;
use std::str::FromStr;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::VaultError;

fn random_bytes() -> Result<[u8; 16], VaultError> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| VaultError::Rng)?;
    Ok(bytes)
}

fn write_hex(bytes: &[u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

/// Identifies a wallet across devices; generated once at creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WalletId([u8; 16]);

impl WalletId {
    pub fn generate() -> Result<Self, VaultError> {
        random_bytes().map(Self)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, f)
    }
}

/// Identifies a credential; random so devices never collide without coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryId([u8; 16]);

impl EntryId {
    pub fn generate() -> Result<Self, VaultError> {
        random_bytes().map(Self)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, f)
    }
}

impl FromStr for EntryId {
    /// Text that is not 32 lowercase hex digits names no entry.
    type Err = VaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(VaultError::EntryNotFound);
        }
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(s.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| VaultError::EntryNotFound)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| VaultError::EntryNotFound)?;
        }
        Ok(Self(bytes))
    }
}

/// Opaque change-tracking label for a device. Not an identity and not secret.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(label: impl Into<String>) -> Result<Self, VaultError> {
        let label = label.into();
        if label.is_empty() || label.len() > 64 {
            return Err(VaultError::InvalidDeviceId);
        }
        Ok(Self(label))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for DeviceId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        Self::new(label).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn random_ids_are_distinct() {
        let wallets: HashSet<_> = (0..1000).map(|_| WalletId::generate().unwrap()).collect();
        let entries: HashSet<_> = (0..1000).map(|_| EntryId::generate().unwrap()).collect();
        assert_eq!(wallets.len(), 1000);
        assert_eq!(entries.len(), 1000);
    }

    #[test]
    fn entry_id_hex_display_round_trips() {
        let id = EntryId::generate().unwrap();
        let text = id.to_string();
        assert_eq!(text.len(), 32);
        assert!(text.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(EntryId::from_str(&text).unwrap(), id);
    }

    #[test]
    fn entry_id_rejects_bad_hex() {
        assert!(EntryId::from_str("zz").is_err());
        assert!(EntryId::from_str(&"0".repeat(31)).is_err());
        assert!(EntryId::from_str(&"g".repeat(32)).is_err());
        assert!(EntryId::from_str(&format!("+f{}", "0".repeat(30))).is_err());
    }

    #[test]
    fn device_id_length_bounds() {
        assert!(matches!(
            DeviceId::new(""),
            Err(VaultError::InvalidDeviceId)
        ));
        assert!(matches!(
            DeviceId::new("a".repeat(65)),
            Err(VaultError::InvalidDeviceId)
        ));
        assert!(DeviceId::new("a").is_ok());
        assert!(DeviceId::new("a".repeat(64)).is_ok());
        assert_eq!(DeviceId::new("laptop").unwrap().as_str(), "laptop");
    }
}
