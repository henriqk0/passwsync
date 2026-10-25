//! Wallet-level state vector (004, research R4): one change counter per device that ever
//! changed the wallet. Stored only inside the encrypted payload (R2).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{DeviceId, VaultError, VersionOrdering};

/// Sorted map `DeviceId -> counter` (counters >= 1, at most 256 devices). Missing devices
/// count as 0. `Debug` shows only the number of devices: device ids and counters reveal
/// activity and are never logged.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct StateVector(BTreeMap<DeviceId, u64>);

impl StateVector {
    pub const MAX_DEVICES: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a vector from pairs that must already be sorted by device id, unique, with
    /// counters >= 1 and at most 256 devices (the canonical encoding rules).
    pub fn from_pairs(pairs: Vec<(DeviceId, u64)>) -> Result<Self, VaultError> {
        if pairs.len() > Self::MAX_DEVICES {
            return Err(VaultError::TooManyDevices);
        }
        let mut map = BTreeMap::new();
        let mut previous: Option<&DeviceId> = None;
        for (device, counter) in &pairs {
            if *counter == 0 || previous.is_some_and(|p| p >= device) {
                return Err(VaultError::InvalidPasswordOrCorrupted);
            }
            previous = Some(device);
        }
        for (device, counter) in pairs {
            map.insert(device, counter);
        }
        Ok(Self(map))
    }

    /// Counter for `device`, 0 if it never changed the wallet.
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `+1` for `device` (checked). A 257th device or an overflow fails and changes nothing.
    pub fn bump(&mut self, device: &DeviceId) -> Result<(), VaultError> {
        let full = self.0.len() >= Self::MAX_DEVICES;
        match self.0.get_mut(device) {
            Some(counter) => {
                *counter = counter.checked_add(1).ok_or(VaultError::CounterOverflow)?;
            }
            None if full => return Err(VaultError::TooManyDevices),
            None => {
                self.0.insert(device.clone(), 1);
            }
        }
        Ok(())
    }

    /// Component-wise maximum (may exceed 256 devices; callers check `len`).
    pub fn join(&self, other: &Self) -> Self {
        let mut map = self.0.clone();
        for (device, counter) in &other.0 {
            let slot = map.entry(device.clone()).or_insert(0);
            *slot = (*slot).max(*counter);
        }
        Self(map)
    }

    /// `self >= other` in every component.
    pub fn dominates(&self, other: &Self) -> bool {
        other
            .0
            .iter()
            .all(|(device, counter)| self.get(device) >= *counter)
    }

    pub fn compare(&self, other: &Self) -> VersionOrdering {
        match (self.dominates(other), other.dominates(self)) {
            (true, true) => VersionOrdering::Equal,
            (true, false) => VersionOrdering::Newer,
            (false, true) => VersionOrdering::Older,
            (false, false) => VersionOrdering::Concurrent,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)> {
        self.0.iter().map(|(device, counter)| (device, *counter))
    }
}

impl fmt::Debug for StateVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StateVector({} devices)", self.0.len())
    }
}

impl Serialize for StateVector {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&str, u64)> = self.iter().map(|(d, c)| (d.as_str(), c)).collect();
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StateVector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pairs = Vec::<(String, u64)>::deserialize(deserializer)?;
        if pairs.len() > Self::MAX_DEVICES {
            return Err(D::Error::custom("too many devices"));
        }
        let mut converted = Vec::with_capacity(pairs.len());
        for (label, counter) in pairs {
            converted.push((DeviceId::new(label).map_err(D::Error::custom)?, counter));
        }
        Self::from_pairs(converted).map_err(|_| D::Error::custom("invalid state vector"))
    }
}
