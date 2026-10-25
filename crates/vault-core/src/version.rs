use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DeviceId;

/// How two copies of the same entry relate, from the first one's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionOrdering {
    Equal,
    Newer,
    Older,
    Concurrent,
}

/// Per-device change counters for one entry. Only the acting device's counter moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionVector(BTreeMap<DeviceId, u64>);

impl VersionVector {
    /// Version of a freshly created entry: `{device: 1}`.
    pub fn new(device: &DeviceId) -> Self {
        Self(BTreeMap::from([(device.clone(), 1)]))
    }

    /// No change by any device yet (used for the password-change epoch, which starts empty).
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Component-wise maximum.
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

    pub fn increment(&mut self, device: &DeviceId) {
        *self.0.entry(device.clone()).or_insert(0) += 1;
    }

    /// Counter for `device`, 0 if it never changed the entry.
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    /// Relates `self` to `other`, treating a missing device as 0.
    pub fn compare(&self, other: &Self) -> VersionOrdering {
        let (mut ahead, mut behind) = (false, false);
        for device in self.0.keys().chain(other.0.keys()) {
            match self.get(device).cmp(&other.get(device)) {
                Ordering::Greater => ahead = true,
                Ordering::Less => behind = true,
                Ordering::Equal => {}
            }
        }
        match (ahead, behind) {
            (false, false) => VersionOrdering::Equal,
            (true, false) => VersionOrdering::Newer,
            (false, true) => VersionOrdering::Older,
            (true, true) => VersionOrdering::Concurrent,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)> {
        self.0.iter().map(|(device, counter)| (device, *counter))
    }
}

impl Serialize for VersionVector {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&str, u64)> = self.iter().map(|(d, c)| (d.as_str(), c)).collect();
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VersionVector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pairs = Vec::<(String, u64)>::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        let mut previous: Option<&str> = None;
        for (label, counter) in &pairs {
            if counter == &0 || previous.is_some_and(|p| p >= label.as_str()) {
                return Err(D::Error::custom("invalid version vector"));
            }
            previous = Some(label);
            map.insert(
                DeviceId::new(label.as_str()).map_err(D::Error::custom)?,
                *counter,
            );
        }
        Ok(Self(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str) -> DeviceId {
        DeviceId::new(name).unwrap()
    }

    #[test]
    fn new_starts_at_one() {
        let v = VersionVector::new(&device("a"));
        assert_eq!(v.get(&device("a")), 1);
        assert_eq!(v.iter().count(), 1);
    }

    #[test]
    fn increment_changes_only_that_device() {
        let mut v = VersionVector::new(&device("a"));
        v.increment(&device("b"));
        v.increment(&device("a"));
        assert_eq!(v.get(&device("a")), 2);
        assert_eq!(v.get(&device("b")), 1);
    }

    #[test]
    fn absent_device_is_zero() {
        assert_eq!(VersionVector::new(&device("a")).get(&device("z")), 0);
    }

    #[test]
    fn iter_is_sorted_by_device() {
        let mut v = VersionVector::new(&device("m"));
        v.increment(&device("c"));
        v.increment(&device("x"));
        let names: Vec<_> = v.iter().map(|(d, _)| d.as_str().to_string()).collect();
        assert_eq!(names, ["c", "m", "x"]);
    }

    #[test]
    fn serde_round_trip_through_postcard() {
        let mut v = VersionVector::new(&device("b"));
        v.increment(&device("a"));
        v.increment(&device("a"));
        let bytes = postcard::to_allocvec(&v).unwrap();
        let back: VersionVector = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn deserialize_rejects_unsorted_duplicate_or_zero() {
        let unsorted =
            postcard::to_allocvec(&vec![("b".to_string(), 1u64), ("a".to_string(), 1)]).unwrap();
        let duplicate =
            postcard::to_allocvec(&vec![("a".to_string(), 1u64), ("a".to_string(), 2)]).unwrap();
        let zero = postcard::to_allocvec(&vec![("a".to_string(), 0u64)]).unwrap();
        for bytes in [unsorted, duplicate, zero] {
            assert!(postcard::from_bytes::<VersionVector>(&bytes).is_err());
        }
    }

    fn vector(counters: &[(&str, u64)]) -> VersionVector {
        let mut v: Option<VersionVector> = None;
        for (name, count) in counters {
            let d = device(name);
            let vv = v.get_or_insert_with(|| VersionVector::new(&d));
            while vv.get(&d) < *count {
                vv.increment(&d);
            }
        }
        v.unwrap()
    }

    #[test]
    fn compare_classifies_copies() {
        use VersionOrdering::*;
        let cases = [
            (vector(&[("a", 1)]), vector(&[("a", 1)]), Equal),
            (vector(&[("a", 2)]), vector(&[("a", 1)]), Newer),
            (vector(&[("a", 1)]), vector(&[("a", 2)]), Older),
            // A device missing from one side counts as 0.
            (vector(&[("a", 1), ("b", 1)]), vector(&[("a", 1)]), Newer),
            (vector(&[("a", 1)]), vector(&[("a", 1), ("b", 1)]), Older),
            (
                vector(&[("a", 2), ("b", 1)]),
                vector(&[("a", 1), ("b", 2)]),
                Concurrent,
            ),
            (vector(&[("a", 1)]), vector(&[("b", 1)]), Concurrent),
        ];
        for (left, right, expected) in cases {
            assert_eq!(left.compare(&right), expected, "{left:?} vs {right:?}");
            let inverse = match expected {
                Newer => Older,
                Older => Newer,
                other => other,
            };
            assert_eq!(
                right.compare(&left),
                inverse,
                "antisymmetry for {left:?} vs {right:?}"
            );
        }
    }
}
