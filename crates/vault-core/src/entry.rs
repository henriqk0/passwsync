use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DeviceId, EntryId, Timestamp, VaultError, VersionOrdering, VersionVector};

/// Upper bound for each text field, to bound memory use.
pub(crate) const MAX_FIELD_LEN: usize = 1024 * 1024;

/// At most this many versions per entry: the current one plus 15 conflicting ones (FR-031).
pub const MAX_VERSIONS: usize = 16;

/// The secret-bearing content of a credential. Wiped from memory on drop.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryFields {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

impl EntryFields {
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.title.trim().is_empty() {
            return Err(VaultError::EmptyTitle);
        }
        let texts = [
            &self.title,
            &self.username,
            &self.password,
            &self.url,
            &self.notes,
        ];
        if texts.iter().any(|text| text.len() > MAX_FIELD_LEN) {
            return Err(VaultError::FieldTooLarge);
        }
        Ok(())
    }

    /// A second copy, wiped on drop like the first (used when a merge keeps a local version
    /// while the previous state must stay intact for rollback).
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
        }
    }
}

impl fmt::Debug for EntryFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryFields")
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum EntryState {
    Live(EntryFields),
    Deleted { deleted_at: Timestamp },
}

impl EntryState {
    fn duplicate(&self) -> Self {
        match self {
            Self::Live(fields) => Self::Live(fields.duplicate()),
            Self::Deleted { deleted_at } => Self::Deleted {
                deleted_at: *deleted_at,
            },
        }
    }
}

/// One version of a credential (live or tombstone). Its identity is its
/// [`content_hash`](Version::content_hash).
#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    modified_at: Timestamp,
    last_modified_by: DeviceId,
    version: VersionVector,
    state: EntryState,
}

impl Version {
    pub fn new_live(
        fields: EntryFields,
        modified_at: Timestamp,
        by: DeviceId,
        version: VersionVector,
    ) -> Result<Self, VaultError> {
        fields.validate()?;
        Ok(Self {
            modified_at,
            last_modified_by: by,
            version,
            state: EntryState::Live(fields),
        })
    }

    pub fn new_deleted(
        deleted_at: Timestamp,
        modified_at: Timestamp,
        by: DeviceId,
        version: VersionVector,
    ) -> Self {
        Self {
            modified_at,
            last_modified_by: by,
            version,
            state: EntryState::Deleted { deleted_at },
        }
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            modified_at: self.modified_at,
            last_modified_by: self.last_modified_by.clone(),
            version: self.version.clone(),
            state: self.state.duplicate(),
        }
    }

    /// SHA-256 of the postcard encoding of this version (FR-014, research R5). The encoding
    /// is built in a buffer wiped afterwards.
    pub fn content_hash(&self) -> [u8; 32] {
        let size = postcard::experimental::serialized_size(self).unwrap_or(0);
        let mut buffer = Zeroizing::new(vec![0u8; size]);
        match postcard::to_slice(self, &mut buffer) {
            Ok(used) => Sha256::digest(&*used).into(),
            Err(_) => [0u8; 32],
        }
    }

    pub fn modified_at(&self) -> Timestamp {
        self.modified_at
    }

    pub fn last_modified_by(&self) -> &DeviceId {
        &self.last_modified_by
    }

    pub fn version(&self) -> &VersionVector {
        &self.version
    }

    /// `None` for tombstones.
    pub fn fields(&self) -> Option<&EntryFields> {
        match &self.state {
            EntryState::Live(fields) => Some(fields),
            EntryState::Deleted { .. } => None,
        }
    }

    /// `Some` for tombstones.
    pub fn deleted_at(&self) -> Option<Timestamp> {
        match &self.state {
            EntryState::Live(_) => None,
            EntryState::Deleted { deleted_at } => Some(*deleted_at),
        }
    }

    pub fn is_deleted(&self) -> bool {
        matches!(self.state, EntryState::Deleted { .. })
    }

    fn is_valid(&self) -> bool {
        self.fields().is_none_or(|fields| fields.validate().is_ok())
    }
}

/// The FR-014 order: live before tombstone, then the latest modification, then the larger
/// device id, then the larger content hash. `Less` means "shown first".
pub(crate) fn canonical_order(a: (&Version, &[u8; 32]), b: (&Version, &[u8; 32])) -> Ordering {
    a.0.is_deleted()
        .cmp(&b.0.is_deleted())
        .then_with(|| b.0.modified_at.cmp(&a.0.modified_at))
        .then_with(|| b.0.last_modified_by.cmp(&a.0.last_modified_by))
        .then_with(|| b.1.cmp(a.1))
}

/// A credential with one or more versions (004): `versions[0]` is the current one, the rest
/// are concurrent versions kept until the person resolves them.
pub struct Entry {
    id: EntryId,
    created_at: Timestamp,
    versions: Vec<Version>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("current", &self.versions[0])
            .field("conflicts", &(self.versions.len() - 1))
            .finish()
    }
}

/// Checks the v2 invariants of a version set: 1..=16 versions, all valid, no equal content
/// hashes, none strictly dominated by another. Returns the hashes (same order).
pub(crate) fn check_versions(versions: &[Version]) -> Result<Vec<[u8; 32]>, VaultError> {
    let corrupt = VaultError::InvalidPasswordOrCorrupted;
    if versions.is_empty() || versions.len() > MAX_VERSIONS {
        return Err(corrupt);
    }
    let hashes: Vec<[u8; 32]> = versions.iter().map(Version::content_hash).collect();
    let mut seen = HashSet::with_capacity(hashes.len());
    if !hashes.iter().all(|h| seen.insert(*h)) || !versions.iter().all(Version::is_valid) {
        return Err(corrupt);
    }
    for (i, a) in versions.iter().enumerate() {
        for b in &versions[i + 1..] {
            if matches!(
                a.version.compare(&b.version),
                VersionOrdering::Newer | VersionOrdering::Older
            ) {
                return Err(corrupt);
            }
        }
    }
    Ok(hashes)
}

impl Entry {
    /// Builds an entry from concurrent versions, ordering them canonically (current first).
    /// Rejects sets that break the v2 invariants.
    pub fn from_versions(
        id: EntryId,
        created_at: Timestamp,
        versions: Vec<Version>,
    ) -> Result<Self, VaultError> {
        let hashes = check_versions(&versions)?;
        let mut paired: Vec<(Version, [u8; 32])> = versions.into_iter().zip(hashes).collect();
        paired.sort_by(|a, b| canonical_order((&a.0, &a.1), (&b.0, &b.1)));
        Ok(Self {
            id,
            created_at,
            versions: paired.into_iter().map(|(v, _)| v).collect(),
        })
    }

    /// As stored: the versions must already be in canonical order.
    pub(crate) fn from_stored(
        id: EntryId,
        created_at: Timestamp,
        versions: Vec<Version>,
    ) -> Result<Self, VaultError> {
        let hashes = check_versions(&versions)?;
        let ordered = versions
            .windows(2)
            .zip(hashes.windows(2))
            .all(|(v, h)| canonical_order((&v[0], &h[0]), (&v[1], &h[1])) == Ordering::Less);
        if !ordered {
            return Err(VaultError::InvalidPasswordOrCorrupted);
        }
        Ok(Self {
            id,
            created_at,
            versions,
        })
    }

    /// Builds an already-checked entry (merge and resolution results).
    pub(crate) fn from_checked(id: EntryId, created_at: Timestamp, versions: Vec<Version>) -> Self {
        Self {
            id,
            created_at,
            versions,
        }
    }

    pub(crate) fn new_live(
        fields: EntryFields,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<Self, VaultError> {
        fields.validate()?;
        Ok(Self {
            id: EntryId::generate()?,
            created_at: now,
            versions: vec![Version {
                modified_at: now,
                last_modified_by: device.clone(),
                version: VersionVector::new(device),
                state: EntryState::Live(fields),
            }],
        })
    }

    /// Whole-value replacement: the old fields are dropped (and so wiped), never grown in place.
    pub(crate) fn replace_fields(
        &mut self,
        fields: EntryFields,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<(), VaultError> {
        fields.validate()?;
        self.versions[0].state = EntryState::Live(fields);
        self.record_change(device, now);
        Ok(())
    }

    /// Turns the entry into a tombstone; its fields are dropped (and so wiped).
    pub(crate) fn mark_deleted(&mut self, device: &DeviceId, now: Timestamp) {
        self.versions[0].state = EntryState::Deleted { deleted_at: now };
        self.record_change(device, now);
    }

    /// The record this entry becomes after a change by `device` at `now`, leaving `self`
    /// untouched so a caller can put it back if persisting the change fails.
    pub(crate) fn successor(&self, state: EntryState, device: &DeviceId, now: Timestamp) -> Self {
        let current = &self.versions[0];
        let mut next = Self {
            id: self.id,
            created_at: self.created_at,
            versions: vec![Version {
                modified_at: current.modified_at,
                last_modified_by: current.last_modified_by.clone(),
                version: current.version.clone(),
                state,
            }],
        };
        next.record_change(device, now);
        next
    }

    fn record_change(&mut self, device: &DeviceId, now: Timestamp) {
        let current = &mut self.versions[0];
        current.modified_at = now;
        current.last_modified_by = device.clone();
        current.version.increment(device);
    }

    #[cfg(feature = "testkit")]
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            id: self.id,
            created_at: self.created_at,
            versions: self.versions.iter().map(Version::duplicate).collect(),
        }
    }

    pub(crate) fn into_versions(self) -> Vec<Version> {
        self.versions
    }

    pub fn id(&self) -> EntryId {
        self.id
    }

    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// The version shown in lists and search.
    pub fn current(&self) -> &Version {
        &self.versions[0]
    }

    /// Concurrent versions besides the current one (FR-014 order).
    pub fn conflicts(&self) -> &[Version] {
        &self.versions[1..]
    }

    /// `[current, conflicts...]`.
    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    pub fn is_conflicted(&self) -> bool {
        self.versions.len() > 1
    }

    pub fn modified_at(&self) -> Timestamp {
        self.current().modified_at
    }

    pub fn last_modified_by(&self) -> &DeviceId {
        &self.current().last_modified_by
    }

    pub fn version(&self) -> &VersionVector {
        &self.current().version
    }

    /// `None` for tombstones.
    pub fn fields(&self) -> Option<&EntryFields> {
        self.current().fields()
    }

    /// `Some` for tombstones.
    pub fn deleted_at(&self) -> Option<Timestamp> {
        self.current().deleted_at()
    }

    pub fn is_deleted(&self) -> bool {
        self.current().is_deleted()
    }
}

/// v2 layout: `{ id, created_at, current, conflicts }` (contracts/file-format-v2.md).
#[derive(Serialize)]
struct EntryRef<'a> {
    id: EntryId,
    created_at: Timestamp,
    current: &'a Version,
    conflicts: &'a [Version],
}

#[derive(Deserialize)]
struct EntryOwned {
    id: EntryId,
    created_at: Timestamp,
    current: Version,
    conflicts: Vec<Version>,
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EntryRef {
            id: self.id,
            created_at: self.created_at,
            current: &self.versions[0],
            conflicts: &self.versions[1..],
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = EntryOwned::deserialize(deserializer)?;
        if raw.conflicts.len() >= MAX_VERSIONS {
            return Err(D::Error::custom("too many versions"));
        }
        let mut versions = Vec::with_capacity(raw.conflicts.len() + 1);
        versions.push(raw.current);
        versions.extend(raw.conflicts);
        Entry::from_stored(raw.id, raw.created_at, versions)
            .map_err(|_| D::Error::custom("invalid entry"))
    }
}

/// The 001 (format version 1) entry layout, read only for migration.
#[derive(Deserialize)]
pub(crate) struct EntryV1 {
    id: EntryId,
    created_at: Timestamp,
    modified_at: Timestamp,
    last_modified_by: DeviceId,
    version: VersionVector,
    state: EntryState,
}

impl EntryV1 {
    pub(crate) fn into_entry(self) -> Entry {
        Entry {
            id: self.id,
            created_at: self.created_at,
            versions: vec![Version {
                modified_at: self.modified_at,
                last_modified_by: self.last_modified_by,
                version: self.version,
                state: self.state,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    fn fields(title: &str) -> EntryFields {
        let mut fields = EntryFields::default();
        fields.title = title.to_string();
        fields
    }

    #[test]
    fn empty_or_blank_title_is_rejected() {
        assert!(matches!(fields("").validate(), Err(VaultError::EmptyTitle)));
        assert!(matches!(
            fields("  \t\n").validate(),
            Err(VaultError::EmptyTitle)
        ));
        assert!(fields("GitHub").validate().is_ok());
    }

    #[test]
    fn oversized_field_is_rejected_in_every_field() {
        let big = "x".repeat(MAX_FIELD_LEN + 1);
        let at_limit = "x".repeat(MAX_FIELD_LEN);
        assert!(fields(&at_limit).validate().is_ok());
        for index in 0..5 {
            let mut f = fields("t");
            match index {
                0 => f.title = big.clone(),
                1 => f.username = big.clone(),
                2 => f.password = big.clone(),
                3 => f.url = big.clone(),
                _ => f.notes = big.clone(),
            }
            assert!(
                matches!(f.validate(), Err(VaultError::FieldTooLarge)),
                "field {index}"
            );
        }
    }

    #[test]
    fn new_live_sets_metadata() {
        let device = DeviceId::new("laptop").unwrap();
        let entry = Entry::new_live(fields("GitHub"), &device, 1_000).unwrap();
        assert_eq!(entry.created_at(), 1_000);
        assert_eq!(entry.modified_at(), 1_000);
        assert_eq!(entry.last_modified_by(), &device);
        assert_eq!(entry.version().get(&device), 1);
        assert_eq!(entry.version().iter().count(), 1);
        assert_eq!(entry.fields().unwrap().title, "GitHub");
        assert!(!entry.is_deleted());
        assert_eq!(entry.deleted_at(), None);
    }

    #[test]
    fn new_live_rejects_invalid_fields() {
        let device = DeviceId::new("laptop").unwrap();
        assert!(matches!(
            Entry::new_live(fields(" "), &device, 0),
            Err(VaultError::EmptyTitle)
        ));
    }

    #[test]
    fn debug_redacts_password_and_notes() {
        let device = DeviceId::new("laptop").unwrap();
        let f = EntryFields {
            title: "GitHub".into(),
            username: "octocat".into(),
            password: "PASSWORD-MARKER".into(),
            url: "https://github.com".into(),
            notes: "NOTES-MARKER".into(),
        };
        let entry = Entry::new_live(f, &device, 0).unwrap();
        for text in [
            format!("{entry:?}"),
            format!("{:?}", entry.fields().unwrap()),
        ] {
            assert!(!text.contains("PASSWORD-MARKER"));
            assert!(!text.contains("NOTES-MARKER"));
            assert!(text.contains("[REDACTED]"));
        }
    }

    #[test]
    fn fields_zeroize_on_drop() {
        assert_zeroize_on_drop::<EntryFields>();
    }
}
