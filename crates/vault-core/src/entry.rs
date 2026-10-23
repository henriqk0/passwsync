use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DeviceId, EntryId, Timestamp, VaultError, VersionVector};

/// Upper bound for each text field, to bound memory use.
pub(crate) const MAX_FIELD_LEN: usize = 1024 * 1024;

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

/// A credential, or the tombstone left behind after it was deleted.
#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    id: EntryId,
    created_at: Timestamp,
    modified_at: Timestamp,
    last_modified_by: DeviceId,
    version: VersionVector,
    state: EntryState,
}

impl Entry {
    pub(crate) fn new_live(
        fields: EntryFields,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<Self, VaultError> {
        fields.validate()?;
        Ok(Self {
            id: EntryId::generate()?,
            created_at: now,
            modified_at: now,
            last_modified_by: device.clone(),
            version: VersionVector::new(device),
            state: EntryState::Live(fields),
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
        self.state = EntryState::Live(fields);
        self.record_change(device, now);
        Ok(())
    }

    /// Turns the entry into a tombstone; its fields are dropped (and so wiped).
    pub(crate) fn mark_deleted(&mut self, device: &DeviceId, now: Timestamp) {
        self.state = EntryState::Deleted { deleted_at: now };
        self.record_change(device, now);
    }

    /// The record this entry becomes after a change by `device` at `now`, leaving `self`
    /// untouched so a caller can put it back if persisting the change fails.
    pub(crate) fn successor(&self, state: EntryState, device: &DeviceId, now: Timestamp) -> Self {
        let mut next = Self {
            id: self.id,
            created_at: self.created_at,
            modified_at: self.modified_at,
            last_modified_by: self.last_modified_by.clone(),
            version: self.version.clone(),
            state,
        };
        next.record_change(device, now);
        next
    }

    fn record_change(&mut self, device: &DeviceId, now: Timestamp) {
        self.modified_at = now;
        self.last_modified_by = device.clone();
        self.version.increment(device);
    }

    pub fn id(&self) -> EntryId {
        self.id
    }

    pub fn created_at(&self) -> Timestamp {
        self.created_at
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
