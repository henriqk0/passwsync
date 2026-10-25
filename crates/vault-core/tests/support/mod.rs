//! Mirrors of the wallet payload layouts (contracts/file-format-v2.md) used to craft
//! authenticated files, valid or not, through `vault_core::testkit::seal_payload`.
#![allow(dead_code)]

use serde::Serialize;
use vault_core::{DeviceId, FixedClock, KdfConfig, MasterPassword, Vault, VaultError};

pub const PASSWORD: &str = "correct horse battery";

#[derive(Serialize, Clone)]
pub enum RawState {
    Live {
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    },
    Deleted {
        deleted_at: i64,
    },
}

pub fn live_state(title: &str) -> RawState {
    RawState::Live {
        title: title.into(),
        username: format!("{title}-user"),
        password: format!("{title}-secret"),
        url: String::new(),
        notes: String::new(),
    }
}

#[derive(Serialize, Clone)]
pub struct RawVersion {
    pub modified_at: i64,
    pub last_modified_by: String,
    pub version: Vec<(String, u64)>,
    pub state: RawState,
}

pub fn rv(title: &str, at: i64, by: &str, version: &[(&str, u64)]) -> RawVersion {
    RawVersion {
        modified_at: at,
        last_modified_by: by.into(),
        version: pairs(version),
        state: live_state(title),
    }
}

pub fn pairs(list: &[(&str, u64)]) -> Vec<(String, u64)> {
    list.iter().map(|(d, c)| (d.to_string(), *c)).collect()
}

#[derive(Serialize, Clone)]
pub struct RawEntryV2 {
    pub id: [u8; 16],
    pub created_at: i64,
    pub current: RawVersion,
    pub conflicts: Vec<RawVersion>,
}

#[derive(Serialize, Clone)]
pub struct RawPayloadV2 {
    pub wallet_id: [u8; 16],
    pub created_at: i64,
    pub state: Vec<(String, u64)>,
    pub password_epoch: Vec<(String, u64)>,
    pub entries: Vec<RawEntryV2>,
}

#[derive(Serialize, Clone)]
pub struct RawEntryV1 {
    pub id: [u8; 16],
    pub created_at: i64,
    pub modified_at: i64,
    pub last_modified_by: String,
    pub version: Vec<(String, u64)>,
    pub state: RawState,
}

#[derive(Serialize, Clone)]
pub struct RawPayloadV1 {
    pub wallet_id: [u8; 16],
    pub created_at: i64,
    pub entries: Vec<RawEntryV1>,
}

pub fn seal<T: Serialize>(version: u16, payload: &T) -> Vec<u8> {
    let plain = postcard::to_allocvec(payload).unwrap();
    vault_core::testkit::seal_payload(PASSWORD, KdfConfig::MINIMUM, version, &plain)
}

pub fn unlock_as(bytes: &[u8], device: &str) -> Result<Vault, VaultError> {
    Vault::unlock(
        bytes,
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new(device).unwrap(),
        Box::new(FixedClock::new(1_000)),
    )
}

pub fn unlock(bytes: &[u8]) -> Result<Vault, VaultError> {
    unlock_as(bytes, "laptop")
}

/// A single-entry v2 payload with the given versions and state.
pub fn one_entry(state: &[(&str, u64)], versions: Vec<RawVersion>) -> RawPayloadV2 {
    let mut versions = versions.into_iter();
    let current = versions.next().unwrap();
    RawPayloadV2 {
        wallet_id: [7; 16],
        created_at: 1,
        state: pairs(state),
        password_epoch: vec![],
        entries: vec![RawEntryV2 {
            id: [1; 16],
            created_at: 1,
            current,
            conflicts: versions.collect(),
        }],
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
