//! 004 T012: reading format version 1 and rewriting it as version 2.

mod support;

use support::*;
use vault_core::{DeviceId, EntryFields, MemoryStorage, VaultStorage};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn v1_entry(id: u8, by: &str, version: &[(&str, u64)], state: RawState) -> RawEntryV1 {
    RawEntryV1 {
        id: [id; 16],
        created_at: 5,
        modified_at: 6 + i64::from(id),
        last_modified_by: by.into(),
        version: pairs(version),
        state,
    }
}

fn v1_file() -> Vec<u8> {
    seal(
        1,
        &RawPayloadV1 {
            wallet_id: [3; 16],
            created_at: 4,
            entries: vec![
                v1_entry(1, "a", &[("a", 2), ("b", 1)], live_state("one")),
                v1_entry(2, "b", &[("b", 3)], RawState::Deleted { deleted_at: 9 }),
                v1_entry(3, "c", &[("a", 1), ("c", 1)], live_state("three")),
            ],
        },
    )
}

#[test]
fn every_v1_entry_becomes_a_single_current_version() {
    let vault = unlock(&v1_file()).unwrap();
    assert_eq!(vault.format_version_loaded(), 1);
    assert_eq!(vault.all_records().count(), 3);
    for entry in vault.all_records() {
        assert!(!entry.is_conflicted());
        assert_eq!(entry.versions().len(), 1);
    }
    let one = vault
        .all_records()
        .find(|e| e.id().as_bytes() == &[1; 16])
        .unwrap();
    assert_eq!(one.fields().unwrap().title, "one");
    assert_eq!(one.modified_at(), 7);
    assert_eq!(one.version().get(&d("a")), 2);
    assert!(vault.password_epoch().is_empty());
}

#[test]
fn state_is_the_exact_sum_of_entry_counters() {
    let vault = unlock(&v1_file()).unwrap();
    let state = vault.state();
    assert_eq!(state.get(&d("a")), 3); // 2 + 1
    assert_eq!(state.get(&d("b")), 4); // 1 + 3
    assert_eq!(state.get(&d("c")), 1);
    assert_eq!(state.len(), 3);
}

#[test]
fn v1_bytes_stay_identical_until_the_next_save_which_writes_v2() {
    let mut storage = MemoryStorage::new();
    storage.store(&v1_file()).unwrap();
    let original = storage.load().unwrap();
    let mut vault = unlock(&original).unwrap();
    vault
        .add_entry({
            let mut f = EntryFields::default();
            f.title = "in memory only".into();
            f
        })
        .unwrap();
    assert_eq!(storage.load().unwrap(), original, "unchanged until saved");
    vault.save(&mut storage).unwrap();
    let saved = storage.load().unwrap();
    assert_eq!(&saved[4..6], &2u16.to_le_bytes());
    let again = unlock(&saved).unwrap();
    assert_eq!(again.format_version_loaded(), 2);
    assert_eq!(again.all_records().count(), 4);
    // The device's counter moved by one for the new entry.
    assert_eq!(again.state().get(&d("laptop")), 1);
    assert_eq!(again.state().get(&d("a")), 3);
}

#[test]
fn a_v2_file_is_never_downgraded() {
    let mut storage = MemoryStorage::new();
    storage.store(&v1_file()).unwrap();
    let vault = unlock(&storage.load().unwrap()).unwrap();
    vault.save(&mut storage).unwrap();
    for _ in 0..2 {
        let reopened = unlock(&storage.load().unwrap()).unwrap();
        assert_eq!(reopened.format_version_loaded(), 2);
        reopened.save(&mut storage).unwrap();
        assert_eq!(&storage.load().unwrap()[4..6], &2u16.to_le_bytes());
    }
}

#[test]
fn v1_sum_overflow_or_too_many_devices_is_corrupt() {
    let overflow = seal(
        1,
        &RawPayloadV1 {
            wallet_id: [3; 16],
            created_at: 4,
            entries: vec![
                v1_entry(1, "a", &[("a", u64::MAX)], live_state("x")),
                v1_entry(2, "a", &[("a", 1)], live_state("y")),
            ],
        },
    );
    assert!(unlock(&overflow).is_err());
    let devices: Vec<String> = (0..257).map(|i| format!("{i:03}")).collect();
    let many = seal(
        1,
        &RawPayloadV1 {
            wallet_id: [3; 16],
            created_at: 4,
            entries: devices
                .iter()
                .enumerate()
                .map(|(i, n)| RawEntryV1 {
                    id: [
                        (i % 256) as u8,
                        (i / 256) as u8,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    created_at: 1,
                    modified_at: 1,
                    last_modified_by: n.clone(),
                    version: vec![(n.clone(), 1)],
                    state: live_state("x"),
                })
                .collect(),
        },
    );
    assert!(unlock(&many).is_err());
}
