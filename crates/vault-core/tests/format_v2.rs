//! 004 T010: format version 2 round trip and parse order (contracts/file-format-v2.md).

mod support;

use support::*;
use vault_core::{
    DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, StateVector, Vault, VaultError,
};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn fields(title: &str) -> EntryFields {
    {
        let mut f = EntryFields::default();
        f.title = title.into();
        f
    }
}

fn new_vault(device: &str) -> Vault {
    Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        d(device),
        Box::new(FixedClock::new(10)),
    )
    .unwrap()
}

#[test]
fn writers_always_write_version_2_with_the_v1_header_layout() {
    let mut vault = new_vault("laptop");
    vault.add_entry(fields("a")).unwrap();
    let bytes = vault.seal().unwrap();
    assert_eq!(&bytes[0..4], b"PWSV");
    assert_eq!(&bytes[4..6], &2u16.to_le_bytes());
    assert_eq!(bytes[6], 1, "Argon2id");
    assert_eq!(&bytes[7..11], &KdfConfig::MINIMUM.memory_kib.to_le_bytes());
    assert_eq!(&bytes[11..15], &KdfConfig::MINIMUM.iterations.to_le_bytes());
    assert_eq!(
        &bytes[15..19],
        &KdfConfig::MINIMUM.parallelism.to_le_bytes()
    );
    // A v1 file of the same wallet differs only in the version field of the header layout.
    let v1 = seal(
        1,
        &RawPayloadV1 {
            wallet_id: [1; 16],
            created_at: 0,
            entries: vec![],
        },
    );
    assert_eq!(&v1[4..6], &1u16.to_le_bytes());
    assert_eq!(v1[0..4], bytes[0..4]);
    assert_eq!(v1[6..19], bytes[6..19]);
}

#[test]
fn v2_payload_round_trips_every_field() {
    let mut vault = new_vault("laptop");
    let a = vault.add_entry(fields("a")).unwrap();
    vault.add_entry(fields("b")).unwrap();
    vault.delete_entry(a).unwrap();
    vault
        .change_master_password(MasterPassword::new(PASSWORD.into()))
        .unwrap();
    let bytes = vault.seal().unwrap();
    let back = unlock(&bytes).unwrap();
    assert_eq!(back.format_version_loaded(), 2);
    assert_eq!(back.wallet_id(), vault.wallet_id());
    assert_eq!(back.created_at(), vault.created_at());
    assert_eq!(back.state(), vault.state());
    assert_eq!(back.password_epoch(), vault.password_epoch());
    assert_eq!(
        back.state().get(&d("laptop")),
        4,
        "3 entry changes + password"
    );
    assert_eq!(back.password_epoch().get(&d("laptop")), 1);
    assert_eq!(back.all_records().count(), 2);
}

#[test]
fn conflicts_survive_the_round_trip() {
    let payload = one_entry(
        &[("a", 1), ("b", 1)],
        vec![
            rv("newer", 20, "b", &[("b", 1)]),
            rv("older", 10, "a", &[("a", 1)]),
        ],
    );
    let vault = unlock(&seal(2, &payload)).unwrap();
    let entry = vault.all_records().next().unwrap();
    assert!(entry.is_conflicted());
    assert_eq!(entry.current().fields().unwrap().title, "newer");
    assert_eq!(entry.conflicts()[0].fields().unwrap().title, "older");
    let again = unlock(&vault.seal().unwrap()).unwrap();
    let entry = again.all_records().next().unwrap();
    assert_eq!(entry.versions().len(), 2);
    assert_eq!(entry.conflicts()[0].fields().unwrap().title, "older");
    let expected = StateVector::from_pairs(vec![(d("a"), 1), (d("b"), 1)]).unwrap();
    assert_eq!(again.state(), &expected);
}

#[test]
fn version_3_is_unsupported_before_any_key_derivation() {
    let mut bytes = new_vault("laptop").seal().unwrap();
    bytes[4..6].copy_from_slice(&3u16.to_le_bytes());
    let started = std::time::Instant::now();
    assert!(matches!(
        unlock(&bytes),
        Err(VaultError::UnsupportedVersion(3))
    ));
    assert!(started.elapsed().as_millis() < 50);
    assert!(matches!(
        vault_core::peek_kdf_config(&bytes),
        Err(VaultError::UnsupportedVersion(3))
    ));
}

#[test]
fn size_bounds_are_unchanged() {
    let bytes = new_vault("laptop").seal().unwrap();
    assert!(bytes.len() >= 79);
    let mut short = bytes[..63].to_vec();
    short.extend_from_slice(&[0; 15]); // 78 bytes
    assert!(matches!(unlock(&short), Err(VaultError::MalformedFile)));
    let mut huge = vec![0u8; 64 * 1024 * 1024 + 1];
    huge[..63].copy_from_slice(&bytes[..63]);
    assert!(matches!(unlock(&huge), Err(VaultError::MalformedFile)));
}

#[test]
fn format_version_is_readable_without_the_password() {
    let bytes = new_vault("laptop").seal().unwrap();
    assert_eq!(vault_core::peek_format_version(&bytes).unwrap(), 2);
    let v1 = seal(
        1,
        &RawPayloadV1 {
            wallet_id: [1; 16],
            created_at: 0,
            entries: vec![],
        },
    );
    assert_eq!(vault_core::peek_format_version(&v1).unwrap(), 1);
}
