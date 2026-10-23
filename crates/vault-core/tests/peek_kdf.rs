//! `peek_kdf_config`: header-only inspection before unlocking (feature 002).

use vault_core::{
    DeviceId, FixedClock, KdfConfig, MasterPassword, Vault, VaultError, peek_kdf_config,
};

const PASSWORD: &str = "correct horse battery";

fn sealed() -> Vec<u8> {
    Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        DeviceId::new("laptop").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap()
    .seal()
    .unwrap()
}

fn unlock_error(bytes: &[u8]) -> VaultError {
    Vault::unlock(
        bytes,
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("laptop").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap_err()
}

fn same_error(bytes: &[u8]) -> VaultError {
    let peeked = peek_kdf_config(bytes).unwrap_err();
    assert_eq!(
        std::mem::discriminant(&peeked),
        std::mem::discriminant(&unlock_error(bytes)),
        "peek and unlock disagree: {peeked:?}"
    );
    peeked
}

#[test]
fn valid_file_returns_its_kdf_config_without_a_password() {
    assert_eq!(peek_kdf_config(&sealed()).unwrap(), KdfConfig::MINIMUM);
}

#[test]
fn bad_magic_is_malformed() {
    let mut bytes = sealed();
    bytes[0] = b'X';
    assert!(matches!(same_error(&bytes), VaultError::MalformedFile));
}

#[test]
fn truncated_file_is_malformed() {
    let bytes = sealed();
    assert!(matches!(
        same_error(&bytes[..40]),
        VaultError::MalformedFile
    ));
    assert!(matches!(same_error(&[]), VaultError::MalformedFile));
}

#[test]
fn bad_version_is_unsupported_version() {
    let mut bytes = sealed();
    bytes[4] = 9;
    assert!(matches!(
        same_error(&bytes),
        VaultError::UnsupportedVersion(9)
    ));
}

#[test]
fn unknown_kdf_id_is_unsupported_kdf() {
    let mut bytes = sealed();
    bytes[6] = 7;
    assert!(matches!(same_error(&bytes), VaultError::UnsupportedKdf));
}

#[test]
fn out_of_range_kdf_params_are_rejected() {
    let mut bytes = sealed();
    bytes[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        same_error(&bytes),
        VaultError::KdfParamsOutOfRange
    ));
    let mut bytes = sealed();
    bytes[11..15].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        same_error(&bytes),
        VaultError::KdfParamsOutOfRange
    ));
}

#[test]
fn oversize_file_is_rejected_like_unlock() {
    let mut bytes = sealed();
    bytes.resize(64 * 1024 * 1024 + 1, 0);
    same_error(&bytes);
}
