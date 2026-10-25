use std::time::Instant;

use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault, VaultError};

const PASSWORD: &str = "correct horse battery";

fn sealed_wallet() -> Vec<u8> {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.to_string()),
        KdfConfig::MINIMUM,
        DeviceId::new("laptop").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    for title in ["alpha", "beta"] {
        let mut fields = EntryFields::default();
        fields.title = title.into();
        fields.password = format!("{title}-secret");
        vault.add_entry(fields).unwrap();
    }
    vault.seal().unwrap()
}

fn unlock(bytes: &[u8]) -> Result<Vault, VaultError> {
    Vault::unlock(
        bytes,
        MasterPassword::new(PASSWORD.to_string()),
        DeviceId::new("laptop").unwrap(),
        Box::new(FixedClock::new(1)),
    )
}

fn mutated(bytes: &[u8], change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    change(&mut copy);
    copy
}

#[test]
fn untouched_wallet_unlocks() {
    assert!(unlock(&sealed_wallet()).is_ok());
}

#[test]
fn flipping_any_single_byte_is_rejected() {
    let bytes = sealed_wallet();
    for index in 0..bytes.len() {
        let tampered = mutated(&bytes, |b| b[index] ^= 0x01);
        assert!(unlock(&tampered).is_err(), "byte {index} flip was accepted");
    }
}

#[test]
fn every_truncation_is_rejected() {
    let bytes = sealed_wallet();
    for length in 0..bytes.len() {
        assert!(
            unlock(&bytes[..length]).is_err(),
            "truncation to {length} was accepted"
        );
    }
}

#[test]
fn appended_bytes_are_rejected() {
    let tampered = mutated(&sealed_wallet(), |b| b.push(0));
    assert!(unlock(&tampered).is_err());
}

#[test]
fn bad_magic_is_malformed() {
    let tampered = mutated(&sealed_wallet(), |b| b[0..4].copy_from_slice(b"XXXX"));
    assert!(matches!(unlock(&tampered), Err(VaultError::MalformedFile)));
}

#[test]
fn unknown_version_and_kdf_are_reported_distinctly() {
    let bytes = sealed_wallet();
    // 004: version 2 is now the written format, so the first unknown version is 3.
    let version = mutated(&bytes, |b| b[4..6].copy_from_slice(&3u16.to_le_bytes()));
    assert!(matches!(
        unlock(&version),
        Err(VaultError::UnsupportedVersion(3))
    ));
    let kdf = mutated(&bytes, |b| b[6] = 2);
    assert!(matches!(unlock(&kdf), Err(VaultError::UnsupportedKdf)));
}

#[test]
fn out_of_range_kdf_parameters_are_rejected_before_any_derivation() {
    let bytes = sealed_wallet();
    let cases: [(usize, u32); 3] = [(7, 4_194_304), (11, 0), (15, 17)];
    for (offset, value) in cases {
        let tampered = mutated(&bytes, |b| {
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
        });
        let started = Instant::now();
        let result = unlock(&tampered);
        assert!(
            matches!(result, Err(VaultError::KdfParamsOutOfRange)),
            "offset {offset}"
        );
        assert!(
            started.elapsed().as_millis() < 50,
            "KDF must not have run (offset {offset})"
        );
    }
}

#[test]
fn oversized_input_is_malformed() {
    let mut huge = vec![0u8; 64 * 1024 * 1024 + 1];
    huge[0..4].copy_from_slice(b"PWSV");
    assert!(matches!(unlock(&huge), Err(VaultError::MalformedFile)));
}

#[test]
fn flipped_ciphertext_with_correct_password_is_the_generic_error() {
    let tampered = mutated(&sealed_wallet(), |b| b[70] ^= 0x80);
    assert!(matches!(
        unlock(&tampered),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}
