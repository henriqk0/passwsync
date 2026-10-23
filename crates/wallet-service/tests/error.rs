use vault_core::{StorageError, VaultError};
use wallet_service::{InvalidName, ServiceError};

fn code(error: VaultError) -> &'static str {
    ServiceError::from(error).code()
}

#[test]
fn vault_errors_map_to_contract_codes() {
    assert_eq!(code(VaultError::PasswordTooShort), "password_too_short");
    assert_eq!(code(VaultError::EmptyTitle), "empty_title");
    assert_eq!(code(VaultError::FieldTooLarge), "field_too_large");
    assert_eq!(code(VaultError::EntryNotFound), "entry_not_found");
    assert_eq!(code(VaultError::MalformedFile), "malformed_file");
    assert_eq!(
        code(VaultError::UnsupportedVersion(7)),
        "unsupported_version"
    );
    assert_eq!(code(VaultError::UnsupportedKdf), "unsupported_kdf");
    assert_eq!(
        code(VaultError::KdfParamsOutOfRange),
        "kdf_params_out_of_range"
    );
    assert_eq!(
        code(VaultError::InvalidPasswordOrCorrupted),
        "invalid_password_or_corrupted"
    );
    assert_eq!(code(VaultError::WalletTooLarge), "wallet_too_large");
    assert_eq!(
        code(VaultError::Storage(StorageError::Io(
            std::io::Error::other("x")
        ))),
        "storage_error"
    );
    assert_eq!(
        code(VaultError::Storage(StorageError::NotFound)),
        "wallet_not_found"
    );
    assert_eq!(code(VaultError::Rng), "internal_error");
    assert_eq!(code(VaultError::InvalidDeviceId), "internal_error");
}

#[test]
fn service_errors_have_contract_codes() {
    let cases = [
        (ServiceError::InvalidName, "invalid_name"),
        (ServiceError::PasswordMismatch, "password_mismatch"),
        (ServiceError::WalletNotFound, "wallet_not_found"),
        (ServiceError::WalletExists, "wallet_exists"),
        (ServiceError::WalletLocked, "wallet_locked"),
        (ServiceError::Internal, "internal_error"),
    ];
    for (error, expected) in cases {
        assert_eq!(error.code(), expected);
    }
    assert_eq!(ServiceError::from(InvalidName), ServiceError::InvalidName);
}

#[test]
fn wrong_password_message_is_generic_and_exact() {
    let error = ServiceError::from(VaultError::InvalidPasswordOrCorrupted);
    assert_eq!(error.message(), "invalid password or corrupted wallet");
}

#[test]
fn kdf_over_the_service_cap_uses_the_format_error_class() {
    assert_eq!(
        ServiceError::KdfParamsOutOfRange.code(),
        "kdf_params_out_of_range"
    );
}

#[test]
fn messages_are_fixed_and_carry_no_data() {
    let error = ServiceError::from(VaultError::Storage(StorageError::Io(
        std::io::Error::other("SECRET-PATH"),
    )));
    assert!(!error.message().contains("SECRET"));
    assert!(!format!("{error:?}").contains("SECRET"));
    assert!(!error.to_string().contains("SECRET"));
}
