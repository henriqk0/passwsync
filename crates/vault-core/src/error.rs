use thiserror::Error;

/// Failure reported by a [`VaultStorage`](crate::VaultStorage) adapter.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("wallet not found in storage")]
    NotFound,
    #[error("storage I/O error")]
    Io(#[source] std::io::Error),
}

/// Every failure of the core. No variant carries secret or plaintext data.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("master password is too short (minimum 12 characters)")]
    PasswordTooShort,
    #[error("entry title must not be empty")]
    EmptyTitle,
    #[error("entry field exceeds the 1 MiB limit")]
    FieldTooLarge,
    #[error("device identifier must be 1 to 64 bytes")]
    InvalidDeviceId,
    #[error("entry not found")]
    EntryNotFound,
    #[error("not a valid wallet file")]
    MalformedFile,
    #[error("unsupported wallet format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported key derivation function")]
    UnsupportedKdf,
    #[error("key derivation parameters out of the accepted range")]
    KdfParamsOutOfRange,
    #[error("invalid password or corrupted wallet")]
    InvalidPasswordOrCorrupted,
    #[error("wallet exceeds the 64 MiB size limit")]
    WalletTooLarge,
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("secure random source failure")]
    Rng,
    #[error("a wallet may be changed by at most 256 devices")]
    TooManyDevices,
    #[error("change counter overflow")]
    CounterOverflow,
    #[error("entry has conflicting versions; resolve the conflict first")]
    EntryConflicted,
    #[error("entry is not conflicted")]
    NotConflicted,
    #[error("no such version of the entry")]
    InvalidVersionIndex,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_error_display_strings_are_fixed() {
        assert_eq!(
            VaultError::PasswordTooShort.to_string(),
            "master password is too short (minimum 12 characters)"
        );
        assert_eq!(
            VaultError::EmptyTitle.to_string(),
            "entry title must not be empty"
        );
        assert_eq!(
            VaultError::FieldTooLarge.to_string(),
            "entry field exceeds the 1 MiB limit"
        );
        assert_eq!(
            VaultError::InvalidDeviceId.to_string(),
            "device identifier must be 1 to 64 bytes"
        );
        assert_eq!(VaultError::EntryNotFound.to_string(), "entry not found");
        assert_eq!(
            VaultError::MalformedFile.to_string(),
            "not a valid wallet file"
        );
        assert_eq!(
            VaultError::UnsupportedVersion(2).to_string(),
            "unsupported wallet format version 2"
        );
        assert_eq!(
            VaultError::UnsupportedKdf.to_string(),
            "unsupported key derivation function"
        );
        assert_eq!(
            VaultError::KdfParamsOutOfRange.to_string(),
            "key derivation parameters out of the accepted range"
        );
        assert_eq!(
            VaultError::InvalidPasswordOrCorrupted.to_string(),
            "invalid password or corrupted wallet"
        );
        assert_eq!(
            VaultError::WalletTooLarge.to_string(),
            "wallet exceeds the 64 MiB size limit"
        );
        assert_eq!(VaultError::Rng.to_string(), "secure random source failure");
    }

    #[test]
    fn storage_error_not_found_is_distinct_from_io() {
        let not_found = StorageError::NotFound;
        let io = StorageError::Io(std::io::Error::other("boom"));
        assert!(matches!(not_found, StorageError::NotFound));
        assert!(matches!(io, StorageError::Io(_)));
        assert_eq!(not_found.to_string(), "wallet not found in storage");
        assert_eq!(io.to_string(), "storage I/O error");
    }

    #[test]
    fn vault_error_wraps_storage_error() {
        let wrapped: VaultError = StorageError::NotFound.into();
        assert!(matches!(
            wrapped,
            VaultError::Storage(StorageError::NotFound)
        ));
        assert_eq!(
            wrapped.to_string(),
            "storage error: wallet not found in storage"
        );
    }
}
