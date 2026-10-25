use std::fmt;

use vault_core::{StorageError, VaultError};

use crate::InvalidName;

/// Every failure of a service use case. Variants carry no data, so nothing from a request
/// or the filesystem can leak through an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    InvalidName,
    PasswordTooShort,
    PasswordMismatch,
    EmptyTitle,
    FieldTooLarge,
    WalletNotFound,
    EntryNotFound,
    WalletExists,
    WalletLocked,
    InvalidPasswordOrCorrupted,
    MalformedFile,
    UnsupportedVersion,
    UnsupportedKdf,
    KdfParamsOutOfRange,
    WalletTooLarge,
    /// 004: the entry has concurrent versions; resolve the conflict first.
    EntryConflicted,
    /// 004: a received copy needs another master password, or is corrupted.
    CannotOpenCopy,
    /// 004: a received copy failed the sync checks (wallet id, claimed state, marks, jump).
    CopyRejected,
    /// 004: merging would give an entry more than 16 versions; resolve conflicts first.
    TooManyConflicts,
    /// 004: the master password was changed on two devices; the person chooses.
    PasswordConflict,
    /// 004: resolve on an entry without concurrent versions.
    NotConflicted,
    /// 004: no such version index.
    InvalidVersionIndex,
    Storage,
    Internal,
}

impl ServiceError {
    /// Stable machine-readable code (contracts/http-api.md).
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::PasswordTooShort => "password_too_short",
            Self::PasswordMismatch => "password_mismatch",
            Self::EmptyTitle => "empty_title",
            Self::FieldTooLarge => "field_too_large",
            Self::WalletNotFound => "wallet_not_found",
            Self::EntryNotFound => "entry_not_found",
            Self::WalletExists => "wallet_exists",
            Self::WalletLocked => "wallet_locked",
            Self::InvalidPasswordOrCorrupted => "invalid_password_or_corrupted",
            Self::MalformedFile => "malformed_file",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedKdf => "unsupported_kdf",
            Self::KdfParamsOutOfRange => "kdf_params_out_of_range",
            Self::WalletTooLarge => "wallet_too_large",
            Self::EntryConflicted => "entry_conflicted",
            Self::CannotOpenCopy => "cannot_open_copy",
            Self::CopyRejected => "invalid_copy",
            Self::TooManyConflicts => "too_many_conflicts",
            Self::PasswordConflict => "password_conflict",
            Self::NotConflicted => "not_conflicted",
            Self::InvalidVersionIndex => "invalid_version",
            Self::Storage => "storage_error",
            Self::Internal => "internal_error",
        }
    }

    /// Fixed English text for people.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidName => {
                "wallet name must be 1 to 64 letters, digits, spaces, '_', '.' or '-', \
                 not starting with '.' or ending with a space"
            }
            Self::PasswordTooShort => "master password is too short (minimum 12 characters)",
            Self::PasswordMismatch => "the two passwords do not match",
            Self::EmptyTitle => "entry title must not be empty",
            Self::FieldTooLarge => "entry field exceeds the 1 MiB limit",
            Self::WalletNotFound => "wallet not found",
            Self::EntryNotFound => "entry not found",
            Self::WalletExists => "a wallet with this name already exists",
            Self::WalletLocked => "wallet is locked",
            Self::InvalidPasswordOrCorrupted => "invalid password or corrupted wallet",
            Self::MalformedFile => "not a valid wallet file",
            Self::UnsupportedVersion => "unsupported wallet format version",
            Self::UnsupportedKdf => "unsupported key derivation function",
            Self::KdfParamsOutOfRange => "key derivation parameters out of the accepted range",
            Self::WalletTooLarge => "wallet exceeds the 64 MiB size limit",
            Self::EntryConflicted => {
                "this credential has conflicting versions; resolve the conflict first"
            }
            Self::CannotOpenCopy => "cannot open: different master password or corrupted",
            Self::CopyRejected => "the received copy is not valid for this wallet",
            Self::TooManyConflicts => "too many conflicts, resolve first",
            Self::PasswordConflict => {
                "the master password was changed on two devices; choose which one to keep"
            }
            Self::NotConflicted => "this credential has no conflict",
            Self::InvalidVersionIndex => "no such version of this credential",
            Self::Storage => "the wallet could not be saved; the change was not applied",
            Self::Internal => "internal error",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ServiceError {}

impl From<InvalidName> for ServiceError {
    fn from(_: InvalidName) -> Self {
        Self::InvalidName
    }
}

impl From<VaultError> for ServiceError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::PasswordTooShort => Self::PasswordTooShort,
            VaultError::EmptyTitle => Self::EmptyTitle,
            VaultError::FieldTooLarge => Self::FieldTooLarge,
            VaultError::EntryNotFound => Self::EntryNotFound,
            VaultError::MalformedFile => Self::MalformedFile,
            VaultError::UnsupportedVersion(_) => Self::UnsupportedVersion,
            VaultError::UnsupportedKdf => Self::UnsupportedKdf,
            VaultError::KdfParamsOutOfRange => Self::KdfParamsOutOfRange,
            VaultError::InvalidPasswordOrCorrupted => Self::InvalidPasswordOrCorrupted,
            VaultError::WalletTooLarge => Self::WalletTooLarge,
            VaultError::Storage(error) => error.into(),
            VaultError::InvalidDeviceId
            | VaultError::Rng
            | VaultError::TooManyDevices
            | VaultError::CounterOverflow => Self::Internal,
            VaultError::EntryConflicted => Self::EntryConflicted,
            VaultError::NotConflicted => Self::NotConflicted,
            VaultError::InvalidVersionIndex => Self::InvalidVersionIndex,
        }
    }
}

impl From<StorageError> for ServiceError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotFound => Self::WalletNotFound,
            StorageError::Io(_) => Self::Storage,
        }
    }
}
