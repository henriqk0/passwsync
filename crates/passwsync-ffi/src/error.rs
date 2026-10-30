#![forbid(unsafe_code)]
//! `CoreError` (contracts/ffi-api.md section 4): one flat enum, 37 variants, fixed English
//! messages and stable codes; no variant carries user data.

use std::fmt;

use wallet_service::ServiceError;

/// The protection whose failure blocks secret operations (data-model.md section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Protection {
    CoreDumps,
    NonDumpable,
}

macro_rules! core_error {
    ($($service:ident),* $(,)?) => {
        /// Every error the app can see. `Display` is a fixed message; [`CoreError::code`] a
        /// stable token.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
        #[uniffi(flat_error)]
        pub enum CoreError {
            $($service,)*
            ProtectionMissing { which: Protection },
            InvalidInput,
            NetworkOff,
            NotForeground,
            NoPeer,
            Busy,
            IdentityUnusable,
            PeersUnusable,
            /// `reason` is a fixed token of the 003 pairing refusals.
            Pairing { reason: &'static str },
            /// `reason` is a fixed token of the 005 share refusals.
            Share { reason: &'static str },
            AlreadyStarted,
            Platform,
        }

        impl From<ServiceError> for CoreError {
            fn from(error: ServiceError) -> Self {
                match error {
                    $(ServiceError::$service => Self::$service,)*
                }
            }
        }

        impl CoreError {
            /// Stable machine-readable code (the 001-005 codes for service errors).
            pub fn code(self) -> &'static str {
                match self {
                    $(Self::$service => ServiceError::$service.code(),)*
                    Self::ProtectionMissing { .. } => "protection_missing",
                    Self::InvalidInput => "invalid_input",
                    Self::NetworkOff => "network_off",
                    Self::NotForeground => "not_foreground",
                    Self::NoPeer => "no_peer",
                    Self::Busy => "busy",
                    Self::IdentityUnusable => "identity_unusable",
                    Self::PeersUnusable => "peers_unusable",
                    Self::Pairing { .. } => "pairing",
                    Self::Share { .. } => "share",
                    Self::AlreadyStarted => "already_started",
                    Self::Platform => "platform",
                }
            }

            fn message(self) -> &'static str {
                match self {
                    $(Self::$service => ServiceError::$service.message(),)*
                    Self::ProtectionMissing { which: Protection::CoreDumps } => {
                        "Core dumps could not be disabled; wallets cannot be opened."
                    }
                    Self::ProtectionMissing { which: Protection::NonDumpable } => {
                        "The process could not be made non-dumpable; wallets cannot be opened."
                    }
                    Self::InvalidInput => "The input is not valid.",
                    Self::NetworkOff => "Networking is off.",
                    Self::NotForeground => "This is only possible while the app is open.",
                    Self::NoPeer => "No paired device is reachable.",
                    Self::Busy => "Another operation is running; try again.",
                    Self::IdentityUnusable => "The device identity cannot be used.",
                    Self::PeersUnusable => "The paired devices cannot be read.",
                    Self::Pairing { .. } => "Pairing failed.",
                    Self::Share { .. } => "Sharing failed.",
                    Self::AlreadyStarted => "The core is already running.",
                    Self::Platform => "A platform service failed.",
                }
            }
        }
    };
}

core_error!(
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
    EntryConflicted,
    CannotOpenCopy,
    CopyRejected,
    TooManyConflicts,
    PasswordConflict,
    NotConflicted,
    InvalidVersionIndex,
    AlreadyPresent,
    Storage,
    Internal,
);

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CoreError {}
