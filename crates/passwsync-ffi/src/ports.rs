#![forbid(unsafe_code)]
//! Foreign ports (contracts/ffi-api.md section 3): implemented in Kotlin, faked in `testkit`.
//! The core never reaches a platform service except through these four traits.

use std::fmt;

use crate::error::CoreError;
use crate::records::CoreEvent;

/// Why a platform port failed. Carries no data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum PlatformError {
    /// The service (Keystore, clipboard) is not available right now.
    Unavailable,
    /// The Keystore key was invalidated or is missing.
    Invalidated,
    /// Any other failure, including an authentication tag mismatch.
    Failed,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "The platform service is unavailable.",
            Self::Invalidated => "The platform key was invalidated.",
            Self::Failed => "The platform service failed.",
        })
    }
}

impl std::error::Error for PlatformError {}

/// An unexpected foreign exception is a plain failure, never a panic.
impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed
    }
}

impl From<PlatformError> for CoreError {
    fn from(_: PlatformError) -> Self {
        Self::Platform
    }
}

/// Seals small secrets under the non-exportable Keystore key. The only labels ever passed are
/// `passwsync identity v1` and `passwsync peers v1` (section 6, FR-035).
#[uniffi::export(with_foreign)]
pub trait KeySealer: Send + Sync {
    /// AES-GCM under the Keystore key; AAD = label. Returns iv, ciphertext and tag.
    fn seal(&self, label: String, plaintext: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
    /// Fails on any tag mismatch, missing or invalidated key.
    fn open(&self, label: String, sealed: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
    /// Deletes and regenerates the Keystore key (identity reset, FR-037).
    fn reset(&self) -> Result<(), PlatformError>;
}

/// The system clipboard (FR-021, FR-022).
#[uniffi::export(with_foreign)]
pub trait Clipboard: Send + Sync {
    /// Sets a plain-text clip marked sensitive; returns the clip timestamp.
    fn set_sensitive(&self, value: Vec<u8>) -> Result<i64, PlatformError>;
    /// Clears when the current clip has `timestamp` or cannot be inspected. True if cleared.
    fn clear_if_ours(&self, timestamp: i64) -> bool;
}

/// One closed-set log line (FR-057); Kotlin writes it with `android.util.Log.i` only.
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    fn line(&self, text: String);
}

/// State changes for the UI; called from any core thread.
#[uniffi::export(with_foreign)]
pub trait UiNotifier: Send + Sync {
    fn changed(&self, event: CoreEvent);
}
