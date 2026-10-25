//! Pure-domain core of the P2P password manager: an encrypted wallet ("vault") holding
//! credentials, with no UI, network, or filesystem code.
//!
//! The product is fully offline here and has no accounts, email, or login. The only secret is
//! a wallet's master password, used to derive a key (Argon2id) that encrypts the wallet
//! (AES-256-GCM). The key lives in memory only while a [`Vault`] is unlocked and is never
//! serialized or persisted. A wallet created on another device opens with the same master
//! password alone.
//!
//! Persistence goes through the [`VaultStorage`] port; [`MemoryStorage`] is the in-memory
//! fake, and `vault-storage-file` provides the file adapter.
//!
//! # Security notes
//!
//! - Secrets (master password, key, entry fields) are wiped on drop with `zeroize`, and
//!   buffers are pre-sized so they do not leave copies by reallocating. This is best effort:
//!   a library cannot control what the operating system does with process memory.
//! - **Host obligation (FR-025a):** every executable embedding this crate MUST lock its memory
//!   against swap (for example `mlockall`) and disable core dumps, and MUST enforce auto-lock
//!   by calling [`Vault::lock`] or dropping the vault. The core has no timer.
//! - Error values and `Debug` output never contain the master password, the key, or entry
//!   passwords and notes.
//! - A wrong password and a tampered file yield the same
//!   [`VaultError::InvalidPasswordOrCorrupted`], so an attacker learns nothing from the error.
#![forbid(unsafe_code)]

mod clock;
mod copy;
mod entry;
mod error;
mod format;
mod ids;
mod kdf;
mod merge;
mod secret;
mod state;
mod storage;
#[cfg(feature = "testkit")]
pub mod testkit;
mod vault;
mod version;

pub use clock::{Clock, FixedClock, SystemClock};
pub use copy::OpenedCopy;
pub use entry::{Entry, EntryFields, MAX_VERSIONS, Version};
pub use error::{StorageError, VaultError};
pub use format::{peek_format_version, peek_kdf_config};
pub use ids::{DeviceId, EntryId, WalletId};
pub use kdf::KdfConfig;
pub use merge::{JUMP_BOUND, MergeError, MergeReport, PasswordChoice, Resolution};
pub use secret::{MasterPassword, VaultKey};
pub use state::StateVector;
pub use storage::{MemoryStorage, SaveMeta, VaultStorage};
pub use vault::Vault;
pub use version::{VersionOrdering, VersionVector};

/// Unix seconds, UTC.
pub type Timestamp = i64;
