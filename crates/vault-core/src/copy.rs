//! A received copy of a wallet, authenticated and decrypted for a merge (004, R5, R6).

use std::fmt;

use zeroize::ZeroizeOnDrop;

use crate::format::{self, Header};
use crate::kdf::derive_key;
use crate::{
    Entry, KdfConfig, MasterPassword, StateVector, Timestamp, Vault, VaultError, VaultKey,
    VersionVector, WalletId,
};

/// Authenticated contents of a received copy. Produced only by
/// [`Vault::open_copy_own_key`] or [`Vault::open_copy_with_password`]; consumed by a merge.
/// Not `Clone`, not `Serialize`; the key and every entry field are wiped on drop.
pub struct OpenedCopy {
    pub(crate) wallet_id: WalletId,
    pub(crate) created_at: Timestamp,
    pub(crate) state: StateVector,
    pub(crate) password_epoch: VersionVector,
    pub(crate) entries: Vec<Entry>,
    pub(crate) kdf: KdfConfig,
    pub(crate) salt: [u8; 32],
    pub(crate) key: VaultKey,
}

/// Every secret part (`key`: `VaultKey`, entry fields: `EntryFields`) zeroizes itself on drop.
impl ZeroizeOnDrop for OpenedCopy {}

impl OpenedCopy {
    fn from_parts(header: &Header, key: VaultKey, payload: format::Payload) -> Self {
        Self {
            wallet_id: payload.wallet_id,
            created_at: payload.created_at,
            state: payload.state,
            password_epoch: payload.password_epoch,
            entries: payload.entries,
            kdf: header.kdf,
            salt: header.salt,
            key,
        }
    }

    /// The authenticated wallet id.
    pub fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    /// The authenticated state vector.
    pub fn state(&self) -> &StateVector {
        &self.state
    }

    /// The authenticated password-change epoch.
    pub fn password_epoch(&self) -> &VersionVector {
        &self.password_epoch
    }
}

impl fmt::Debug for OpenedCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedCopy")
            .field("wallet_id", &self.wallet_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens a copy encrypted with this vault's current KDF config and salt, with the key in
    /// memory (no KDF run). A copy under other parameters fails with the generic error; see
    /// [`Vault::needs_password`].
    pub fn open_copy_own_key(&self, bytes: &[u8]) -> Result<OpenedCopy, VaultError> {
        let header = Header::parse(bytes)?;
        if header.kdf != self.kdf || header.salt != self.salt {
            return Err(VaultError::InvalidPasswordOrCorrupted);
        }
        let key = VaultKey::from_bytes(*self.key.as_bytes());
        let payload = format::open_with_key(bytes, &header, &key)?;
        Ok(OpenedCopy::from_parts(&header, key, payload))
    }

    /// Opens a copy with a password (one Argon2id run); the password is wiped on return.
    pub fn open_copy_with_password(
        bytes: &[u8],
        password: MasterPassword,
    ) -> Result<OpenedCopy, VaultError> {
        let header = Header::parse(bytes)?;
        let key = derive_key(&password, &header.kdf, &header.salt)?;
        drop(password);
        let payload = format::open_with_key(bytes, &header, &key)?;
        Ok(OpenedCopy::from_parts(&header, key, payload))
    }

    /// Whether the copy's (unauthenticated) header names other key parameters than this
    /// vault's, i.e. it can only be opened with a password.
    pub fn needs_password(&self, bytes: &[u8]) -> Result<bool, VaultError> {
        let header = Header::parse(bytes)?;
        Ok(header.kdf != self.kdf || header.salt != self.salt)
    }
}
