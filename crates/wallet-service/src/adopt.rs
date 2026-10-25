//! Opening a received wallet (005 contracts/core-api-share.md "wallet-service", research
//! R10): the received ciphertext, authenticated with the master password, becomes a held and
//! unlocked wallet whose file is byte-for-byte the received one (so the first 004 round finds
//! both devices in sync). 002 rules apply: name validation, create lock, KDF memory cap, one
//! derivation at a time, generic error, password wiped.

use std::sync::Arc;

use vault_core::{MasterPassword, Vault, peek_kdf_config};
use zeroize::Zeroizing;

use crate::registry::{KDF_MEMORY_CAP_KIB, Slot, WalletSlot, lock};
use crate::{Service, ServiceError, UnlockFacts, WalletName};

/// The host's decision once the received wallet's identity is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdoptVerdict {
    Proceed,
    /// The same wallet (by wallet id) is already held under this local name.
    AlreadyPresent(WalletName),
}

impl Service {
    /// Opens `bytes` (a received wallet file) with `password` and makes it the held,
    /// unlocked wallet `name`. Order: validate the name, not existing (create lock), KDF cap,
    /// derive (KDF gate), format 2, `decide(facts)`, store the bytes verbatim, notify the 004
    /// hook, register unlocked. On any error nothing is written and the password is wiped.
    pub fn adopt_received(
        &self,
        name: &str,
        bytes: &[u8],
        password: Zeroizing<String>,
        decide: &dyn Fn(&UnlockFacts) -> AdoptVerdict,
    ) -> Result<WalletName, ServiceError> {
        let name = WalletName::parse(name)?;
        let _creating = lock(&self.create_lock);
        let unlocked_here = lock(&self.slots)
            .get(&name)
            .cloned()
            .is_some_and(|slot| matches!(*lock(&slot.state), Slot::Unlocked { .. }));
        if unlocked_here || self.dir.exists(&name)? {
            return Err(ServiceError::WalletExists);
        }
        if peek_kdf_config(bytes)?.memory_kib > KDF_MEMORY_CAP_KIB {
            return Err(ServiceError::KdfParamsOutOfRange);
        }
        let vault = self.derive(|| {
            Vault::unlock(
                bytes,
                MasterPassword::new(crate::registry::take(password)),
                self.config.device.clone(),
                self.vault_clock(),
            )
        })?;
        if vault.format_version_loaded() != 2 {
            return Err(ServiceError::UnsupportedVersion);
        }
        let facts = UnlockFacts {
            wallet_id: vault.wallet_id(),
            state: vault.state().clone(),
            format_version: vault.format_version_loaded(),
        };
        if let AdoptVerdict::AlreadyPresent(_) = decide(&facts) {
            return Err(ServiceError::AlreadyPresent);
        }
        self.dir.storage(&name).store(bytes)?;
        if let Some(port) = self.pending_port() {
            port.unlocked(&name, bytes, &facts);
        }
        let slot = Arc::clone(
            lock(&self.slots)
                .entry(name.clone())
                .or_insert_with(|| WalletSlot::new(Slot::Locked)),
        );
        *lock(&slot.state) = Slot::Unlocked {
            vault: Box::new(vault),
            last_activity: self.elapsed.monotonic(),
        };
        Ok(name)
    }
}
