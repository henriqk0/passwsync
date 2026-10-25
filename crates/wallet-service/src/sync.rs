//! Sync-facing use cases (004, contracts/vault-core-sync-api.md "wallet-service"): merging a
//! received copy into an unlocked wallet. Background activity: never touches idle timers
//! (FR-006b) and never needs or sees a master password.

use vault_core::{
    EntryId, MasterPassword, MergeError, MergeReport, OpenedCopy, PasswordChoice, Resolution,
    StateVector, Timestamp, Vault, VersionOrdering, WalletId,
};
use zeroize::Zeroizing;

use crate::registry::{KDF_MEMORY_CAP_KIB, Slot, copy, lock};
use crate::{
    Field, PeerRef, PendingCopies, PendingOutcome, Service, ServiceError, UnlockFacts, WalletName,
};

/// A conflicted credential in the conflict list (no password).
#[derive(Debug)]
pub struct ConflictSummary {
    pub id: EntryId,
    pub title: Zeroizing<String>,
    pub versions: usize,
}

/// One version of a conflicted credential (no password; reveal goes through
/// [`Service::conflict_field`]).
pub struct ConflictVersion {
    pub index: usize,
    pub deleted: bool,
    pub title: Option<Zeroizing<String>>,
    pub username: Option<Zeroizing<String>>,
    pub url: Option<Zeroizing<String>>,
    pub notes: Option<Zeroizing<String>>,
    pub modified_at: Timestamp,
    /// The version was made on this device.
    pub this_device: bool,
}

impl std::fmt::Debug for ConflictVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConflictVersion")
            .field("index", &self.index)
            .field("deleted", &self.deleted)
            .finish_non_exhaustive()
    }
}

/// How a copy's password-change epoch relates to the local one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochRelation {
    Equal,
    /// The copy carries a newer password change (its key will be adopted).
    Newer,
    Older,
    Concurrent,
}

impl From<VersionOrdering> for EpochRelation {
    fn from(ordering: VersionOrdering) -> Self {
        match ordering {
            VersionOrdering::Equal => Self::Equal,
            VersionOrdering::Newer => Self::Newer,
            VersionOrdering::Older => Self::Older,
            VersionOrdering::Concurrent => Self::Concurrent,
        }
    }
}

/// Authenticated facts about a copy, shown to the sync layer's check before the merge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyFacts {
    pub wallet_id: WalletId,
    pub state: StateVector,
    pub password_epoch: EpochRelation,
}

/// The sync layer's decision on a copy (requested wallet id, claimed state, peer mark,
/// jump bound).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyVerdict {
    Accept,
    Reject,
}

pub(crate) fn map_merge(error: MergeError) -> ServiceError {
    match error {
        MergeError::TooManyConflicts => ServiceError::TooManyConflicts,
        MergeError::PasswordConflict => ServiceError::PasswordConflict,
        MergeError::WalletMismatch | MergeError::JumpTooLarge | MergeError::TooManyDevices => {
            ServiceError::CopyRejected
        }
        MergeError::Save(error) => error.into(),
    }
}

impl Service {
    /// Conflicted credentials of an unlocked wallet (deliberate action).
    pub fn conflicts(&self, name: &WalletName) -> Result<Vec<ConflictSummary>, ServiceError> {
        self.with_unlocked(name, |vault| {
            Ok(vault
                .conflicted()
                .into_iter()
                .map(|e| ConflictSummary {
                    id: e.id(),
                    title: copy(e.fields().map_or("", |f| f.title.as_str())),
                    versions: e.versions().len(),
                })
                .collect())
        })
    }

    /// Every version of one conflicted credential, current first (deliberate action).
    pub fn conflict_versions(
        &self,
        name: &WalletName,
        id: EntryId,
    ) -> Result<Vec<ConflictVersion>, ServiceError> {
        self.with_unlocked(name, |vault| {
            let me = vault.device().clone();
            let versions = vault.versions(id).ok_or(ServiceError::EntryNotFound)?;
            if versions.len() < 2 {
                return Err(ServiceError::NotConflicted);
            }
            Ok(versions
                .iter()
                .enumerate()
                .map(|(index, v)| {
                    let f = v.fields();
                    ConflictVersion {
                        index,
                        deleted: v.is_deleted(),
                        title: f.map(|f| copy(&f.title)),
                        username: f.map(|f| copy(&f.username)),
                        url: f.map(|f| copy(&f.url)),
                        notes: f.map(|f| copy(&f.notes)),
                        modified_at: v.modified_at(),
                        this_device: v.last_modified_by() == &me,
                    }
                })
                .collect())
        })
    }

    /// The password or username of one version (002 reveal/copy rules).
    pub fn conflict_field(
        &self,
        name: &WalletName,
        id: EntryId,
        index: usize,
        field: Field,
    ) -> Result<Zeroizing<String>, ServiceError> {
        self.with_unlocked(name, |vault| {
            let versions = vault.versions(id).ok_or(ServiceError::EntryNotFound)?;
            let version = versions
                .get(index)
                .ok_or(ServiceError::InvalidVersionIndex)?;
            let fields = version.fields().ok_or(ServiceError::EntryNotFound)?;
            Ok(copy(match field {
                Field::Password => &fields.password,
                Field::Username => &fields.username,
            }))
        })
    }

    /// Resolves a conflict and saves before returning (rolled back on a save failure).
    /// A deliberate action: it counts as activity for auto-lock.
    pub fn resolve_conflict(
        &self,
        name: &WalletName,
        id: EntryId,
        how: Resolution,
    ) -> Result<Vec<EntryId>, ServiceError> {
        let mut storage = self.dir.storage(name);
        self.with_unlocked(name, |vault| {
            Ok(vault.resolve_saved(id, how, storage.as_mut())?)
        })
    }

    /// Tells the sync layer about a fresh unlock and rewrites a version 1 file as version 2
    /// when it asks (networking on with a paired peer, research R3). A failed rewrite never
    /// fails the unlock.
    pub(crate) fn after_unlock(&self, name: &WalletName, file: &[u8], vault: &Vault) {
        let Some(port) = self.pending_port() else {
            return;
        };
        let facts = UnlockFacts {
            wallet_id: vault.wallet_id(),
            state: vault.state().clone(),
            format_version: vault.format_version_loaded(),
        };
        if port.unlocked(name, file, &facts)
            && vault.format_version_loaded() == 1
            && vault.save(self.dir.storage(name).as_mut()).is_ok()
        {
            port.upgraded(name);
        }
    }

    /// Merges every pending copy of a wallet just unlocked, one at a time, while the
    /// password is still held (research R13): copies under the wallet's key open without a
    /// KDF run; others are tried with the entered password (one derivation at a time, under
    /// the memory cap). One save at the end. Nothing here can make the unlock fail.
    pub(crate) fn merge_pending_at_unlock(
        &self,
        name: &WalletName,
        vault: &mut Vault,
        password: &Zeroizing<String>,
    ) {
        let Some(port) = self.pending_port() else {
            return;
        };
        let mut outcomes = Vec::new();
        let mut changed = false;
        for pending in port.list(name) {
            if let Some(outcome) =
                self.merge_one(name, vault, port.as_ref(), &pending.peer, password)
            {
                changed |= matches!(outcome, PendingOutcome::Merged { .. });
                outcomes.push((pending.peer, outcome));
            }
        }
        if changed && vault.save(self.dir.storage(name).as_mut()).is_err() {
            // Not saved: the copies stay pending and merge again later (idempotent).
            outcomes.retain(|(_, o)| !matches!(o, PendingOutcome::Merged { .. }));
        }
        for (peer, outcome) in outcomes {
            port.outcome(name, &peer, outcome);
        }
    }

    fn merge_one(
        &self,
        name: &WalletName,
        vault: &mut Vault,
        port: &dyn PendingCopies,
        peer: &PeerRef,
        password: &Zeroizing<String>,
    ) -> Option<PendingOutcome> {
        let bytes = port.load(name, peer).ok()?;
        let copy = match vault.needs_password(&bytes) {
            Err(_) => return Some(PendingOutcome::Invalid),
            Ok(false) => vault.open_copy_own_key(&bytes).ok(),
            Ok(true) => {
                let within_cap = vault_core::peek_kdf_config(&bytes)
                    .is_ok_and(|kdf| kdf.memory_kib <= KDF_MEMORY_CAP_KIB);
                if within_cap {
                    self.derive(|| {
                        Vault::open_copy_with_password(
                            &bytes,
                            vault_core::MasterPassword::new(password.as_str().to_owned()),
                        )
                    })
                    .ok()
                } else {
                    None
                }
            }
        };
        let Some(copy) = copy else {
            return Some(PendingOutcome::CannotOpen);
        };
        let facts = CopyFacts {
            wallet_id: copy.wallet_id(),
            state: copy.state().clone(),
            password_epoch: copy.password_epoch().compare(vault.password_epoch()).into(),
        };
        if port.check(name, peer, &facts) == CopyVerdict::Reject {
            return Some(PendingOutcome::Invalid);
        }
        Some(match vault.merge(copy) {
            Ok(report) if report.changed => PendingOutcome::Merged {
                conflicts: report.conflicts_added,
                self_rollback: report.self_rollback_recovered,
                password_adopted: report.password_adopted,
            },
            Ok(_) => PendingOutcome::Unchanged,
            Err(MergeError::PasswordConflict) => PendingOutcome::PasswordConflict,
            Err(MergeError::TooManyConflicts) => PendingOutcome::TooManyConflicts,
            Err(_) => PendingOutcome::Invalid,
        })
    }

    /// Changes the master password of an unlocked wallet and saves (journaled; counts as a
    /// change and moves the password-change epoch, FR-022). Deliberate action.
    pub fn change_password(
        &self,
        name: &WalletName,
        new: Zeroizing<String>,
        confirm: Zeroizing<String>,
    ) -> Result<(), ServiceError> {
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            new.as_bytes(),
            confirm.as_bytes(),
        )) {
            return Err(ServiceError::PasswordMismatch);
        }
        drop(confirm);
        let mut storage = self.dir.storage(name);
        // Lock order: KDF gate, then the wallet state (as merges).
        let _gate = lock(&self.kdf_gate);
        self.with_unlocked(name, |vault| {
            Ok(vault.change_master_password_saved(
                MasterPassword::new(new.as_str().to_owned()),
                storage.as_mut(),
            )?)
        })
    }

    /// Opens a pending copy with the password the person typed for it and merges it into the
    /// unlocked wallet (FR-022). A wrong password leaves the copy pending.
    pub fn open_pending_with_password(
        &self,
        name: &WalletName,
        peer: &PeerRef,
        password: Zeroizing<String>,
    ) -> Result<MergeReport, ServiceError> {
        self.merge_pending_with(name, peer, password, None)
    }

    /// Resolves concurrent password changes: `password` opens the copy (it is the copy's
    /// password), the merge keeps `keep`'s key and dominates both epochs.
    pub fn choose_password(
        &self,
        name: &WalletName,
        peer: &PeerRef,
        keep: PasswordChoice,
        password: Zeroizing<String>,
    ) -> Result<MergeReport, ServiceError> {
        self.merge_pending_with(name, peer, password, Some(keep))
    }

    fn merge_pending_with(
        &self,
        name: &WalletName,
        peer: &PeerRef,
        password: Zeroizing<String>,
        keep: Option<PasswordChoice>,
    ) -> Result<MergeReport, ServiceError> {
        let port = self.pending_port().ok_or(ServiceError::EntryNotFound)?;
        let slot = self.slot(name)?;
        if !matches!(*lock(&slot.state), Slot::Unlocked { .. }) {
            return Err(ServiceError::WalletLocked);
        }
        let bytes = port
            .load(name, peer)
            .map_err(|_| ServiceError::EntryNotFound)?;
        if vault_core::peek_kdf_config(&bytes)
            .map_err(|_| ServiceError::CopyRejected)?
            .memory_kib
            > KDF_MEMORY_CAP_KIB
        {
            return Err(ServiceError::KdfParamsOutOfRange);
        }
        let mut storage = self.dir.storage(name);
        let _gate = lock(&self.kdf_gate);
        let copy: OpenedCopy = Vault::open_copy_with_password(
            &bytes,
            MasterPassword::new(password.as_str().to_owned()),
        )
        .map_err(|_| ServiceError::InvalidPasswordOrCorrupted)?;
        drop(password);
        let mut state = lock(&slot.state);
        let Slot::Unlocked {
            vault,
            last_activity,
        } = &mut *state
        else {
            return Err(ServiceError::WalletLocked);
        };
        *last_activity = self.elapsed.monotonic();
        let facts = CopyFacts {
            wallet_id: copy.wallet_id(),
            state: copy.state().clone(),
            password_epoch: copy.password_epoch().compare(vault.password_epoch()).into(),
        };
        if port.check(name, peer, &facts) == CopyVerdict::Reject {
            drop(state);
            port.outcome(name, peer, PendingOutcome::Invalid);
            return Err(ServiceError::CopyRejected);
        }
        let result = match keep {
            None => vault.merge_saved(copy, storage.as_mut()),
            Some(keep) => vault.merge_choosing_password_saved(copy, keep, storage.as_mut()),
        };
        drop(state);
        let outcome = match &result {
            Ok(r) if r.changed => Some(PendingOutcome::Merged {
                conflicts: r.conflicts_added,
                self_rollback: r.self_rollback_recovered,
                password_adopted: r.password_adopted,
            }),
            Ok(_) => Some(PendingOutcome::Unchanged),
            Err(MergeError::PasswordConflict) => Some(PendingOutcome::PasswordConflict),
            Err(MergeError::TooManyConflicts) => Some(PendingOutcome::TooManyConflicts),
            Err(MergeError::Save(_)) => None,
            Err(_) => Some(PendingOutcome::Invalid),
        };
        if let Some(outcome) = outcome {
            port.outcome(name, peer, outcome);
        }
        result.map_err(map_merge)
    }

    /// Number of conflicted credentials of an unlocked wallet; `None` while locked.
    /// Background: never touches the idle timer.
    pub fn conflict_count(&self, name: &WalletName) -> Option<u32> {
        let slot = self.slot(name).ok()?;
        let state = lock(&slot.state);
        match &*state {
            Slot::Unlocked { vault, .. } => Some(vault.conflicted().len() as u32),
            Slot::Locked => None,
        }
    }

    /// Wallet id and state of an unlocked wallet; `None` while locked. Background.
    pub fn sync_facts(&self, name: &WalletName) -> Option<(WalletId, StateVector)> {
        let slot = self.slot(name).ok()?;
        let state = lock(&slot.state);
        match &*state {
            Slot::Unlocked { vault, .. } => Some((vault.wallet_id(), vault.state().clone())),
            Slot::Locked => None,
        }
    }

    /// Merges a received copy (encrypted under the wallet's current key) into the unlocked
    /// wallet and saves before returning; on a save failure nothing changes. Locked:
    /// `WalletLocked` (the caller keeps the copy pending). Serialized with key derivations
    /// so peak memory stays within the 002 budget. Never touches the idle timer.
    pub fn merge_copy(
        &self,
        name: &WalletName,
        bytes: &[u8],
        check: &dyn Fn(&CopyFacts) -> CopyVerdict,
    ) -> Result<MergeReport, ServiceError> {
        let slot = self.slot(name)?;
        let _gate = lock(&self.kdf_gate);
        let mut storage = self.dir.storage(name);
        let mut state = lock(&slot.state);
        let Slot::Unlocked { vault, .. } = &mut *state else {
            return Err(ServiceError::WalletLocked);
        };
        if vault
            .needs_password(bytes)
            .map_err(|_| ServiceError::CopyRejected)?
        {
            return Err(ServiceError::CannotOpenCopy);
        }
        let copy = vault
            .open_copy_own_key(bytes)
            .map_err(|_| ServiceError::CannotOpenCopy)?;
        let facts = CopyFacts {
            wallet_id: copy.wallet_id(),
            state: copy.state().clone(),
            password_epoch: copy.password_epoch().compare(vault.password_epoch()).into(),
        };
        if check(&facts) == CopyVerdict::Reject {
            return Err(ServiceError::CopyRejected);
        }
        vault.merge_saved(copy, storage.as_mut()).map_err(map_merge)
    }
}
