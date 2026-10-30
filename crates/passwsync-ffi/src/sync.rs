#![forbid(unsafe_code)]
//! Sync status, conflicts and pending copies (US5; contracts/ffi-api.md section 5, FR-047,
//! FR-049) over the shared `SyncRuntime` and the wallet service, with the 004 shapes and the
//! 002 reveal and clipboard rules of the desktop. No view carries a password.

use device_link::identity::DeviceId;
use host_runtime::sync_runtime::device;
use vault_core::{PasswordChoice, Resolution};
use wallet_service::{Field, PeerRef, WalletName};

use crate::api::{Inner, PasswsyncCore, wallet};
use crate::error::CoreError;
use crate::network::{device_id, device_view};
use crate::records::{
    ConflictChoice, ConflictVersionView, ConflictView, CopyField, CopyTicket, CoreEvent,
    PasswordChoiceKind, PeerSyncView, PendingCopyView, PendingStatus, RevealTicket, SyncView,
    WalletSyncState, WalletSyncView,
};
use crate::secret::SecretInput;

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// `wallet_sync::status::WalletSyncState` with its fixed reason tokens.
pub(crate) fn sync_state(state: wallet_sync::status::WalletSyncState) -> WalletSyncState {
    use wallet_sync::status::WalletSyncState as S;
    let reason = state.reason().unwrap_or("").to_owned();
    match state {
        S::SyncOff => WalletSyncState::SyncOff,
        S::Disabled(_) => WalletSyncState::Disabled { reason },
        S::PossibleRollback => WalletSyncState::PossibleRollback,
        S::Conflicts(count) => WalletSyncState::Conflicts { count },
        S::ChangesWaiting => WalletSyncState::ChangesWaiting,
        S::Syncing => WalletSyncState::Syncing,
        S::SyncError => WalletSyncState::SyncError,
        S::NotSynced(_) => WalletSyncState::NotSynced { reason },
        S::InSync => WalletSyncState::InSync,
    }
}

fn peer_ref(id: &DeviceId) -> PeerRef {
    PeerRef(*id.as_bytes())
}

impl Inner {
    /// The sync state of one wallet; never touches an idle timer.
    pub(crate) fn wallet_sync(&self, name: &WalletName) -> (WalletSyncState, u32, Option<u64>) {
        let conflicts = self.host.service.conflict_count(name).unwrap_or(0);
        let (state, last, _) = self.host.sync.wallet_status(name, conflicts);
        (sync_state(state), conflicts, last)
    }
}

#[uniffi::export]
impl PasswsyncCore {
    /// Per wallet and per paired device (004 `GET /api/sync`).
    pub fn sync_status(&self) -> SyncView {
        let core = &self.inner;
        let wallets = core
            .host
            .service
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|status| {
                let (state, conflicts, last) = core.wallet_sync(&status.name);
                WalletSyncView {
                    wallet: status.name.as_str().to_owned(),
                    state,
                    conflicts,
                    last_synced_at: last.map(as_i64),
                }
            })
            .collect();
        let peers = core
            .snapshot()
            .paired
            .iter()
            .map(|p| PeerSyncView {
                device: device_view(&p.id, Some(p.name.as_str())),
                state: if core.host.net.is_legacy(&p.id) {
                    "unsupported"
                } else {
                    "supported"
                }
                .to_owned(),
                last_synced_at: core.host.sync.peer_round(&p.id).0.map(as_i64),
            })
            .collect();
        SyncView {
            wallets,
            peers,
            running: !core.host.sync.running().is_empty(),
        }
    }

    /// A round with every connected device now (foreground only).
    pub fn sync_now(&self) -> Result<(), CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        if core.host.sync.sync_now() {
            core.notify(CoreEvent::SyncChanged);
            Ok(())
        } else {
            Err(CoreError::NetworkOff)
        }
    }

    /// The conflicted credentials of an unlocked wallet (no password).
    pub fn conflicts(&self, name: String) -> Result<Vec<ConflictView>, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let list = core.host.service.conflicts(&name)?;
        core.touch(&name);
        Ok(list
            .into_iter()
            .map(|c| ConflictView {
                id: c.id.to_string(),
                title: c.title.as_str().to_owned(),
                versions: u32::try_from(c.versions).unwrap_or(u32::MAX),
            })
            .collect())
    }

    /// Every version of one conflicted credential (no password).
    pub fn conflict_versions(
        &self,
        name: String,
        id: String,
    ) -> Result<Vec<ConflictVersionView>, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let list = core
            .host
            .service
            .conflict_versions(&name, crate::api::entry_id(&id)?)?;
        core.touch(&name);
        let text = |t: &Option<zeroize::Zeroizing<String>>| {
            t.as_ref()
                .map(|v| v.as_str().to_owned())
                .unwrap_or_default()
        };
        Ok(list
            .iter()
            .map(|v| ConflictVersionView {
                index: u32::try_from(v.index).unwrap_or(u32::MAX),
                deleted: v.deleted,
                title: text(&v.title),
                username: text(&v.username),
                url: text(&v.url),
                notes: text(&v.notes),
                modified_at: v.modified_at,
                device: if v.this_device {
                    "this device"
                } else {
                    "unknown device"
                }
                .to_owned(),
            })
            .collect())
    }

    /// One version's password, hidden again after the clipboard timeout (desktop parity).
    pub fn reveal_conflict_password(
        &self,
        name: String,
        id: String,
        index: u32,
    ) -> Result<RevealTicket, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let id = crate::api::entry_id(&id)?;
        let value = core
            .host
            .service
            .conflict_field(&name, id, index as usize, Field::Password)?;
        core.touch(&name);
        Ok(core.reveal(&name, id, value))
    }

    /// Copies one version's field to the clipboard with the 002 rules.
    pub fn copy_conflict_field(
        &self,
        name: String,
        id: String,
        index: u32,
        field: CopyField,
    ) -> Result<CopyTicket, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let field = match field {
            CopyField::Username => Field::Username,
            CopyField::Password => Field::Password,
        };
        let value = core.host.service.conflict_field(
            &name,
            crate::api::entry_id(&id)?,
            index as usize,
            field,
        )?;
        core.touch(&name);
        core.copy(&name, value)
    }

    /// Keeps one version, or the current one plus every other version as new credentials.
    pub fn resolve_conflict(
        &self,
        name: String,
        id: String,
        choice: ConflictChoice,
    ) -> Result<(), CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let how = match choice {
            ConflictChoice::Keep { index } => Resolution::Keep(index as usize),
            ConflictChoice::Both => Resolution::KeepBoth,
        };
        core.host
            .service
            .resolve_conflict(&name, crate::api::entry_id(&id)?, how)?;
        core.touch(&name);
        core.notify(CoreEvent::WalletsChanged);
        Ok(())
    }

    /// Received copies of `name` waiting for an unlock or a password (004 pending list).
    pub fn pending_copies(&self, name: String) -> Result<Vec<PendingCopyView>, CoreError> {
        let core = &self.inner;
        let name = wallet(&name)?;
        let Some(record) = core.host.sync.record_of(&name) else {
            return Ok(Vec::new());
        };
        Ok(record
            .pending
            .iter()
            .map(|(peer, copy)| {
                let id = device(*peer);
                PendingCopyView {
                    peer: device_view(&id, core.peer_name(&id).as_deref()),
                    received_at: as_i64(copy.received_at),
                    status: match copy.status {
                        wallet_sync::record::PendingStatus::Waiting => PendingStatus::Waiting,
                        wallet_sync::record::PendingStatus::CannotOpen => PendingStatus::CannotOpen,
                        wallet_sync::record::PendingStatus::PasswordConflict => {
                            PendingStatus::PasswordConflict
                        }
                        wallet_sync::record::PendingStatus::TooManyConflicts => {
                            PendingStatus::TooManyConflicts
                        }
                    },
                }
            })
            .collect())
    }

    /// Opens a copy made under another master password with that password and merges it.
    pub fn open_pending_with_password(
        &self,
        name: String,
        peer_id: String,
        password: Vec<u8>,
    ) -> Result<(), CoreError> {
        let password = SecretInput::try_from(password)?;
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let peer = device_id(&peer_id).map_err(|_| CoreError::EntryNotFound)?;
        core.host.service.open_pending_with_password(
            &name,
            &peer_ref(&peer),
            password.into_zeroizing(),
        )?;
        core.touch(&name);
        core.notify(CoreEvent::WalletsChanged);
        Ok(())
    }

    /// Concurrent password changes: keeps the local or the copy's password. `password` opens
    /// the copy (it is the copy's password), as on the desktop.
    pub fn resolve_password_choice(
        &self,
        name: String,
        peer_id: String,
        choice: PasswordChoiceKind,
        password: Vec<u8>,
    ) -> Result<(), CoreError> {
        let password = SecretInput::try_from(password)?;
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let peer = device_id(&peer_id).map_err(|_| CoreError::EntryNotFound)?;
        let keep = match choice {
            PasswordChoiceKind::Local => PasswordChoice::Local,
            PasswordChoiceKind::Copy => PasswordChoice::Copy,
        };
        core.host.service.choose_password(
            &name,
            &peer_ref(&peer),
            keep,
            password.into_zeroizing(),
        )?;
        core.touch(&name);
        core.notify(CoreEvent::WalletsChanged);
        Ok(())
    }
}
