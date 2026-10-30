#![forbid(unsafe_code)]
//! Wallet sharing (US6; contracts/ffi-api.md section 5, FR-051, FR-052): invitations and
//! received wallets over the shared `ShareRuntime`, exactly as 005.

use device_link::code::normalize_code;
use host_runtime::hex;
use host_runtime::share_runtime::ShareError;
use host_runtime::sync_runtime::device;
use wallet_sync::share::{NoticeKind, RECEIVED_RETENTION_SECS};

use crate::api::{Inner, PasswsyncCore, wallet};
use crate::error::CoreError;
use crate::network::{device_id, device_view};
use crate::records::{CoreEvent, InvitationState, InvitationView, ReceivedView};
use crate::secret::SecretInput;

fn share_error(error: ShareError) -> CoreError {
    let reason = |reason: &'static str| CoreError::Share { reason };
    match error {
        ShareError::NetworkingOff => CoreError::NetworkOff,
        ShareError::WalletNotFound => CoreError::WalletNotFound,
        ShareError::WalletLocked => CoreError::WalletLocked,
        ShareError::NotEligible(word) => reason(word),
        ShareError::LockedCancelled => reason("wallet_locked_cancelled"),
        ShareError::DeviceNotFound => reason("device_not_found"),
        ShareError::PeerUnsupported => reason("peer_unsupported"),
        ShareError::Busy => CoreError::Busy,
        ShareError::TooManyInvitations => reason("too_many_invitations"),
        ShareError::NothingPending => reason("nothing_pending"),
        ShareError::Mismatch => reason("mismatch"),
        ShareError::Expired => reason("expired"),
        ShareError::SenderError => reason("sender_error"),
        ShareError::SelfDevice => reason("self"),
        ShareError::ReceivedLimit => reason("received_limit"),
        ShareError::ReceivedNotFound => reason("received_not_found"),
        ShareError::AlreadyPresent(_) => CoreError::AlreadyPresent,
        ShareError::Service(error) => error.into(),
        ShareError::Internal => CoreError::Internal,
    }
}

fn invitation_state(word: &str) -> InvitationState {
    match word {
        "active" => InvitationState::Active,
        "awaiting_acceptance" => InvitationState::AwaitingAcceptance,
        "transferring" => InvitationState::Transferring,
        "completed" => InvitationState::Completed,
        "expired" => InvitationState::Expired,
        // rejected | refused | failed | cancelled: the invitation is over.
        _ => InvitationState::Cancelled,
    }
}

/// A received wallet id as 32 lowercase hex digits.
fn received_id(text: &str) -> Result<[u8; 16], CoreError> {
    let not_found = || CoreError::Share {
        reason: "received_not_found",
    };
    if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(not_found());
    }
    let mut out = [0u8; 16];
    for (slot, i) in out.iter_mut().zip((0..32).step_by(2)) {
        *slot = u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| not_found())?;
    }
    Ok(out)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Inner {
    /// Leaving the foreground ends an invitation whose transfer has not started and a
    /// redemption that is not receiving (FR-051).
    pub(crate) fn cancel_unstarted_shares(&self) {
        let share = &self.host.share;
        let view = share.core().engine().view();
        if view
            .invitation
            .as_ref()
            .is_some_and(|i| matches!(i.state, "active" | "awaiting_acceptance"))
        {
            let _ = share.cancel();
        }
        if view
            .receive
            .as_ref()
            .is_some_and(|r| matches!(r.state, "connecting" | "awaiting_sender"))
        {
            share.cancel_redemption();
        }
    }
}

impl Inner {
    /// 005: received wallets unopened for 24 h are deleted (at start and at each window) and
    /// reported once (`ReceivedExpired`; the notice is dismissed once reported).
    pub(crate) fn sweep_received(&self) {
        self.host.share.tick();
        let expired: Vec<u64> = self
            .host
            .share
            .core()
            .engine()
            .view()
            .notices
            .iter()
            .filter(|n| matches!(n.kind, NoticeKind::ReceivedExpired { .. }))
            .map(|n| n.id)
            .collect();
        if !expired.is_empty() {
            self.host.share.dismiss(&expired);
            self.notify(CoreEvent::ReceivedExpired);
        }
    }

    fn invitation_view(&self) -> Option<InvitationView> {
        let view = self.host.share.core().engine().view().invitation?;
        let recipient = device(view.recipient);
        Some(InvitationView {
            code: view
                .code
                .as_ref()
                .map(|c| c.as_str().to_owned())
                .unwrap_or_default(),
            recipient: device_view(&recipient, self.peer_name(&recipient).as_deref()),
            expires_in_ms: view.expires_in.saturating_mul(1000),
            state: invitation_state(view.state),
        })
    }
}

#[uniffi::export]
impl PasswsyncCore {
    /// Invites the paired device `recipient_id` to receive the unlocked wallet (005); the
    /// code is shown here only.
    pub fn create_invitation(
        &self,
        wallet_name: String,
        recipient_id: String,
    ) -> Result<InvitationView, CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        core.housekeep();
        let name = wallet(&wallet_name)?;
        let recipient = device_id(&recipient_id).map_err(|_| CoreError::Share {
            reason: "device_not_found",
        })?;
        core.host
            .share
            .create(&name, &recipient)
            .map_err(share_error)?;
        core.touch(&name);
        core.notify(CoreEvent::ShareChanged);
        core.invitation_view().ok_or(CoreError::Internal)
    }

    /// The sender confirms the recipient (name and fingerprint compared) and the transfer starts.
    pub fn accept_recipient(&self, recipient_id: String) -> Result<(), CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        let recipient = device_id(&recipient_id).map_err(|_| CoreError::Share {
            reason: "device_not_found",
        })?;
        core.host.share.accept(&recipient).map_err(share_error)?;
        core.notify(CoreEvent::ShareChanged);
        Ok(())
    }

    /// Ends the invitation (or refuses the waiting recipient).
    pub fn cancel_invitation(&self) {
        let _ = self.inner.host.share.cancel();
        self.inner.notify(CoreEvent::ShareChanged);
    }

    /// The current invitation, if any.
    pub fn invitation(&self) -> Option<InvitationView> {
        self.inner.invitation_view()
    }

    /// Redeems the code the paired device `sender_id` shows (005 recipient).
    pub fn redeem_invitation(&self, sender_id: String, code: Vec<u8>) -> Result<(), CoreError> {
        let code = SecretInput::try_from(code)?;
        let core = &self.inner;
        core.require_foreground()?;
        let digits = normalize_code(code.as_str()).map_err(|_| CoreError::Share {
            reason: "invalid_code",
        })?;
        drop(code);
        let sender = device_id(&sender_id).map_err(|_| CoreError::Share {
            reason: "device_not_found",
        })?;
        core.host
            .share
            .redeem(digits, Some(sender), None)
            .map_err(share_error)?;
        core.notify(CoreEvent::ShareChanged);
        Ok(())
    }

    /// Received wallets not opened yet (ciphertext; deleted after 24 h).
    pub fn received(&self) -> Vec<ReceivedView> {
        let core = &self.inner;
        let share = &core.host.share;
        if share.received_unusable() {
            return Vec::new();
        }
        let now = unix_now();
        share
            .core()
            .received
            .list_report()
            .map(|(entries, _)| entries)
            .unwrap_or_default()
            .into_iter()
            .map(|meta| {
                let from = device(meta.sender);
                let left = (meta.received_at + RECEIVED_RETENTION_SECS).saturating_sub(now);
                ReceivedView {
                    id: hex::encode(&meta.id),
                    from: device_view(&from, core.peer_name(&from).as_deref()),
                    received_at: i64::try_from(meta.received_at).unwrap_or(i64::MAX),
                    expires_in_ms: left.saturating_mul(1000),
                }
            })
            .collect()
    }

    /// Opens a received wallet with its master password under `local_name`; it then syncs like
    /// any wallet.
    pub fn open_received(
        &self,
        id: String,
        local_name: String,
        password: Vec<u8>,
    ) -> Result<(), CoreError> {
        let password = SecretInput::try_from(password)?;
        let core = &self.inner;
        core.require_protections()?;
        core.housekeep();
        let id = received_id(&id)?;
        let name = core
            .host
            .share
            .open(id, &local_name, password.into_zeroizing())
            .map_err(share_error)?;
        core.touch(&name);
        core.notify(CoreEvent::WalletsChanged);
        core.notify(CoreEvent::ShareChanged);
        Ok(())
    }

    /// Deletes a received wallet without opening it.
    pub fn discard_received(&self, id: String) -> Result<(), CoreError> {
        let core = &self.inner;
        core.host
            .share
            .discard(received_id(&id)?)
            .map_err(share_error)?;
        core.notify(CoreEvent::ShareChanged);
        Ok(())
    }
}

#[cfg(feature = "testkit")]
impl PasswsyncCore {
    /// Test hook: moves the share engine's clocks forward (24 h expiry).
    pub fn advance_share_clock(&self, by: std::time::Duration) {
        self.inner.host.share.advance_clock(by);
    }
}
