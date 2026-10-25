//! Received wallets (005 data-model.md "ReceivedWallet", research R9): the port lives in
//! [`crate::ports`]; the rules (limit, retention, revocation) are applied by the share engine.

pub use crate::ports::{ReceivedMeta, ReceivedStore};

use super::{
    DeleteCause, MAX_RECEIVED, NoticeKind, RECEIVED_FUTURE_SLACK_SECS, RECEIVED_RETENTION_SECS,
    ShareEngine, ShareEvent,
};
use crate::ports::{PeerId, StoreError};

/// Why a received wallet could not be discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscardError {
    NotFound,
    Storage,
}

impl ShareEngine {
    /// Whether another received wallet fits (FR-018).
    pub(crate) fn received_room(&self) -> Result<bool, StoreError> {
        self.received.list().map(|l| l.len() < MAX_RECEIVED)
    }

    /// The person discards a received wallet: its ciphertext is deleted. Returns its sender.
    pub fn discard(&mut self, id: [u8; 16]) -> Result<PeerId, DiscardError> {
        let meta = self
            .received
            .list()
            .map_err(|_| DiscardError::Storage)?
            .into_iter()
            .find(|m| m.id == id)
            .ok_or(DiscardError::NotFound)?;
        match self.received.delete(id) {
            Ok(()) => Ok(meta.sender),
            Err(StoreError::NotFound) => Err(DiscardError::NotFound),
            Err(_) => Err(DiscardError::Storage),
        }
    }

    /// Received-wallet retention on the sweeper tick: deleted 24 hours after receipt, or when
    /// the receipt time lies more than 5 minutes in the future (clock moved back).
    pub(crate) fn received_tick(&mut self) {
        let now = self.wall.unix_now();
        let Ok(list) = self.received.list() else {
            return;
        };
        for meta in list {
            let expired = meta.received_at.saturating_add(RECEIVED_RETENTION_SECS) <= now
                || meta.received_at > now.saturating_add(RECEIVED_FUTURE_SLACK_SECS);
            if expired && self.received.delete(meta.id).is_ok() {
                self.events.push(ShareEvent::ReceivedDeleted {
                    sender: meta.sender,
                    why: DeleteCause::Expired,
                });
                self.push_notice(NoticeKind::ReceivedExpired {
                    sender: meta.sender,
                });
            }
        }
    }

    /// A sender was revoked: its received wallets are deleted (FR-023).
    pub(crate) fn received_peer_revoked(&mut self, peer: PeerId) {
        let Ok(list) = self.received.list() else {
            return;
        };
        let mut deleted = false;
        for meta in list.into_iter().filter(|m| m.sender == peer) {
            if self.received.delete(meta.id).is_ok() {
                deleted = true;
                self.events.push(ShareEvent::ReceivedDeleted {
                    sender: peer,
                    why: DeleteCause::Revoked,
                });
            }
        }
        if deleted {
            self.push_notice(NoticeKind::ReceivedDeletedRevoked { sender: peer });
        }
    }
}
