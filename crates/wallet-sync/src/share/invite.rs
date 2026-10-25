//! The sender's invitation (005 data-model.md "Invitation", contracts/share-protocol.md
//! "Exchange"): creation and eligibility, redemption check, acceptance and the transfer of the
//! stored encrypted file (reusing the 004 whole-file sender, which re-hashes the file against
//! its sync-record digest).

use std::time::Duration;

use zeroize::Zeroizing;

use super::codec::{AbortReason, MAX_SECONDS_LEFT, ShareMsg};
use super::proof::verify_proof;
use super::{
    AcceptError, CancelOutcome, CreateError, Failure, INVITE_VALIDITY, Ineligible, InvitationEnd,
    InvitationView, InviteWallet, MAX_INVITATIONS, MAX_TRANSFER, OutFrame, PROGRESS_TIMEOUT,
    RATE_WINDOW, RESULT_RETENTION, Refusal, RejectError, ShareEngine, ShareEvent, secs_until,
};
use crate::codec::{MAX_COPY, MIN_COPY};
use crate::ports::PeerId;
use crate::record::SyncRecord;
use crate::transfer::{ServeStep, Serving};

/// Why an invitation was cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelCause {
    ByPerson,
    WalletLocked,
    RecipientRevoked,
    Replaced,
}

impl CancelCause {
    fn word(self) -> &'static str {
        match self {
            Self::ByPerson => "by_person",
            Self::WalletLocked => "wallet_locked",
            Self::RecipientRevoked => "recipient_revoked",
            Self::Replaced => "replaced",
        }
    }

    fn end(self) -> InvitationEnd {
        match self {
            Self::ByPerson => InvitationEnd::Cancelled,
            Self::WalletLocked => InvitationEnd::Locked,
            Self::RecipientRevoked => InvitationEnd::Revoked,
            Self::Replaced => InvitationEnd::Replaced,
        }
    }
}

/// Why a redemption was refused (the invitation is consumed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseCause {
    WrongCode,
    NotRecipient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvState {
    Active,
    AwaitingAcceptance,
    Transferring,
    Completed,
    Cancelled(CancelCause),
    Expired,
    Rejected,
    Refused(RefuseCause),
    Failed(Failure),
}

impl InvState {
    fn terminal(self) -> bool {
        !matches!(
            self,
            Self::Active | Self::AwaitingAcceptance | Self::Transferring
        )
    }

    fn word(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::AwaitingAcceptance => "awaiting_acceptance",
            Self::Transferring => "transferring",
            Self::Completed => "completed",
            Self::Cancelled(_) => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Refused(_) => "refused",
            Self::Failed(_) => "failed",
        }
    }

    fn reason(self) -> Option<&'static str> {
        match self {
            Self::Cancelled(cause) => Some(cause.word()),
            Self::Rejected => Some("by_person"),
            Self::Refused(RefuseCause::WrongCode) => Some("wrong_code"),
            Self::Refused(RefuseCause::NotRecipient) => Some("not_recipient"),
            Self::Failed(failure) => Some(failure.word()),
            _ => None,
        }
    }
}

/// What a late `Redeem` from the recipient is told after the invitation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TombReason {
    Cancelled,
    Expired,
    Used,
}

/// A code-less, name-less trace of an ended invitation (data-model.md "Tombstone").
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tombstone {
    pub recipient: PeerId,
    pub reason: TombReason,
    pub until: Duration,
}

pub(crate) struct Invitation {
    pub wallet: InviteWallet,
    pub recipient: PeerId,
    pub code: Option<Zeroizing<String>>,
    pub expires: Duration,
    pub state: InvState,
    /// `(conn, rid)` once redeemed.
    pub exchange: Option<(u64, u32)>,
    pub serving: Option<Serving>,
    pub size: u64,
    pub sent: u64,
    pub last_progress: Duration,
    pub transfer_started: Duration,
    /// When `End` was queued (the recipient then has 30 s to answer `Stored`).
    pub end_sent: Option<Duration>,
    pub ended_at: Option<Duration>,
}

impl ShareEngine {
    /// Checks the wallet's sync record and file (FR-002).
    fn eligibility(&self, wallet: &InviteWallet) -> Result<SyncRecord, Ineligible> {
        if wallet.format != 2 {
            return Err(Ineligible::FormatV1);
        }
        let record = match self.store.load(&wallet.id) {
            Ok(Some(record)) if record.wallet_name == wallet.name => record,
            _ => return Err(Ineligible::NoRecord),
        };
        if record.flags.disabled() {
            return Err(Ineligible::Disabled);
        }
        if record.flags.possible_rollback() {
            return Err(Ineligible::PossibleRollback);
        }
        match self.source.digest(&wallet.name) {
            Ok(Some(digest)) if digest == record.digest => Ok(record),
            Ok(Some(_)) => Err(Ineligible::Changed),
            _ => Err(Ineligible::NoRecord),
        }
    }

    /// Creates the device's invitation for `wallet` (unlocked, checked by the host) and
    /// `recipient` (a pinned device), holding `code` until the first `Redeem`.
    pub fn create(
        &mut self,
        wallet: InviteWallet,
        recipient: PeerId,
        code: Zeroizing<String>,
    ) -> Result<(), CreateError> {
        let now = self.mono.now();
        self.expire_invitation(now);
        if self
            .invitation
            .as_ref()
            .is_some_and(|inv| inv.state == InvState::Transferring)
        {
            return Err(CreateError::Busy);
        }
        self.eligibility(&wallet).map_err(CreateError::Ineligible)?;
        while self
            .created
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= RATE_WINDOW)
        {
            self.created.pop_front();
        }
        if self.created.len() >= MAX_INVITATIONS {
            return Err(CreateError::TooMany);
        }
        self.created.push_back(now);
        // A new invitation replaces the previous one and drops any tombstone.
        self.end_invitation(
            InvState::Cancelled(CancelCause::Replaced),
            Some(AbortReason::Cancelled),
        );
        self.tombstone = None;
        self.invitation = Some(Invitation {
            wallet,
            recipient,
            code: Some(code),
            expires: now + INVITE_VALIDITY,
            state: InvState::Active,
            exchange: None,
            serving: None,
            size: 0,
            sent: 0,
            last_progress: now,
            transfer_started: now,
            end_sent: None,
            ended_at: None,
        });
        self.events
            .push(ShareEvent::InvitationCreated { recipient });
        Ok(())
    }

    /// Ends the invitation in `state` (terminal): wipes the code, stops a transfer, sends
    /// `abort` on its exchange if given, and logs.
    pub(crate) fn end_invitation(&mut self, state: InvState, abort: Option<AbortReason>) {
        let now = self.mono.now();
        let Some(inv) = self.invitation.as_mut() else {
            return;
        };
        if inv.state.terminal() {
            return;
        }
        inv.state = state;
        inv.code = None;
        inv.serving = None;
        inv.ended_at = Some(now);
        let (recipient, exchange, sent) = (inv.recipient, inv.exchange, inv.sent);
        let was_transferring = inv.size > 0;
        let tomb = match state {
            InvState::Cancelled(_) => TombReason::Cancelled,
            InvState::Expired => TombReason::Expired,
            _ => TombReason::Used,
        };
        // Until the original expiry; an expiry itself is remembered for the result period
        // so a late `Redeem` still learns "expired".
        let until = if tomb == TombReason::Expired {
            inv.expires.max(now + RESULT_RETENTION)
        } else {
            inv.expires
        };
        self.tombstone = Some(Tombstone {
            recipient,
            reason: tomb,
            until,
        });
        if let Some((conn, rid)) = exchange {
            if let Some(reason) = abort {
                self.abort_to(recipient, rid, reason);
            }
            self.end_exchange(recipient, conn, rid);
        }
        let end = match state {
            InvState::Cancelled(cause) => cause.end(),
            InvState::Expired => InvitationEnd::Expired,
            InvState::Rejected => InvitationEnd::Rejected,
            InvState::Completed => InvitationEnd::Completed,
            _ => InvitationEnd::Failed,
        };
        if was_transferring && state != InvState::Completed {
            let reason = match state {
                InvState::Failed(failure) => failure,
                InvState::Cancelled(_) => Failure::CancelledBySender,
                _ => Failure::ChannelLost,
            };
            self.events.push(ShareEvent::TransferAborted {
                peer: recipient,
                reason,
                bytes: sent,
            });
        }
        self.events.push(ShareEvent::InvitationEnded { end });
    }

    /// Ends an `Active` or `AwaitingAcceptance` invitation whose time is up.
    pub(crate) fn expire_invitation(&mut self, now: Duration) {
        let due = self.invitation.as_ref().is_some_and(|inv| {
            matches!(inv.state, InvState::Active | InvState::AwaitingAcceptance)
                && now >= inv.expires
        });
        if due {
            self.end_invitation(InvState::Expired, Some(AbortReason::Expired));
        }
    }

    /// A `Redeem` from `peer`; returns whether it was understood (false: protocol error).
    pub(crate) fn on_redeem(
        &mut self,
        peer: PeerId,
        conn: u64,
        rid: u32,
        proof: &[u8; 32],
    ) -> bool {
        let Some(link) = self.links.get_mut(&peer) else {
            return true;
        };
        if link.active_rid.is_some() {
            return false; // one exchange per channel at a time
        }
        link.exchanges += 1;
        if link.exchanges > super::MAX_EXCHANGES_PER_CHANNEL {
            return false; // a Redeem flood
        }
        link.active_rid = Some(rid);
        let session = link.session;
        let now = self.mono.now();
        self.expire_invitation(now);
        let active = self
            .invitation
            .as_ref()
            .is_some_and(|inv| inv.state == InvState::Active);
        if !active {
            self.refuse_without_invitation(peer, conn, rid);
            return true;
        }
        let Some(inv) = self.invitation.as_mut() else {
            return true;
        };
        let refusal = if peer != inv.recipient {
            Some(RefuseCause::NotRecipient)
        } else {
            let code = inv.code.as_deref().map_or("", String::as_str);
            (!verify_proof(code, &session, &self.own_id, &peer, rid, proof))
                .then_some(RefuseCause::WrongCode)
        };
        if let Some(cause) = refusal {
            self.abort_to(peer, rid, AbortReason::Invalid);
            self.end_exchange(peer, conn, rid);
            self.end_invitation(InvState::Refused(cause), None);
            self.events.push(ShareEvent::RedeemRefused {
                peer,
                why: match cause {
                    RefuseCause::WrongCode => Refusal::WrongCode,
                    RefuseCause::NotRecipient => Refusal::NotRecipient,
                },
            });
            return true;
        }
        inv.code = None; // single attempt: the code is never needed again
        inv.state = InvState::AwaitingAcceptance;
        inv.exchange = Some((conn, rid));
        let seconds_left = secs_until(inv.expires, now).clamp(1, u64::from(MAX_SECONDS_LEFT));
        let seconds_left = u16::try_from(seconds_left).unwrap_or(MAX_SECONDS_LEFT);
        self.queue(peer, OutFrame::Msg(ShareMsg::Pending { rid, seconds_left }));
        self.events.push(ShareEvent::Redeemed { peer });
        true
    }

    /// No active invitation: the recipient of an ended one learns why; anyone else gets
    /// `invalid`.
    fn refuse_without_invitation(&mut self, peer: PeerId, conn: u64, rid: u32) {
        let now = self.mono.now();
        let tomb = self
            .tombstone
            .filter(|t| t.recipient == peer && now < t.until);
        let (reason, why) = match tomb.map(|t| t.reason) {
            Some(TombReason::Cancelled) => (AbortReason::Cancelled, Refusal::Cancelled),
            Some(TombReason::Expired) => (AbortReason::Expired, Refusal::Expired),
            Some(TombReason::Used) => (AbortReason::Invalid, Refusal::Used),
            None => {
                let busy = self
                    .invitation
                    .as_ref()
                    .is_some_and(|inv| !inv.state.terminal() && inv.recipient == peer);
                if busy {
                    (AbortReason::Invalid, Refusal::Used)
                } else {
                    (AbortReason::Invalid, Refusal::NoInvitation)
                }
            }
        };
        self.abort_to(peer, rid, reason);
        self.end_exchange(peer, conn, rid);
        self.events.push(ShareEvent::RedeemRefused { peer, why });
    }

    /// The person accepted on the sender: re-checks expiry, the wallet and a free transfer
    /// slot, then sends `Offer` (the start of the transfer, FR-005, FR-009a).
    pub fn accept(
        &mut self,
        recipient: PeerId,
        eligible: &dyn Fn(&str) -> bool,
    ) -> Result<(), AcceptError> {
        let now = self.mono.now();
        let Some(inv) = self.invitation.as_ref() else {
            return Err(AcceptError::NothingPending);
        };
        match inv.state {
            InvState::AwaitingAcceptance => {}
            InvState::Expired => return Err(AcceptError::Expired),
            _ => return Err(AcceptError::NothingPending),
        }
        if inv.recipient != recipient {
            return Err(AcceptError::Mismatch);
        }
        if now >= inv.expires {
            self.end_invitation(InvState::Expired, Some(AbortReason::Expired));
            return Err(AcceptError::Expired);
        }
        let wallet = inv.wallet.clone();
        if !eligible(&wallet.name) {
            self.end_invitation(
                InvState::Cancelled(CancelCause::WalletLocked),
                Some(AbortReason::Cancelled),
            );
            return Err(AcceptError::WalletLocked);
        }
        let Ok(record) = self.eligibility(&wallet) else {
            self.end_invitation(
                InvState::Cancelled(CancelCause::WalletLocked),
                Some(AbortReason::Cancelled),
            );
            return Err(AcceptError::WalletLocked);
        };
        let Some(guard) = self.slots.try_take() else {
            self.end_invitation(InvState::Failed(Failure::Busy), Some(AbortReason::Busy));
            return Err(AcceptError::Busy);
        };
        let opened = self.source.open(&wallet.name).ok().filter(|(size, _)| {
            u32::try_from(*size).is_ok_and(|s| (MIN_COPY..=MAX_COPY).contains(&s))
        });
        let Some((size, reader)) = opened else {
            self.end_invitation(
                InvState::Failed(Failure::SenderError),
                Some(AbortReason::SenderError),
            );
            return Err(AcceptError::SenderError);
        };
        let Some(inv) = self.invitation.as_mut() else {
            return Err(AcceptError::NothingPending);
        };
        let Some((_, rid)) = inv.exchange else {
            return Err(AcceptError::NothingPending);
        };
        inv.state = InvState::Transferring;
        inv.serving = Some(Serving::new(0, size, reader, record.digest).holding(guard));
        inv.size = size;
        inv.sent = 0;
        inv.last_progress = now;
        inv.transfer_started = now;
        let size32 = u32::try_from(size).unwrap_or(MAX_COPY);
        self.queue(
            recipient,
            OutFrame::Msg(ShareMsg::Offer { rid, size: size32 }),
        );
        self.events.push(ShareEvent::Accepted { peer: recipient });
        Ok(())
    }

    /// The person cancelled on the sender (FR-009): takes effect at once, also during the
    /// transfer (`Abort(cancelled)`). After completion nothing changes (US4.4).
    pub fn cancel(&mut self) -> CancelOutcome {
        match self.invitation.as_ref().map(|inv| inv.state) {
            Some(InvState::Active | InvState::AwaitingAcceptance | InvState::Transferring) => {
                self.end_invitation(
                    InvState::Cancelled(CancelCause::ByPerson),
                    Some(AbortReason::Cancelled),
                );
                CancelOutcome::Cancelled
            }
            Some(InvState::Completed) => CancelOutcome::AlreadyDelivered,
            _ => CancelOutcome::Nothing,
        }
    }

    /// The person rejected the waiting recipient.
    pub fn reject(&mut self) -> Result<(), RejectError> {
        let pending = self
            .invitation
            .as_ref()
            .is_some_and(|inv| inv.state == InvState::AwaitingAcceptance);
        if !pending {
            return Err(RejectError::NothingPending);
        }
        self.end_invitation(InvState::Rejected, Some(AbortReason::Rejected));
        Ok(())
    }

    /// A wallet was locked (any cause, FR-009a): an invitation for it whose transfer has not
    /// started is cancelled; a running transfer finishes from its snapshot.
    pub fn wallet_locked(&mut self, wallet: &str) {
        let ours = self.invitation.as_ref().is_some_and(|inv| {
            inv.wallet.name == wallet
                && matches!(inv.state, InvState::Active | InvState::AwaitingAcceptance)
        });
        if ours {
            self.end_invitation(
                InvState::Cancelled(CancelCause::WalletLocked),
                Some(AbortReason::Cancelled),
            );
        }
    }

    /// A device was revoked (003): an invitation for it is cancelled (a running transfer
    /// too) and an exchange with it ends.
    pub fn peer_revoked(&mut self, peer: PeerId) {
        let ours = self
            .invitation
            .as_ref()
            .is_some_and(|inv| inv.recipient == peer && !inv.state.terminal());
        if ours {
            self.end_invitation(InvState::Cancelled(CancelCause::RecipientRevoked), None);
        }
        if self.tombstone.is_some_and(|t| t.recipient == peer) {
            self.tombstone = None;
        }
        self.recipient_peer_revoked(peer);
        self.received_peer_revoked(peer);
    }

    /// Whether a transfer is being served to `peer` on `conn`.
    pub(crate) fn serving_to(&self, peer: &PeerId, conn: u64) -> bool {
        self.invitation.as_ref().is_some_and(|inv| {
            inv.recipient == *peer
                && inv.serving.is_some()
                && inv.exchange.is_some_and(|(c, _)| c == conn)
        })
    }

    /// Produces the next transfer frame for `peer` into `out`; false when nothing to serve.
    pub(crate) fn serve_next(&mut self, peer: PeerId, conn: u64, out: &mut Vec<OutFrame>) -> bool {
        if !self.serving_to(&peer, conn) {
            return false;
        }
        let now = self.mono.now();
        let Some(inv) = self.invitation.as_mut() else {
            return false;
        };
        let Some(serving) = inv.serving.as_mut() else {
            return false;
        };
        let rid = inv.exchange.map_or(0, |(_, rid)| rid);
        match serving.next() {
            ServeStep::Chunk(bytes) => {
                inv.sent += bytes.len() as u64;
                inv.last_progress = now;
                out.push(OutFrame::Data(bytes));
            }
            ServeStep::End => {
                inv.serving = None; // releases the transfer slot
                inv.end_sent = Some(now);
                inv.last_progress = now;
                out.push(OutFrame::Msg(ShareMsg::End { rid }));
            }
            ServeStep::Changed | ServeStep::ReadError => {
                self.end_invitation(
                    InvState::Failed(Failure::SenderError),
                    Some(AbortReason::SenderError),
                );
            }
        }
        true
    }

    /// `Stored` from the recipient; false when it matches nothing running.
    pub(crate) fn on_stored(&mut self, peer: PeerId, conn: u64, rid: u32) -> bool {
        let Some(inv) = self.invitation.as_ref() else {
            return false;
        };
        if inv.recipient != peer || inv.exchange != Some((conn, rid)) {
            return false;
        }
        if inv.state != InvState::Transferring || inv.end_sent.is_none() {
            return false;
        }
        let bytes = inv.sent;
        self.end_invitation(InvState::Completed, None);
        self.events
            .push(ShareEvent::TransferCompleted { peer, bytes });
        true
    }

    /// `Abort` from the recipient on the invitation's exchange; false when not ours.
    pub(crate) fn sender_abort(
        &mut self,
        peer: PeerId,
        conn: u64,
        rid: u32,
        reason: AbortReason,
    ) -> bool {
        let ours = self.invitation.as_ref().is_some_and(|inv| {
            inv.recipient == peer && inv.exchange == Some((conn, rid)) && !inv.state.terminal()
        });
        if !ours {
            return false;
        }
        let failure = match reason {
            AbortReason::Busy => Failure::Busy,
            AbortReason::Storage => Failure::Storage,
            AbortReason::TooLarge => Failure::TooLarge,
            AbortReason::ReceivedLimit => Failure::ReceivedLimit,
            _ => Failure::RecipientCancelled,
        };
        self.end_invitation(InvState::Failed(failure), None);
        true
    }

    /// The channel of the invitation's exchange closed.
    pub(crate) fn sender_channel_lost(&mut self, peer: PeerId, conn: u64) {
        let ours = self.invitation.as_ref().is_some_and(|inv| {
            inv.recipient == peer
                && inv.exchange.is_some_and(|(c, _)| c == conn)
                && !inv.state.terminal()
        });
        if ours {
            self.end_invitation(InvState::Failed(Failure::ChannelLost), None);
        }
    }

    pub(crate) fn sender_tick(&mut self, now: Duration) {
        self.expire_invitation(now);
        let timed_out = self.invitation.as_ref().is_some_and(|inv| {
            inv.state == InvState::Transferring
                && (now.saturating_sub(inv.last_progress) >= PROGRESS_TIMEOUT
                    || now.saturating_sub(inv.transfer_started) >= MAX_TRANSFER)
        });
        if timed_out {
            self.end_invitation(
                InvState::Failed(Failure::Timeout),
                Some(AbortReason::SenderError),
            );
        }
        if self.tombstone.is_some_and(|t| now >= t.until) {
            self.tombstone = None;
        }
        let stale = self.invitation.as_ref().is_some_and(|inv| {
            inv.state.terminal()
                && inv
                    .ended_at
                    .is_some_and(|at| now.saturating_sub(at) >= RESULT_RETENTION)
        });
        if stale {
            self.invitation = None;
        }
    }

    pub(crate) fn invitation_view(&self, now: Duration) -> Option<InvitationView> {
        let inv = self.invitation.as_ref()?;
        if inv.state.terminal()
            && inv
                .ended_at
                .is_some_and(|at| now.saturating_sub(at) >= RESULT_RETENTION)
        {
            return None;
        }
        // Expiry is applied lazily for display; the next step or tick records it.
        let state = match inv.state {
            InvState::Active | InvState::AwaitingAcceptance if now >= inv.expires => {
                InvState::Expired
            }
            other => other,
        };
        Some(InvitationView {
            state: state.word(),
            wallet: inv.wallet.name.clone(),
            recipient: inv.recipient,
            code: if state == InvState::Active {
                inv.code.clone()
            } else {
                None
            },
            expires_in: if state.terminal() || state == InvState::Transferring {
                0
            } else {
                secs_until(inv.expires, now)
            },
            progress: (state == InvState::Transferring).then_some((inv.sent, inv.size)),
            reason: state.reason(),
        })
    }
}
