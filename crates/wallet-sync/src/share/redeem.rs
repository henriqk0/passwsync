//! The recipient's redemption (005 data-model.md "Redemption", contracts/share-protocol.md
//! "Exchange", "Timeouts"): the code is turned into a session-bound proof and wiped at once;
//! the offered ciphertext streams into the `ReceivedStore` and is answered with `Stored` only
//! after the atomic store.

use std::time::Duration;

use zeroize::Zeroizing;

use super::codec::{AbortReason, ShareMsg};
use super::proof::redeem_proof;
use super::{
    ANSWER_TIMEOUT, CHANNEL_WAIT, Failure, MAX_RECEIVED, MAX_TRANSFER, OutFrame, PROGRESS_TIMEOUT,
    RESULT_RETENTION, ReceiveView, RedeemError, ShareEngine, ShareEvent, secs_until,
};
use crate::codec::{MAX_COPY, MIN_COPY};
use crate::ports::{IncomingCopy, PeerId};
use crate::slots::SlotGuard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecvState {
    Connecting,
    /// `Redeem` sent; `pending` once the sender answered `Pending`.
    AwaitingSender {
        pending: bool,
    },
    Receiving,
    Stored,
    Failed(Failure),
    Cancelled,
}

impl RecvState {
    pub(crate) fn terminal(self) -> bool {
        matches!(self, Self::Stored | Self::Failed(_) | Self::Cancelled)
    }

    fn word(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::AwaitingSender { .. } => "awaiting_sender",
            Self::Receiving => "receiving",
            Self::Stored => "stored",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

pub(crate) struct Redemption {
    pub sender: Option<PeerId>,
    pub code: Option<Zeroizing<String>>,
    pub state: RecvState,
    /// `(peer, conn, rid)` once `Redeem` was queued.
    pub exchange: Option<(PeerId, u64, u32)>,
    pub seconds_left: Option<u16>,
    /// Current waiting bound (connecting, answer, decision).
    pub deadline: Duration,
    pub size: u64,
    pub received: u64,
    pub writer: Option<Box<dyn IncomingCopy>>,
    pub slot: Option<SlotGuard>,
    pub last_progress: Duration,
    pub transfer_started: Duration,
    pub received_id: Option<[u8; 16]>,
    pub ended_at: Option<Duration>,
}

impl ShareEngine {
    /// Starts redeeming `code` from `sender` (from the paired list or a QR; `None` when only
    /// an address is known). The host then ensures a channel and calls
    /// [`sender_channel`](Self::sender_channel) or [`connect_failed`](Self::connect_failed).
    pub fn redeem(
        &mut self,
        sender: Option<PeerId>,
        code: Zeroizing<String>,
    ) -> Result<(), RedeemError> {
        if self
            .redemption
            .as_ref()
            .is_some_and(|r| !r.state.terminal())
        {
            return Err(RedeemError::Busy);
        }
        if !self.received_room().unwrap_or(false) {
            return Err(RedeemError::ReceivedLimit);
        }
        let now = self.mono.now();
        self.redemption = Some(Redemption {
            sender,
            code: Some(code),
            state: RecvState::Connecting,
            exchange: None,
            seconds_left: None,
            deadline: now + CHANNEL_WAIT,
            size: 0,
            received: 0,
            writer: None,
            slot: None,
            last_progress: now,
            transfer_started: now,
            received_id: None,
            ended_at: None,
        });
        Ok(())
    }

    /// The channel to the sender is up (`peer` as authenticated by it): sends `Redeem` with
    /// the session-bound proof and wipes the code.
    pub fn sender_channel(&mut self, peer: PeerId, conn: u64) {
        let now = self.mono.now();
        let Some(r) = self.redemption.as_ref() else {
            return;
        };
        if r.state != RecvState::Connecting {
            return;
        }
        if r.sender.is_some_and(|s| s != peer) {
            self.end_redemption(RecvState::Failed(Failure::IdMismatch), None);
            return;
        }
        let Some(session) = self.link_session(&peer, conn) else {
            self.end_redemption(RecvState::Failed(Failure::Unsupported), None);
            return;
        };
        if self
            .links
            .get(&peer)
            .is_some_and(|l| l.active_rid.is_some())
        {
            self.end_redemption(RecvState::Failed(Failure::Busy), None);
            return;
        }
        let rid = self.rng.next_u32();
        let own = self.own_id;
        let Some(r) = self.redemption.as_mut() else {
            return;
        };
        let proof = {
            let code = r.code.take().unwrap_or_default();
            redeem_proof(&code, &session, &peer, &own, rid)
            // `code` is wiped here (Zeroizing).
        };
        r.sender = Some(peer);
        r.exchange = Some((peer, conn, rid));
        r.state = RecvState::AwaitingSender { pending: false };
        r.deadline = now + ANSWER_TIMEOUT;
        if let Some(link) = self.links.get_mut(&peer) {
            link.active_rid = Some(rid);
            link.exchanges += 1;
        }
        self.queue(peer, OutFrame::Msg(ShareMsg::Redeem { rid, proof }));
        self.events.push(ShareEvent::ReceiveStarted { peer });
    }

    /// The person cancelled the wait or the transfer on the recipient: `Abort(recipient
    /// cancelled)` if an exchange runs; a partial file is deleted.
    pub fn cancel_redemption(&mut self) {
        let running = self
            .redemption
            .as_ref()
            .is_some_and(|r| !r.state.terminal());
        if running {
            self.end_redemption(RecvState::Cancelled, Some(AbortReason::RecipientCancelled));
        }
    }

    /// The host could not get a channel to the sender.
    pub fn connect_failed(&mut self, reason: Failure) {
        let connecting = self
            .redemption
            .as_ref()
            .is_some_and(|r| r.state == RecvState::Connecting);
        if connecting {
            self.end_redemption(RecvState::Failed(reason), None);
        }
    }

    /// Ends the redemption in `state`: wipes the code, deletes a partial file, releases the
    /// slot, sends `abort` on the exchange if given.
    pub(crate) fn end_redemption(&mut self, state: RecvState, abort: Option<AbortReason>) {
        let now = self.mono.now();
        let Some(r) = self.redemption.as_mut() else {
            return;
        };
        if r.state.terminal() {
            return;
        }
        r.state = state;
        r.code = None;
        r.slot = None;
        r.ended_at = Some(now);
        if let Some(writer) = r.writer.take() {
            writer.abort();
        }
        let exchange = r.exchange;
        if let Some((peer, conn, rid)) = exchange {
            if let Some(reason) = abort {
                self.abort_to(peer, rid, reason);
            }
            self.end_exchange(peer, conn, rid);
            if let RecvState::Failed(reason) = state {
                self.events.push(ShareEvent::ReceiveFailed { peer, reason });
            }
        }
    }

    fn redemption_matches(&self, peer: PeerId, conn: u64, rid: u32) -> bool {
        self.redemption
            .as_ref()
            .is_some_and(|r| r.exchange == Some((peer, conn, rid)) && !r.state.terminal())
    }

    pub(crate) fn on_pending(
        &mut self,
        peer: PeerId,
        conn: u64,
        rid: u32,
        seconds_left: u16,
    ) -> bool {
        if !self.redemption_matches(peer, conn, rid) {
            return false;
        }
        let now = self.mono.now();
        let Some(r) = self.redemption.as_mut() else {
            return false;
        };
        if r.state != (RecvState::AwaitingSender { pending: false }) {
            return false;
        }
        r.state = RecvState::AwaitingSender { pending: true };
        r.seconds_left = Some(seconds_left);
        r.deadline = now + Duration::from_secs(u64::from(seconds_left)) + ANSWER_TIMEOUT;
        true
    }

    pub(crate) fn on_offer(&mut self, peer: PeerId, conn: u64, rid: u32, size: u32) -> bool {
        if !self.redemption_matches(peer, conn, rid) {
            return false;
        }
        let pending = self
            .redemption
            .as_ref()
            .is_some_and(|r| r.state == (RecvState::AwaitingSender { pending: true }));
        if !pending {
            return false;
        }
        if !(MIN_COPY..=MAX_COPY).contains(&size) {
            self.end_redemption(
                RecvState::Failed(Failure::TooLarge),
                Some(AbortReason::TooLarge),
            );
            return true;
        }
        let count = self.received.list().map(|l| l.len());
        match count {
            Ok(n) if n >= MAX_RECEIVED => {
                self.end_redemption(
                    RecvState::Failed(Failure::ReceivedLimit),
                    Some(AbortReason::ReceivedLimit),
                );
                return true;
            }
            Ok(_) => {}
            Err(_) => {
                self.end_redemption(
                    RecvState::Failed(Failure::Storage),
                    Some(AbortReason::Storage),
                );
                return true;
            }
        }
        let Some(slot) = self.slots.try_take() else {
            self.end_redemption(RecvState::Failed(Failure::Busy), Some(AbortReason::Busy));
            return true;
        };
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let received_at = self.wall.unix_now();
        let writer = match self.received.begin(id, peer, received_at) {
            Ok(writer) => writer,
            Err(_) => {
                self.end_redemption(
                    RecvState::Failed(Failure::Storage),
                    Some(AbortReason::Storage),
                );
                return true;
            }
        };
        let now = self.mono.now();
        let Some(r) = self.redemption.as_mut() else {
            return true;
        };
        r.state = RecvState::Receiving;
        r.size = u64::from(size);
        r.received = 0;
        r.writer = Some(writer);
        r.slot = Some(slot);
        r.received_id = Some(id);
        r.last_progress = now;
        r.transfer_started = now;
        true
    }

    /// A `ShareData` chunk; false outside a transfer or beyond `size` (protocol error).
    pub(crate) fn recipient_data(&mut self, peer: PeerId, conn: u64, bytes: &[u8]) -> bool {
        let now = self.mono.now();
        let Some(r) = self.redemption.as_mut() else {
            return false;
        };
        let ours = r.exchange.is_some_and(|(p, c, _)| p == peer && c == conn);
        if !ours || r.state != RecvState::Receiving || bytes.is_empty() {
            return false;
        }
        let received = r.received + bytes.len() as u64;
        if received > r.size {
            return false;
        }
        r.received = received;
        r.last_progress = now;
        let ok = r.writer.as_mut().is_some_and(|w| w.append(bytes).is_ok());
        if !ok {
            self.end_redemption(
                RecvState::Failed(Failure::Storage),
                Some(AbortReason::Storage),
            );
        }
        true
    }

    /// Data of an exchange this side just ended (still in flight from the sender): ignored.
    pub(crate) fn data_in_flight(&self, peer: PeerId, conn: u64) -> bool {
        let last = self
            .links
            .get(&peer)
            .filter(|l| l.conn == conn)
            .and_then(|l| l.last_rid);
        self.redemption.as_ref().is_some_and(|r| {
            r.state.terminal()
                && r.exchange
                    .is_some_and(|(p, c, rid)| p == peer && c == conn && Some(rid) == last)
        })
    }

    pub(crate) fn on_end(&mut self, peer: PeerId, conn: u64, rid: u32) -> bool {
        if !self.redemption_matches(peer, conn, rid) {
            return false;
        }
        let Some(r) = self.redemption.as_mut() else {
            return false;
        };
        if r.state != RecvState::Receiving || r.received != r.size {
            return false;
        }
        let finished = r.writer.take().map(|w| w.finish());
        if !matches!(finished, Some(Ok(()))) {
            self.end_redemption(
                RecvState::Failed(Failure::Storage),
                Some(AbortReason::Storage),
            );
            return true;
        }
        let bytes = r.received;
        self.queue(peer, OutFrame::Msg(ShareMsg::Stored { rid }));
        self.end_redemption(RecvState::Stored, None);
        self.events.push(ShareEvent::Received { peer, bytes });
        true
    }

    /// `Abort` from the sender on the redemption's exchange; false when not ours.
    pub(crate) fn recipient_abort(
        &mut self,
        peer: PeerId,
        conn: u64,
        rid: u32,
        reason: AbortReason,
    ) -> bool {
        if !self.redemption_matches(peer, conn, rid) {
            return false;
        }
        let failure = match reason {
            AbortReason::Invalid => Failure::Invalid,
            AbortReason::Rejected => Failure::Rejected,
            AbortReason::Cancelled => Failure::CancelledBySender,
            AbortReason::Expired => Failure::Expired,
            AbortReason::Busy => Failure::Busy,
            AbortReason::Storage => Failure::Storage,
            AbortReason::TooLarge => Failure::TooLarge,
            AbortReason::SenderError => Failure::SenderError,
            AbortReason::ReceivedLimit => Failure::ReceivedLimit,
            AbortReason::RecipientCancelled => Failure::Invalid,
        };
        self.end_redemption(RecvState::Failed(failure), None);
        true
    }

    /// The channel of the redemption's exchange closed.
    pub(crate) fn recipient_channel_lost(&mut self, peer: PeerId, conn: u64) {
        let ours = self.redemption.as_ref().is_some_and(|r| {
            !r.state.terminal() && r.exchange.is_some_and(|(p, c, _)| p == peer && c == conn)
        });
        if ours {
            self.end_redemption(RecvState::Failed(Failure::ChannelLost), None);
        }
    }

    /// The sender of the running redemption was revoked: the exchange ends, nothing is kept.
    pub(crate) fn recipient_peer_revoked(&mut self, peer: PeerId) {
        let ours = self
            .redemption
            .as_ref()
            .is_some_and(|r| !r.state.terminal() && r.sender == Some(peer));
        if ours {
            self.end_redemption(RecvState::Failed(Failure::ChannelLost), None);
        }
    }

    pub(crate) fn recipient_tick(&mut self, now: Duration) {
        let Some(r) = self.redemption.as_ref() else {
            return;
        };
        match r.state {
            RecvState::Connecting if now >= r.deadline => {
                self.end_redemption(RecvState::Failed(Failure::Unreachable), None);
            }
            RecvState::AwaitingSender { .. } if now >= r.deadline => {
                self.end_redemption(
                    RecvState::Failed(Failure::Timeout),
                    Some(AbortReason::RecipientCancelled),
                );
            }
            RecvState::Receiving
                if now.saturating_sub(r.last_progress) >= PROGRESS_TIMEOUT
                    || now.saturating_sub(r.transfer_started) >= MAX_TRANSFER =>
            {
                self.end_redemption(
                    RecvState::Failed(Failure::Timeout),
                    Some(AbortReason::RecipientCancelled),
                );
            }
            state
                if state.terminal()
                    && r.ended_at
                        .is_some_and(|at| now.saturating_sub(at) >= RESULT_RETENTION) =>
            {
                self.redemption = None;
            }
            _ => {}
        }
    }

    pub(crate) fn receive_view(&self, now: Duration) -> Option<ReceiveView> {
        let r = self.redemption.as_ref()?;
        if r.state.terminal()
            && r.ended_at
                .is_some_and(|at| now.saturating_sub(at) >= RESULT_RETENTION)
        {
            return None;
        }
        Some(ReceiveView {
            state: r.state.word(),
            sender: r.sender,
            seconds_left: match r.state {
                RecvState::AwaitingSender { pending: true } => r.seconds_left.map(|s| {
                    let left = secs_until(r.deadline.saturating_sub(ANSWER_TIMEOUT), now);
                    u16::try_from(left).unwrap_or(s).min(s)
                }),
                _ => None,
            },
            progress: (r.state == RecvState::Receiving).then_some((r.received, r.size)),
            reason: match r.state {
                RecvState::Failed(failure) => Some(failure.word()),
                _ => None,
            },
            received_id: if r.state == RecvState::Stored {
                r.received_id
            } else {
                None
            },
        })
    }
}
