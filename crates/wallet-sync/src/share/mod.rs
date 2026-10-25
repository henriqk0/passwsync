//! Wallet sharing (feature 005), sans-IO: share message codec, redemption proof, the
//! sender's invitation, the recipient's redemption and received-wallet rules
//! (specs/005-wallet-sharing/contracts/share-protocol.md, core-api-share.md).
//!
//! The [`ShareEngine`] never logs and never exposes the invite code after redemption; `Debug`
//! of every type omits codes, proofs, `rid`s, received ids and wallet names or ids.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rand_core::RngCore;
use vault_core::WalletId;
use zeroize::Zeroizing;

use crate::ports::{MonoClock, PeerId, ReceivedStore, SyncStore, WallClock, WalletSource};
use crate::slots::TransferSlots;

pub mod codec;
pub mod invite;
pub mod proof;
pub mod received;
pub mod redeem;

use codec::{AbortReason, ShareMsg};
use invite::{Invitation, Tombstone};
use redeem::Redemption;

pub use received::DiscardError;

/// An invitation is valid for 5 minutes on the sender's monotonic clock (FR-005).
pub const INVITE_VALIDITY: Duration = Duration::from_secs(300);
/// At most this many received wallets wait for opening (FR-018).
pub const MAX_RECEIVED: usize = 8;
/// Received wallets are deleted 24 hours after receipt (FR-022a).
pub const RECEIVED_RETENTION_SECS: u64 = 86_400;
/// A receipt time further than this in the future (clock moved back) is deleted too.
pub const RECEIVED_FUTURE_SLACK_SECS: u64 = 300;
/// Memory bound of one transfer's buffers (FR-017, 004 rule).
pub const MAX_TRANSFER_BUFFER: usize = 1024 * 1024;
/// The sender answers a `Redeem` within this bound; the recipient waits this long for it.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// The recipient waits at most this long for a channel to the sender.
pub const CHANNEL_WAIT: Duration = Duration::from_secs(300);
/// No transfer progress for this long fails the exchange (004).
pub const PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);
/// A transfer never lasts longer than this (004 `max_round`).
pub const MAX_TRANSFER: Duration = Duration::from_secs(15 * 60);
/// A terminal invitation or redemption result stays visible this long.
pub const RESULT_RETENTION: Duration = Duration::from_secs(60);
/// Invitations created per [`RATE_WINDOW`] (FR-007).
pub const MAX_INVITATIONS: usize = 5;
pub const RATE_WINDOW: Duration = Duration::from_secs(600);
/// Notices kept (oldest dropped).
pub const MAX_NOTICES: usize = 16;
/// Frames queued for one peer beyond this mean it does not read: protocol error.
const MAX_OUTBOX: usize = 64;
/// Exchanges one channel connection may start; more is a `Redeem` flood (protocol error).
pub const MAX_EXCHANGES_PER_CHANNEL: u32 = 8;

/// What the share engine needs from its host.
pub struct ShareDeps {
    pub store: Arc<dyn SyncStore>,
    pub received: Arc<dyn ReceivedStore>,
    pub source: Arc<dyn WalletSource>,
    pub mono: Arc<dyn MonoClock>,
    pub wall: Arc<dyn WallClock>,
    pub rng: Box<dyn RngCore + Send>,
    pub slots: Arc<TransferSlots>,
    /// This device's id (the recipient id in proofs it creates, the sender id it verifies).
    pub own_id: PeerId,
}

/// The wallet an invitation is for (the host checked that it is unlocked).
#[derive(Clone, PartialEq, Eq)]
pub struct InviteWallet {
    /// Local wallet name (shown only locally, never sent).
    pub name: String,
    pub id: WalletId,
    /// Format version of the stored file (only 2 can be shared).
    pub format: u16,
}

impl fmt::Debug for InviteWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteWallet")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

/// Why a wallet cannot be shared (FR-002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ineligible {
    FormatV1,
    PossibleRollback,
    Disabled,
    NoRecord,
    Changed,
}

impl Ineligible {
    pub fn word(self) -> &'static str {
        match self {
            Self::FormatV1 => "format_v1",
            Self::PossibleRollback => "possible_rollback",
            Self::Disabled => "disabled",
            Self::NoRecord => "no_record",
            Self::Changed => "changed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateError {
    Ineligible(Ineligible),
    /// More than 5 invitations in 10 minutes.
    TooMany,
    /// The current invitation is transferring.
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    NothingPending,
    /// The device named is not the pending recipient.
    Mismatch,
    Expired,
    /// The wallet is no longer unlocked or eligible: the invitation was cancelled.
    WalletLocked,
    /// No free transfer slot: the invitation failed.
    Busy,
    /// The stored file cannot be read or is out of bounds: the invitation failed.
    SenderError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectError {
    NothingPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled,
    /// The encrypted copy already reached the recipient (US4.4).
    AlreadyDelivered,
    Nothing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedeemError {
    /// A redemption is already running.
    Busy,
    /// 8 received wallets already wait for opening.
    ReceivedLimit,
}

/// Closed set of failure reasons shown to the person (data-model.md, http-api-share.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Failure {
    Invalid,
    CancelledBySender,
    Expired,
    Rejected,
    Busy,
    TooLarge,
    Storage,
    SenderError,
    Unreachable,
    Unsupported,
    ReceivedLimit,
    ChannelLost,
    Timeout,
    IdMismatch,
    RecipientCancelled,
}

/// The recipient-side name of [`Failure`].
pub use Failure as ReceiveFailure;

impl Failure {
    pub fn word(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::CancelledBySender => "cancelled_by_sender",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
            Self::TooLarge => "too_large",
            Self::Storage => "storage",
            Self::SenderError => "sender_error",
            Self::Unreachable => "unreachable",
            Self::Unsupported => "unsupported",
            Self::ReceivedLimit => "received_limit",
            Self::ChannelLost => "channel_lost",
            Self::Timeout => "timeout",
            Self::IdMismatch => "id_mismatch",
            Self::RecipientCancelled => "recipient_cancelled",
        }
    }
}

/// How an invitation ended (for the log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationEnd {
    Cancelled,
    Replaced,
    Locked,
    Revoked,
    Expired,
    Rejected,
    Completed,
    Failed,
}

/// Why a `Redeem` was refused (for the log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongCode,
    NotRecipient,
    NoInvitation,
    Expired,
    Used,
    Cancelled,
}

/// Why a received wallet was deleted by the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteCause {
    Expired,
    Revoked,
}

/// One frame for a peer's share-enabled channel.
#[derive(Clone, PartialEq, Eq)]
pub enum OutFrame {
    Msg(ShareMsg),
    Data(Vec<u8>),
}

impl fmt::Debug for OutFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msg(msg) => write!(f, "Msg({msg:?})"),
            Self::Data(bytes) => write!(f, "Data({} bytes)", bytes.len()),
        }
    }
}

/// What happened, for the host's log, notices and channel handling. No code, proof, `rid`,
/// received id, wallet name or id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareEvent {
    InvitationCreated {
        recipient: PeerId,
    },
    InvitationEnded {
        end: InvitationEnd,
    },
    RedeemRefused {
        peer: PeerId,
        why: Refusal,
    },
    Redeemed {
        peer: PeerId,
    },
    Accepted {
        peer: PeerId,
    },
    TransferCompleted {
        peer: PeerId,
        bytes: u64,
    },
    TransferAborted {
        peer: PeerId,
        reason: Failure,
        bytes: u64,
    },
    ReceiveStarted {
        peer: PeerId,
    },
    Received {
        peer: PeerId,
        bytes: u64,
    },
    ReceiveFailed {
        peer: PeerId,
        reason: Failure,
    },
    ReceivedDeleted {
        sender: PeerId,
        why: DeleteCause,
    },
    /// A protocol error: the host closes this channel.
    CloseChannel {
        peer: PeerId,
        conn: u64,
    },
}

/// Closed set of notices (data-model.md "ShareNotice").
#[derive(Clone, PartialEq, Eq)]
pub enum NoticeKind {
    ReceivedExpired { sender: PeerId },
    ReceivedDeletedRevoked { sender: PeerId },
    ReceivedCleaned { count: usize },
    AlreadyPresent { local_name: String },
}

impl fmt::Debug for NoticeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceivedExpired { sender } => write!(f, "ReceivedExpired({sender:?})"),
            Self::ReceivedDeletedRevoked { sender } => {
                write!(f, "ReceivedDeletedRevoked({sender:?})")
            }
            Self::ReceivedCleaned { count } => write!(f, "ReceivedCleaned({count})"),
            Self::AlreadyPresent { .. } => f.write_str("AlreadyPresent"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub id: u64,
    pub kind: NoticeKind,
    /// Unix seconds.
    pub at: u64,
}

/// The sender's invitation as the UI shows it.
#[derive(Clone)]
pub struct InvitationView {
    /// `active | awaiting_acceptance | transferring | completed | cancelled | expired |
    /// rejected | refused | failed`.
    pub state: &'static str,
    /// Local wallet name (shown locally only).
    pub wallet: String,
    pub recipient: PeerId,
    /// Only while `active`.
    pub code: Option<Zeroizing<String>>,
    pub expires_in: u64,
    /// `(sent, size)` while transferring.
    pub progress: Option<(u64, u64)>,
    pub reason: Option<&'static str>,
}

impl fmt::Debug for InvitationView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvitationView")
            .field("state", &self.state)
            .field("recipient", &self.recipient)
            .field("expires_in", &self.expires_in)
            .field("progress", &self.progress)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// The recipient's redemption as the UI shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiveView {
    /// `connecting | awaiting_sender | receiving | stored | failed | cancelled`.
    pub state: &'static str,
    pub sender: Option<PeerId>,
    pub seconds_left: Option<u16>,
    /// `(received, size)` while receiving.
    pub progress: Option<(u64, u64)>,
    pub reason: Option<&'static str>,
    pub received_id: Option<[u8; 16]>,
}

impl fmt::Debug for ReceiveView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveView")
            .field("state", &self.state)
            .field("sender", &self.sender)
            .field("seconds_left", &self.seconds_left)
            .field("progress", &self.progress)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct ShareView {
    pub invitation: Option<InvitationView>,
    pub receive: Option<ReceiveView>,
    pub notices: Vec<Notice>,
}

/// One share-capable (or not) channel to a peer.
pub(crate) struct Link {
    pub conn: u64,
    pub session: [u8; 32],
    pub share: bool,
    pub closed: bool,
    pub outbox: VecDeque<OutFrame>,
    /// The exchange running on this channel (either role).
    pub active_rid: Option<u32>,
    /// The last exchange that ended on this channel; its late messages are ignored.
    pub last_rid: Option<u32>,
    /// Exchanges started on this connection (bounded, flood protection).
    pub exchanges: u32,
}

pub struct ShareEngine {
    pub(crate) store: Arc<dyn SyncStore>,
    pub(crate) received: Arc<dyn ReceivedStore>,
    pub(crate) source: Arc<dyn WalletSource>,
    pub(crate) mono: Arc<dyn MonoClock>,
    pub(crate) wall: Arc<dyn WallClock>,
    pub(crate) rng: Box<dyn RngCore + Send>,
    pub(crate) slots: Arc<TransferSlots>,
    pub(crate) own_id: PeerId,
    pub(crate) links: BTreeMap<PeerId, Link>,
    pub(crate) invitation: Option<Invitation>,
    pub(crate) tombstone: Option<Tombstone>,
    pub(crate) redemption: Option<Redemption>,
    pub(crate) created: VecDeque<Duration>,
    pub(crate) notices: VecDeque<Notice>,
    pub(crate) next_notice: u64,
    pub(crate) events: Vec<ShareEvent>,
}

/// Counts only: never a code, proof, `rid`, received id or wallet name.
impl fmt::Debug for ShareEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareEngine")
            .field("links", &self.links.len())
            .field("invitation", &self.invitation.is_some())
            .field("redemption", &self.redemption.is_some())
            .field("notices", &self.notices.len())
            .finish_non_exhaustive()
    }
}

impl ShareEngine {
    pub fn new(deps: ShareDeps) -> Self {
        Self {
            store: deps.store,
            received: deps.received,
            source: deps.source,
            mono: deps.mono,
            wall: deps.wall,
            rng: deps.rng,
            slots: deps.slots,
            own_id: deps.own_id,
            links: BTreeMap::new(),
            invitation: None,
            tombstone: None,
            redemption: None,
            created: VecDeque::new(),
            notices: VecDeque::new(),
            next_notice: 1,
            events: Vec::new(),
        }
    }

    /// A channel to `peer` came up (`share`: negotiated with channel v3).
    pub fn channel_up(&mut self, peer: PeerId, conn: u64, session: [u8; 32], share: bool) {
        if let Some(old) = self.links.get(&peer) {
            let old_conn = old.conn;
            if old_conn != conn {
                self.channel_down(peer, old_conn);
            }
        }
        self.links.insert(
            peer,
            Link {
                conn,
                session,
                share,
                closed: false,
                outbox: VecDeque::new(),
                active_rid: None,
                last_rid: None,
                exchanges: 0,
            },
        );
    }

    /// The channel closed: an exchange running on it ends (`channel_lost`).
    pub fn channel_down(&mut self, peer: PeerId, conn: u64) {
        if !self.links.get(&peer).is_some_and(|l| l.conn == conn) {
            return;
        }
        self.sender_channel_lost(peer, conn);
        self.recipient_channel_lost(peer, conn);
        self.links.remove(&peer);
    }

    /// Whether `peer`'s current channel carries share frames.
    pub fn share_enabled(&self, peer: &PeerId) -> Option<bool> {
        self.links.get(peer).map(|l| l.share)
    }

    /// One share message from `peer` on connection `conn`.
    pub fn on_msg(&mut self, peer: PeerId, conn: u64, msg: ShareMsg) {
        let Some(link) = self.links.get(&peer) else {
            return;
        };
        if link.conn != conn || link.closed || !link.share {
            return; // stale connection, or not share-enabled: dropped
        }
        let last = link.last_rid;
        let rid = msg.rid();
        let handled = match msg {
            ShareMsg::Redeem { rid, proof } => {
                if last == Some(rid) && link.active_rid.is_none() {
                    true // a late duplicate of the exchange that ended here
                } else {
                    self.on_redeem(peer, conn, rid, &proof)
                }
            }
            ShareMsg::Stored { rid } => self.on_stored(peer, conn, rid),
            ShareMsg::Abort { rid, reason } => {
                self.sender_abort(peer, conn, rid, reason)
                    || self.recipient_abort(peer, conn, rid, reason)
            }
            ShareMsg::Pending { rid, seconds_left } => {
                self.on_pending(peer, conn, rid, seconds_left)
            }
            ShareMsg::Offer { rid, size } => self.on_offer(peer, conn, rid, size),
            ShareMsg::End { rid } => self.on_end(peer, conn, rid),
        };
        if !handled && last != Some(rid) {
            self.protocol_error(peer, conn);
        }
        self.check_flood(peer, conn);
    }

    /// One `ShareData` chunk from `peer`.
    pub fn on_data(&mut self, peer: PeerId, conn: u64, bytes: &[u8]) {
        let Some(link) = self.links.get(&peer) else {
            return;
        };
        if link.conn != conn || link.closed || !link.share {
            return;
        }
        if !self.recipient_data(peer, conn, bytes) && !self.data_in_flight(peer, conn) {
            self.protocol_error(peer, conn);
        }
    }

    /// Peers with frames waiting, as `(peer, conn)`.
    pub fn outgoing_peers(&self) -> Vec<(PeerId, u64)> {
        self.links
            .iter()
            .filter(|(peer, l)| {
                !l.closed && (!l.outbox.is_empty() || self.serving_to(peer, l.conn))
            })
            .map(|(peer, l)| (*peer, l.conn))
            .collect()
    }

    /// Up to `max` frames for `peer`, pulling wallet bytes from a transfer being served.
    pub fn poll_outgoing(&mut self, peer: PeerId, max: usize) -> Vec<OutFrame> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(link) = self.links.get_mut(&peer) else {
                break;
            };
            if link.closed {
                link.outbox.clear();
                break;
            }
            if let Some(frame) = link.outbox.pop_front() {
                out.push(frame);
                continue;
            }
            let conn = link.conn;
            if !self.serve_next(peer, conn, &mut out) {
                break;
            }
        }
        out
    }

    pub fn take_events(&mut self) -> Vec<ShareEvent> {
        std::mem::take(&mut self.events)
    }

    /// Time-driven steps (the host's 15-second sweeper tick, and tests): expiry of the
    /// invitation, waiting bounds, transfer timeouts, tombstones, received-wallet retention.
    pub fn tick(&mut self) -> Vec<ShareEvent> {
        let now = self.mono.now();
        self.sender_tick(now);
        self.recipient_tick(now);
        self.received_tick();
        self.take_events()
    }

    pub fn view(&self) -> ShareView {
        let now = self.mono.now();
        ShareView {
            invitation: self.invitation_view(now),
            receive: self.receive_view(now),
            notices: self.notices.iter().cloned().collect(),
        }
    }

    /// Service shutdown: a live invitation is cancelled and a running redemption ends, both
    /// with an `Abort` queued for a final best-effort flush; partial files are deleted and the
    /// code is wiped.
    pub fn shutdown(&mut self) {
        self.cancel();
        self.cancel_redemption();
    }

    /// Adds a notice (oldest dropped beyond 16); returns its id.
    pub fn push_notice(&mut self, kind: NoticeKind) -> u64 {
        let id = self.next_notice;
        self.next_notice += 1;
        if self.notices.len() >= MAX_NOTICES {
            self.notices.pop_front();
        }
        self.notices.push_back(Notice {
            id,
            kind,
            at: self.wall.unix_now(),
        });
        id
    }

    /// Removes the notices `ids` (nothing else changes).
    pub fn dismiss(&mut self, ids: &[u64]) {
        self.notices.retain(|n| !ids.contains(&n.id));
    }

    // --- shared helpers ---

    pub(crate) fn queue(&mut self, peer: PeerId, frame: OutFrame) {
        if let Some(link) = self.links.get_mut(&peer) {
            if !link.closed {
                link.outbox.push_back(frame);
            }
        }
    }

    pub(crate) fn abort_to(&mut self, peer: PeerId, rid: u32, reason: AbortReason) {
        self.queue(peer, OutFrame::Msg(ShareMsg::Abort { rid, reason }));
    }

    /// Marks the exchange `rid` on `peer`'s channel `conn` as ended.
    pub(crate) fn end_exchange(&mut self, peer: PeerId, conn: u64, rid: u32) {
        if let Some(link) = self.links.get_mut(&peer).filter(|l| l.conn == conn) {
            if link.active_rid == Some(rid) {
                link.active_rid = None;
            }
            link.last_rid = Some(rid);
        }
    }

    /// A peer broke the share protocol: its exchanges end, the channel is closed.
    pub(crate) fn protocol_error(&mut self, peer: PeerId, conn: u64) {
        self.sender_channel_lost(peer, conn);
        self.recipient_channel_lost(peer, conn);
        if let Some(link) = self.links.get_mut(&peer).filter(|l| l.conn == conn) {
            link.closed = true;
            link.outbox.clear();
        }
        self.events.push(ShareEvent::CloseChannel { peer, conn });
    }

    fn check_flood(&mut self, peer: PeerId, conn: u64) {
        let flooded = self
            .links
            .get(&peer)
            .is_some_and(|l| l.conn == conn && !l.closed && l.outbox.len() > MAX_OUTBOX);
        if flooded {
            self.protocol_error(peer, conn);
        }
    }

    pub(crate) fn link_session(&self, peer: &PeerId, conn: u64) -> Option<[u8; 32]> {
        self.links
            .get(peer)
            .filter(|l| l.conn == conn && !l.closed && l.share)
            .map(|l| l.session)
    }
}

/// Whole seconds left until `deadline` (rounded up).
pub(crate) fn secs_until(deadline: Duration, now: Duration) -> u64 {
    let left = deadline.saturating_sub(now);
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link")
            .field("share", &self.share)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
