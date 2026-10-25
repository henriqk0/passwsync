//! The wallet sync state shown in the UI (data-model.md "Wallet sync state (UI, derived)")
//! and per-peer positions.

use crate::record::{Outcome, PeerSyncState, Position, SyncRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisabledReason {
    CorruptedRecord,
    DuplicateWalletId,
    TooManyConflicts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotSyncedReason {
    NoPeer,
    UnlockOnce,
    FormatV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletSyncState {
    SyncOff,
    Disabled(DisabledReason),
    PossibleRollback,
    Conflicts(u32),
    ChangesWaiting,
    Syncing,
    SyncError,
    NotSynced(NotSyncedReason),
    InSync,
}

impl WalletSyncState {
    pub fn word(self) -> &'static str {
        match self {
            Self::SyncOff => "sync_off",
            Self::Disabled(_) => "disabled",
            Self::PossibleRollback => "possible_rollback",
            Self::Conflicts(_) => "conflicts",
            Self::ChangesWaiting => "changes_waiting",
            Self::Syncing => "syncing",
            Self::SyncError => "sync_error",
            Self::NotSynced(_) => "not_synced",
            Self::InSync => "in_sync",
        }
    }

    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Disabled(DisabledReason::CorruptedRecord) => Some("corrupted_record"),
            Self::Disabled(DisabledReason::DuplicateWalletId) => Some("duplicate_wallet_id"),
            Self::Disabled(DisabledReason::TooManyConflicts) => Some("too_many_conflicts"),
            Self::NotSynced(NotSyncedReason::NoPeer) => Some("no_peer"),
            Self::NotSynced(NotSyncedReason::UnlockOnce) => Some("unlock_once"),
            Self::NotSynced(NotSyncedReason::FormatV1) => Some("format_v1"),
            _ => None,
        }
    }
}

/// The record as the host could read it.
pub enum RecordView<'a> {
    Missing,
    Corrupted,
    Present(&'a SyncRecord),
}

pub struct StatusInput<'a> {
    pub networking_on: bool,
    pub record: RecordView<'a>,
    /// Format version of the wallet file (header; 1 or 2), when readable.
    pub format_version: Option<u16>,
    /// Conflicted credentials (known only while unlocked).
    pub conflicts: u32,
    /// A round is exchanging this wallet now.
    pub syncing: bool,
}

/// First state that applies, in the data-model priority order.
pub fn wallet_state(input: &StatusInput<'_>) -> WalletSyncState {
    use WalletSyncState::*;
    if !input.networking_on {
        return SyncOff;
    }
    let record = match input.record {
        RecordView::Corrupted => return Disabled(DisabledReason::CorruptedRecord),
        RecordView::Missing => {
            return NotSynced(if input.format_version == Some(1) {
                NotSyncedReason::FormatV1
            } else {
                NotSyncedReason::UnlockOnce
            });
        }
        RecordView::Present(r) => r,
    };
    if record.flags.duplicate_wallet_id {
        return Disabled(DisabledReason::DuplicateWalletId);
    }
    if record.flags.too_many_conflicts {
        return Disabled(DisabledReason::TooManyConflicts);
    }
    if record.flags.possible_rollback() {
        return PossibleRollback;
    }
    if input.conflicts > 0 {
        return Conflicts(input.conflicts);
    }
    if !record.pending.is_empty() {
        return ChangesWaiting;
    }
    if input.syncing {
        return Syncing;
    }
    if record
        .peers
        .values()
        .any(|p| matches!(p.last_outcome, Outcome::Failed | Outcome::InvalidCopy))
    {
        return SyncError;
    }
    if record.peers.is_empty() {
        return NotSynced(NotSyncedReason::NoPeer);
    }
    InSync
}

/// Time of the last successful round with any peer.
pub fn last_synced_at(record: &SyncRecord) -> Option<u64> {
    record
        .peers
        .values()
        .filter(|p| p.last_outcome == Outcome::Ok)
        .filter_map(|p| p.last_round_at)
        .max()
}

/// A peer's position for one wallet; `offline` and `error` derive from the connection and
/// the last round's outcome.
pub fn peer_position(peer: &PeerSyncState, connected: bool) -> Position {
    match peer.last_outcome {
        Outcome::OlderStateOffered => Position::OlderStateOffered,
        Outcome::Failed | Outcome::InvalidCopy => Position::Error,
        _ if !connected => Position::Offline,
        _ => peer.position,
    }
}
