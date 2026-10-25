//! 004 T115 (US5): the derived wallet sync state and per-peer positions.

mod support;

use support::*;
use wallet_sync::ports::PeerId;
use wallet_sync::record::{
    Outcome, PeerSyncState, PendingCopy, PendingStatus, Position, SyncRecord,
};
use wallet_sync::status::{
    DisabledReason, NotSyncedReason, RecordView, StatusInput, WalletSyncState, last_synced_at,
    peer_position, wallet_state,
};

const P: PeerId = PeerId([4; 32]);

fn record() -> SyncRecord {
    let mut r = SyncRecord::new(wid(1), "W".into(), [0; 32], sv(&[("a", 1)]));
    r.peers.insert(
        P,
        PeerSyncState {
            peer_mark: None,
            last_round_at: Some(100),
            last_outcome: Outcome::Ok,
            position: Position::InSync,
        },
    );
    r
}

fn input(r: &SyncRecord) -> StatusInput<'_> {
    StatusInput {
        networking_on: true,
        record: RecordView::Present(r),
        format_version: Some(2),
        conflicts: 0,
        syncing: false,
    }
}

#[test]
fn each_state_in_priority_order() {
    use WalletSyncState::*;
    let r = record();
    assert_eq!(wallet_state(&input(&r)), InSync);
    let mut i = input(&r);
    i.networking_on = false;
    assert_eq!(wallet_state(&i), SyncOff, "sync_off wins over everything");

    let mut corrupted = input(&r);
    corrupted.record = RecordView::Corrupted;
    assert_eq!(
        wallet_state(&corrupted),
        Disabled(DisabledReason::CorruptedRecord)
    );
    let mut dup = record();
    dup.flags.duplicate_wallet_id = true;
    dup.flags.rollback_state = true;
    assert_eq!(
        wallet_state(&input(&dup)),
        Disabled(DisabledReason::DuplicateWalletId)
    );
    let mut many = record();
    many.flags.too_many_conflicts = true;
    assert_eq!(
        wallet_state(&input(&many)),
        Disabled(DisabledReason::TooManyConflicts)
    );

    let mut rolled = record();
    rolled.flags.rollback_digest = true;
    let mut i = input(&rolled);
    i.conflicts = 2;
    assert_eq!(wallet_state(&i), PossibleRollback);

    let mut i = input(&r);
    i.conflicts = 3;
    i.syncing = true;
    assert_eq!(wallet_state(&i), Conflicts(3));

    let mut waiting = record();
    waiting.pending.insert(
        P,
        PendingCopy {
            claimed: sv(&[("a", 2)]),
            size: 1,
            received_at: 1,
            status: PendingStatus::Waiting,
        },
    );
    let mut i = input(&waiting);
    i.syncing = true;
    assert_eq!(wallet_state(&i), ChangesWaiting);

    let mut i = input(&r);
    i.syncing = true;
    assert_eq!(wallet_state(&i), Syncing);

    let mut failed = record();
    failed.peers.get_mut(&P).unwrap().last_outcome = Outcome::Failed;
    assert_eq!(wallet_state(&input(&failed)), SyncError);

    let mut lonely = record();
    lonely.peers.clear();
    assert_eq!(
        wallet_state(&input(&lonely)),
        NotSynced(NotSyncedReason::NoPeer)
    );
    let mut missing = input(&r);
    missing.record = RecordView::Missing;
    assert_eq!(
        wallet_state(&missing),
        NotSynced(NotSyncedReason::UnlockOnce)
    );
    missing.format_version = Some(1);
    assert_eq!(wallet_state(&missing), NotSynced(NotSyncedReason::FormatV1));
}

#[test]
fn words_match_the_http_contract() {
    use WalletSyncState::*;
    assert_eq!(SyncOff.word(), "sync_off");
    assert_eq!(Disabled(DisabledReason::CorruptedRecord).word(), "disabled");
    assert_eq!(
        Disabled(DisabledReason::CorruptedRecord).reason(),
        Some("corrupted_record")
    );
    assert_eq!(
        Disabled(DisabledReason::DuplicateWalletId).reason(),
        Some("duplicate_wallet_id")
    );
    assert_eq!(
        Disabled(DisabledReason::TooManyConflicts).reason(),
        Some("too_many_conflicts")
    );
    assert_eq!(PossibleRollback.word(), "possible_rollback");
    assert_eq!(Conflicts(2).word(), "conflicts");
    assert_eq!(ChangesWaiting.word(), "changes_waiting");
    assert_eq!(Syncing.word(), "syncing");
    assert_eq!(SyncError.word(), "sync_error");
    assert_eq!(NotSynced(NotSyncedReason::NoPeer).reason(), Some("no_peer"));
    assert_eq!(
        NotSynced(NotSyncedReason::UnlockOnce).reason(),
        Some("unlock_once")
    );
    assert_eq!(
        NotSynced(NotSyncedReason::FormatV1).reason(),
        Some("format_v1")
    );
    assert_eq!(InSync.word(), "in_sync");
    assert_eq!(InSync.reason(), None);
}

#[test]
fn peer_positions_and_last_sync_time() {
    let mut r = record();
    assert_eq!(peer_position(&r.peers[&P], true), Position::InSync);
    assert_eq!(peer_position(&r.peers[&P], false), Position::Offline);
    r.peers.get_mut(&P).unwrap().last_outcome = Outcome::Failed;
    assert_eq!(peer_position(&r.peers[&P], true), Position::Error);
    r.peers.get_mut(&P).unwrap().last_outcome = Outcome::OlderStateOffered;
    r.peers.get_mut(&P).unwrap().position = Position::OlderStateOffered;
    assert_eq!(
        peer_position(&r.peers[&P], false),
        Position::OlderStateOffered
    );
    for pos in [
        Position::Behind,
        Position::Ahead,
        Position::Diverged,
        Position::Unknown,
    ] {
        let p = PeerSyncState {
            position: pos,
            last_outcome: Outcome::Ok,
            ..PeerSyncState::default()
        };
        assert_eq!(peer_position(&p, true), pos);
    }
    let mut r = record();
    r.peers.insert(
        PeerId([5; 32]),
        PeerSyncState {
            last_round_at: Some(300),
            last_outcome: Outcome::Failed,
            ..PeerSyncState::default()
        },
    );
    assert_eq!(last_synced_at(&r), Some(100), "last successful sync");
}
