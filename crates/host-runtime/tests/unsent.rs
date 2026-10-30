//! FR-045/FR-046: `SyncRuntime::has_unsent_changes` and `rounds_idle` (additive, used only by
//! the Android app's background planning).

mod common;

use std::sync::Arc;

use common::*;
use host_runtime::config::NetworkSettings;
use host_runtime::log::Log;
use host_runtime::net_runtime::NetRuntime;
use host_runtime::share_store::FsReceivedStore;
use host_runtime::sync_runtime::SyncRuntime;
use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{PeerSyncState, SyncRecord};

struct Fixture {
    _root: TempDir,
    sync: SyncRuntime,
}

fn fixture() -> Fixture {
    let root = TempDir::new("unsent");
    for d in ["sync", "wallets", "received"] {
        std::fs::create_dir(root.path().join(d)).unwrap();
        set_mode(&root.path().join(d), 0o700);
    }
    let (log, _) = Log::to_buffer();
    let net = Arc::new(NetRuntime::start(
        NetworkSettings::default(),
        &MemoryIdentity::new(31),
        loopback_deps(),
        &log,
    ));
    let sync = SyncRuntime::new(
        root.path().join("sync"),
        root.path().join("wallets"),
        Arc::new(FsReceivedStore::new(root.path().join("received"))),
        wallet_sync::slots::TransferSlots::new(2),
        net,
        log,
        std::time::Duration::from_secs(3600),
    );
    Fixture { _root: root, sync }
}

fn me() -> DeviceId {
    DeviceId::new("0123456789abcdef0123456789abcdef").unwrap()
}

fn state(counter: u64) -> StateVector {
    StateVector::from_pairs(vec![(me(), counter)]).unwrap()
}

fn put(f: &Fixture, id: WalletId, name: &str, local: u64, peer_marks: &[(u8, u64)]) {
    let mut record = SyncRecord::new(id, name.to_string(), [0; 32], state(local));
    for (peer, counter) in peer_marks {
        record.peers.insert(
            PeerId([*peer; 32]),
            PeerSyncState {
                peer_mark: Some(state(*counter)),
                ..PeerSyncState::default()
            },
        );
    }
    f.sync
        .shared()
        .store
        .update(&id, &mut |_| Some(record.clone()))
        .unwrap();
}

#[test]
fn a_fresh_store_has_no_unsent_changes() {
    let f = fixture();
    assert!(!f.sync.has_unsent_changes());
}

#[test]
fn a_local_save_not_covered_by_any_peer_mark_is_unsent() {
    let f = fixture();
    let id = WalletId::from_bytes([1; 16]);
    put(&f, id, "Personal", 3, &[]);
    assert!(f.sync.has_unsent_changes(), "no peer has it");
    put(&f, id, "Personal", 3, &[(9, 2)]);
    assert!(f.sync.has_unsent_changes(), "the peer is behind");
    put(&f, id, "Personal", 3, &[(9, 2), (8, 3)]);
    assert!(!f.sync.has_unsent_changes(), "one peer mark covers it");
}

#[test]
fn unsent_changes_are_per_wallet_across_wallets() {
    let f = fixture();
    put(&f, WalletId::from_bytes([1; 16]), "Personal", 3, &[(9, 3)]);
    put(&f, WalletId::from_bytes([2; 16]), "Work", 1, &[(9, 1)]);
    assert!(!f.sync.has_unsent_changes());
    put(&f, WalletId::from_bytes([2; 16]), "Work", 2, &[(9, 1)]);
    assert!(f.sync.has_unsent_changes());
}

#[test]
fn rounds_are_idle_when_nothing_is_running_or_queued() {
    let f = fixture();
    assert!(f.sync.rounds_idle());
}
