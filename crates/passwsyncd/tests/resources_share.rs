//! 005 T084 (SC-007, FR-017): with no invitation or redemption sharing costs nothing (no
//! traffic, no thread, no wake), and sync and share draw from one transfer limit.
//! `cargo test -p passwsyncd --test resources_share -- --ignored`.

mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::share::*;
use wallet_sync::ports::PeerId;
use wallet_sync::share::{AcceptError, ShareDeps, ShareEngine};
use wallet_sync::slots::TransferSlots;
use wallet_sync::testkit::{
    FakeMonoClock, FakeWallClock, FakeWalletSource, InMemoryReceivedStore, MemorySyncStore,
};

fn thread_names() -> Vec<String> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .map(|n| n.trim().to_string())
        .collect()
}

#[test]
#[ignore = "resource check (SC-007)"]
fn idle_sharing_sends_nothing_and_wakes_nothing() {
    let mono = Arc::new(FakeMonoClock::new());
    let mut engine = ShareEngine::new(ShareDeps {
        store: Arc::new(MemorySyncStore::new()),
        received: Arc::new(InMemoryReceivedStore::new()),
        source: Arc::new(FakeWalletSource::new()),
        mono: mono.clone(),
        wall: Arc::new(FakeWallClock::new(1)),
        rng: Box::new(rand_core::OsRng),
        slots: TransferSlots::new(2),
        own_id: PeerId([1; 32]),
    });
    for p in 2..7u8 {
        engine.channel_up(PeerId([p; 32]), u64::from(p), [p; 32], true);
    }
    // A day of sweeper ticks: no frame, no event.
    for _ in 0..(24 * 3600 / 15) {
        mono.advance(Duration::from_secs(15));
        assert!(engine.tick().is_empty());
        assert!(engine.outgoing_peers().is_empty());
    }
    // A running service with paired peers has no sharing thread while idle.
    let (a, _b) = paired("Laptop", "Phone");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !thread_names().iter().any(|n| n.starts_with("share")),
        "{:?}",
        thread_names()
    );
    let log = a.server.log_text();
    assert!(!log.contains("share "), "nothing logged while idle");
}

#[test]
#[ignore = "resource check (FR-017)"]
fn two_sync_transfers_make_a_share_busy() {
    let slots = TransferSlots::new(2);
    let _sync_one = slots.try_take().unwrap();
    let _sync_two = slots.try_take().unwrap();
    // The share engine sees the same counter: acceptance fails as busy.
    let (mut a, b, _) = {
        // Reuse the 005 wallet-sync harness shape inline: an invitation redeemed by B.
        let store = MemorySyncStore::new();
        let source = FakeWalletSource::new();
        let bytes = vec![7u8; 500];
        source.set("W", bytes.clone());
        let record = wallet_sync::record::SyncRecord::new(
            vault_core::WalletId::from_bytes([1; 16]),
            "W".into(),
            wallet_sync::record::sha256(&bytes),
            vault_core::StateVector::new(),
        );
        wallet_sync::ports::SyncStore::update(&store, &record.wallet_id.clone(), &mut |_| {
            Some(record.clone())
        })
        .unwrap();
        let engine = ShareEngine::new(ShareDeps {
            store: Arc::new(store),
            received: Arc::new(InMemoryReceivedStore::new()),
            source: Arc::new(source),
            mono: Arc::new(FakeMonoClock::new()),
            wall: Arc::new(FakeWallClock::new(1)),
            rng: Box::new(rand_core::OsRng),
            slots: Arc::clone(&slots),
            own_id: PeerId([1; 32]),
        });
        (engine, PeerId([2; 32]), ())
    };
    a.channel_up(b, 1, [3; 32], true);
    a.create(
        wallet_sync::share::InviteWallet {
            name: "W".into(),
            id: vault_core::WalletId::from_bytes([1; 16]),
            format: 2,
        },
        b,
        zeroize::Zeroizing::new("12345678".into()),
    )
    .unwrap();
    let proof =
        wallet_sync::share::proof::redeem_proof("12345678", &[3; 32], &PeerId([1; 32]), &b, 9);
    a.on_msg(
        b,
        1,
        wallet_sync::share::codec::ShareMsg::Redeem { rid: 9, proof },
    );
    assert_eq!(a.accept(b, &|_| true), Err(AcceptError::Busy));
}
