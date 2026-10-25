//! 004 T038: the ports' in-memory fakes behave like the real adapters must.

use std::io::Read;
use std::time::Duration;

use vault_core::{StateVector, WalletId};
use wallet_sync::ports::{
    MergeOutcome, MergeRequest, Merger, MonoClock, PeerId, StoreError, SyncStore, WallClock,
    WalletSource,
};
use wallet_sync::record::SyncRecord;
use wallet_sync::testkit::{
    FakeMerger, FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore, Step,
};

fn wid(b: u8) -> WalletId {
    WalletId::from_bytes([b; 16])
}

fn record(b: u8) -> SyncRecord {
    SyncRecord::new(wid(b), "Personal".into(), [b; 32], StateVector::new())
}

#[test]
fn records_load_update_and_list() {
    let store = MemorySyncStore::new();
    assert_eq!(store.load(&wid(1)), Ok(None));
    store
        .update(&wid(1), &mut |current| {
            assert!(current.is_none());
            Some(record(1))
        })
        .unwrap();
    assert_eq!(
        store.load(&wid(1)).unwrap().unwrap().wallet_name,
        "Personal"
    );
    let updated = store
        .update(&wid(1), &mut |current| {
            let mut r = current.unwrap();
            r.wallet_name = "Renamed".into();
            Some(r)
        })
        .unwrap();
    assert_eq!(updated.unwrap().wallet_name, "Renamed");
    // Returning None leaves the record as it is.
    store.update(&wid(1), &mut |_| None).unwrap();
    assert_eq!(store.load(&wid(1)).unwrap().unwrap().wallet_name, "Renamed");
    assert_eq!(store.wallets().unwrap(), vec![wid(1)]);
    assert_eq!(store.record_writes(), 2);
}

#[test]
fn failure_injection_per_step() {
    let store = MemorySyncStore::new();
    store.fail_once(Step::RecordWrite, StoreError::NoSpace);
    assert_eq!(
        store.update(&wid(1), &mut |_| Some(record(1))),
        Err(StoreError::NoSpace)
    );
    assert_eq!(store.load(&wid(1)), Ok(None), "nothing written");
    store.update(&wid(1), &mut |_| Some(record(1))).unwrap();
    store.corrupt(&wid(1));
    assert_eq!(store.load(&wid(1)), Err(StoreError::Corrupted));
}

#[test]
fn incoming_copies_become_pending_only_when_finished() {
    let store = MemorySyncStore::new();
    let peer = PeerId([9; 32]);
    let mut part = store.begin_incoming(&wid(1), &peer).unwrap();
    part.append(b"abc").unwrap();
    assert!(store.has_partial(&wid(1), &peer));
    assert!(store.read_pending(&wid(1), &peer).is_err());
    part.append(b"def").unwrap();
    part.finish().unwrap();
    assert!(!store.has_partial(&wid(1), &peer));
    assert_eq!(store.read_pending(&wid(1), &peer).unwrap(), b"abcdef");
    assert_eq!(store.pending_peers(&wid(1)).unwrap(), vec![peer]);
    // A newer copy replaces the older one.
    let mut part = store.begin_incoming(&wid(1), &peer).unwrap();
    part.append(b"new").unwrap();
    part.finish().unwrap();
    assert_eq!(store.read_pending(&wid(1), &peer).unwrap(), b"new");
    // Aborted partials leave nothing behind.
    let mut part = store.begin_incoming(&wid(1), &peer).unwrap();
    part.append(b"x").unwrap();
    part.abort();
    assert!(!store.has_partial(&wid(1), &peer));
    assert_eq!(store.read_pending(&wid(1), &peer).unwrap(), b"new");
    store.delete_pending(&wid(1), &peer).unwrap();
    assert!(store.pending_peers(&wid(1)).unwrap().is_empty());
}

#[test]
fn storage_full_while_receiving_is_reported() {
    let store = MemorySyncStore::new();
    let peer = PeerId([9; 32]);
    store.fail_once(Step::IncomingAppend, StoreError::NoSpace);
    let mut part = store.begin_incoming(&wid(1), &peer).unwrap();
    assert_eq!(part.append(b"abc"), Err(StoreError::NoSpace));
    part.abort();
    store.fail_once(Step::IncomingFinish, StoreError::NoSpace);
    let mut part = store.begin_incoming(&wid(1), &peer).unwrap();
    part.append(b"abc").unwrap();
    assert_eq!(part.finish(), Err(StoreError::NoSpace));
    assert!(store.pending_peers(&wid(1)).unwrap().is_empty());
    assert!(!store.has_partial(&wid(1), &peer));
}

#[test]
fn clocks_are_settable() {
    let mono = FakeMonoClock::new();
    mono.advance(Duration::from_secs(5));
    assert_eq!(mono.now(), Duration::from_secs(5));
    let wall = FakeWallClock::new(100);
    wall.set(200);
    assert_eq!(wall.unix_now(), 200);
}

#[test]
fn wallet_source_streams_stored_bytes_and_their_digest() {
    let source = FakeWalletSource::new();
    source.set("Personal", b"ciphertext".to_vec());
    let (size, mut reader) = source.open("Personal").unwrap();
    assert_eq!(size, 10);
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"ciphertext");
    let digest = source.digest("Personal").unwrap().unwrap();
    assert_eq!(digest, wallet_sync::record::sha256(b"ciphertext"));
    assert_eq!(source.digest("Missing").unwrap(), None);
    assert!(source.open("Missing").is_err());
}

#[test]
fn merger_fake_scripts_outcomes_and_records_requests() {
    let merger = FakeMerger::new();
    merger.push(MergeOutcome::Locked);
    let request = MergeRequest {
        wallet: wid(1),
        wallet_name: "Personal".into(),
        peer: PeerId([2; 32]),
        claimed: StateVector::new(),
        peer_mark: None,
    };
    assert_eq!(merger.merge(&request), MergeOutcome::Locked);
    assert_eq!(merger.merge(&request), MergeOutcome::Unchanged, "default");
    assert_eq!(merger.requests().len(), 2);
}

#[test]
fn peer_ids_print_as_hex_only() {
    let peer = PeerId([0xab; 32]);
    assert_eq!(peer.to_hex(), "ab".repeat(32));
    assert_eq!(PeerId::from_hex(&"ab".repeat(32)), Some(peer));
    assert_eq!(PeerId::from_hex("zz"), None);
}
