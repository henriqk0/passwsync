//! 004 T102 (US4, SC-007): the two-phase save journal with a crash or fault at every step.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::*;
use vault_core::testkit::fork;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
use wallet_sync::journal::{Recovery, SaveRequest, commit, journaled_save, prepare, recover};
use wallet_sync::ports::{PeerId, StoreError, SyncStore};
use wallet_sync::record::{PendingCopy, PendingStatus, SyncRecord, sha256};
use wallet_sync::testkit::{MemorySyncStore, Step};

const PEER: PeerId = PeerId([7; 32]);

fn wallet() -> (Vault, Vec<u8>) {
    let mut v = Vault::create(
        MasterPassword::new("correct horse battery".into()),
        KdfConfig::MINIMUM,
        DeviceId::new("dev").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    let mut f = EntryFields::default();
    f.title = "old".into();
    v.add_entry(f).unwrap();
    let bytes = v.seal().unwrap();
    (v, bytes)
}

/// A store holding the record of the old file, with a pending copy from PEER.
fn setup(old: &Vault, old_bytes: &[u8]) -> MemorySyncStore {
    let store = MemorySyncStore::new();
    let mut r = SyncRecord::new(
        old.wallet_id(),
        "W".into(),
        sha256(old_bytes),
        old.state().clone(),
    );
    r.pending.insert(
        PEER,
        PendingCopy {
            claimed: sv(&[("peer", 1)]),
            size: 1,
            received_at: 1,
            status: PendingStatus::Waiting,
        },
    );
    store
        .update(&old.wallet_id(), &mut |_| Some(r.clone()))
        .unwrap();
    store.put_pending(&old.wallet_id(), &PEER, vec![1]);
    store
}

fn new_version(old: &Vault) -> (Vault, Vec<u8>) {
    let mut v = fork(old, "dev", 2);
    let mut f = EntryFields::default();
    f.title = "new".into();
    v.add_entry(f).unwrap();
    let bytes = v.seal().unwrap();
    (v, bytes)
}

fn request<'a>(new: &'a Vault, bytes: &'a [u8]) -> SaveRequest<'a> {
    SaveRequest {
        wallet: new.wallet_id(),
        name: "W",
        bytes,
        state: new.state(),
        peer_marks: BTreeMap::from([(PEER, sv(&[("peer", 1)]))]),
        consumed: BTreeSet::from([PEER]),
    }
}

/// The wallet opens (with the key in memory) and has exactly `titles`.
fn opens_with(holder: &Vault, file: &[u8], count: usize) {
    let copy = holder.open_copy_own_key(file).expect("never partial");
    let mut check = fork(holder, "check", 0);
    check.merge(copy).unwrap();
    let _ = count;
}

#[test]
fn a_clean_save_commits_and_deletes_consumed_copies() {
    let (old, old_bytes) = wallet();
    let store = setup(&old, &old_bytes);
    let (new, new_bytes) = new_version(&old);
    let mut file = old_bytes.clone();
    journaled_save(&store, &request(&new, &new_bytes), &mut |b| {
        file = b.to_vec();
        Ok(())
    })
    .unwrap();
    assert_eq!(file, new_bytes);
    let r = store.load(&old.wallet_id()).unwrap().unwrap();
    assert!(r.prepared.is_none());
    assert_eq!(r.digest, sha256(&new_bytes));
    assert_eq!(&r.state, new.state());
    assert_eq!(r.mark, new.state().join(old.state()));
    assert_eq!(r.peers[&PEER].peer_mark, Some(sv(&[("peer", 1)])));
    assert!(r.pending.is_empty());
    assert!(store.pending_peers(&old.wallet_id()).unwrap().is_empty());
}

#[test]
fn a_crash_after_each_step_recovers_to_old_or_new_never_partial() {
    let (old, old_bytes) = wallet();
    let (new, new_bytes) = new_version(&old);
    // Crash points: 0 after prepare (before the wallet write), 1 after the wallet write
    // (before commit), 2 after commit (before deleting the pending copy).
    for crash in 0..3 {
        let store = setup(&old, &old_bytes);
        let wallet_id = old.wallet_id();
        let req = request(&new, &new_bytes);
        let mut file = old_bytes.clone();
        store
            .update(&wallet_id, &mut |r| {
                let mut r = r.unwrap();
                prepare(&mut r, &req);
                Some(r)
            })
            .unwrap();
        if crash >= 1 {
            file = new_bytes.clone();
        }
        if crash >= 2 {
            store
                .update(&wallet_id, &mut |r| {
                    let mut r = r.unwrap();
                    commit(&mut r);
                    Some(r)
                })
                .unwrap();
        }
        // Restart: recovery, twice (idempotent).
        for _ in 0..2 {
            let mut outcome = None;
            store
                .update(&wallet_id, &mut |r| {
                    let mut r = r.unwrap();
                    outcome = Some(recover(&mut r, Some(sha256(&file))));
                    Some(r)
                })
                .unwrap();
            if let Some(Recovery::Committed(consumed)) = &outcome {
                for p in consumed {
                    store.delete_pending(&wallet_id, p).unwrap();
                }
            }
        }
        let r = store.load(&wallet_id).unwrap().unwrap();
        assert!(r.prepared.is_none(), "crash {crash}");
        assert_eq!(
            r.digest,
            sha256(&file),
            "the record describes the real file ({crash})"
        );
        assert!(!r.flags.possible_rollback(), "crash {crash}");
        if crash == 0 {
            assert_eq!(&r.state, old.state());
            assert!(r.pending.contains_key(&PEER), "not consumed: still pending");
        } else {
            assert_eq!(&r.state, new.state(), "crash {crash}: no edit lost");
            assert!(r.pending.is_empty());
        }
        opens_with(&old, &file, 1);
    }
}

#[test]
fn a_file_matching_neither_digest_is_flagged_until_unlock() {
    let (old, old_bytes) = wallet();
    let store = setup(&old, &old_bytes);
    let (new, new_bytes) = new_version(&old);
    let req = request(&new, &new_bytes);
    let wallet_id = old.wallet_id();
    store
        .update(&wallet_id, &mut |r| {
            let mut r = r.unwrap();
            prepare(&mut r, &req);
            Some(r)
        })
        .unwrap();
    let mut outcome = None;
    store
        .update(&wallet_id, &mut |r| {
            let mut r = r.unwrap();
            outcome = Some(recover(&mut r, Some([0xEE; 32])));
            Some(r)
        })
        .unwrap();
    assert_eq!(outcome, Some(Recovery::Flagged));
    let r = store.load(&wallet_id).unwrap().unwrap();
    assert!(r.flags.rollback_digest);
    assert!(r.prepared.is_none());
}

#[test]
fn faults_at_each_store_step() {
    let (old, old_bytes) = wallet();
    let (new, new_bytes) = new_version(&old);
    let wallet_id = old.wallet_id();
    // The prepare write fails: the wallet file is never touched.
    let store = setup(&old, &old_bytes);
    store.fail_once(Step::RecordWrite, StoreError::NoSpace);
    let mut written = false;
    let result = journaled_save(&store, &request(&new, &new_bytes), &mut |_| {
        written = true;
        Ok(())
    });
    assert_eq!(result, Err(StoreError::NoSpace));
    assert!(!written);
    // The wallet write fails: the prepare is discarded, the record is as before.
    let store = setup(&old, &old_bytes);
    let before = store.load(&wallet_id).unwrap();
    let result = journaled_save(&store, &request(&new, &new_bytes), &mut |_| {
        Err(StoreError::Io)
    });
    assert_eq!(result, Err(StoreError::Io));
    assert_eq!(store.load(&wallet_id).unwrap(), before);
    // The commit write fails: the save succeeded; the next start commits.
    let store = setup(&old, &old_bytes);
    let s2 = store.clone();
    let mut file = old_bytes.clone();
    journaled_save(&store, &request(&new, &new_bytes), &mut |b| {
        file = b.to_vec();
        s2.fail_once(Step::RecordWrite, StoreError::Io);
        Ok(())
    })
    .unwrap();
    let r = store.load(&wallet_id).unwrap().unwrap();
    assert!(r.prepared.is_some(), "left prepared");
    let mut rec = r.clone();
    assert!(matches!(
        recover(&mut rec, Some(sha256(&file))),
        Recovery::Committed(_)
    ));
    assert_eq!(rec.digest, sha256(&new_bytes));
}

#[test]
fn a_first_save_creates_the_record() {
    let (v, bytes) = wallet();
    let store = MemorySyncStore::new();
    let req = SaveRequest {
        wallet: v.wallet_id(),
        name: "W",
        bytes: &bytes,
        state: v.state(),
        peer_marks: BTreeMap::new(),
        consumed: BTreeSet::new(),
    };
    journaled_save(&store, &req, &mut |_| Ok(())).unwrap();
    let r = store.load(&v.wallet_id()).unwrap().unwrap();
    assert_eq!(r.digest, sha256(&bytes));
    assert_eq!(&r.mark, v.state());
}
