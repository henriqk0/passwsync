//! 005 T019: the `ReceivedStore` port and its in-memory fake (data-model.md "Ports",
//! contracts/core-api-share.md): entries become visible only when complete, aborted or
//! dropped writers leave nothing, every step can fail.

use wallet_sync::ports::{PeerId, StoreError};
use wallet_sync::share::received::{ReceivedMeta, ReceivedStore};
use wallet_sync::testkit::{InMemoryReceivedStore, ReceivedStep};

const ID: [u8; 16] = [0x11; 16];
const SENDER: PeerId = PeerId([0x22; 32]);

fn ciphertext(len: usize) -> Vec<u8> {
    let mut bytes = b"PWSV\x02\x00".to_vec();
    bytes.resize(len, 0x5a);
    bytes
}

#[test]
fn an_entry_is_visible_only_after_finish() {
    let store = InMemoryReceivedStore::new();
    let mut writer = store.begin(ID, SENDER, 1_761_400_000).unwrap();
    let bytes = ciphertext(2500);
    for chunk in bytes.chunks(1000) {
        writer.append(chunk).unwrap();
    }
    assert!(
        store.list().unwrap().is_empty(),
        "not visible while partial"
    );
    assert_eq!(store.partial_count(), 1);
    writer.finish().unwrap();
    assert_eq!(store.partial_count(), 0);
    assert_eq!(
        store.list().unwrap(),
        vec![ReceivedMeta {
            id: ID,
            sender: SENDER,
            received_at: 1_761_400_000,
            size: 2500,
        }]
    );
    assert_eq!(store.read(ID).unwrap(), bytes, "ciphertext stored verbatim");
}

#[test]
fn an_aborted_or_dropped_writer_leaves_nothing() {
    let store = InMemoryReceivedStore::new();
    let mut writer = store.begin(ID, SENDER, 1).unwrap();
    writer.append(&ciphertext(100)).unwrap();
    writer.abort();
    assert!(store.list().unwrap().is_empty());
    assert_eq!(store.partial_count(), 0);

    let mut writer = store.begin(ID, SENDER, 1).unwrap();
    writer.append(&ciphertext(100)).unwrap();
    drop(writer);
    assert!(store.list().unwrap().is_empty());
    assert_eq!(store.partial_count(), 0, "drop = abort");
}

#[test]
fn list_read_and_delete() {
    let store = InMemoryReceivedStore::new();
    for (i, at) in [(1u8, 30u64), (2, 10), (3, 20)] {
        let mut w = store.begin([i; 16], SENDER, at).unwrap();
        w.append(&ciphertext(100 + usize::from(i))).unwrap();
        w.finish().unwrap();
    }
    let listed: Vec<u64> = store
        .list()
        .unwrap()
        .iter()
        .map(|m| m.received_at)
        .collect();
    assert_eq!(listed, vec![10, 20, 30], "oldest first");
    store.delete([2; 16]).unwrap();
    assert_eq!(store.list().unwrap().len(), 2);
    assert_eq!(store.read([2; 16]), Err(StoreError::NotFound));
    assert_eq!(store.delete([2; 16]), Err(StoreError::NotFound));
    assert_eq!(store.read([9; 16]), Err(StoreError::NotFound));
}

#[test]
fn faults_at_every_step_leave_no_usable_entry() {
    for (step, error) in [
        (ReceivedStep::Begin, StoreError::NoSpace),
        (ReceivedStep::Append, StoreError::NoSpace),
        (ReceivedStep::Append, StoreError::Io),
        (ReceivedStep::Finish, StoreError::Io),
        (ReceivedStep::Finish, StoreError::NoSpace),
    ] {
        let store = InMemoryReceivedStore::new();
        store.fail_once(step, error);
        let outcome = (|| {
            let mut w = store.begin(ID, SENDER, 1)?;
            w.append(&ciphertext(500))?;
            w.finish()
        })();
        assert_eq!(outcome, Err(error), "{step:?}");
        assert!(store.list().unwrap().is_empty(), "{step:?}");
        assert_eq!(store.partial_count(), 0, "{step:?}");
    }
    let store = InMemoryReceivedStore::new();
    let mut w = store.begin(ID, SENDER, 1).unwrap();
    w.append(&ciphertext(100)).unwrap();
    w.finish().unwrap();
    for step in [ReceivedStep::List, ReceivedStep::Read, ReceivedStep::Delete] {
        store.fail_once(step, StoreError::Io);
    }
    assert_eq!(store.list(), Err(StoreError::Io));
    assert_eq!(store.read(ID), Err(StoreError::Io));
    assert_eq!(store.delete(ID), Err(StoreError::Io));
    assert_eq!(
        store.list().unwrap().len(),
        1,
        "a failed delete keeps the entry"
    );
}

#[test]
fn metadata_is_non_secret_and_debug_shows_no_id() {
    let meta = ReceivedMeta {
        id: [0xAB; 16],
        sender: SENDER,
        received_at: 5,
        size: 79,
    };
    let text = format!("{meta:?}");
    assert!(!text.contains("171") && !text.contains("abab"), "{text}");
}
