//! 005 T069 (US4, SC-004): storage faults, crashes and an oversize offer leave no partial
//! data and no wallet on the recipient.

mod common;

use std::fs;
use std::sync::Arc;

use common::server::{Fixture, TestServer};
use common::share::*;
use common::sync::*;
use passwsyncd::share_store::ReceiveFault;
use wallet_sync::ports::{PeerId, ReceivedStore};
use wallet_sync::share::codec::{AbortReason, ShareMsg};
use wallet_sync::share::{OutFrame, ShareDeps, ShareEngine};
use wallet_sync::slots::TransferSlots;
use wallet_sync::testkit::{
    FakeMonoClock, FakeWallClock, FakeWalletSource, InMemoryReceivedStore, MemorySyncStore,
};
use zeroize::Zeroizing;

fn received_files(i: &Instance) -> Vec<String> {
    let dir = i.server.fx.home.join(".local/share/passwsync/received");
    fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |d| {
            d.map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        },
    )
}

#[test]
fn a_storage_fault_at_any_step_leaves_nothing_and_is_shown_on_both_sides() {
    for fault in [
        ReceiveFault::Create,
        ReceiveFault::Append,
        ReceiveFault::Fsync,
        ReceiveFault::Rename,
        ReceiveFault::DirFsync,
        ReceiveFault::MetaWrite,
    ] {
        let (a, b) = paired("Laptop", "Phone");
        a.create_wallet("Personal");
        let code = invite_code(&a, "Personal", &b.device_id());
        assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
        assert!(wait_invitation(&a, "awaiting_acceptance"));
        b.server.running().inject_receive_fault(fault);
        assert_eq!(accept(&a, &b.device_id()).status, 200);
        assert!(wait_receive(&b, "failed"), "{fault:?}: {}", share_state(&b));
        assert_eq!(share_state(&b)["receive"]["reason"], "storage", "{fault:?}");
        assert!(
            wait_invitation(&a, "failed"),
            "{fault:?}: {}",
            share_state(&a)
        );
        assert_eq!(share_state(&a)["invitation"]["reason"], "storage");
        assert!(
            received_files(&b).is_empty(),
            "{fault:?}: {:?}",
            received_files(&b)
        );
        assert!(received(&b).is_empty());
        let state = b.api("GET", "/api/state", None).json();
        assert_eq!(state["wallets"], serde_json::json!([]));
    }
}

#[test]
fn files_left_by_a_crash_of_the_recipient_are_cleaned_at_start_up() {
    let (a, mut b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let dir = b.server.fx.home.join(".local/share/passwsync/received");
    let fx = std::mem::replace(&mut b.server.fx, Fixture::new(""));
    b.server.stop();
    // What a kill leaves behind (no orderly shutdown ran): a partial file from a transfer,
    // and a lone .pwsw from a kill between the rename and the meta write.
    for (name, bytes) in [
        (format!("{}.part", "ab".repeat(16)), vec![1u8; 300]),
        (format!("{}.pwsw", "cd".repeat(16)), vec![2u8; 300]),
    ] {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        common::set_mode(&path, 0o600);
    }
    let server = TestServer::start_in(fx);
    let session = server.login();
    let b = Instance {
        server,
        session,
        peer_port: b.peer_port,
    };
    assert!(received_files(&b).is_empty(), "{:?}", received_files(&b));
    let log = b.server.log_text();
    assert!(log.contains("received cleaned (partial) count=1"));
    assert!(log.contains("received cleaned (orphan) count=1"));
}

#[test]
fn the_sender_going_away_fails_the_recipient_with_channel_lost() {
    let (mut a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    a.server.stop();
    assert!(wait_receive(&b, "failed"), "{}", share_state(&b));
    let reason = share_state(&b)["receive"]["reason"].clone();
    assert!(
        reason == "channel_lost" || reason == "cancelled_by_sender",
        "{reason}"
    );
    assert!(received_files(&b).is_empty());
}

fn engine(id: u8, received: &InMemoryReceivedStore) -> ShareEngine {
    ShareEngine::new(ShareDeps {
        store: Arc::new(MemorySyncStore::new()),
        received: Arc::new(received.clone()),
        source: Arc::new(FakeWalletSource::new()),
        mono: Arc::new(FakeMonoClock::new()),
        wall: Arc::new(FakeWallClock::new(1_000)),
        rng: Box::new(rand_core::OsRng),
        slots: TransferSlots::new(2),
        own_id: PeerId([id; 32]),
    })
}

#[test]
fn an_oversize_offer_aborts_as_too_large_before_any_byte_is_stored() {
    let received = InMemoryReceivedStore::new();
    let mut b = engine(2, &received);
    let a = PeerId([1; 32]);
    b.channel_up(a, 1, [5; 32], true);
    b.redeem(Some(a), Zeroizing::new("12345678".into()))
        .unwrap();
    b.sender_channel(a, 1);
    let rid = match b.poll_outgoing(a, 8).pop() {
        Some(OutFrame::Msg(ShareMsg::Redeem { rid, .. })) => rid,
        other => panic!("{other:?}"),
    };
    b.on_msg(
        a,
        1,
        ShareMsg::Pending {
            rid,
            seconds_left: 100,
        },
    );
    // Encoded and decoded as on the wire: the size field is a plain u32.
    let offer = ShareMsg::decode(
        &ShareMsg::Offer {
            rid,
            size: 64 * 1024 * 1024 + 1,
        }
        .encode(),
    )
    .unwrap();
    b.on_msg(a, 1, offer);
    let out = b.poll_outgoing(a, 8);
    assert!(out.iter().any(|f| matches!(
        f,
        OutFrame::Msg(ShareMsg::Abort {
            reason: AbortReason::TooLarge,
            ..
        })
    )));
    assert_eq!(b.view().receive.unwrap().reason, Some("too_large"));
    assert_eq!(received.partial_count(), 0);
    assert!(received.list().unwrap().is_empty());
}
