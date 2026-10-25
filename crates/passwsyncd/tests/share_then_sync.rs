//! 005 T047 (US2): opening a received wallet creates its 004 sync record with the sender's
//! peer mark, so the first round finds both devices equal and later edits sync normally.

mod common;

use std::fs;
use std::time::Duration;

use common::server::wait_for;
use common::share::*;
use common::sync::*;
use passwsyncd::sync_store::FileSyncStore;
use vault_core::{DeviceId, FixedClock, MasterPassword, Vault};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::sha256;

fn peer_id(hex: &str) -> PeerId {
    PeerId::from_hex(hex).unwrap()
}

fn open_vault(path: &std::path::Path) -> Vault {
    Vault::unlock(
        &fs::read(path).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("check").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap()
}

#[test]
fn the_record_carries_the_sender_mark_and_the_first_round_transfers_nothing() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    let id = share_to(&a, &b, "Personal");
    assert_eq!(open_received(&b, &id, "Shared", PASSWORD).status, 200);

    let file = fs::read(b.wallet_file("Shared")).unwrap();
    let vault = open_vault(&b.wallet_file("Shared"));
    let store = FileSyncStore::new(b.server.fx.home.join(".local/share/passwsync/sync"));
    let record = store
        .load(&vault.wallet_id())
        .unwrap()
        .expect("record created");
    assert_eq!(record.wallet_name, "Shared");
    assert_eq!(record.digest, sha256(&file), "digest of the received bytes");
    assert_eq!(&record.state, vault.state(), "authenticated state");
    let a_peer = peer_id(&a.device_id());
    assert_eq!(
        record.peers.get(&a_peer).and_then(|p| p.peer_mark.clone()),
        Some(vault.state().clone()),
        "peer_mark[sender] = the state received"
    );

    // The first round between the two finds them equal: nothing is copied or merged.
    let rounds_before = b.server.log_text().matches("sync round end").count();
    assert_eq!(
        b.api("POST", "/api/sync/now", Some(r#"{"wallet":null}"#))
            .status,
        202
    );
    assert!(wait_for(Duration::from_secs(10), || b
        .server
        .log_text()
        .matches("sync round end")
        .count()
        > rounds_before));
    for log in [a.server.log_text(), b.server.log_text()] {
        assert!(!log.contains("sync pending stored"), "{log}");
        assert!(!log.contains("sync merged"), "{log}");
    }
    assert_eq!(fs::read(b.wallet_file("Shared")).unwrap(), file);

    // A later edit on A transfers normally.
    a.add("Personal", "Mail", "u2", "p2", "", "");
    assert!(
        wait_for(Duration::from_secs(15), || b.titles("Shared")
            == ["Bank", "Mail"]),
        "B: {:?}\n{}",
        b.titles("Shared"),
        b.server.log_text()
    );
    // The mark only rises (an older offer from A would be flagged as in 004).
    let record = store.load(&vault.wallet_id()).unwrap().unwrap();
    let mark = record
        .peers
        .get(&a_peer)
        .and_then(|p| p.peer_mark.clone())
        .unwrap();
    assert!(mark.dominates(vault.state()));
}
