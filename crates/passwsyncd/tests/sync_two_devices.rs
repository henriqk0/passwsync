//! 004 T063 (US1): two real service instances over loopback converge on add, edit and delete;
//! captured traffic carries no plaintext (SC-001, SC-005).

mod common;

use std::time::Duration;

use common::server::wait_for;
use common::sync::*;
use vault_core::{DeviceId, FixedClock, MasterPassword, Vault};

const WALLET: &str = "Wallet-Secret-Name";

#[test]
fn edits_on_one_device_appear_on_the_other_without_plaintext_on_the_wire() {
    let a = instance("Laptop-Secret-Name");
    let b = instance("Phone-Secret-Name");
    a.create_wallet(WALLET);
    a.add(
        WALLET,
        "TITLE-MARKER-1",
        "USER-MARKER-1",
        "PASSWORD-MARKER-1",
        "https://URL-MARKER-1.example",
        "NOTES-MARKER-1",
    );
    let (proxy, seen) = recording_proxy(a.peer_port);
    pair_via(&a, &b, proxy);
    // B holds the same wallet (copied by hand) and unlocks it once.
    copy_wallet_file(&a, &b, WALLET);
    b.unlock(WALLET);
    assert_eq!(b.titles(WALLET), ["TITLE-MARKER-1"]);

    // Add on A appears on B.
    let id = a.add(
        WALLET,
        "TITLE-MARKER-2",
        "USER-MARKER-2",
        "PASSWORD-MARKER-2",
        "",
        "",
    );
    assert!(
        wait_for(Duration::from_secs(15), || b.titles(WALLET)
            == ["TITLE-MARKER-1", "TITLE-MARKER-2"]),
        "B: {:?}\nA log:\n{}\nB log:\n{}",
        b.titles(WALLET),
        a.server.log_text(),
        b.server.log_text()
    );
    // Edit on A appears on B.
    let edit = serde_json::json!({"title": "TITLE-MARKER-3", "username": "USER-MARKER-3", "password": "PASSWORD-MARKER-3", "url": "", "notes": ""});
    assert_eq!(
        a.api(
            "PUT",
            &format!("/api/wallets/{WALLET}/entries/{id}"),
            Some(&edit.to_string())
        )
        .status,
        200
    );
    assert!(wait_for(Duration::from_secs(15), || b.titles(WALLET)
        == ["TITLE-MARKER-1", "TITLE-MARKER-3"]));
    // Delete on A disappears on B.
    assert_eq!(
        a.api(
            "DELETE",
            &format!("/api/wallets/{WALLET}/entries/{id}"),
            None
        )
        .status,
        200
    );
    assert!(wait_for(Duration::from_secs(15), || b.titles(WALLET)
        == ["TITLE-MARKER-1"]));
    // And B's changes reach A.
    b.add(WALLET, "TITLE-MARKER-4", "", "", "", "");
    assert!(wait_for(Duration::from_secs(15), || a.titles(WALLET)
        == ["TITLE-MARKER-1", "TITLE-MARKER-4"]));
    assert!(wait_for(Duration::from_secs(5), || b.titles(WALLET)
        == a.titles(WALLET)));

    // Identical state vectors and tombstones on both sides.
    let open = |path: &std::path::Path| {
        Vault::unlock(
            &std::fs::read(path).unwrap(),
            MasterPassword::new(PASSWORD.into()),
            DeviceId::new("check").unwrap(),
            Box::new(FixedClock::new(0)),
        )
        .unwrap()
    };
    assert!(wait_for(Duration::from_secs(10), || {
        open(&a.wallet_file(WALLET)).state() == open(&b.wallet_file(WALLET)).state()
    }));
    let (va, vb) = (open(&a.wallet_file(WALLET)), open(&b.wallet_file(WALLET)));
    assert_eq!(va.all_records().count(), vb.all_records().count());
    assert_eq!(
        va.all_records().filter(|e| e.is_deleted()).count(),
        1,
        "the tombstone is kept"
    );
    assert!(a.server.log_text().contains("sync round end"));
    assert!(
        b.server
            .log_text()
            .contains("sync merged wallet=Wallet-Secret-Name")
    );

    // SC-005: nothing readable crossed the network.
    let traffic = seen.lock().unwrap().clone();
    assert!(traffic.len() > 1000, "traffic was captured");
    let wallet_id = *va.wallet_id().as_bytes();
    for needle in [
        "TITLE-MARKER",
        "USER-MARKER",
        "PASSWORD-MARKER",
        "URL-MARKER",
        "NOTES-MARKER",
        WALLET,
        "Laptop-Secret-Name",
        "Phone-Secret-Name",
        PASSWORD,
    ] {
        assert!(
            !contains(&traffic, needle.as_bytes()),
            "{needle} crossed the network"
        );
    }
    assert!(
        !contains(&traffic, &wallet_id),
        "the wallet id crossed the network"
    );
}
