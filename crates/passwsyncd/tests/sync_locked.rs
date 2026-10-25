//! 004 T091 (US3, SC-001): a locked receiver stores ciphertext only and merges at unlock.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::server::wait_for;
use common::sync::*;

const WALLET: &str = "Personal";

fn pending_count(i: &Instance) -> usize {
    let dir = i.server.fx.home.join(".local/share/passwsync/sync");
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|d| fs::read_dir(d.path()).into_iter().flatten().flatten())
        .filter(|f| f.file_name().to_string_lossy().starts_with("pending-"))
        .count()
}

#[test]
fn a_locked_device_stores_the_copy_and_merges_it_at_unlock() {
    let a = instance("Laptop");
    let b = instance("Phone");
    a.create_wallet(WALLET);
    pair_via(&a, &b, a.peer_port);
    copy_wallet_file(&a, &b, WALLET);
    b.unlock(WALLET);
    assert_eq!(
        b.api("POST", &format!("/api/wallets/{WALLET}/lock"), None)
            .status,
        200
    );
    let file_before = fs::read(b.wallet_file(WALLET)).unwrap();

    a.add(WALLET, "SECRET-TITLE-WHILE-LOCKED", "u", "p", "", "");
    assert!(wait_for(Duration::from_secs(10), || pending_count(&b) == 1));
    assert_eq!(
        fs::read(b.wallet_file(WALLET)).unwrap(),
        file_before,
        "wallet file untouched"
    );
    // Nothing of the wallet's content is served while it is locked.
    let resp = b.api(
        "POST",
        &format!("/api/wallets/{WALLET}/search"),
        Some(r#"{"query":""}"#),
    );
    assert_eq!(resp.status, 423);
    assert!(!resp.text().contains("SECRET-TITLE"));
    assert!(
        b.server
            .log_text()
            .contains("sync pending stored wallet=Personal")
    );

    let started = Instant::now();
    b.unlock(WALLET);
    assert!(
        wait_for(Duration::from_secs(10), || b.titles(WALLET)
            == ["SECRET-TITLE-WHILE-LOCKED"]),
        "merged within 10 s of unlock"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(pending_count(&b), 0, "pending removed once saved");
    assert_ne!(
        fs::read(b.wallet_file(WALLET)).unwrap(),
        file_before,
        "merged result saved"
    );
}
