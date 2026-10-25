//! 005 T078 (US5, FR-019, FR-020): every outcome of `POST /api/received/{id}/open`.

mod common;

use std::fs;

use common::share::*;
use common::sync::*;

fn pwsw(i: &Instance, id: &str) -> std::path::PathBuf {
    i.server
        .fx
        .home
        .join(format!(".local/share/passwsync/received/{id}.pwsw"))
}

fn still_listed(i: &Instance, id: &str) -> bool {
    received(i).iter().any(|r| r["id"] == id)
}

#[test]
fn failures_keep_the_entry_and_never_echo_the_password() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    let id = share_to(&a, &b, "Personal");
    let secret = "SECRET-WRONG-PASSWORD-MARKER";

    let resp = open_received(&b, &id, "Shared", secret);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (422, "invalid_password_or_corrupted")
    );
    assert!(!resp.text().contains(secret));
    assert!(still_listed(&b, &id), "retry allowed");

    let resp = open_received(&b, &id, ".bad", PASSWORD);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_name")
    );
    b.create_wallet("Taken");
    let resp = open_received(&b, &id, "Taken", PASSWORD);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "wallet_exists")
    );
    assert!(still_listed(&b, &id));

    // A storage failure creates nothing and keeps the entry.
    let wallets = b.server.fx.wallets_dir.clone();
    common::set_mode(&wallets, 0o500);
    let resp = open_received(&b, &id, "Shared", PASSWORD);
    common::set_mode(&wallets, 0o700);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (500, "storage_error")
    );
    assert!(!b.wallet_file("Shared").exists());
    assert!(still_listed(&b, &id));

    // Damaged ciphertext: a broken header is a malformed file, a broken body is the generic
    // error; both stay and can be discarded.
    let path = pwsw(&b, &id);
    let good = fs::read(&path).unwrap();
    let mut header = good.clone();
    header[0] = b'X';
    fs::write(&path, &header).unwrap();
    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (422, "malformed_file")
    );
    let mut body = good.clone();
    let last = body.len() - 1;
    body[last] ^= 1;
    fs::write(&path, &body).unwrap();
    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (422, "invalid_password_or_corrupted")
    );
    assert!(still_listed(&b, &id));
    assert_eq!(
        b.api("POST", &format!("/api/received/{id}/discard"), None)
            .status,
        200
    );
    assert!(!b.server.log_text().contains(secret));
    assert!(!b.server.log_text().contains(PASSWORD));
}

#[test]
fn a_wallet_already_held_is_reported_with_its_local_name() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let id = share_to(&a, &b, "Personal");
    assert_eq!(open_received(&b, &id, "Mine", PASSWORD).status, 200);
    let id = share_to(&a, &b, "Personal");
    let resp = open_received(&b, &id, "Second", PASSWORD);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "already_present")
    );
    assert_eq!(resp.json()["existing"], "Mine");
    assert!(!b.wallet_file("Second").exists(), "no second wallet");
    assert!(!still_listed(&b, &id), "received files deleted");
    assert!(!pwsw(&b, &id).exists());
    let notices = share_state(&b)["notices"].as_array().unwrap().clone();
    assert!(
        notices
            .iter()
            .any(|n| n["kind"] == "already_present" && n["existing"] == "Mine")
    );
    assert!(
        b.server
            .log_text()
            .contains("received wallet already present peer=")
    );
}
