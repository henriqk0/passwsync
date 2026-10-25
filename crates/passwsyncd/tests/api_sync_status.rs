//! 004 T117 (US5): sync status routes and "Sync now" (contracts/http-api-sync.md).

mod common;

use std::time::Duration;

use common::server::{TestServer, wait_for};
use common::sync::*;
use serde_json::json;

const WALLET: &str = "Personal";

#[test]
fn networking_off_shows_no_sync_and_refuses_sync_now() {
    let server = TestServer::start();
    let s = server.login();
    let body = json!({"name": WALLET, "password": PASSWORD, "password_confirm": PASSWORD});
    server.api(&s, "POST", "/api/wallets", Some(&body.to_string()));
    let state = server.api(&s, "GET", "/api/state", None).json();
    assert!(
        state["wallets"][0].get("sync").is_none(),
        "no sync object: sync off"
    );
    let sync = server.api(&s, "GET", "/api/sync", None).json();
    assert_eq!(sync["enabled"], false);
    let now = server.api(&s, "POST", "/api/sync/now", Some(r#"{"wallet":null}"#));
    assert_eq!(now.status, 409);
    assert_eq!(now.error_code(), "networking_off");
    let detail = server
        .api(&s, "GET", &format!("/api/wallets/{WALLET}/sync"), None)
        .json();
    assert_eq!(detail["state"], "sync_off");
}

#[test]
fn status_follows_the_wallet_and_its_peers() {
    let a = instance("Laptop");
    let b = instance("Phone");
    a.create_wallet(WALLET);
    // Unlocked here, never matched with a peer yet.
    let state = a.api("GET", "/api/state", None).json();
    assert_eq!(state["wallets"][0]["sync"]["state"], "not_synced");
    assert_eq!(state["wallets"][0]["sync"]["reason"], "no_peer");
    // B has the file but never unlocked it here.
    pair_via(&a, &b, a.peer_port);
    copy_wallet_file(&a, &b, WALLET);
    let state = b.api("GET", "/api/state", None).json();
    assert_eq!(state["wallets"][0]["sync"]["state"], "not_synced");
    assert_eq!(state["wallets"][0]["sync"]["reason"], "unlock_once");
    b.unlock(WALLET);
    a.add(WALLET, "x", "", "", "", "");
    assert!(wait_for(Duration::from_secs(10), || {
        let s = b.api("GET", "/api/state", None).json();
        s["wallets"][0]["sync"]["state"] == "in_sync"
            && s["wallets"][0]["sync"]["last_synced_at"].is_u64()
    }));
    // The position is refreshed by the round B starts after merging (quiet period).
    assert!(wait_for(Duration::from_secs(10), || {
        b.api("GET", &format!("/api/wallets/{WALLET}/sync"), None)
            .json()["peers"][0]["position"]
            == "in_sync"
    }));
    let detail = b
        .api("GET", &format!("/api/wallets/{WALLET}/sync"), None)
        .json();
    assert_eq!(detail["state"], "in_sync");
    assert_eq!(detail["peers"][0]["peer"], a.device_id());
    assert_eq!(detail["peers"][0]["name"], "Laptop");
    assert_eq!(detail["peers"][0]["position"], "in_sync");
    assert!(detail["pending"].as_array().unwrap().is_empty());
    let sync = b.api("GET", "/api/sync", None).json();
    assert_eq!(sync["enabled"], true);
    assert_eq!(sync["interval_minutes"], 60);
    assert_eq!(sync["peers"][0]["device_id"], a.device_id());
    assert_eq!(sync["peers"][0]["sync"], "supported");
    assert_eq!(sync["peers"][0]["last_outcome"], "ok");
    // Locked: still no credential content, the state is still shown.
    b.api("POST", &format!("/api/wallets/{WALLET}/lock"), None);
    let detail = b.api("GET", &format!("/api/wallets/{WALLET}/sync"), None);
    assert_eq!(detail.status, 200);
    assert!(!detail.text().contains("\"x\""));
}

#[test]
fn sync_now_starts_a_round_and_is_coalesced() {
    let a = instance("Laptop");
    let b = instance("Phone");
    a.create_wallet(WALLET);
    pair_via(&a, &b, a.peer_port);
    copy_wallet_file(&a, &b, WALLET);
    b.unlock(WALLET);
    std::thread::sleep(Duration::from_millis(500));
    let before = a.server.log_text().matches("sync round start").count();
    let resp = a.api("POST", "/api/sync/now", Some(r#"{"wallet":null}"#));
    assert_eq!(resp.status, 202);
    assert!(
        wait_for(Duration::from_secs(2), || {
            a.server.log_text().matches("sync round start").count() > before
        }),
        "a round within 2 s"
    );
    assert_eq!(
        a.api("POST", "/api/sync/now", Some(r#"{"wallet":"Personal"}"#))
            .status,
        202
    );
    assert_eq!(
        a.api("POST", "/api/sync/now", Some(r#"{"wallet":"Nope"}"#))
            .status,
        404
    );
    assert_eq!(
        a.api("POST", "/api/sync/now", Some(r#"{"wallet":"../x"}"#))
            .status,
        400
    );
    assert_eq!(a.api("GET", "/api/sync/now", None).status, 405);
}
