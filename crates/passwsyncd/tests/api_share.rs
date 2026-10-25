//! 005 T034: sender routes over raw HTTP (contracts/http-api-share.md): `GET /api/share`,
//! `POST /api/wallets/{name}/share`, `POST /api/share/accept`.

mod common;

use std::fs;
use std::time::Duration;

use common::server::TestServer;
use common::share::*;
use common::sync::*;
use serde_json::json;

#[test]
fn with_networking_off_sharing_is_unavailable() {
    let server = TestServer::start();
    let s = server.login();
    let view = server.api(&s, "GET", "/api/share", None).json();
    assert_eq!(view["available"], false);
    assert_eq!(view["unavailable_reason"], "networking_off");
    assert_eq!(view["invitation"], serde_json::Value::Null);
    assert_eq!(view["receive"], serde_json::Value::Null);
    assert_eq!(view["received"], json!([]));
    assert_eq!(view["notices"], json!([]));
    assert_eq!(view["peers"], json!([]));
    let body = json!({"name": "W", "password": PASSWORD, "password_confirm": PASSWORD});
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets", Some(&body.to_string()))
            .status,
        201
    );
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/W/share",
        Some(&json!({"device_id": "ab".repeat(32)}).to_string()),
    );
    assert_eq!(resp.status, 409);
    assert_eq!(resp.error_code(), "networking_off");
}

#[test]
fn an_invitation_has_the_documented_shape_and_code_only_while_active() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let b_id = b.device_id();
    let resp = invite(&a, "Personal", &b_id);
    assert_eq!(resp.status, 200, "{}", resp.text());
    let inv = resp.json();
    assert_eq!(inv["state"], "active");
    assert_eq!(inv["wallet"], "Personal");
    assert_eq!(inv["recipient"]["device_id"], b_id.as_str());
    assert_eq!(inv["recipient"]["name"], "Phone");
    assert!(inv["recipient"]["fingerprint"].as_str().unwrap().len() >= 19);
    let code = inv["code"].as_str().unwrap();
    assert_eq!(code.len(), 9);
    assert_eq!(&code[4..5], " ");
    assert!(inv["expires_in"].as_u64().unwrap() > 290);
    assert!(inv["qr"]["size"].as_u64().unwrap() > 29);
    assert!(!inv["qr"]["path"].as_str().unwrap().is_empty());
    let qr_text = inv["qr_text"].as_str().unwrap();
    assert!(qr_text.starts_with(&format!(
        "passwsync://share?v=1&code={}&id={}&addr=",
        code.replace(' ', ""),
        a.device_id()
    )));
    assert_eq!(inv["progress"], serde_json::Value::Null);
    assert_eq!(inv["reason"], serde_json::Value::Null);

    let view = share_state(&a);
    assert_eq!(view["available"], true);
    assert_eq!(view["unavailable_reason"], serde_json::Value::Null);
    let peers = view["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["device_id"], b_id.as_str());
    assert_eq!(peers[0]["status"], "connected");
    assert_eq!(peers[0]["share"], "supported");
    assert_eq!(view["invitation"]["code"], code);

    // After redemption no code, QR or QR text is shown any more.
    let resp = receive(&b, &code.replace(' ', ""), Some(&a.device_id()), None);
    assert_eq!(resp.status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let inv = share_state(&a)["invitation"].clone();
    assert_eq!(inv["code"], serde_json::Value::Null);
    assert_eq!(inv["qr"], serde_json::Value::Null);
    assert_eq!(inv["qr_text"], serde_json::Value::Null);
}

#[test]
fn share_route_errors() {
    let (a, b) = paired("Laptop", "Phone");
    let b_id = b.device_id();
    // Unknown wallet.
    let resp = invite(&a, "Missing", &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "wallet_not_found")
    );
    // Locked wallet.
    a.create_wallet("Personal");
    assert_eq!(
        a.api("POST", "/api/wallets/Personal/lock", None).status,
        200
    );
    let resp = invite(&a, "Personal", &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (423, "wallet_locked")
    );
    a.unlock("Personal");
    // Not a pinned device; not a device id at all.
    let resp = invite(&a, "Personal", &"cd".repeat(32));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "device_not_found")
    );
    let resp = invite(&a, "Personal", "nope");
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_device_id")
    );
    // A wallet whose file no longer matches its record is not eligible.
    a.create_wallet("Other");
    let other = fs::read(a.wallet_file("Other")).unwrap();
    fs::write(a.wallet_file("Personal"), other).unwrap();
    let resp = invite(&a, "Personal", &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "not_eligible")
    );
    let reason = resp.json()["reason"].as_str().unwrap().to_string();
    assert!(
        ["changed", "possible_rollback"].contains(&reason.as_str()),
        "{reason}"
    );
    // At most 5 invitations per 10 minutes.
    for _ in 0..5 {
        assert_eq!(invite(&a, "Other", &b_id).status, 200);
    }
    let resp = invite(&a, "Other", &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (429, "too_many_invitations")
    );
    // Malformed body.
    let resp = a.api("POST", "/api/wallets/Other/share", Some("{\"x\":1}"));
    assert_eq!(resp.status, 400);
}

#[test]
fn accept_route_errors() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let b_id = b.device_id();
    let resp = accept(&a, &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "nothing_pending")
    );
    let code = invite_code(&a, "Personal", &b_id);
    let resp = accept(&a, &b_id);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "nothing_pending"),
        "not redeemed yet"
    );
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let resp = accept(&a, &"ef".repeat(32));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "share_mismatch")
    );
    // Locking the wallet cancels the invitation; accept then reports wallet_locked or
    // nothing pending (the invitation is gone).
    assert_eq!(
        a.api("POST", "/api/wallets/Personal/lock", None).status,
        200
    );
    let resp = accept(&a, &b_id);
    assert_eq!(resp.status, 409);
    assert!(
        ["wallet_locked", "nothing_pending"].contains(&resp.error_code().as_str()),
        "{}",
        resp.text()
    );
    assert_eq!(invitation_state(&a), "cancelled");
}

#[test]
fn only_the_share_route_counts_as_activity_on_the_wallet() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let b_id = b.device_id();
    // Background route and other share routes do not touch the idle timer.
    a.server.clock.advance(Duration::from_secs(14 * 60));
    share_state(&a);
    let _ = accept(&a, &b_id);
    a.server.clock.advance(Duration::from_secs(2 * 60));
    a.server.running().sweep_now();
    let unlocked = a.api("GET", "/api/state", None).json()["wallets"][0]["unlocked"].clone();
    assert_eq!(unlocked, false, "locked by the idle timer");
    // The share route does.
    a.unlock("Personal");
    a.server.clock.advance(Duration::from_secs(14 * 60));
    assert_eq!(invite(&a, "Personal", &b_id).status, 200);
    a.server.clock.advance(Duration::from_secs(2 * 60));
    a.server.running().sweep_now();
    let unlocked = a.api("GET", "/api/state", None).json()["wallets"][0]["unlocked"].clone();
    assert_eq!(unlocked, true, "the share route reset the idle timer");
}
