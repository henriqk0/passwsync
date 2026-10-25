//! 005 T035: recipient routes over raw HTTP (contracts/http-api-share.md): `POST /api/receive`
//! and `POST /api/received/{received_id}/open`.

mod common;

use common::server::TestServer;
use common::share::*;
use common::sync::*;
use serde_json::json;

#[test]
fn receive_validation_errors() {
    let (a, b) = paired("Laptop", "Phone");
    let a_id = a.device_id();
    let addr = format!("127.0.0.1:{}", a.peer_port);
    for code in ["1234567", "1234567a", "123456789", ""] {
        let resp = receive(&b, code, Some(&a_id), None);
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (400, "invalid_code"),
            "{code}"
        );
    }
    // Spaces and dashes are removed before checking.
    for bad in [
        "8.8.8.8:27472",
        "127.0.0.1",
        "host.example:1",
        "127.0.0.1:0",
    ] {
        let resp = receive(&b, "1234-5678", None, Some(bad));
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (400, "invalid_address"),
            "{bad}"
        );
    }
    let resp = receive(&b, "1234 5678", Some("xyz"), None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_device_id")
    );
    let resp = receive(&b, "12345678", None, None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "missing_sender")
    );
    let resp = receive(&b, "12345678", Some(&"cd".repeat(32)), None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "device_not_found")
    );
    let resp = receive(&b, "12345678", Some(&b.device_id()), None);
    assert_eq!((resp.status, resp.error_code().as_str()), (409, "self"));
    // One redemption at a time (this one waits for A's decision).
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a_id), Some(&addr)).status, 202);
    assert!(wait_receive(&b, "awaiting_sender"), "{}", share_state(&b));
    let resp = receive(&b, "12345678", Some(&a_id), None);
    assert_eq!((resp.status, resp.error_code().as_str()), (409, "busy"));
}

#[test]
fn receive_with_networking_off_is_refused() {
    let server = TestServer::start();
    let s = server.login();
    let body = json!({"code": "12345678", "device_id": "ab".repeat(32), "address": null});
    let resp = server.api(&s, "POST", "/api/receive", Some(&body.to_string()));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "networking_off")
    );
}

#[test]
fn a_full_receive_lists_a_received_wallet_that_opens_with_the_master_password() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "me", "pw1", "", "");
    let code = invite_code(&a, "Personal", &b.device_id());
    let resp = receive(&b, &code, Some(&a.device_id()), None);
    assert_eq!(resp.status, 202);
    assert_eq!(resp.json(), json!({}));
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let view = share_state(&b)["receive"].clone();
    assert_eq!(view["state"], "awaiting_sender");
    assert_eq!(view["sender"]["device_id"], a.device_id().as_str());
    assert!(view["seconds_left"].as_u64().unwrap() > 0);
    assert_eq!(accept(&a, &b.device_id()).status, 200);
    assert!(wait_receive(&b, "stored"), "{}", share_state(&b));
    let view = share_state(&b);
    let id = view["receive"]["received_id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    let listed = view["received"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], id.as_str());
    assert_eq!(listed[0]["sender"]["device_id"], a.device_id().as_str());
    assert_eq!(listed[0]["sender"]["name"], "Laptop");
    let at = listed[0]["received_at"].as_u64().unwrap();
    assert_eq!(listed[0]["expires_at"].as_u64().unwrap(), at + 86_400);
    assert!(listed[0]["size"].as_u64().unwrap() >= 79);

    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.json(), json!({"name": "Shared", "unlocked": true}));
    assert_eq!(b.titles("Shared"), ["Bank"]);
    let state = b.api("GET", "/api/state", None).json();
    let wallet = state["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["name"] == "Shared")
        .cloned()
        .unwrap();
    assert_eq!(wallet["unlocked"], true);
    assert!(wallet["sync"].is_object(), "{wallet}");
    assert!(
        received(&b).is_empty(),
        "received files deleted after opening"
    );
}

#[test]
fn bad_received_ids_are_not_found() {
    let (_a, b) = paired("Laptop", "Phone");
    for id in ["0".repeat(32), "xyz".to_string(), "AB".repeat(16)] {
        let resp = open_received(&b, &id, "Shared", PASSWORD);
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (404, "received_not_found"),
            "{id}"
        );
    }
}

#[test]
fn a_qr_device_id_that_does_not_match_the_address_sends_nothing() {
    // C answers at the address but B expects A's identity (FR-012).
    let (a, b) = paired("Laptop", "Phone");
    let c = instance("Tablet");
    pair_via(&c, &b, c.peer_port);
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    let c_addr = format!("127.0.0.1:{}", c.peer_port);
    assert_eq!(
        receive(&b, &code, Some(&a.device_id()), Some(&c_addr)).status,
        202
    );
    assert!(wait_receive(&b, "failed"), "{}", share_state(&b));
    assert_eq!(share_state(&b)["receive"]["reason"], "id_mismatch");
    assert_eq!(invitation_state(&a), "active", "nothing reached A");
    assert!(share_state(&c)["invitation"].is_null());
}

#[test]
fn a_manual_address_finds_the_pinned_sender() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    let addr = format!("127.0.0.1:{}", a.peer_port);
    assert_eq!(receive(&b, &code, None, Some(&addr)).status, 202);
    assert!(
        wait_invitation(&a, "awaiting_acceptance"),
        "{}",
        share_state(&a)
    );
    assert_eq!(
        share_state(&b)["receive"]["sender"]["device_id"],
        a.device_id().as_str()
    );
}
