mod common;

use std::fs;

use common::mode;
use common::server::TestServer;
use serde_json::json;

const PW: &str = "MARKER-pw-correct-horse";

fn create_body(name: &str) -> String {
    json!({"name": name, "password": PW, "password_confirm": PW}).to_string()
}

#[test]
fn state_lists_settings_and_wallets_as_json() {
    let server = TestServer::start_with("auto_lock_minutes = 7\nclipboard_clear_seconds = 12\n");
    let s = server.login();
    let resp = server.api(&s, "GET", "/api/state", None);
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(
        resp.json(),
        json!({
            "settings": {"port": server.port, "auto_lock_minutes": 7, "clipboard_clear_seconds": 12},
            "wallets": []
        })
    );
}

#[test]
fn create_wallet_returns_201_and_writes_an_encrypted_private_file() {
    let server = TestServer::start();
    let s = server.login();
    let resp = server.api(&s, "POST", "/api/wallets", Some(&create_body("Personal")));
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.json(), json!({"name": "Personal", "unlocked": true}));
    let path = server.fx.wallets_dir.join("Personal.pwsw");
    assert_eq!(mode(&path), 0o600);
    let state = server.api(&s, "GET", "/api/state", None).json();
    assert_eq!(
        state["wallets"],
        json!([{"name": "Personal", "unlocked": true}])
    );
    assert!(!server.log_text().contains(PW));
}

#[test]
fn create_wallet_errors() {
    let server = TestServer::start();
    let s = server.login();
    let cases = [
        (
            json!({"name": "../x", "password": PW, "password_confirm": PW}),
            400,
            "invalid_name",
        ),
        (
            json!({"name": "", "password": PW, "password_confirm": PW}),
            400,
            "invalid_name",
        ),
        (
            json!({"name": "A", "password": PW, "password_confirm": "other"}),
            400,
            "password_mismatch",
        ),
        (
            json!({"name": "A", "password": "short", "password_confirm": "short"}),
            400,
            "password_too_short",
        ),
    ];
    for (body, status, code) in cases {
        let resp = server.api(&s, "POST", "/api/wallets", Some(&body.to_string()));
        assert_eq!(resp.status, status, "{body}");
        assert_eq!(resp.error_code(), code, "{body}");
        assert!(resp.json()["message"].is_string());
        assert!(!resp.text().contains(PW), "never echoes input");
    }
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets", Some(&create_body("A")))
            .status,
        201
    );
    let resp = server.api(&s, "POST", "/api/wallets", Some(&create_body("A")));
    assert_eq!(resp.status, 409);
    assert_eq!(resp.error_code(), "wallet_exists");
}

#[test]
fn malformed_json_or_unknown_fields_are_bad_request() {
    let server = TestServer::start();
    let s = server.login();
    for body in [
        "not json".to_string(),
        "{}".to_string(),
        json!({"name": "A", "password": PW, "password_confirm": PW, "extra": 1}).to_string(),
        json!({"name": 5, "password": PW, "password_confirm": PW}).to_string(),
    ] {
        let resp = server.api(&s, "POST", "/api/wallets", Some(&body));
        assert_eq!(resp.status, 400, "{body}");
        assert_eq!(resp.error_code(), "bad_request");
        assert!(!resp.text().contains(PW));
    }
}

#[test]
fn add_entry_returns_its_id_and_the_file_holds_no_plaintext() {
    let server = TestServer::start();
    let s = server.login();
    server.api(&s, "POST", "/api/wallets", Some(&create_body("Work 1")));
    let entry = json!({"title": "MARKER-title-GitHub", "username": "me", "password": "MARKER-secret", "url": "https://github.com", "notes": ""});
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Work%201/entries",
        Some(&entry.to_string()),
    );
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = resp.json()["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    let bytes = fs::read(server.fx.wallets_dir.join("Work 1.pwsw")).unwrap();
    for marker in ["MARKER", "GitHub", "github.com"] {
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "{marker}"
        );
    }
    let partial = json!({"title": "Only title"});
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Work%201/entries",
        Some(&partial.to_string()),
    );
    assert_eq!(resp.status, 201, "missing optional fields default to empty");
}

#[test]
fn add_entry_errors() {
    let server = TestServer::start();
    let s = server.login();
    server.api(&s, "POST", "/api/wallets", Some(&create_body("Personal")));
    let add =
        |path: &str, body: serde_json::Value| server.api(&s, "POST", path, Some(&body.to_string()));
    let resp = add("/api/wallets/Personal/entries", json!({"title": "  "}));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "empty_title")
    );
    let big = "x".repeat(1024 * 1024 + 1);
    let resp = add(
        "/api/wallets/Personal/entries",
        json!({"title": "t", "notes": big}),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "field_too_large")
    );
    let resp = add("/api/wallets/Nobody/entries", json!({"title": "t"}));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "wallet_not_found")
    );
    let resp = add("/api/wallets/..%2Fx/entries", json!({"title": "t"}));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_name")
    );
    let resp = add(
        "/api/wallets/Personal/entries",
        json!({"title": "t", "bogus": ""}),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "bad_request")
    );
    let resp = server.api(&s, "GET", "/api/wallets/Personal/entries", None);
    assert_eq!(resp.status, 405);
}

#[test]
fn add_entry_to_a_locked_wallet_is_423() {
    let mut server = TestServer::start();
    let s = server.login();
    server.api(&s, "POST", "/api/wallets", Some(&create_body("Personal")));
    // Restart: every wallet starts locked.
    let fx = std::mem::replace(&mut server.fx, common::server::Fixture::new(""));
    server.stop();
    let server = TestServer::start_in(fx);
    let s = server.login();
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&json!({"title": "t"}).to_string()),
    );
    assert_eq!(resp.status, 423);
    assert_eq!(resp.error_code(), "wallet_locked");
    assert_eq!(
        server.api(&s, "GET", "/api/state", None).json()["wallets"],
        json!([{"name": "Personal", "unlocked": false}])
    );
}
