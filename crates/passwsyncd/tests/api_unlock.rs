mod common;

use common::server::{Fixture, TestServer};
use serde_json::json;

const PW: &str = "MARKER-pw-correct-horse";

/// A server whose `Personal` wallet (one credential) was created in an earlier run.
fn restarted_with_wallet() -> TestServer {
    let mut first = TestServer::start();
    let s = first.login();
    let body = json!({"name": "Personal", "password": PW, "password_confirm": PW});
    assert_eq!(
        first
            .api(&s, "POST", "/api/wallets", Some(&body.to_string()))
            .status,
        201
    );
    let entry = json!({"title": "GitHub"}).to_string();
    assert_eq!(
        first
            .api(&s, "POST", "/api/wallets/Personal/entries", Some(&entry))
            .status,
        201
    );
    let fx = std::mem::replace(&mut first.fx, Fixture::new(""));
    first.stop();
    TestServer::start_in(fx)
}

fn unlock(
    server: &TestServer,
    s: &common::server::Session,
    wallet: &str,
    password: &str,
) -> common::server::Resp {
    let body = json!({"password": password}).to_string();
    server.api(
        s,
        "POST",
        &format!("/api/wallets/{wallet}/unlock"),
        Some(&body),
    )
}

#[test]
fn unlock_with_the_correct_password() {
    let server = restarted_with_wallet();
    let s = server.login();
    let resp = unlock(&server, &s, "Personal", PW);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.json(), json!({"name": "Personal", "unlocked": true}));
    assert!(server.log_text().contains("unlocked Personal"));
    assert!(!server.log_text().contains(PW));
    assert!(!resp.text().contains(PW));
    let again = unlock(&server, &s, "Personal", "whatever, already unlocked");
    assert_eq!(again.status, 200);
}

#[test]
fn wrong_password_is_422_with_the_exact_generic_message() {
    let server = restarted_with_wallet();
    let s = server.login();
    let resp = unlock(&server, &s, "Personal", "wrong password here");
    assert_eq!(resp.status, 422);
    assert_eq!(
        resp.json(),
        json!({"error": "invalid_password_or_corrupted", "message": "invalid password or corrupted wallet"})
    );
    let state = server.api(&s, "GET", "/api/state", None).json();
    assert_eq!(state["wallets"][0]["unlocked"], json!(false));
}

#[test]
fn kdf_over_the_cap_unknown_and_invalid_names() {
    let server = restarted_with_wallet();
    let s = server.login();
    let path = server.fx.wallets_dir.join("Personal.pwsw");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[7..11].copy_from_slice(&262_144u32.to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let resp = unlock(&server, &s, "Personal", PW);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (422, "kdf_params_out_of_range")
    );
    let resp = unlock(&server, &s, "Nobody", PW);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "wallet_not_found")
    );
    let resp = unlock(&server, &s, "%2E%2E", PW);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_name")
    );
    let resp = unlock(&server, &s, "Bad%ZZ", PW);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "invalid_name")
    );
    let resp = server.api(&s, "GET", "/api/wallets/Personal/unlock", None);
    assert_eq!(resp.status, 405);
}

#[test]
fn unlocked_state_is_shared_by_other_sessions_and_reloads() {
    let server = restarted_with_wallet();
    let first = server.login();
    assert_eq!(unlock(&server, &first, "Personal", PW).status, 200);
    let second = server.login();
    let state = server.api(&second, "GET", "/api/state", None).json();
    assert_eq!(
        state["wallets"],
        json!([{"name": "Personal", "unlocked": true}])
    );
    let entry = json!({"title": "GitLab"}).to_string();
    let resp = server.api(
        &second,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&entry),
    );
    assert_eq!(resp.status, 201, "no second password prompt");
}
