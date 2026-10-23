mod common;

use common::server::{Session, TestServer};
use serde_json::json;

const PW: &str = "MARKER-pw-correct-horse";

fn setup() -> (TestServer, Session, String) {
    let server = TestServer::start();
    let s = server.login();
    let body = json!({"name": "Personal", "password": PW, "password_confirm": PW});
    server.api(&s, "POST", "/api/wallets", Some(&body.to_string()));
    let entry =
        json!({"title": "GitHub", "username": "octo \"cat\"", "password": "pa\"ss\\wörd-SECRET"});
    let id = server
        .api(
            &s,
            "POST",
            "/api/wallets/Personal/entries",
            Some(&entry.to_string()),
        )
        .json()["id"]
        .as_str()
        .unwrap()
        .to_string();
    (server, s, id)
}

#[test]
fn field_route_returns_one_value_uncached() {
    let (server, s, id) = setup();
    let path = format!("/api/wallets/Personal/entries/{id}/field");
    let resp = server.api(
        &s,
        "POST",
        &path,
        Some(&json!({"field": "password"}).to_string()),
    );
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json(), json!({"value": "pa\"ss\\wörd-SECRET"}));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let resp = server.api(
        &s,
        "POST",
        &path,
        Some(&json!({"field": "username"}).to_string()),
    );
    assert_eq!(resp.json(), json!({"value": "octo \"cat\""}));
    assert!(!server.log_text().contains("SECRET"));
}

#[test]
fn password_appears_only_in_the_field_route() {
    let (server, s, id) = setup();
    let search = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/search",
        Some("{\"query\":\"\"}"),
    );
    let get = server.api(
        &s,
        "GET",
        &format!("/api/wallets/Personal/entries/{id}"),
        None,
    );
    let state = server.api(&s, "GET", "/api/state", None);
    for resp in [search, get, state] {
        assert!(!resp.text().contains("SECRET"));
    }
}

#[test]
fn bad_field_names_and_methods() {
    let (server, s, id) = setup();
    let path = format!("/api/wallets/Personal/entries/{id}/field");
    for body in [
        json!({"field": "notes"}),
        json!({"field": "Password"}),
        json!({}),
        json!({"field": "password", "x": 1}),
    ] {
        let resp = server.api(&s, "POST", &path, Some(&body.to_string()));
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (400, "bad_request"),
            "{body}"
        );
    }
    assert_eq!(server.api(&s, "GET", &path, None).status, 405);
    let other = format!("/api/wallets/Personal/entries/{}/field", "0".repeat(32));
    let resp = server.api(
        &s,
        "POST",
        &other,
        Some(&json!({"field": "password"}).to_string()),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "entry_not_found")
    );
    let unknown = format!("/api/wallets/Personal/entries/{id}/other");
    assert_eq!(server.api(&s, "POST", &unknown, Some("{}")).status, 404);
}

#[test]
fn locked_wallet_field_is_423() {
    let (mut server, _, id) = setup();
    let fx = std::mem::replace(&mut server.fx, common::server::Fixture::new(""));
    server.stop();
    let server = TestServer::start_in(fx);
    let s = server.login();
    let path = format!("/api/wallets/Personal/entries/{id}/field");
    let resp = server.api(
        &s,
        "POST",
        &path,
        Some(&json!({"field": "password"}).to_string()),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (423, "wallet_locked")
    );
    assert!(!resp.text().contains("SECRET"));
}
