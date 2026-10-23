mod common;

use common::server::{Resp, Session, TestServer};
use serde_json::{Value, json};

const PW: &str = "MARKER-pw-correct-horse";

fn setup() -> (TestServer, Session) {
    let server = TestServer::start();
    let s = server.login();
    let body = json!({"name": "Personal", "password": PW, "password_confirm": PW});
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets", Some(&body.to_string()))
            .status,
        201
    );
    (server, s)
}

fn add(server: &TestServer, s: &Session, title: &str) -> String {
    let body = json!({
        "title": title, "username": format!("{title}-user"), "password": format!("{title}-SECRET"),
        "url": format!("https://{}.example", title.to_lowercase()), "notes": format!("{title} notes")
    });
    let resp = server.api(
        s,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&body.to_string()),
    );
    assert_eq!(resp.status, 201);
    resp.json()["id"].as_str().unwrap().to_string()
}

fn search(server: &TestServer, s: &Session, query: &str) -> Resp {
    let body = json!({"query": query}).to_string();
    server.api(s, "POST", "/api/wallets/Personal/search", Some(&body))
}

fn titles(resp: &Resp) -> Vec<String> {
    resp.json()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn search_returns_summaries_only() {
    let (server, s) = setup();
    for title in ["GitHub", "GitLab", "Bank"] {
        add(&server, &s, title);
    }
    let all = search(&server, &s, "");
    assert_eq!(all.status, 200);
    assert_eq!(all.header("cache-control"), Some("no-store"));
    assert_eq!(titles(&all), ["Bank", "GitHub", "GitLab"]);
    assert_eq!(titles(&search(&server, &s, "git")), ["GitHub", "GitLab"]);
    assert!(!all.text().contains("SECRET"), "no passwords in lists");
    assert!(!all.text().contains("notes"), "no notes in lists");
    let first = &all.json()["entries"][0];
    let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "title", "url", "username"]);
}

#[test]
fn get_entry_has_details_and_unix_timestamps_but_no_password() {
    let (server, s) = setup();
    let id = add(&server, &s, "GitHub");
    let resp = server.api(
        &s,
        "GET",
        &format!("/api/wallets/Personal/entries/{id}"),
        None,
    );
    assert_eq!(resp.status, 200);
    let entry = resp.json();
    assert_eq!(entry["id"], json!(id));
    assert_eq!(entry["title"], json!("GitHub"));
    assert_eq!(entry["username"], json!("GitHub-user"));
    assert_eq!(entry["url"], json!("https://github.example"));
    assert_eq!(entry["notes"], json!("GitHub notes"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let created = entry["created_at"].as_i64().unwrap();
    assert!((now - created).abs() < 60);
    assert!(entry["modified_at"].is_i64());
    assert!(entry.get("password").is_none());
    assert!(!resp.text().contains("SECRET"));
}

#[test]
fn put_replaces_and_delete_removes() {
    let (server, s) = setup();
    let id = add(&server, &s, "GitHub");
    let path = format!("/api/wallets/Personal/entries/{id}");
    let body = json!({"title": "GitHub (work)", "username": "w", "password": "p2", "url": "", "notes": ""});
    let resp = server.api(&s, "PUT", &path, Some(&body.to_string()));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json(), json!({}));
    let entry: Value = server.api(&s, "GET", &path, None).json();
    assert_eq!(entry["title"], json!("GitHub (work)"));
    assert_eq!(entry["notes"], json!(""));
    let resp = server.api(&s, "DELETE", &path, None);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json(), json!({}));
    let resp = server.api(&s, "GET", &path, None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "entry_not_found")
    );
    assert!(titles(&search(&server, &s, "")).is_empty());
}

fn password_of(server: &TestServer, s: &Session, id: &str) -> String {
    let resp = server.api(
        s,
        "POST",
        &format!("/api/wallets/Personal/entries/{id}/field"),
        Some("{\"field\":\"password\"}"),
    );
    resp.json()["value"].as_str().unwrap().to_string()
}

#[test]
fn put_with_keep_password_keeps_the_stored_password() {
    let (server, s) = setup();
    let id = add(&server, &s, "GitHub");
    let path = format!("/api/wallets/Personal/entries/{id}");
    let body = json!({"title": "GitHub (work)", "username": "w", "keep_password": true});
    let resp = server.api(&s, "PUT", &path, Some(&body.to_string()));
    assert_eq!(resp.status, 200);
    let entry: Value = server.api(&s, "GET", &path, None).json();
    assert_eq!(entry["title"], json!("GitHub (work)"));
    assert_eq!(password_of(&server, &s, &id), "GitHub-SECRET");
    // Without the flag the body replaces the whole credential, password included.
    let body = json!({"title": "GitHub", "keep_password": false});
    assert_eq!(
        server.api(&s, "PUT", &path, Some(&body.to_string())).status,
        200
    );
    assert_eq!(password_of(&server, &s, &id), "");
    // Keeping and setting a password at once is ambiguous; adding cannot keep anything.
    let body = json!({"title": "GitHub", "password": "x", "keep_password": true});
    let resp = server.api(&s, "PUT", &path, Some(&body.to_string()));
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "bad_request")
    );
    let body = json!({"title": "New", "keep_password": true});
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&body.to_string()),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "bad_request")
    );
}

#[test]
fn bad_ids_locked_wallets_and_methods() {
    let (server, s) = setup();
    for id in ["nothex", "0123", &"0".repeat(32), &"G".repeat(32)] {
        let resp = server.api(
            &s,
            "GET",
            &format!("/api/wallets/Personal/entries/{id}"),
            None,
        );
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (404, "entry_not_found"),
            "{id}"
        );
    }
    let resp = server.api(&s, "PATCH", "/api/wallets/Personal/entries/00", None);
    assert_eq!(resp.status, 405);
    let resp = server.api(
        &s,
        "POST",
        &format!("/api/wallets/Personal/entries/{}", "0".repeat(32)),
        Some("{}"),
    );
    assert_eq!(resp.status, 405);
    let resp = server.api(&s, "GET", "/api/wallets/Personal/search", None);
    assert_eq!(resp.status, 405);
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/search",
        Some("{\"q\":\"x\"}"),
    );
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (400, "bad_request")
    );
}

#[test]
fn locked_wallet_operations_are_423_without_data() {
    let mut server = TestServer::start();
    let s = server.login();
    let body = json!({"name": "Personal", "password": PW, "password_confirm": PW});
    server.api(&s, "POST", "/api/wallets", Some(&body.to_string()));
    let id = {
        let b = json!({"title": "GitHub"}).to_string();
        server
            .api(&s, "POST", "/api/wallets/Personal/entries", Some(&b))
            .json()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let fx = std::mem::replace(&mut server.fx, common::server::Fixture::new(""));
    server.stop();
    let server = TestServer::start_in(fx);
    let s = server.login();
    let path = format!("/api/wallets/Personal/entries/{id}");
    let responses = [
        server.api(
            &s,
            "POST",
            "/api/wallets/Personal/search",
            Some("{\"query\":\"\"}"),
        ),
        server.api(&s, "GET", &path, None),
        server.api(&s, "PUT", &path, Some("{\"title\":\"x\"}")),
        server.api(&s, "DELETE", &path, None),
    ];
    for resp in responses {
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (423, "wallet_locked")
        );
        assert!(!resp.text().contains("GitHub"));
    }
}

#[test]
fn failed_save_is_500_storage_error_and_changes_nothing() {
    let (server, s) = setup();
    let id = add(&server, &s, "GitHub");
    let file = server.fx.wallets_dir.join("Personal.pwsw");
    let before = std::fs::read(&file).unwrap();
    // Make the directory unwritable so the atomic temp file cannot be created.
    common::set_mode(&server.fx.wallets_dir, 0o500);
    let path = format!("/api/wallets/Personal/entries/{id}");
    let put = server.api(
        &s,
        "PUT",
        &path,
        Some(&json!({"title": "Changed"}).to_string()),
    );
    let del = server.api(&s, "DELETE", &path, None);
    let add = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&json!({"title": "New"}).to_string()),
    );
    common::set_mode(&server.fx.wallets_dir, 0o700);
    if put.status == 200 {
        eprintln!("skipped: running as root, directory permissions are not enforced");
        return;
    }
    for resp in [put, del, add] {
        assert_eq!(
            (resp.status, resp.error_code().as_str()),
            (500, "storage_error")
        );
    }
    assert_eq!(std::fs::read(&file).unwrap(), before);
    assert_eq!(titles(&search(&server, &s, "")), ["GitHub"]);
}
