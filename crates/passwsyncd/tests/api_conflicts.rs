//! 004 T076: conflict routes (contracts/http-api-sync.md "Actions") behind the 002/003
//! protections.

mod common;

use common::server::{Fixture, TestServer};
use common::sync::*;
use serde_json::Value;

fn server() -> (TestServer, common::server::Session) {
    let fx = Fixture::new("");
    place_wallet(&fx, "Personal", &conflicted_wallet());
    let server = TestServer::start_in(fx);
    let s = server.login();
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Personal/unlock", Some(&body))
            .status,
        200
    );
    (server, s)
}

fn base() -> String {
    format!("/api/wallets/Personal/conflicts/{CONFLICT_ID}")
}

#[test]
fn search_marks_conflicted_credentials() {
    let (server, s) = server();
    let found = server
        .api(
            &s,
            "POST",
            "/api/wallets/Personal/search",
            Some(r#"{"query":""}"#),
        )
        .json();
    let flags: Vec<(String, bool)> = found["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["title"].as_str().unwrap().to_string(),
                e["conflicted"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    assert_eq!(
        flags,
        [
            ("Phone edit".to_string(), true),
            ("Plain".to_string(), false)
        ]
    );
}

#[test]
fn conflict_list_view_reveal_and_resolve() {
    let (server, s) = server();
    let list = server.api(&s, "GET", "/api/wallets/Personal/conflicts", None);
    assert_eq!(list.status, 200);
    let entries = list.json()["entries"].clone();
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["id"], CONFLICT_ID);
    assert_eq!(entries[0]["title"], "Phone edit");
    assert_eq!(entries[0]["versions"], 2);

    let view = server.api(&s, "GET", &base(), None);
    assert_eq!(view.status, 200);
    let versions = view.json()["versions"].clone();
    assert_eq!(versions[0]["index"], 0);
    assert_eq!(versions[0]["title"], "Phone edit");
    assert_eq!(versions[1]["title"], "Laptop edit");
    assert_eq!(versions[1]["username"], "Laptop edit-user");
    assert_eq!(versions[1]["deleted"], false);
    assert_eq!(versions[1]["modified_at"], 10);
    assert_eq!(versions[1]["device"], "unknown device");
    assert!(!view.text().contains("secret"), "no passwords in the view");

    let field = server.api(
        &s,
        "POST",
        &format!("{}/field", base()),
        Some(r#"{"index":1,"field":"password"}"#),
    );
    assert_eq!(field.status, 200);
    assert_eq!(field.json()["value"], "Laptop edit-secret");
    assert_eq!(
        server
            .api(
                &s,
                "POST",
                &format!("{}/field", base()),
                Some(r#"{"index":7,"field":"password"}"#)
            )
            .status,
        400
    );

    let resolved = server.api(
        &s,
        "POST",
        &format!("{}/resolve", base()),
        Some(r#"{"keep":"both"}"#),
    );
    assert_eq!(resolved.status, 200, "{}", resolved.text());
    assert_eq!(resolved.json()["created"].as_array().unwrap().len(), 1);
    let again = server.api(
        &s,
        "POST",
        &format!("{}/resolve", base()),
        Some(r#"{"keep":0}"#),
    );
    assert_eq!(again.status, 409);
    assert_eq!(again.error_code(), "not_conflicted");
    let list = server
        .api(&s, "GET", "/api/wallets/Personal/conflicts", None)
        .json();
    assert_eq!(list["entries"], Value::Array(vec![]));
}

#[test]
fn locked_wallets_bad_input_and_unknown_paths() {
    let (server, s) = server();
    assert_eq!(
        server
            .api(
                &s,
                "POST",
                &format!("{}/resolve", base()),
                Some(r#"{"keep":"maybe"}"#)
            )
            .status,
        400
    );
    assert_eq!(
        server
            .api(&s, "GET", "/api/wallets/Personal/conflicts/zz", None)
            .status,
        404
    );
    assert_eq!(
        server
            .api(&s, "GET", &format!("{}/nowhere", base()), None)
            .status,
        404
    );
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Personal/lock", None)
            .status,
        200
    );
    for (method, path, body) in [
        ("GET", "/api/wallets/Personal/conflicts".to_string(), None),
        ("GET", base(), None),
        ("POST", format!("{}/resolve", base()), Some(r#"{"keep":0}"#)),
        (
            "POST",
            format!("{}/field", base()),
            Some(r#"{"index":0,"field":"password"}"#),
        ),
    ] {
        let resp = server.api(&s, method, &path, body);
        assert_eq!(resp.status, 423, "{method} {path}");
        assert!(!resp.text().contains("edit"), "no content while locked");
    }
}

#[test]
fn every_conflict_route_keeps_the_002_protections() {
    let (server, s) = server();
    let routes = [
        ("GET", "/api/wallets/Personal/conflicts".to_string()),
        ("GET", base()),
        ("POST", format!("{}/resolve", base())),
        ("POST", format!("{}/field", base())),
    ];
    let cookie = format!("pws_session={}", s.cookie);
    let origin = server.origin();
    for (method, path) in &routes {
        // No session.
        let resp = server.send(method, path, &[("X-CSRF-Token", &s.csrf)], b"{}");
        assert_eq!(resp.status, 401, "{method} {path}");
        // No CSRF token.
        let resp = server.send(
            method,
            path,
            &[("Cookie", &cookie), ("Origin", &origin)],
            b"{}",
        );
        assert_eq!(resp.status, 403, "{method} {path}");
        if *method == "POST" {
            let resp = server.send(
                method,
                path,
                &[("Cookie", &cookie), ("X-CSRF-Token", &s.csrf)],
                b"{}",
            );
            assert_eq!(resp.status, 403, "Origin required: {path}");
        }
        let ok = server.api(&s, method, path, Some("{}"));
        assert!(ok.header("content-security-policy").is_some(), "{path}");
    }
    // Wrong Host is refused before routing.
    let raw = format!("GET {} HTTP/1.1\r\nHost: evil.example\r\n\r\n", base());
    assert_eq!(server.raw(raw.as_bytes()).status, 403);
}
