//! 003 US2: pairing routes (contracts/http-api-network.md) between two in-process services
//! on loopback, plus the full 002 guard matrix on every new route.

mod common;

use std::time::Duration;

use common::server::{Session, TestServer, net_config, wait_for};
use serde_json::{Value, json};

fn net(server: &TestServer, s: &Session) -> Value {
    let resp = server.api(s, "GET", "/api/network", None);
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.json()
}

fn peer_addr(server: &TestServer) -> String {
    format!("127.0.0.1:{}", server.peer_port())
}

fn start_code(server: &TestServer, s: &Session) -> Value {
    let resp = server.api(s, "POST", "/api/pairing/start", None);
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.json()
}

fn join(
    server: &TestServer,
    s: &Session,
    addr: &str,
    code: &str,
    id: Option<&str>,
) -> (u16, Value) {
    let body = json!({"address": addr, "code": code, "device_id": id}).to_string();
    let resp = server.api(s, "POST", "/api/pairing/join", Some(&body));
    let value = if resp.body.is_empty() {
        Value::Null
    } else {
        resp.json()
    };
    (resp.status, value)
}

#[test]
fn start_returns_code_qr_and_text_and_network_shows_it() {
    let a = TestServer::start_with(&net_config());
    let s = a.login();
    let v = start_code(&a, &s);
    assert_eq!(v["state"], "waiting");
    let code = v["code"].as_str().unwrap();
    assert_eq!(code.len(), 9, "grouped `1234 5678`");
    assert_eq!(&code[4..5], " ");
    assert!(v["expires_in"].as_u64().unwrap() > 290);
    assert!(v["qr"]["size"].as_u64().unwrap() >= 29);
    assert!(v["qr"]["path"].as_str().unwrap().starts_with('M'));
    let id = net(&a, &s)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let digits = code.replace(' ', "");
    assert_eq!(
        v["qr_text"],
        format!(
            "passwsync://pair?v=1&code={digits}&id={id}&addr={}",
            peer_addr(&a)
        )
    );
    assert_eq!(net(&a, &s)["pairing"]["code"], v["code"]);
    assert!(a.log_text().contains("pairing started"));
    assert!(!a.log_text().contains(&digits), "code never logged");
    // Cancel is idempotent and removes everything.
    assert_eq!(a.api(&s, "POST", "/api/pairing/cancel", None).status, 200);
    assert_eq!(a.api(&s, "POST", "/api/pairing/cancel", None).status, 200);
    assert_eq!(net(&a, &s)["pairing"], Value::Null);
}

#[test]
fn two_services_pair_through_the_api() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    let code = start_code(&a, &sa)["code"].as_str().unwrap().to_string();
    let a_id = net(&a, &sa)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b_id = net(&b, &sb)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = join(
        &b,
        &sb,
        &peer_addr(&a),
        &code.replace(' ', "-"),
        Some(&a_id),
    );
    assert_eq!(status, 202);
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    let pending = net(&a, &sa)["pairing"].clone();
    assert_eq!(pending["peer"]["device_id"], b_id.as_str());
    assert!(
        pending["peer"]["name"]
            .as_str()
            .unwrap()
            .starts_with("passwsync device")
    );
    assert!(pending["peer"]["fingerprint"].as_str().unwrap().len() == 19);
    assert!(pending["code"].is_null(), "code gone once consumed");
    assert!(pending["qr"].is_null() && pending["qr_text"].is_null());
    let joining = net(&b, &sb)["join"].clone();
    assert_eq!(joining["state"], "awaiting_acceptance");
    // Wrong id: mismatch; right id: accepted.
    let wrong = json!({"device_id": "00".repeat(32)}).to_string();
    let resp = a.api(&sa, "POST", "/api/pairing/accept", Some(&wrong));
    assert_eq!(
        (resp.status, resp.error_code()),
        (409, "pairing_mismatch".into())
    );
    let right = json!({"device_id": b_id}).to_string();
    let resp = a.api(&sa, "POST", "/api/pairing/accept", Some(&right));
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.json()["peer"]["device_id"], b_id.as_str());
    assert!(wait_for(
        Duration::from_secs(5),
        || net(&b, &sb)["join"]["state"] == "paired"
    ));
    let a_view = net(&a, &sa);
    assert_eq!(a_view["paired"][0]["device_id"], b_id.as_str());
    assert!(a_view["paired"][0]["paired_at"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(net(&b, &sb)["paired"][0]["device_id"], a_id.as_str());
    assert!(a.log_text().contains("pairing succeeded"));
    assert!(wait_for(Duration::from_secs(2), || b
        .log_text()
        .contains("pairing succeeded")));
    // Already paired now.
    let code = start_code(&a, &sa)["code"].as_str().unwrap().to_string();
    let (status, v) = join(&b, &sb, &peer_addr(&a), &code, Some(&a_id));
    assert_eq!((status, v["error"].as_str()), (409, Some("already_paired")));
}

#[test]
fn wrong_code_fails_both_and_a_second_start_invalidates_the_first_code() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    let first = start_code(&a, &sa)["code"]
        .as_str()
        .unwrap()
        .replace(' ', "");
    let second = start_code(&a, &sa)["code"]
        .as_str()
        .unwrap()
        .replace(' ', "");
    let old = if first == second {
        "00000000".to_string()
    } else {
        first
    };
    let (status, _) = join(&b, &sb, &peer_addr(&a), &old, None);
    assert_eq!(status, 202);
    assert!(wait_for(
        Duration::from_secs(5),
        || net(&b, &sb)["join"]["state"] == "failed"
    ));
    let reason = net(&b, &sb)["join"]["reason"].as_str().unwrap().to_string();
    assert!(
        matches!(
            reason.as_str(),
            "wrong_code_or_tampered" | "refused_not_pairing"
        ),
        "{reason}"
    );
    assert!(net(&a, &sa)["paired"].as_array().unwrap().is_empty());
    assert!(net(&b, &sb)["paired"].as_array().unwrap().is_empty());
    assert!(b.log_text().contains("pairing failed ("));
}

#[test]
fn reject_and_nothing_pending() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    let any = json!({"device_id": "11".repeat(32)}).to_string();
    let resp = a.api(&sa, "POST", "/api/pairing/accept", Some(&any));
    assert_eq!(
        (resp.status, resp.error_code()),
        (409, "nothing_pending".into())
    );
    let code = start_code(&a, &sa)["code"].as_str().unwrap().to_string();
    join(&b, &sb, &peer_addr(&a), &code, None);
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    assert_eq!(a.api(&sa, "POST", "/api/pairing/reject", None).status, 200);
    assert!(wait_for(
        Duration::from_secs(5),
        || net(&b, &sb)["join"]["reason"] == "rejected"
    ));
    assert_eq!(net(&a, &sa)["pairing"]["state"], "failed");
    assert!(net(&a, &sa)["paired"].as_array().unwrap().is_empty());
}

#[test]
fn storage_error_on_accept_pins_nothing() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    let code = start_code(&a, &sa)["code"].as_str().unwrap().to_string();
    let b_id = net(&b, &sb)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    join(&b, &sb, &peer_addr(&a), &code, None);
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    // Make the config directory unwritable so the peers file cannot be saved.
    common::set_mode(&a.fx.config_dir, 0o500);
    let body = json!({"device_id": b_id}).to_string();
    let resp = a.api(&sa, "POST", "/api/pairing/accept", Some(&body));
    common::set_mode(&a.fx.config_dir, 0o700);
    assert_eq!(
        (resp.status, resp.error_code()),
        (500, "storage_error".into())
    );
    assert!(net(&a, &sa)["paired"].as_array().unwrap().is_empty());
    assert!(wait_for(
        Duration::from_secs(5),
        || net(&b, &sb)["join"]["state"] == "failed"
    ));
    assert!(net(&b, &sb)["paired"].as_array().unwrap().is_empty());
}

#[test]
fn join_validates_its_input() {
    let b = TestServer::start_with(&net_config());
    let s = b.login();
    let own = net(&b, &s)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let addr = "192.168.1.5:27472";
    let cases: Vec<(Value, u16, &str)> = vec![
        (
            json!({"address": "example.com:27472", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": "localhost:27472", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": "8.8.8.8:27472", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": "192.168.1.5", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": "[::1]:27472", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": "192.168.1.5:0", "code": "12345678", "device_id": null}),
            400,
            "invalid_address",
        ),
        (
            json!({"address": addr, "code": "1234567", "device_id": null}),
            400,
            "invalid_code",
        ),
        (
            json!({"address": addr, "code": "1234567x", "device_id": null}),
            400,
            "invalid_code",
        ),
        (
            json!({"address": addr, "code": "12345678", "device_id": "XYZ"}),
            400,
            "invalid_device_id",
        ),
        (
            json!({"address": addr, "code": "12345678", "device_id": own}),
            409,
            "self",
        ),
    ];
    for (body, status, code) in cases {
        let resp = b.api(&s, "POST", "/api/pairing/join", Some(&body.to_string()));
        assert_eq!(
            (resp.status, resp.error_code()),
            (status, code.to_string()),
            "{body}"
        );
    }
    let resp = b.api(&s, "POST", "/api/pairing/join", Some("{\"address\":1}"));
    assert_eq!(resp.status, 400);
}

#[test]
fn networking_off_refuses_pairing_routes() {
    let a = TestServer::start();
    let s = a.login();
    let resp = a.api(&s, "POST", "/api/pairing/start", None);
    assert_eq!(
        (resp.status, resp.error_code()),
        (409, "networking_off".into())
    );
    let body = json!({"address": "192.168.1.5:27472", "code": "12345678", "device_id": null});
    let resp = a.api(&s, "POST", "/api/pairing/join", Some(&body.to_string()));
    assert_eq!(
        (resp.status, resp.error_code()),
        (409, "networking_off".into())
    );
    assert_eq!(a.api(&s, "POST", "/api/pairing/cancel", None).status, 200);
}

#[test]
fn busy_while_joining_and_code_rate_limit() {
    let a = TestServer::start_with(&net_config());
    let s = a.login();
    for _ in 0..5 {
        assert_eq!(a.api(&s, "POST", "/api/pairing/start", None).status, 200);
    }
    let resp = a.api(&s, "POST", "/api/pairing/start", None);
    assert_eq!(
        (resp.status, resp.error_code()),
        (429, "too_many_codes".into())
    );

    // A join towards a silent listener keeps B busy for the step timeout.
    let b = TestServer::start_with(&net_config());
    let sb = b.login();
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = silent.local_addr().unwrap().to_string();
    let (status, _) = join(&b, &sb, &addr, "12345678", None);
    assert_eq!(status, 202);
    let (status, v) = join(&b, &sb, &addr, "12345678", None);
    assert_eq!((status, v["error"].as_str()), (409, Some("busy")));
    let resp = b.api(&sb, "POST", "/api/pairing/start", None);
    assert_eq!((resp.status, resp.error_code()), (409, "busy".into()));
}

#[test]
fn the_002_guard_matrix_applies_to_every_new_route() {
    let server = TestServer::start_with(&net_config());
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    let origin = server.origin();
    let revoke = format!("/api/devices/{}/revoke", "00".repeat(32));
    let routes = [
        ("POST", "/api/pairing/start", "{}"),
        ("POST", "/api/pairing/cancel", "{}"),
        ("POST", "/api/pairing/accept", "{\"device_id\":\"00\"}"),
        ("POST", "/api/pairing/reject", "{}"),
        ("POST", "/api/pairing/join", "{}"),
        ("POST", revoke.as_str(), "{}"),
        ("POST", "/api/network/warnings/clear", "{}"),
    ];
    for (method, path, body) in routes {
        let b = body.as_bytes();
        // Missing cookie.
        let resp = server.send(
            method,
            path,
            &[("X-CSRF-Token", &s.csrf), ("Origin", &origin)],
            b,
        );
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (401, "unauthorized"),
            "{path}"
        );
        // Missing and wrong CSRF.
        let resp = server.send(method, path, &[("Cookie", &cookie), ("Origin", &origin)], b);
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (403, "forbidden"),
            "{path}"
        );
        let bad = "11".repeat(32);
        let resp = server.send(
            method,
            path,
            &[
                ("Cookie", &cookie),
                ("X-CSRF-Token", &bad),
                ("Origin", &origin),
            ],
            b,
        );
        assert_eq!(resp.status, 403, "{path}");
        // Missing and wrong Origin.
        let resp = server.send(
            method,
            path,
            &[("Cookie", &cookie), ("X-CSRF-Token", &s.csrf)],
            b,
        );
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (403, "forbidden"),
            "{path}"
        );
        let resp = server.send(
            method,
            path,
            &[
                ("Cookie", &cookie),
                ("X-CSRF-Token", &s.csrf),
                ("Origin", "http://evil.example"),
            ],
            b,
        );
        assert_eq!(resp.status, 403, "{path}");
        // Wrong Host.
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: evil.example\r\nCookie: {cookie}\r\nX-CSRF-Token: {}\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n{body}",
            s.csrf,
            body.len()
        );
        let resp = server.raw(raw.as_bytes());
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (403, "forbidden"),
            "{path}"
        );
        // Oversized body (announced length above the 002 limit).
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nCookie: {cookie}\r\nX-CSRF-Token: {}\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
            server.host(),
            s.csrf,
            9 * 1024 * 1024
        );
        let resp = server.raw(raw.as_bytes());
        assert_eq!(resp.status, 413, "{path}");
        // Wrong method.
        let resp = server.api(&s, "GET", path, None);
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (405, "method not allowed"),
            "{path}"
        );
    }
    // A wrong peer UID cannot be produced without a second user account; the shared 002
    // pipeline these routes go through is covered by tests/http_guards.rs.
}

#[test]
fn pairing_routes_need_no_unlock_and_do_not_reset_idle_timers() {
    let a = TestServer::start_with(&format!("auto_lock_minutes = 1\n{}", net_config()));
    let s = a.login();
    let body = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;
    assert_eq!(a.api(&s, "POST", "/api/wallets", Some(body)).status, 201);
    a.clock.advance(Duration::from_secs(50));
    start_code(&a, &s);
    a.api(&s, "POST", "/api/pairing/cancel", None);
    a.api(&s, "POST", "/api/network/warnings/clear", None);
    a.clock.advance(Duration::from_secs(10));
    a.running().sweep_now();
    assert!(a.log_text().contains("locked Personal (idle)"));
}
