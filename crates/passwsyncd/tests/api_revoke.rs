//! 003 US5: `POST /api/devices/{id}/revoke` (contracts/http-api-network.md).

mod common;

use std::time::{Duration, Instant};

use common::server::{Session, TestServer, net_config, wait_for};
use serde_json::{Value, json};

fn net(server: &TestServer, s: &Session) -> Value {
    server.api(s, "GET", "/api/network", None).json()
}

fn id_of(server: &TestServer, s: &Session) -> String {
    net(server, s)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Pairs `a` (code) with `b` (joins) and waits for the channel.
fn pair(a: &TestServer, sa: &Session, b: &TestServer, sb: &Session) {
    let code = a.api(sa, "POST", "/api/pairing/start", None).json()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let body = json!({"address": format!("127.0.0.1:{}", a.peer_port()), "code": code, "device_id": id_of(a, sa)});
    assert_eq!(
        b.api(sb, "POST", "/api/pairing/join", Some(&body.to_string()))
            .status,
        202
    );
    assert!(wait_for(
        Duration::from_secs(5),
        || net(a, sa)["pairing"]["state"] == "awaiting_acceptance"
    ));
    let accept = json!({"device_id": id_of(b, sb)}).to_string();
    assert_eq!(
        a.api(sa, "POST", "/api/pairing/accept", Some(&accept))
            .status,
        200
    );
    assert!(wait_for(Duration::from_secs(8), || net(a, sa)["paired"][0]
        ["status"]
        == "connected"
        && net(b, sb)["paired"][0]["status"] == "connected"));
}

#[test]
fn unknown_and_malformed_ids_are_device_not_found() {
    let a = TestServer::start_with(&net_config());
    let s = a.login();
    for id in [
        "00".repeat(32),
        "XYZ".to_string(),
        "AB".repeat(32),
        "0".repeat(63),
    ] {
        let resp = a.api(&s, "POST", &format!("/api/devices/{id}/revoke"), None);
        assert_eq!(
            (resp.status, resp.error_code()),
            (404, "device_not_found".to_string()),
            "{id}"
        );
    }
    let off = TestServer::start();
    let so = off.login();
    let resp = off.api(
        &so,
        "POST",
        &format!("/api/devices/{}/revoke", "00".repeat(32)),
        None,
    );
    assert_eq!(resp.status, 404);
}

#[test]
fn revoke_closes_the_channel_within_a_second_and_refuses_reconnection() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    pair(&a, &sa, &b, &sb);
    let b_id = id_of(&b, &sb);
    let started = Instant::now();
    let resp = a.api(&sa, "POST", &format!("/api/devices/{b_id}/revoke"), None);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(net(&a, &sa)["paired"].as_array().unwrap().is_empty());
    assert!(
        wait_for(
            Duration::from_secs(1),
            || net(&b, &sb)["paired"][0]["status"] != "connected"
        ),
        "B's channel closed"
    );
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert!(a.log_text().contains("device revoked"));
    // B keeps its pin and is refused from now on.
    assert!(
        wait_for(
            Duration::from_secs(5),
            || net(&b, &sb)["paired"][0]["status"] == "refused_by_peer"
        ),
        "{}",
        net(&b, &sb)["paired"]
    );
    assert!(wait_for(Duration::from_secs(2), || a
        .log_text()
        .contains("(revoked)")));
    let resp = a.api(&sa, "POST", &format!("/api/devices/{b_id}/revoke"), None);
    assert_eq!(resp.status, 404, "already gone");
}

#[test]
fn a_failed_save_keeps_the_pin_and_the_channel() {
    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    pair(&a, &sa, &b, &sb);
    let b_id = id_of(&b, &sb);
    common::set_mode(&a.fx.config_dir, 0o500);
    let resp = a.api(&sa, "POST", &format!("/api/devices/{b_id}/revoke"), None);
    common::set_mode(&a.fx.config_dir, 0o700);
    assert_eq!(
        (resp.status, resp.error_code()),
        (500, "storage_error".into())
    );
    assert_eq!(net(&a, &sa)["paired"][0]["device_id"], b_id.as_str());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(net(&a, &sa)["paired"][0]["status"], "connected");
}

#[test]
fn revoke_needs_no_unlock_and_keeps_the_guards() {
    let a = TestServer::start_with(&format!("auto_lock_minutes = 1\n{}", net_config()));
    let s = a.login();
    let body = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;
    assert_eq!(a.api(&s, "POST", "/api/wallets", Some(body)).status, 201);
    a.clock.advance(Duration::from_secs(55));
    let path = format!("/api/devices/{}/revoke", "00".repeat(32));
    assert_eq!(a.api(&s, "POST", &path, None).status, 404);
    a.clock.advance(Duration::from_secs(5));
    a.running().sweep_now();
    assert!(a.log_text().contains("locked Personal (idle)"));
    // Guards: no cookie, no CSRF, no Origin, wrong method.
    let resp = a.send("POST", &path, &[("X-CSRF-Token", &s.csrf)], b"");
    assert_eq!(resp.status, 401);
    let cookie = format!("pws_session={}", s.cookie);
    let resp = a.send("POST", &path, &[("Cookie", &cookie)], b"");
    assert_eq!(resp.status, 403);
    let resp = a.send(
        "POST",
        &path,
        &[("Cookie", &cookie), ("X-CSRF-Token", &s.csrf)],
        b"",
    );
    assert_eq!(resp.status, 403, "missing Origin");
    assert_eq!(a.api(&s, "GET", &path, None).status, 405);
}
