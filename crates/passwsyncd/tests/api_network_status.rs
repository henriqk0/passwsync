//! 003 US1: `GET /api/network` with networking off (contracts/http-api-network.md).

mod common;

use std::fs;
use std::time::Duration;

use common::server::{Fixture, TestServer};
use common::set_mode;
use serde_json::json;

#[test]
fn network_view_with_networking_off_has_identity_and_empty_lists() {
    let server = TestServer::start();
    let s = server.login();
    let resp = server.api(&s, "GET", "/api/network", None);
    assert_eq!(resp.status, 200);
    assert!(
        resp.header("content-type")
            .unwrap()
            .starts_with("application/json")
    );
    assert!(resp.header("content-security-policy").is_some());
    let v = resp.json();
    assert_eq!(
        v["settings"],
        json!({"network": "off", "peer_port": 27472, "discovery_port": 27473, "interface": null})
    );
    assert_eq!(
        v["status"],
        json!({"state": "off", "port": null, "interfaces": []})
    );
    let fp = server.running().fingerprint().unwrap();
    assert_eq!(v["this_device"]["fingerprint"], json!(fp));
    assert_eq!(
        v["this_device"]["name"],
        json!(format!("passwsync device {}", &fp[..4]))
    );
    let id = v["this_device"]["device_id"].as_str().unwrap();
    assert_eq!(id.len(), 64);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(v["nearby"], json!([]));
    assert_eq!(v["paired"], json!([]));
    assert_eq!(v["pairing"], json!(null));
    assert_eq!(v["join"], json!(null));
    assert_eq!(v["warnings"], json!([]));
}

#[test]
fn configured_settings_are_shown_read_only() {
    let server = TestServer::start_with(
        "peer_port = 30100\ndiscovery_port = 30101\ndevice_name = \"Work laptop\"\nnetwork_interface = \"eth9\"\n",
    );
    let s = server.login();
    let v = server.api(&s, "GET", "/api/network", None).json();
    assert_eq!(
        v["settings"],
        json!({"network": "off", "peer_port": 30100, "discovery_port": 30101, "interface": "eth9"})
    );
    assert_eq!(v["this_device"]["name"], json!("Work laptop"));
}

#[test]
fn unusable_identity_and_peers_are_reported() {
    let fx = Fixture::new("");
    let key = fx.config_dir.join("device-key");
    fs::write(&key, "nope").unwrap();
    set_mode(&key, 0o600);
    let server = TestServer::start_in(fx);
    let s = server.login();
    let v = server.api(&s, "GET", "/api/network", None).json();
    assert_eq!(v["status"]["state"], json!("identity_unusable"));
    assert_eq!(v["this_device"], json!(null));
    assert!(
        server
            .log_text()
            .contains("network unavailable (identity-unusable)")
    );

    let fx = Fixture::new("network = on\n");
    let peers = fx.config_dir.join("peers");
    fs::write(&peers, "nope").unwrap();
    set_mode(&peers, 0o600);
    let server = TestServer::start_in(fx);
    let s = server.login();
    let v = server.api(&s, "GET", "/api/network", None).json();
    assert_eq!(v["status"]["state"], json!("peers_unusable"));
    assert!(v["this_device"]["fingerprint"].is_string());
    assert!(
        server
            .log_text()
            .contains("network unavailable (peers-unusable)")
    );
}

#[test]
fn the_002_guards_apply_to_the_network_route() {
    let server = TestServer::start();
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    // No session cookie.
    let resp = server.send("GET", "/api/network", &[("X-CSRF-Token", &s.csrf)], b"");
    assert_eq!((resp.status, resp.text().as_str()), (401, "unauthorized"));
    // No / wrong CSRF token.
    let resp = server.send("GET", "/api/network", &[("Cookie", &cookie)], b"");
    assert_eq!((resp.status, resp.text().as_str()), (403, "forbidden"));
    let wrong = "00".repeat(32);
    let resp = server.send(
        "GET",
        "/api/network",
        &[("Cookie", &cookie), ("X-CSRF-Token", &wrong)],
        b"",
    );
    assert_eq!(resp.status, 403);
    // Bad Host.
    let raw = format!(
        "GET /api/network HTTP/1.1\r\nHost: evil.example:{}\r\nCookie: {cookie}\r\nX-CSRF-Token: {}\r\n\r\n",
        server.port, s.csrf
    );
    let resp = server.raw(raw.as_bytes());
    assert_eq!((resp.status, resp.text().as_str()), (403, "forbidden"));
    // Wrong method.
    assert_eq!(
        server.api(&s, "POST", "/api/network", Some("{}")).status,
        405
    );
    assert_eq!(server.api(&s, "DELETE", "/api/network", None).status, 405);
}

#[test]
fn no_route_can_change_network_settings() {
    let server = TestServer::start();
    let s = server.login();
    for path in [
        "/api/network/settings",
        "/api/network/enable",
        "/api/network/on",
        "/api/settings",
        "/api/network/config",
    ] {
        for method in ["POST", "PUT"] {
            let status = server
                .api(&s, method, path, Some("{\"network\":\"on\"}"))
                .status;
            assert!(matches!(status, 404 | 405), "{method} {path}: {status}");
        }
    }
    let v = server.api(&s, "GET", "/api/network", None).json();
    assert_eq!(v["settings"]["network"], json!("off"));
}

#[test]
fn network_view_needs_no_unlock_and_does_not_reset_wallet_idle_timers() {
    let server = TestServer::start_with("auto_lock_minutes = 1\n");
    let s = server.login();
    let body = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;
    assert_eq!(
        server.api(&s, "POST", "/api/wallets", Some(body)).status,
        201
    );
    server.clock.advance(Duration::from_secs(50));
    for _ in 0..3 {
        assert_eq!(server.api(&s, "GET", "/api/network", None).status, 200);
    }
    server.clock.advance(Duration::from_secs(10));
    server.running().sweep_now();
    assert!(
        server.log_text().contains("locked Personal (idle)"),
        "{}",
        server.log_text()
    );
}
