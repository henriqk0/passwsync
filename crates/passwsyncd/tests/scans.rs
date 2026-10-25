//! SC-006, FR-012, FR-032, FR-033, FR-033a: no secrets in outputs, no external assets.

mod common;

use std::fs;
use std::path::Path;

use common::server::TestServer;
use passwsyncd::assets;

const MARKER: &str = "MARKER-scan";

fn files_under(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let Ok(items) = fs::read_dir(dir) else { return };
    for item in items.flatten() {
        let path = item.path();
        if path.is_dir() {
            files_under(&path, out);
        } else if let Ok(bytes) = fs::read(&path) {
            out.push((path.display().to_string(), bytes));
        }
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

pub fn assert_no_marker(server: &TestServer, marker: &str) {
    let log = server.log_text();
    assert!(!log.contains(marker), "log leaks: {log}");
    let mut files = Vec::new();
    files_under(&server.fx.runtime_dir, &mut files);
    files_under(&server.fx.config_dir, &mut files);
    for (path, bytes) in files {
        assert!(!contains(&bytes, marker), "{path} leaks");
    }
}

#[test]
fn rejected_and_accepted_requests_never_log_request_data() {
    let server = TestServer::start();
    let s = server.login();
    let marker_cookie = format!("pws_session={MARKER}");
    let _ = server.send(
        "GET",
        &format!("/{MARKER}"),
        &[("Cookie", &marker_cookie)],
        b"",
    );
    let _ = server.send(
        "GET",
        &format!("/api/{MARKER}?q={MARKER}"),
        &[("X-CSRF-Token", MARKER)],
        b"",
    );
    let _ = server.raw(format!("GET / HTTP/1.1\r\nHost: {MARKER}\r\n\r\n").as_bytes());
    let _ = server.api(
        &s,
        "POST",
        "/api/lock-all",
        Some(&format!("{{\"x\":\"{MARKER}\"}}")),
    );
    assert_no_marker(&server, MARKER);
    let log = server.log_text();
    assert!(
        !log.contains(&s.cookie) && !log.contains(&s.csrf),
        "tokens never logged"
    );
}

#[test]
fn launch_file_holds_only_the_url() {
    let server = TestServer::start();
    let text = server.launch_url();
    let prefix = format!("http://127.0.0.1:{}/launch/", server.port);
    let token = text
        .strip_prefix(&prefix)
        .unwrap()
        .strip_suffix('\n')
        .unwrap();
    assert_eq!(token.len(), 64);
    let entries: Vec<_> = fs::read_dir(&server.fx.runtime_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut entries = entries;
    entries.sort();
    assert_eq!(entries, ["instance.lock", "launch-url"]);
    assert!(
        fs::read(server.fx.runtime_dir.join("instance.lock"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn embedded_assets_reference_nothing_outside_the_service() {
    assert!(!assets::ALL.is_empty());
    for (name, bytes) in assets::ALL {
        // The SVG namespace URI is an identifier the browser never fetches (also passed to
        // `createElementNS` by the 003 QR code).
        let text = String::from_utf8_lossy(bytes)
            .to_ascii_lowercase()
            .replace("xmlns=\"http://www.w3.org/2000/svg\"", "")
            .replace("const svg_ns = \"http://www.w3.org/2000/svg\";", "");
        for banned in [
            "http://",
            "https://",
            "@import",
            "src=\"//",
            "href=\"//",
            "url(//",
            "url(http",
            "ws://",
            "wss://",
        ] {
            assert!(!text.contains(banned), "{name} contains {banned}");
        }
    }
}

#[test]
fn end_to_end_flow_leaks_no_marker_to_logs_runtime_or_config() {
    use serde_json::json;
    let mut server = TestServer::start();
    let s = server.login();
    let pw = "MARKER-pw-master-secret";
    let create = json!({"name": "Personal", "password": pw, "password_confirm": pw});
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets", Some(&create.to_string()))
            .status,
        201
    );
    let entry = json!({
        "title": "MARKER-title", "username": "MARKER-user", "password": "MARKER-entry-pw",
        "url": "https://MARKER.example", "notes": "MARKER-notes"
    });
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/Personal/entries",
        Some(&entry.to_string()),
    );
    let id = resp.json()["id"].as_str().unwrap().to_string();
    let field = format!("/api/wallets/Personal/entries/{id}/field");
    let copied = server.api(&s, "POST", &field, Some("{\"field\":\"password\"}"));
    assert_eq!(copied.json()["value"], "MARKER-entry-pw");
    server.api(
        &s,
        "POST",
        "/api/wallets/Personal/search",
        Some("{\"query\":\"MARKER\"}"),
    );
    server.api(
        &s,
        "GET",
        &format!("/api/wallets/Personal/entries/{id}"),
        None,
    );
    server.api(&s, "POST", "/api/wallets/Personal/lock", None);
    let wrong = json!({"password": "MARKER-wrong-pw"}).to_string();
    server.api(&s, "POST", "/api/wallets/Personal/unlock", Some(&wrong));
    let right = json!({"password": pw}).to_string();
    server.api(&s, "POST", "/api/wallets/Personal/unlock", Some(&right));
    server.api(&s, "POST", "/api/lock-all", None);
    let fx = std::mem::replace(&mut server.fx, common::server::Fixture::new(""));
    server.stop();
    let restarted = TestServer::start_in(fx);
    let s2 = restarted.login();
    restarted.api(&s2, "POST", "/api/wallets/Personal/unlock", Some(&right));
    assert!(!server.log_text().contains("MARKER"), "first run log leaks");
    assert_no_marker(&restarted, "MARKER");
    let log = server.log_text() + &restarted.log_text();
    assert!(log.contains("unlocked Personal") && log.contains("locked Personal (manual)"));
    // The wallet file itself is encrypted.
    let bytes = fs::read(restarted.fx.wallets_dir.join("Personal.pwsw")).unwrap();
    assert!(!contains(&bytes, "MARKER"));
}

/// 003 FR-040, SC-006: after a full pairing, neither the code nor a private key appears in
/// the log, the runtime or config directories (other than the key file itself) or the
/// process environment.
#[test]
fn pairing_leaks_no_code_or_key() {
    use std::time::Duration;

    use common::server::{net_config, wait_for};
    use serde_json::json;

    let a = TestServer::start_with(&net_config());
    let b = TestServer::start_with(&net_config());
    let (sa, sb) = (a.login(), b.login());
    let started = a.api(&sa, "POST", "/api/pairing/start", None).json();
    let code = started["code"].as_str().unwrap().replace(' ', "");
    let a_id = a.api(&sa, "GET", "/api/network", None).json()["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b_id = b.api(&sb, "GET", "/api/network", None).json()["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let body =
        json!({"address": format!("127.0.0.1:{}", a.peer_port()), "code": code, "device_id": a_id});
    assert_eq!(
        b.api(&sb, "POST", "/api/pairing/join", Some(&body.to_string()))
            .status,
        202
    );
    assert!(wait_for(Duration::from_secs(5), || a
        .api(&sa, "GET", "/api/network", None)
        .json()["pairing"]["state"]
        == "awaiting_acceptance"));
    let accept = json!({"device_id": b_id}).to_string();
    assert_eq!(
        a.api(&sa, "POST", "/api/pairing/accept", Some(&accept))
            .status,
        200
    );
    assert!(wait_for(Duration::from_secs(5), || b
        .api(&sb, "GET", "/api/network", None)
        .json()["join"]["state"]
        == "paired"));
    let environ = fs::read("/proc/self/environ").unwrap();
    for server in [&a, &b] {
        let key_text = fs::read_to_string(server.fx.config_dir.join("device-key")).unwrap();
        let private = key_text.lines().nth(1).unwrap().to_string();
        assert_eq!(private.len(), 64);
        for other in [&a, &b] {
            let log = other.log_text();
            assert!(!log.contains(&code), "log leaks the code");
            assert!(!log.contains(&private), "log leaks a private key");
            let mut files = Vec::new();
            files_under(&other.fx.runtime_dir, &mut files);
            files_under(&other.fx.config_dir, &mut files);
            for (path, bytes) in files {
                if path.ends_with("/device-key") {
                    continue;
                }
                assert!(!contains(&bytes, &code), "{path} leaks the code");
                assert!(!contains(&bytes, &private), "{path} leaks a key");
            }
        }
        assert!(!contains(&environ, &private));
    }
    assert!(!contains(&environ, &code));
}

/// 003 FR-040, FR-041: pairing, the channel and revocation leave no code, key, device name
/// or master password in the log (wallet names are logged by 002 design), and no code or key in the runtime or config directories (the
/// key file itself excepted).
#[test]
fn pair_channel_and_revoke_leak_nothing() {
    use std::time::Duration;

    use common::server::{free_net_port, wait_for};
    use serde_json::json;

    let config = |name: &str| {
        format!(
            "network = on\npeer_port = {}\ndiscovery_port = {}\ndevice_name = \"{name}\"\n",
            free_net_port(),
            free_net_port()
        )
    };
    let a = TestServer::start_with(&config("MARKER-name-a"));
    let b = TestServer::start_with(&config("MARKER-name-b"));
    let (sa, sb) = (a.login(), b.login());
    let wallet = r#"{"name":"MARKER-wallet","password":"MARKER-master-pw","password_confirm":"MARKER-master-pw"}"#;
    assert_eq!(a.api(&sa, "POST", "/api/wallets", Some(wallet)).status, 201);
    let net = |server: &TestServer, s: &common::server::Session| {
        server.api(s, "GET", "/api/network", None).json()
    };
    let code = a.api(&sa, "POST", "/api/pairing/start", None).json()["code"]
        .as_str()
        .unwrap()
        .replace(' ', "");
    let a_id = net(&a, &sa)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b_id = net(&b, &sb)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let join =
        json!({"address": format!("127.0.0.1:{}", a.peer_port()), "code": code, "device_id": a_id});
    b.api(&sb, "POST", "/api/pairing/join", Some(&join.to_string()));
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    let accept = json!({"device_id": b_id}).to_string();
    a.api(&sa, "POST", "/api/pairing/accept", Some(&accept));
    assert!(wait_for(Duration::from_secs(8), || net(&a, &sa)["paired"]
        [0]["status"]
        == "connected"));
    let revoke = format!("/api/devices/{b_id}/revoke");
    assert_eq!(a.api(&sa, "POST", &revoke, None).status, 200);
    assert!(wait_for(Duration::from_secs(5), || net(&b, &sb)["paired"]
        [0]["status"]
        == "refused_by_peer"));
    for server in [&a, &b] {
        let log = server.log_text();
        for needle in [
            code.as_str(),
            "MARKER-name-a",
            "MARKER-name-b",
            "MARKER-master-pw",
        ] {
            assert!(!log.contains(needle), "log leaks {needle}:\n{log}");
        }
        let key_text = fs::read_to_string(server.fx.config_dir.join("device-key")).unwrap();
        let private = key_text.lines().nth(1).unwrap().to_string();
        let mut files = Vec::new();
        files_under(&server.fx.runtime_dir, &mut files);
        files_under(&server.fx.config_dir, &mut files);
        for (path, bytes) in files {
            assert!(!contains(&bytes, &code), "{path} leaks the code");
            if !path.ends_with("/device-key") {
                assert!(!contains(&bytes, &private), "{path} leaks the key");
            }
            assert!(!contains(&bytes, "MARKER-master-pw"), "{path}");
        }
    }
    let log = a.log_text();
    assert!(log.contains("pairing succeeded") && log.contains("device revoked"));
}

// --- 004 T133: the sync modules print nothing and use no unsafe code ---

#[test]
fn sync_modules_print_nothing_and_have_no_unsafe_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in ["sync_runtime.rs", "sync_store.rs", "http/api_sync.rs"] {
        let text = fs::read_to_string(root.join(file)).unwrap();
        for needle in ["unsafe ", "println!", "eprintln!", "dbg!", "print!("] {
            assert!(!text.contains(needle), "{needle} in {file}");
        }
        // Logging goes only through the closed `LogEvent` set.
        assert!(!text.contains("log.fatal("), "{file}");
    }
}
