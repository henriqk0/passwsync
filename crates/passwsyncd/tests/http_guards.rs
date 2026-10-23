mod common;

use std::fs;

use common::server::TestServer;
use passwsyncd::log::Reason;

const MARKER: &str = "MARKER-echo-check";

#[test]
fn foreign_or_missing_host_is_403_before_routing() {
    let server = TestServer::start();
    let port = server.port;
    let hosts = [
        format!("evil.example:{port}"),
        format!("localhost:{port}"),
        "127.0.0.1".to_string(),
        format!("127.0.0.1:{}", port + 1),
        format!("{MARKER}:{port}"),
    ];
    for host in &hosts {
        for path in ["/", "/static/app.js", "/nowhere", "/api/state"] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let resp = server.raw(raw.as_bytes());
            assert_eq!(resp.status, 403, "{host} {path}");
            assert_eq!(resp.text(), "forbidden");
            assert!(!String::from_utf8_lossy(&resp.raw).contains(MARKER));
        }
    }
    let resp = server.raw(b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(resp.status, 403, "missing Host");
    let resp = server.raw(
        format!(
            "GET / HTTP/1.1\r\nHost: {0}\r\nHost: {0}\r\n\r\n",
            server.host()
        )
        .as_bytes(),
    );
    assert_eq!(resp.status, 403, "duplicate Host");
    assert_eq!(server.running().rejections().get(Reason::Host), 22);
}

#[test]
fn api_without_or_with_stale_session_is_401() {
    let server = TestServer::start();
    let s = server.login();
    let resp = server.send("GET", "/api/state", &[("X-CSRF-Token", &s.csrf)], b"");
    assert_eq!(resp.status, 401);
    assert_eq!(resp.text(), "unauthorized");
    let stale = format!("pws_session={}", "ab".repeat(32));
    let resp = server.send(
        "GET",
        "/api/state",
        &[("Cookie", &stale), ("X-CSRF-Token", &s.csrf)],
        b"",
    );
    assert_eq!(resp.status, 401);
    let marker = format!("pws_session={MARKER}");
    let resp = server.send("GET", "/api/state", &[("Cookie", &marker)], b"");
    assert_eq!(resp.status, 401);
    assert!(!String::from_utf8_lossy(&resp.raw).contains(MARKER));
    assert_eq!(server.running().rejections().get(Reason::Session), 3);
}

#[test]
fn api_with_missing_or_wrong_csrf_is_403() {
    let server = TestServer::start();
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    let resp = server.send("GET", "/api/state", &[("Cookie", &cookie)], b"");
    assert_eq!(resp.status, 403);
    assert_eq!(resp.text(), "forbidden");
    let mut wrong = s.csrf.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    for token in [wrong.as_str(), s.cookie.as_str(), "", "zz", MARKER] {
        let resp = server.send(
            "GET",
            "/api/state",
            &[("Cookie", &cookie), ("X-CSRF-Token", token)],
            b"",
        );
        assert_eq!(resp.status, 403, "{token:?}");
    }
    assert_eq!(server.running().rejections().get(Reason::Csrf), 6);
}

#[test]
fn state_changes_need_the_exact_origin() {
    let server = TestServer::start();
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    let base = [
        ("Cookie", cookie.as_str()),
        ("X-CSRF-Token", s.csrf.as_str()),
    ];
    let bad_origins = [
        None,
        Some("http://evil.example".to_string()),
        Some("null".to_string()),
        Some(format!("http://localhost:{}", server.port)),
        Some(format!("https://127.0.0.1:{}", server.port)),
        Some(format!("http://127.0.0.1:{}/", server.port)),
    ];
    for method in ["POST", "PUT", "DELETE"] {
        for origin in &bad_origins {
            let mut headers = base.to_vec();
            if let Some(origin) = origin {
                headers.push(("Origin", origin));
            }
            let resp = server.send(method, "/api/lock-all", &headers, b"");
            assert_eq!(resp.status, 403, "{method} {origin:?}");
            assert_eq!(resp.text(), "forbidden");
        }
    }
    assert_eq!(server.running().rejections().get(Reason::Origin), 18);
    let mut headers = base.to_vec();
    let origin = server.origin();
    headers.push(("Origin", &origin));
    let resp = server.send("POST", "/api/lock-all", &headers, b"");
    assert!(
        resp.status != 403 && resp.status != 401,
        "valid request passes guards"
    );
}

#[test]
fn unknown_methods_are_405() {
    let server = TestServer::start();
    for method in ["PATCH", "HEAD", "OPTIONS", "TRACE", "BREW"] {
        let resp = server.send(method, "/", &[], b"");
        assert_eq!(resp.status, 405, "{method}");
    }
    assert_eq!(server.send("POST", "/static/app.js", &[], b"").status, 405);
    assert_eq!(server.send("DELETE", "/", &[], b"").status, 405);
}

#[test]
fn rejected_requests_change_no_state_and_return_no_data() {
    let server = TestServer::start();
    let before = server.launch_url();
    let path = server.launch_path();
    let raw = format!(
        "GET {path} HTTP/1.1\r\nHost: evil.example:{}\r\n\r\n",
        server.port
    );
    let resp = server.raw(raw.as_bytes());
    assert_eq!(resp.status, 403);
    assert!(resp.header("set-cookie").is_none());
    assert_eq!(fs::read_to_string(&server.fx.launch_file).unwrap(), before);
    server.login();
}
