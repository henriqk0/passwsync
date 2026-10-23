mod common;

use common::{mode, server::TestServer};
use passwsyncd::log::Reason;

fn is_url(text: &str, port: u16) -> bool {
    let prefix = format!("http://127.0.0.1:{port}/launch/");
    text.strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix('\n'))
        .is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

#[test]
fn launch_exchange_sets_session_cookie_and_rotates_the_launch_file() {
    let server = TestServer::start();
    let before = server.launch_url();
    assert!(is_url(&before, server.port), "{before:?}");
    assert_eq!(mode(&server.fx.launch_file), 0o600);
    let resp = server.get(&server.launch_path());
    assert_eq!(resp.status, 303);
    assert_eq!(resp.header("location"), Some("/"));
    let cookie = resp.header("set-cookie").unwrap();
    let (value, attributes) = cookie.split_once(';').unwrap();
    let hex = value.strip_prefix("pws_session=").unwrap();
    assert_eq!(hex.len(), 64);
    assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(attributes, " Path=/; HttpOnly; SameSite=Strict");
    let after = server.launch_url();
    assert!(is_url(&after, server.port));
    assert_ne!(before, after);
    assert_eq!(mode(&server.fx.launch_file), 0o600);
}

#[test]
fn reusing_a_spent_or_wrong_token_gets_the_static_403_page() {
    let server = TestServer::start();
    let old = server.launch_path();
    assert_eq!(server.get(&old).status, 303);
    for path in [
        old,
        "/launch/".to_string(),
        "/launch/zz".to_string(),
        format!("/launch/{}", "0".repeat(64)),
    ] {
        let resp = server.get(&path);
        assert_eq!(resp.status, 403, "{path}");
        assert!(resp.header("set-cookie").is_none());
        assert!(
            resp.text()
                .contains("This launch address is no longer valid"),
            "{}",
            resp.text()
        );
        assert_eq!(
            resp.header("content-type"),
            Some("text/html; charset=utf-8")
        );
    }
    assert_eq!(server.running().rejections().get(Reason::Session), 4);
}

#[test]
fn index_with_session_carries_the_csrf_meta_and_without_shows_instructions() {
    let server = TestServer::start();
    let s = server.login();
    let resp = server.send(
        "GET",
        "/",
        &[("Cookie", &format!("pws_session={}", s.cookie))],
        b"",
    );
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let html = resp.text();
    assert!(html.contains(&format!(
        "<meta name=\"csrf-token\" content=\"{}\">",
        s.csrf
    )));
    let resp = server.get("/");
    assert_eq!(resp.status, 200);
    let html = resp.text();
    assert!(!html.contains("csrf-token"));
    assert!(html.contains("launch-url"), "{html}");
}

#[test]
fn sessions_do_not_survive_a_restart() {
    let mut server = TestServer::start();
    let s = server.login();
    let fx = std::mem::replace(&mut server.fx, common::server::Fixture::new(""));
    server.stop();
    let restarted = TestServer::start_in(fx);
    let resp = restarted.api(&s, "GET", "/api/state", None);
    assert_eq!(resp.status, 401);
}

#[test]
fn static_assets_are_served_without_a_session() {
    let server = TestServer::start();
    let cases = [
        ("/static/app.js", "text/javascript; charset=utf-8"),
        ("/static/app.css", "text/css; charset=utf-8"),
        ("/static/icon.svg", "image/svg+xml"),
    ];
    for (path, content_type) in cases {
        let resp = server.get(path);
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(resp.header("content-type"), Some(content_type), "{path}");
        assert!(!resp.body.is_empty());
    }
    assert_eq!(server.get("/static/missing.js").status, 404);
}
