mod common;

use common::server::{Resp, TestServer};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

fn assert_security_headers(resp: &Resp, what: &str) {
    let expected = [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("connection", "close"),
    ];
    assert!(resp.status != 0, "{what}: no response");
    for (name, value) in expected {
        assert_eq!(resp.header(name), Some(value), "{what}: {name}");
    }
    assert!(
        !resp
            .headers
            .iter()
            .any(|(n, _)| n.to_ascii_lowercase().starts_with("access-control-")),
        "{what}: CORS header present"
    );
    let length: usize = resp.header("content-length").unwrap().parse().unwrap();
    assert_eq!(length, resp.body.len(), "{what}: content-length");
}

#[test]
fn every_response_carries_the_security_headers() {
    let server = TestServer::start();
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    let cases: Vec<(&str, Resp)> = vec![
        (
            "index",
            server.send("GET", "/", &[("Cookie", &cookie)], b""),
        ),
        ("instructions", server.get("/")),
        ("app.js", server.get("/static/app.js")),
        ("app.css", server.get("/static/app.css")),
        ("icon", server.get("/static/icon.svg")),
        ("launch", server.get(&server.launch_path())),
        ("launch 403", server.get("/launch/00")),
        ("401", server.get("/api/state")),
        (
            "csrf 403",
            server.send("GET", "/api/state", &[("Cookie", &cookie)], b""),
        ),
        (
            "host 403",
            server.raw(b"GET / HTTP/1.1\r\nHost: evil\r\n\r\n"),
        ),
        ("404", server.get("/nowhere")),
        ("405", server.send("PATCH", "/", &[], b"")),
        (
            "413",
            server.send(
                "POST",
                "/api/wallets",
                &[("Content-Length", "99999999")],
                b"",
            ),
        ),
        ("400", server.raw(b"garbage\r\n\r\n")),
        (
            "431",
            server.send("GET", "/", &[("X-Pad", &"a".repeat(20_000))], b""),
        ),
    ];
    for (what, resp) in &cases {
        assert_security_headers(resp, what);
    }
}
