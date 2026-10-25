//! 005 T036: every sharing route goes through the 002 guard pipeline, and no response ever
//! carries a code after redemption, a proof, a wallet id or credential data (FR-027).

mod common;

use common::server::TestServer;
use common::share::*;
use common::sync::*;
use passwsyncd::log::Reason;

const POSTS: &[&str] = &[
    "/api/wallets/W/share",
    "/api/share/cancel",
    "/api/share/accept",
    "/api/share/reject",
    "/api/receive",
    "/api/receive/cancel",
    "/api/received/00000000000000000000000000000000/open",
    "/api/received/00000000000000000000000000000000/discard",
    "/api/share/notices/dismiss",
];

#[test]
fn sharing_routes_need_host_session_csrf_and_origin() {
    let server = TestServer::start();
    let s = server.login();
    let cookie = format!("pws_session={}", s.cookie);
    let origin = server.origin();
    let mut expected = (0, 0, 0, 0);
    for (method, path) in
        std::iter::once(("GET", "/api/share")).chain(POSTS.iter().map(|p| ("POST", *p)))
    {
        // Wrong Host.
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: evil.example:{}\r\nContent-Length: 0\r\n\r\n",
            server.port
        );
        let resp = server.raw(raw.as_bytes());
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (403, "forbidden"),
            "{path}"
        );
        expected.0 += 1;
        // No session.
        let resp = server.send(
            method,
            path,
            &[("X-CSRF-Token", &s.csrf), ("Origin", &origin)],
            b"{}",
        );
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (401, "unauthorized"),
            "{path}"
        );
        expected.1 += 1;
        // No CSRF token.
        let resp = server.send(
            method,
            path,
            &[("Cookie", &cookie), ("Origin", &origin)],
            b"{}",
        );
        assert_eq!(
            (resp.status, resp.text().as_str()),
            (403, "forbidden"),
            "{path}"
        );
        expected.2 += 1;
        if method == "POST" {
            // Missing or foreign Origin on a state change.
            for bad in [None, Some("http://evil.example")] {
                let mut headers = vec![
                    ("Cookie", cookie.as_str()),
                    ("X-CSRF-Token", s.csrf.as_str()),
                ];
                if let Some(o) = bad {
                    headers.push(("Origin", o));
                }
                let resp = server.send(method, path, &headers, b"{}");
                assert_eq!(
                    (resp.status, resp.text().as_str()),
                    (403, "forbidden"),
                    "{path}"
                );
                expected.3 += 1;
            }
            // Oversized body refused before reading.
            let raw = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nCookie: {cookie}\r\nX-CSRF-Token: {}\r\nOrigin: {origin}\r\nContent-Length: {}\r\n\r\n",
                server.host(),
                s.csrf,
                9 * 1024 * 1024
            );
            assert_eq!(server.raw(raw.as_bytes()).status, 413, "{path}");
        }
    }
    let r = server.running().rejections();
    assert_eq!(r.get(Reason::Host), expected.0);
    assert_eq!(r.get(Reason::Session), expected.1);
    assert_eq!(r.get(Reason::Csrf), expected.2);
    assert_eq!(r.get(Reason::Origin), expected.3);
}

#[test]
fn wrong_methods_and_error_bodies() {
    let server = TestServer::start();
    let s = server.login();
    let resp = server.api(&s, "POST", "/api/share", None);
    assert_eq!(resp.status, 405);
    for path in POSTS {
        let resp = server.api(&s, "GET", path, None);
        assert_eq!(resp.status, 405, "{path}");
    }
    // Error bodies keep the `{error, message}` shape.
    let resp = server.api(&s, "POST", "/api/receive", Some("not json"));
    assert_eq!(resp.status, 400);
    let body = resp.json();
    assert!(body["error"].is_string() && body["message"].is_string());
}

#[test]
fn no_response_carries_a_used_code_proof_wallet_id_or_credentials() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add(
        "Personal",
        "TITLE-MARKER",
        "USER-MARKER",
        "PASSWORD-MARKER",
        "",
        "NOTES-MARKER",
    );
    let code = invite_code(&a, "Personal", &b.device_id());
    let id = share_to_with_code(&a, &b, &code);
    let wallet_id = {
        let v = vault_core::Vault::unlock(
            &std::fs::read(a.wallet_file("Personal")).unwrap(),
            vault_core::MasterPassword::new(PASSWORD.into()),
            vault_core::DeviceId::new("x").unwrap(),
            Box::new(vault_core::FixedClock::new(0)),
        )
        .unwrap();
        v.wallet_id().to_string()
    };
    for (i, label) in [(&a, "A"), (&b, "B")] {
        let text = i.api("GET", "/api/share", None).text();
        for needle in [
            code.as_str(),
            &code[..4],
            wallet_id.as_str(),
            "TITLE-MARKER",
            "PASSWORD-MARKER",
            "proof",
        ] {
            assert!(!text.contains(needle), "{label}: {needle} in {text}");
        }
    }
    let opened = open_received(&b, &id, "Shared", PASSWORD).text();
    for needle in [code.as_str(), wallet_id.as_str(), "TITLE-MARKER", PASSWORD] {
        assert!(!opened.contains(needle), "{needle} in {opened}");
    }
}

fn share_to_with_code(a: &Instance, b: &Instance, code: &str) -> String {
    assert_eq!(receive(b, code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(a, "awaiting_acceptance"));
    assert_eq!(accept(a, &b.device_id()).status, 200);
    assert!(wait_receive(b, "stored"));
    share_state(b)["receive"]["received_id"]
        .as_str()
        .unwrap()
        .to_string()
}
