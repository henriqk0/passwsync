mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::server::{TestServer, parse_response};
use passwsyncd::log::Reason;

#[test]
fn header_block_over_16_kib_is_431() {
    let server = TestServer::start();
    let pad = "a".repeat(17 * 1024);
    let resp = server.send("GET", "/static/app.css", &[("X-Pad", &pad)], b"");
    assert_eq!(resp.status, 431);
    assert_eq!(resp.text(), "too large");
    assert_eq!(server.running().rejections().get(Reason::Size), 1);
}

#[test]
fn header_block_just_under_16_kib_is_accepted() {
    let server = TestServer::start();
    let pad = "a".repeat(15 * 1024);
    let resp = server.send("GET", "/static/app.css", &[("X-Pad", &pad)], b"");
    assert_eq!(resp.status, 200);
}

#[test]
fn more_than_48_headers_is_431() {
    let server = TestServer::start();
    let names: Vec<String> = (0..48).map(|i| format!("X-H{i}")).collect();
    let headers: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
    // 48 extra headers plus Host = 49.
    let resp = server.send("GET", "/static/app.css", &headers, b"");
    assert_eq!(resp.status, 431);
    let resp = server.send("GET", "/static/app.css", &headers[..47], b"");
    assert_eq!(resp.status, 200, "48 headers in total are allowed");
}

#[test]
fn transfer_encoding_is_rejected_with_400() {
    let server = TestServer::start();
    let resp = server.send(
        "POST",
        "/api/wallets",
        &[("Transfer-Encoding", "chunked")],
        b"0\r\n\r\n",
    );
    assert_eq!(resp.status, 400);
    assert_eq!(resp.text(), "bad request");
    assert_eq!(server.running().rejections().get(Reason::Size), 1);
}

#[test]
fn content_length_over_8_mib_is_413_before_any_body_is_read() {
    let server = TestServer::start();
    let raw = format!(
        "POST /api/wallets HTTP/1.1\r\nHost: {}\r\nContent-Length: 99999999\r\n\r\n",
        server.host()
    );
    let resp = server.raw(raw.as_bytes());
    assert_eq!(resp.status, 413);
    assert_eq!(resp.text(), "too large");
    let limit = format!(
        "POST /api/wallets HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        server.host(),
        8 * 1024 * 1024 + 1
    );
    assert_eq!(server.raw(limit.as_bytes()).status, 413);
}

#[test]
fn invalid_or_conflicting_content_length_is_400() {
    let server = TestServer::start();
    for value in ["abc", "-1", "1, 2", ""] {
        let raw = format!(
            "POST /api/wallets HTTP/1.1\r\nHost: {}\r\nContent-Length: {value}\r\n\r\n",
            server.host()
        );
        assert_eq!(server.raw(raw.as_bytes()).status, 400, "{value:?}");
    }
    let raw = format!(
        "POST /api/wallets HTTP/1.1\r\nHost: {}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        server.host()
    );
    assert_eq!(server.raw(raw.as_bytes()).status, 400);
}

#[test]
fn malformed_request_line_is_400() {
    let server = TestServer::start();
    assert_eq!(server.raw(b"\x00\x01garbage\r\n\r\n").status, 400);
}

#[test]
fn one_request_per_connection() {
    let server = TestServer::start();
    let one = format!(
        "GET /static/app.css HTTP/1.1\r\nHost: {}\r\n\r\n",
        server.host()
    );
    let resp = server.raw(format!("{one}{one}").as_bytes());
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("connection"), Some("close"));
    let text = String::from_utf8_lossy(&resp.raw);
    assert_eq!(text.matches("HTTP/1.1 ").count(), 1, "{text}");
}

#[test]
fn idle_connection_is_closed_after_the_10_second_read_timeout() {
    let server = TestServer::start();
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .write_all(b"GET /static/app.css HTTP/1.1\r\n")
        .unwrap();
    let started = Instant::now();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(9),
        "closed too early: {waited:?}"
    );
    assert!(
        waited <= Duration::from_secs(15),
        "closed too late: {waited:?}"
    );
    let resp = parse_response(out);
    assert!(
        resp.status == 0 || resp.status == 408,
        "status {}",
        resp.status
    );
}
