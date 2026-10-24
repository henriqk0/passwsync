//! 003 US3: nearby devices in `GET /api/network` (FR-015, FR-016, SC-008).

mod common;

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use common::server::{Fixture, TestServer, net_config, wait_for};
use serde_json::Value;

#[test]
fn a_device_showing_a_code_appears_nearby_with_fingerprint_and_address() {
    let b = TestServer::start_with(&net_config());
    let a = TestServer::start_announcing(Fixture::new(&net_config()), vec![b.discovery_port()]);
    let (sa, sb) = (a.login(), b.login());
    assert_eq!(a.api(&sa, "POST", "/api/pairing/start", None).status, 200);
    let a_view = a.api(&sa, "GET", "/api/network", None).json();
    let a_id = a_view["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a_fp = a_view["this_device"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let found = || -> Option<Value> {
        let v = b.api(&sb, "GET", "/api/network", None).json();
        v["nearby"]
            .as_array()?
            .iter()
            .find(|n| n["device_id"] == a_id.as_str())
            .cloned()
    };
    assert!(wait_for(Duration::from_secs(3), || found().is_some()));
    let entry = found().unwrap();
    assert_eq!(entry["fingerprint"], a_fp.as_str());
    assert_eq!(entry["addr"], format!("127.0.0.1:{}", a.peer_port()));
    assert_eq!(entry["paired"], false);
}

/// SC-008: bounded under a flood and the UI answers within 1 s. Slow; `--ignored`.
#[test]
#[ignore]
fn nearby_stays_bounded_and_responsive_under_a_flood() {
    let b = TestServer::start_with(&net_config());
    let sb = b.login();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = ("127.0.0.1", b.discovery_port());
    let end = Instant::now() + Duration::from_secs(60);
    let mut sent = 0u32;
    while Instant::now() < end && sent < 10_000 {
        let mut packet = [0u8; 39];
        packet[..5].copy_from_slice(b"PWSD\x01");
        packet[5..9].copy_from_slice(&sent.to_be_bytes());
        packet[37..].copy_from_slice(&27472u16.to_be_bytes());
        let _ = sender.send_to(&packet, target);
        sent += 1;
        if sent % 1000 == 0 {
            let started = Instant::now();
            let v = b.api(&sb, "GET", "/api/network", None).json();
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(v["nearby"].as_array().unwrap().len() <= 64);
        }
    }
}
