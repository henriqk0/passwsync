//! 003 SC-008: 10 000 announcements and 10 000 connection attempts per minute from one
//! address keep memory bounded and the loopback UI responsive. Slow; `--ignored`.

mod common;

use std::fs;
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use common::server::{TestServer, net_config};

fn rss_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

#[test]
#[ignore]
fn udp_and_tcp_flood_keeps_memory_bounded_and_the_ui_responsive() {
    let a = TestServer::start_with(&net_config());
    let s = a.login();
    let before = rss_kib();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let end = Instant::now() + Duration::from_secs(60);
    let mut sent = 0u32;
    while Instant::now() < end && sent < 10_000 {
        let mut packet = [0u8; 39];
        packet[..5].copy_from_slice(b"PWSD\x01");
        packet[5..9].copy_from_slice(&sent.to_be_bytes());
        packet[37..].copy_from_slice(&27472u16.to_be_bytes());
        let _ = udp.send_to(&packet, ("127.0.0.1", a.discovery_port()));
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", a.peer_port())) {
            let _ = stream.write_all(b"\x00\x06PWSC\x01\x01");
        }
        sent += 1;
        if sent % 500 == 0 {
            let started = Instant::now();
            let v = a.api(&s, "GET", "/api/network", None).json();
            assert!(started.elapsed() < Duration::from_secs(1), "UI slow");
            assert!(v["nearby"].as_array().unwrap().len() <= 64);
        }
    }
    let grown = rss_kib().saturating_sub(before);
    eprintln!("RSS +{grown} KiB after {sent} datagrams and connections");
    assert!(grown < 20 * 1024, "{grown} KiB");
}
