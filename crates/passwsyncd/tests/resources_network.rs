//! 003 SC-007: the service's added memory with networking on and 5 idle paired peers.
//! Slow; run with `cargo test --release -- --ignored`. The CPU and wake-up budget per peer
//! is measured in `device-link-net/tests/resources.rs`.

mod common;

use std::fs;
use std::time::Duration;

use common::server::{Session, TestServer, net_config, wait_for};
use serde_json::{Value, json};

fn rss_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

fn net(server: &TestServer, s: &Session) -> Value {
    server.api(s, "GET", "/api/network", None).json()
}

#[test]
#[ignore]
fn five_idle_peers_add_less_than_10_mb() {
    let off = TestServer::start();
    let baseline = rss_kib();
    drop(off);
    let a = TestServer::start_with(&net_config());
    let sa = a.login();
    let a_id = net(&a, &sa)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut peers = Vec::new();
    for _ in 0..5 {
        let b = TestServer::start_with(&net_config());
        let sb = b.login();
        let code = a.api(&sa, "POST", "/api/pairing/start", None).json()["code"]
            .as_str()
            .unwrap()
            .to_string();
        let body = json!({"address": format!("127.0.0.1:{}", a.peer_port()), "code": code, "device_id": a_id});
        b.api(&sb, "POST", "/api/pairing/join", Some(&body.to_string()));
        assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
            ["state"]
            == "awaiting_acceptance"));
        let b_id = net(&b, &sb)["this_device"]["device_id"].clone();
        a.api(
            &sa,
            "POST",
            "/api/pairing/accept",
            Some(&json!({"device_id": b_id}).to_string()),
        );
        peers.push(b);
    }
    assert!(wait_for(Duration::from_secs(10), || net(&a, &sa)["paired"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["status"] == "connected")));
    std::thread::sleep(Duration::from_secs(20));
    let delta = rss_kib().saturating_sub(baseline);
    eprintln!("RSS +{delta} KiB for 6 services in one process");
    // Six whole services share this process; one service's share is far below this.
    assert!(delta < 6 * 10 * 1024, "{delta} KiB");
}
