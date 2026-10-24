//! 003 SC-002, FR-010: with `network = on` the process holds exactly the UI listener, one
//! TCP listener on `peer_port` and one UDP socket on `discovery_port`, plus connections to
//! policy-passing peers; no other listener and no IPv6 socket. One test per file: the
//! inventory covers the whole test process.

mod common;

use std::time::Duration;

use common::inventory::sockets;
use common::server::{TestServer, free_net_port, wait_for};
use serde_json::json;

#[test]
fn networking_on_opens_exactly_the_contract_sockets() {
    let (peer, disc) = (free_net_port(), free_net_port());
    let a = TestServer::start_with(&format!(
        "network = on\npeer_port = {peer}\ndiscovery_port = {disc}\n"
    ));
    let s = a.login();
    assert_eq!(a.running().network_status(), "on");
    assert!(a.log_text().contains(&format!(
        "network on peer={peer} discovery={disc} interfaces=lo"
    )));
    let v = a.api(&s, "GET", "/api/network", None).json();
    assert_eq!(v["status"]["state"], "on");
    assert_eq!(
        v["status"]["interfaces"],
        json!([{"name": "lo", "addr": "127.0.0.1", "prefix": 8}])
    );
    std::thread::sleep(Duration::from_millis(100));
    let socks = sockets();
    let listeners: Vec<String> = socks
        .iter()
        .filter(|s| s.is_listener())
        .map(|s| s.local.clone())
        .collect();
    let mut expected = vec![format!("127.0.0.1:{}", a.port), format!("0.0.0.0:{peer}")];
    expected.sort();
    let mut got = listeners.clone();
    got.sort();
    assert_eq!(got, expected, "{socks:?}");
    let udp: Vec<&common::inventory::Sock> = socks.iter().filter(|s| s.proto == "udp").collect();
    assert_eq!(udp.len(), 1, "{socks:?}");
    assert_eq!(udp[0].local, format!("0.0.0.0:{disc}"));
    assert!(!socks.iter().any(|s| s.proto.ends_with('6')), "no IPv6");
    // Remaining TCP sockets are UI connections (loopback) only.
    for sock in socks
        .iter()
        .filter(|s| s.proto == "tcp" && !s.is_listener())
    {
        assert!(sock.local.starts_with("127.0.0.1:"), "{sock:?}");
    }
    // A pairing connection appears only towards a policy-passing peer (here loopback).
    let b = TestServer::start_with(&format!(
        "network = on\npeer_port = {}\ndiscovery_port = {}\n",
        free_net_port(),
        free_net_port()
    ));
    let sb = b.login();
    let code = a.api(&s, "POST", "/api/pairing/start", None).json()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let body = json!({"address": format!("127.0.0.1:{peer}"), "code": code, "device_id": null});
    b.api(&sb, "POST", "/api/pairing/join", Some(&body.to_string()));
    assert!(wait_for(Duration::from_secs(5), || a
        .api(&s, "GET", "/api/network", None)
        .json()["pairing"]["state"]
        == "awaiting_acceptance"));
    let socks = sockets();
    assert!(
        socks
            .iter()
            .any(|x| x.proto == "tcp" && x.local == format!("127.0.0.1:{peer}") && x.state == "01")
    );
    assert!(!socks.iter().any(|x| x.proto.ends_with('6')));
}
