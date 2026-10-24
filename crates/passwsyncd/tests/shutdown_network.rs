//! 003 host runtime: shutdown order (contracts/host-runtime-network.md "Shutdown"):
//! Close(shutdown) on channels, sockets closed, last_seen saved, key and code wiped, then
//! wallets locked; a code shown before the stop is gone after a restart.

mod common;

use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

use common::server::{Fixture, Session, TestServer, free_net_port, wait_for};
use serde_json::{Value, json};

fn net(server: &TestServer, s: &Session) -> Value {
    server.api(s, "GET", "/api/network", None).json()
}

#[test]
fn stopping_closes_the_network_before_locking_wallets() {
    let (peer, disc) = (free_net_port(), free_net_port());
    let config = format!("network = on\npeer_port = {peer}\ndiscovery_port = {disc}\n");
    let mut a = TestServer::start_in(Fixture::new(&config));
    let b = TestServer::start_with(&format!(
        "network = on\npeer_port = {}\ndiscovery_port = {}\n",
        free_net_port(),
        free_net_port()
    ));
    let (sa, sb) = (a.login(), b.login());
    let wallet = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;
    assert_eq!(a.api(&sa, "POST", "/api/wallets", Some(wallet)).status, 201);
    // Pair and connect.
    let code = a.api(&sa, "POST", "/api/pairing/start", None).json()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let a_id = net(&a, &sa)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let b_id = net(&b, &sb)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let join = json!({"address": format!("127.0.0.1:{peer}"), "code": code, "device_id": a_id});
    b.api(&sb, "POST", "/api/pairing/join", Some(&join.to_string()));
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    let accept = json!({"device_id": b_id}).to_string();
    a.api(&sa, "POST", "/api/pairing/accept", Some(&accept));
    assert!(wait_for(Duration::from_secs(8), || net(&a, &sa)["paired"]
        [0]["status"]
        == "connected"));
    // A fresh code is on screen when the service stops.
    assert_eq!(a.api(&sa, "POST", "/api/pairing/start", None).status, 200);
    assert!(a.running().device_key_held());

    let fx = std::mem::replace(&mut a.fx, Fixture::new(""));
    assert_eq!(a.stop(), 0);
    let log = a.log_text();
    let network_off = log.rfind("network off").expect("network closed on stop");
    let locked = log.find("locked Personal (stop)").expect("wallet locked");
    assert!(network_off < locked, "network first, then wallets:\n{log}");
    // B received Close(shutdown): a clean close, not an error or a timeout.
    assert!(
        wait_for(Duration::from_secs(3), || b
            .log_text()
            .contains(") (closed)")
            || b.log_text().contains(" (closed)")),
        "{}",
        b.log_text()
    );
    assert!(!b.log_text().contains("(error)") && !b.log_text().contains("(timeout)"));
    // Sockets are closed: both ports can be bound again.
    assert!(TcpListener::bind(("0.0.0.0", peer)).is_ok());
    assert!(UdpSocket::bind(("0.0.0.0", disc)).is_ok());
    // last_seen was saved.
    let peers = std::fs::read_to_string(fx.config_dir.join("peers")).unwrap();
    let line = peers.lines().nth(1).unwrap();
    assert_ne!(line.split(' ').nth(2), Some("-"), "last_seen saved: {line}");
    // After a restart the old code is gone.
    let again = TestServer::start_in(fx);
    let s = again.login();
    assert_eq!(net(&again, &s)["pairing"], Value::Null);
}
