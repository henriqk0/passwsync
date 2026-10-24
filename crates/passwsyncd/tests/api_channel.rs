//! 003 US4: channel status in `GET /api/network`, and captured peer traffic carries no
//! names, codes or wallet strings in clear (SC-006).

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::server::{Fixture, Session, TestServer, free_net_port, wait_for};
use serde_json::{Value, json};

fn net(server: &TestServer, s: &Session) -> Value {
    server.api(s, "GET", "/api/network", None).json()
}

/// A TCP relay to `target` that records every byte in both directions.
fn recording_proxy(target: u16) -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(("127.0.0.1", target)) else {
                continue;
            };
            for (mut from, mut to) in [
                (client.try_clone().unwrap(), server.try_clone().unwrap()),
                (server, client),
            ] {
                let record = Arc::clone(&record);
                thread::spawn(move || {
                    let mut buf = [0u8; 2048];
                    while let Ok(n) = from.read(&mut buf) {
                        if n == 0 || to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        record.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    let _ = to.shutdown(Shutdown::Write);
                });
            }
        }
    });
    (port, seen)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn config(name: &str, peer: u16, discovery: u16) -> String {
    format!(
        "network = on\npeer_port = {peer}\ndiscovery_port = {discovery}\ndevice_name = \"{name}\"\n"
    )
}

#[test]
fn channel_status_and_captured_traffic() {
    let (a_peer, a_disc) = (free_net_port(), free_net_port());
    let a_fx = Fixture::new(&config("Laptop-Secret-Name", a_peer, a_disc));
    let mut a = TestServer::start_in(a_fx);
    let b = TestServer::start_with(&config(
        "Phone-Secret-Name",
        free_net_port(),
        free_net_port(),
    ));
    let (sa, sb) = (a.login(), b.login());
    // A wallet exists on both; its name must never cross the network.
    let wallet = r#"{"name":"Wallet-Secret-Name","password":"correct horse battery","password_confirm":"correct horse battery"}"#;
    assert_eq!(a.api(&sa, "POST", "/api/wallets", Some(wallet)).status, 201);
    let (proxy, seen) = recording_proxy(a_peer);
    let started = a.api(&sa, "POST", "/api/pairing/start", None).json();
    let code = started["code"].as_str().unwrap().replace(' ', "");
    let b_id = net(&b, &sb)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a_id = net(&a, &sa)["this_device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    let join = json!({"address": format!("127.0.0.1:{proxy}"), "code": code, "device_id": a_id});
    assert_eq!(
        b.api(&sb, "POST", "/api/pairing/join", Some(&join.to_string()))
            .status,
        202
    );
    assert!(wait_for(Duration::from_secs(5), || net(&a, &sa)["pairing"]
        ["state"]
        == "awaiting_acceptance"));
    let accept = json!({"device_id": b_id}).to_string();
    assert_eq!(
        a.api(&sa, "POST", "/api/pairing/accept", Some(&accept))
            .status,
        200
    );
    // B dials A (through the proxy) once paired; both show "connected".
    assert!(
        wait_for(
            Duration::from_secs(8),
            || net(&a, &sa)["paired"][0]["status"] == "connected"
                && net(&b, &sb)["paired"][0]["status"] == "connected"
        ),
        "{} / {}",
        net(&a, &sa)["paired"],
        net(&b, &sb)["paired"]
    );
    assert_eq!(net(&b, &sb)["paired"][0]["name"], "Laptop-Secret-Name");
    assert_eq!(net(&a, &sa)["paired"][0]["name"], "Phone-Secret-Name");
    assert!(b.log_text().contains("peer connected"));
    std::thread::sleep(Duration::from_millis(1500)); // some keepalives
    let traffic = seen.lock().unwrap().clone();
    assert!(traffic.len() > 300, "traffic was captured");
    for needle in [
        "Laptop-Secret-Name",
        "Phone-Secret-Name",
        "Wallet-Secret-Name",
        code.as_str(),
        "correct horse battery",
    ] {
        assert!(!contains(&traffic, needle), "{needle} crossed the network");
    }

    // A goes away: B shows it offline.
    let a_fx = std::mem::replace(&mut a.fx, Fixture::new(""));
    a.stop();
    assert!(wait_for(Duration::from_secs(8), || net(&b, &sb)["paired"]
        [0]["status"]
        == "offline"));
    assert!(b.log_text().contains("peer disconnected"));

    // A comes back without B's pin (revoked while away): B is refused by peer.
    let peers = a_fx.config_dir.join("peers");
    std::fs::write(&peers, "passwsync-peers-v1\n").unwrap();
    let a2 = TestServer::start_in(a_fx);
    assert!(
        wait_for(
            Duration::from_secs(10),
            || net(&b, &sb)["paired"][0]["status"] == "refused_by_peer"
        ),
        "{}",
        net(&b, &sb)["paired"]
    );
    assert!(b.log_text().contains("refused by peer"));
    assert!(wait_for(Duration::from_secs(2), || a2
        .log_text()
        .contains("peer refused")));
}
