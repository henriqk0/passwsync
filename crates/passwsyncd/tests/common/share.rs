//! 005: helpers for wallet-sharing tests over real service instances.
#![allow(dead_code)]

use std::time::Duration;

use serde_json::{Value, json};

use super::server::{Resp, wait_for};
use super::sync::{Instance, PASSWORD, instance, pair_via};

/// Two instances with networking on, paired with each other (channel up).
pub fn paired(a_name: &str, b_name: &str) -> (Instance, Instance) {
    let a = instance(a_name);
    let b = instance(b_name);
    pair_via(&a, &b, a.peer_port);
    assert!(
        wait_for(Duration::from_secs(10), || peer_share(&a, &b.device_id())
            == "supported"
            && peer_share(&b, &a.device_id()) == "supported"),
        "share support negotiated: {}",
        share_state(&a)
    );
    (a, b)
}

pub fn share_state(i: &Instance) -> Value {
    let resp = i.api("GET", "/api/share", None);
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.json()
}

/// `peers[].share` of `device_id` in `i`'s view (`""` when not listed).
pub fn peer_share(i: &Instance, device_id: &str) -> String {
    share_state(i)["peers"]
        .as_array()
        .and_then(|peers| {
            peers
                .iter()
                .find(|p| p["device_id"] == device_id)
                .map(|p| p["share"].as_str().unwrap_or("").to_string())
        })
        .unwrap_or_default()
}

pub fn invite(i: &Instance, wallet: &str, recipient: &str) -> Resp {
    let body = json!({ "device_id": recipient }).to_string();
    i.api("POST", &format!("/api/wallets/{wallet}/share"), Some(&body))
}

/// Creates an invitation and returns the code digits (spaces removed).
pub fn invite_code(i: &Instance, wallet: &str, recipient: &str) -> String {
    let resp = invite(i, wallet, recipient);
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.json()["code"].as_str().unwrap().replace(' ', "")
}

pub fn receive(i: &Instance, code: &str, device_id: Option<&str>, address: Option<&str>) -> Resp {
    let body = json!({ "code": code, "device_id": device_id, "address": address }).to_string();
    i.api("POST", "/api/receive", Some(&body))
}

pub fn invitation_state(i: &Instance) -> String {
    share_state(i)["invitation"]["state"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

pub fn receive_state(i: &Instance) -> String {
    share_state(i)["receive"]["state"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

pub fn wait_invitation(i: &Instance, state: &str) -> bool {
    wait_for(Duration::from_secs(10), || invitation_state(i) == state)
}

pub fn wait_receive(i: &Instance, state: &str) -> bool {
    wait_for(Duration::from_secs(10), || receive_state(i) == state)
}

pub fn accept(i: &Instance, recipient: &str) -> Resp {
    let body = json!({ "device_id": recipient }).to_string();
    i.api("POST", "/api/share/accept", Some(&body))
}

/// The received wallets listed by `i`.
pub fn received(i: &Instance) -> Vec<Value> {
    share_state(i)["received"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

pub fn open_received(i: &Instance, id: &str, name: &str, password: &str) -> Resp {
    let body = json!({ "name": name, "password": password }).to_string();
    i.api("POST", &format!("/api/received/{id}/open"), Some(&body))
}

/// Full happy path: `a` shares `wallet` with `b`, `b` redeems by paired id, `a` accepts;
/// returns the received id on `b`.
pub fn share_to(a: &Instance, b: &Instance, wallet: &str) -> String {
    let code = invite_code(a, wallet, &b.device_id());
    let resp = receive(b, &code, Some(&a.device_id()), None);
    assert_eq!(resp.status, 202, "{}", resp.text());
    assert!(
        wait_invitation(a, "awaiting_acceptance"),
        "A: {}\nB: {}",
        share_state(a),
        share_state(b)
    );
    assert_eq!(accept(a, &b.device_id()).status, 200);
    assert!(
        wait_receive(b, "stored"),
        "B: {}\nA: {}",
        share_state(b),
        share_state(a)
    );
    assert!(wait_invitation(a, "completed"), "A: {}", share_state(a));
    share_state(b)["receive"]["received_id"]
        .as_str()
        .unwrap()
        .to_string()
}

pub const MASTER: &str = PASSWORD;

/// A device on the 004 build (channel v2 at most): closes on Hello v3 before any crypto,
/// completes a v1/v2 channel handshake with any dialer and keeps the channel open.
pub struct FakeV2Peer {
    pub key: device_link::identity::DeviceKey,
    pub addr: std::net::SocketAddrV4,
    pub v3_refused: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub channels: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

pub fn fake_v2_peer(seed: u8) -> FakeV2Peer {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use device_link::channel::ChannelResponder;
    use device_link::identity::DeviceKey;
    use device_link::name::DeviceName;
    use device_link::wire::{HelloKind, HelloVersion, parse_hello_versioned};
    use device_link_net::framed::{FrameError, read_frame, write_frame};

    let key = DeviceKey::from_private([seed; 32]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let v3_refused = Arc::new(AtomicUsize::new(0));
    let channels = Arc::new(AtomicUsize::new(0));
    let (refused, opened) = (Arc::clone(&v3_refused), Arc::clone(&channels));
    let responder_key = DeviceKey::from_private([seed; 32]);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let step = Duration::from_secs(2);
            let Ok(hello) = read_frame(&stream, step) else {
                continue;
            };
            match parse_hello_versioned(&hello) {
                Ok((HelloKind::Channel, HelloVersion::V1 | HelloVersion::V2)) => {}
                _ => {
                    refused.fetch_add(1, Ordering::SeqCst);
                    continue; // a 004 parser rejects version 3: close
                }
            }
            let mut responder =
                ChannelResponder::new(&responder_key, DeviceName::parse("Old").unwrap(), &hello);
            let opened = Arc::clone(&opened);
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let Ok(body) = read_frame(&stream, step) else {
                        return;
                    };
                    let result = responder.on_frame(&body, &|_| true);
                    for frame in responder.outgoing() {
                        let _ = write_frame(&stream, &frame);
                    }
                    if let Ok(Some(mut channel)) = result {
                        opened.fetch_add(1, Ordering::SeqCst);
                        // Answer keepalives so the channel stays up; drop everything else.
                        loop {
                            match read_frame(&stream, Duration::from_millis(400)) {
                                Ok(frame) => {
                                    if channel.open(&frame).is_err() {
                                        return;
                                    }
                                }
                                Err(FrameError::Timeout) => {
                                    let Ok(frame) =
                                        channel.seal(&device_link::wire::Payload::Keepalive)
                                    else {
                                        return;
                                    };
                                    if write_frame(&stream, &frame).is_err() {
                                        return;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                    }
                }
            });
        }
    });
    FakeV2Peer {
        key,
        addr: std::net::SocketAddrV4::new([127, 0, 0, 1].into(), port),
        v3_refused,
        channels,
    }
}
