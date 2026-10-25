//! 004: helpers for multi-instance sync tests (pairing, a recording proxy, wallet files).
#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::server::{Fixture, Session, TestServer, free_net_port, wait_for};

pub const PASSWORD: &str = "correct horse battery";

pub fn config(name: &str, peer: u16, discovery: u16) -> String {
    format!(
        "network = on\npeer_port = {peer}\ndiscovery_port = {discovery}\ndevice_name = \"{name}\"\n"
    )
}

pub fn net(server: &TestServer, s: &Session) -> Value {
    server.api(s, "GET", "/api/network", None).json()
}

/// A TCP relay to `target` that records every byte in both directions.
pub fn recording_proxy(target: u16) -> (u16, Arc<Mutex<Vec<u8>>>) {
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
                    let mut buf = [0u8; 4096];
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

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A started instance with networking on and its own peer/discovery ports.
pub struct Instance {
    pub server: TestServer,
    pub session: Session,
    pub peer_port: u16,
}

pub fn instance(name: &str) -> Instance {
    let (peer, disc) = (free_net_port(), free_net_port());
    let server = TestServer::start_in(Fixture::new(&config(name, peer, disc)));
    let session = server.login();
    Instance {
        server,
        session,
        peer_port: peer,
    }
}

impl Instance {
    pub fn api(&self, method: &str, path: &str, body: Option<&str>) -> super::server::Resp {
        self.server.api(&self.session, method, path, body)
    }

    pub fn device_id(&self) -> String {
        net(&self.server, &self.session)["this_device"]["device_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn create_wallet(&self, name: &str) {
        let body = json!({"name": name, "password": PASSWORD, "password_confirm": PASSWORD});
        let resp = self.api("POST", "/api/wallets", Some(&body.to_string()));
        assert_eq!(resp.status, 201, "{}", resp.text());
    }

    pub fn unlock(&self, wallet: &str) {
        let body = json!({ "password": PASSWORD });
        let resp = self.api(
            "POST",
            &format!("/api/wallets/{wallet}/unlock"),
            Some(&body.to_string()),
        );
        assert_eq!(resp.status, 200, "{}", resp.text());
    }

    pub fn add(
        &self,
        wallet: &str,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
    ) -> String {
        let body = json!({"title": title, "username": username, "password": password, "url": url, "notes": notes});
        let resp = self.api(
            "POST",
            &format!("/api/wallets/{wallet}/entries"),
            Some(&body.to_string()),
        );
        assert_eq!(resp.status, 201, "{}", resp.text());
        resp.json()["id"].as_str().unwrap().to_string()
    }

    /// Titles of the wallet's credentials, sorted (search with an empty query).
    pub fn titles(&self, wallet: &str) -> Vec<String> {
        let resp = self.api(
            "POST",
            &format!("/api/wallets/{wallet}/search"),
            Some(r#"{"query":""}"#),
        );
        if resp.status != 200 {
            return Vec::new();
        }
        let mut titles: Vec<String> = resp.json()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["title"].as_str().unwrap().to_string())
            .collect();
        titles.sort();
        titles
    }

    pub fn wallet_file(&self, wallet: &str) -> std::path::PathBuf {
        self.server.fx.wallets_dir.join(format!("{wallet}.pwsw"))
    }
}

/// Pairs `b` with `a` through `via` (a port relaying to `a`'s peer port) and waits until the
/// channel is up on both.
pub fn pair_via(a: &Instance, b: &Instance, via: u16) {
    let started = a.api("POST", "/api/pairing/start", None).json();
    let code = started["code"].as_str().unwrap().replace(' ', "");
    let (a_id, b_id) = (a.device_id(), b.device_id());
    let join = json!({"address": format!("127.0.0.1:{via}"), "code": code, "device_id": a_id});
    assert_eq!(
        b.api("POST", "/api/pairing/join", Some(&join.to_string()))
            .status,
        202
    );
    assert!(wait_for(Duration::from_secs(5), || net(
        &a.server, &a.session
    )["pairing"]["state"]
        == "awaiting_acceptance"));
    let accept = json!({"device_id": b_id}).to_string();
    assert_eq!(
        a.api("POST", "/api/pairing/accept", Some(&accept)).status,
        200
    );
    assert!(
        wait_for(Duration::from_secs(8), || connected(a) && connected(b)),
        "channel up"
    );
}

pub fn connected(i: &Instance) -> bool {
    net(&i.server, &i.session)["paired"]
        .as_array()
        .is_some_and(|p| p.iter().any(|d| d["status"] == "connected"))
}

/// Copies `wallet` from `from`'s wallet directory into `to`'s (as a person would by hand).
pub fn copy_wallet_file(from: &Instance, to: &Instance, wallet: &str) {
    let bytes = fs::read(from.wallet_file(wallet)).unwrap();
    let dest = to.wallet_file(wallet);
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::write(&dest, bytes).unwrap();
    super::set_mode(&dest, 0o600);
}

// --- crafted wallet files (contracts/file-format-v2.md) ---

#[derive(serde::Serialize)]
pub enum RawState {
    Live {
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    },
}

#[derive(serde::Serialize)]
pub struct RawVersion {
    pub modified_at: i64,
    pub last_modified_by: String,
    pub version: Vec<(String, u64)>,
    pub state: RawState,
}

#[derive(serde::Serialize)]
pub struct RawEntryV2 {
    pub id: [u8; 16],
    pub created_at: i64,
    pub current: RawVersion,
    pub conflicts: Vec<RawVersion>,
}

#[derive(serde::Serialize)]
pub struct RawPayloadV2 {
    pub wallet_id: [u8; 16],
    pub created_at: i64,
    pub state: Vec<(String, u64)>,
    pub password_epoch: Vec<(String, u64)>,
    pub entries: Vec<RawEntryV2>,
}

pub fn raw_version(title: &str, at: i64, by: &str) -> RawVersion {
    RawVersion {
        modified_at: at,
        last_modified_by: by.into(),
        version: vec![(by.into(), 1)],
        state: RawState::Live {
            title: title.into(),
            username: format!("{title}-user"),
            password: format!("{title}-secret"),
            url: format!("https://{}.example", title.replace(' ', "-")),
            notes: format!("{title} notes"),
        },
    }
}

/// A v2 wallet whose entry `[1; 16]` is conflicted ("Phone edit" current, "Laptop edit")
/// plus a plain entry `[2; 16]` ("Plain").
pub fn conflicted_wallet() -> Vec<u8> {
    let payload = RawPayloadV2 {
        wallet_id: [9; 16],
        created_at: 1,
        state: vec![
            ("laptop".into(), 1),
            ("other".into(), 1),
            ("phone".into(), 1),
        ],
        password_epoch: vec![],
        entries: vec![
            RawEntryV2 {
                id: [1; 16],
                created_at: 1,
                current: raw_version("Phone edit", 20, "phone"),
                conflicts: vec![raw_version("Laptop edit", 10, "laptop")],
            },
            RawEntryV2 {
                id: [2; 16],
                created_at: 1,
                current: raw_version("Plain", 5, "other"),
                conflicts: vec![],
            },
        ],
    };
    let plain = postcard::to_allocvec(&payload).unwrap();
    vault_core::testkit::seal_payload(PASSWORD, vault_core::KdfConfig::MINIMUM, 2, &plain)
}

/// Places `bytes` as wallet `name` in a fixture's wallet directory (before start).
pub fn place_wallet(fx: &Fixture, name: &str, bytes: &[u8]) {
    fs::create_dir_all(&fx.wallets_dir).unwrap();
    super::set_mode(fx.wallets_dir.parent().unwrap(), 0o700);
    super::set_mode(&fx.wallets_dir, 0o700);
    let path = fx.wallets_dir.join(format!("{name}.pwsw"));
    fs::write(&path, bytes).unwrap();
    super::set_mode(&path, 0o600);
}

pub const CONFLICT_ID: &str = "01010101010101010101010101010101";
