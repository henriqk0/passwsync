//! 004 T061: a version 1 wallet is rewritten as version 2 at unlock only when networking is
//! on and at least one device is paired (research R3); otherwise it stays byte-identical.

mod common;

use std::fs;

use common::server::{Fixture, TestServer, net_config};
use device_link::files::encode_peers;
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::registry::PeerPin;
use serde::Serialize;
use vault_core::KdfConfig;

const PASSWORD: &str = "correct horse battery";

#[derive(Serialize)]
enum RawState {
    Live {
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    },
}

#[derive(Serialize)]
struct RawEntryV1 {
    id: [u8; 16],
    created_at: i64,
    modified_at: i64,
    last_modified_by: String,
    version: Vec<(String, u64)>,
    state: RawState,
}

#[derive(Serialize)]
struct RawPayloadV1 {
    wallet_id: [u8; 16],
    created_at: i64,
    entries: Vec<RawEntryV1>,
}

fn v1_wallet() -> Vec<u8> {
    let payload = RawPayloadV1 {
        wallet_id: [4; 16],
        created_at: 1,
        entries: vec![RawEntryV1 {
            id: [1; 16],
            created_at: 1,
            modified_at: 1,
            last_modified_by: "old-device".into(),
            version: vec![("old-device".into(), 1)],
            state: RawState::Live {
                title: "Old".into(),
                username: String::new(),
                password: String::new(),
                url: String::new(),
                notes: String::new(),
            },
        }],
    };
    let plain = postcard::to_allocvec(&payload).unwrap();
    vault_core::testkit::seal_payload(PASSWORD, KdfConfig::MINIMUM, 1, &plain)
}

fn place_wallet(fx: &Fixture) -> std::path::PathBuf {
    fs::create_dir_all(&fx.wallets_dir).unwrap();
    common::set_mode(&fx.wallets_dir, 0o700);
    common::set_mode(fx.wallets_dir.parent().unwrap(), 0o700);
    let path = fx.wallets_dir.join("Old.pwsw");
    fs::write(&path, v1_wallet()).unwrap();
    common::set_mode(&path, 0o600);
    path
}

fn pin_a_peer(fx: &Fixture) {
    let pin = PeerPin {
        public: *DeviceKey::from_private([77; 32]).public(),
        name: DeviceName::parse("Phone").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    };
    let path = fx.config_dir.join("peers");
    fs::write(&path, encode_peers(&[pin])).unwrap();
    common::set_mode(&path, 0o600);
}

fn unlock(server: &TestServer) {
    let s = server.login();
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    let resp = server.api(&s, "POST", "/api/wallets/Old/unlock", Some(&body));
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[test]
fn networking_off_keeps_a_v1_file_byte_identical() {
    let fx = Fixture::new("");
    let path = place_wallet(&fx);
    let before = fs::read(&path).unwrap();
    let server = TestServer::start_in(fx);
    unlock(&server);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!server.log_text().contains("wallet upgraded"));
}

#[test]
fn networking_on_without_a_paired_device_keeps_it_too() {
    let fx = Fixture::new(&net_config());
    let path = place_wallet(&fx);
    let before = fs::read(&path).unwrap();
    let server = TestServer::start_in(fx);
    assert_eq!(server.running().network_status(), "on");
    unlock(&server);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn networking_on_with_a_paired_device_rewrites_it_as_version_2() {
    let fx = Fixture::new(&net_config());
    let path = place_wallet(&fx);
    pin_a_peer(&fx);
    let server = TestServer::start_in(fx);
    assert_eq!(server.running().network_status(), "on");
    unlock(&server);
    let after = fs::read(&path).unwrap();
    assert_eq!(&after[4..6], &2u16.to_le_bytes(), "now format 2");
    assert!(
        server
            .log_text()
            .contains("wallet upgraded to format 2 wallet=Old"),
        "{}",
        server.log_text()
    );
    // The upgraded wallet now has a sync record.
    let sync_dir = server.fx.home.join(".local/share/passwsync/sync");
    assert_eq!(fs::read_dir(sync_dir).unwrap().count(), 1);
}
