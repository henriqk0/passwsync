//! 003: the `device-key` and `peers` files (contracts/host-runtime-network.md "Files").

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use common::server::{Fixture, TestServer};
use common::{TempDir, mode, set_mode};
use device_link::name::DeviceName;
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::registry::PeerPin;
use passwsyncd::net_store::FilePeerStore;
use passwsyncd::paths::load_or_create_device_key;

const KEY: &str =
    "passwsync-device-key-v1\n77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n";

#[test]
fn missing_key_is_created_once_private_and_reused() {
    let dir = TempDir::new("devkey");
    let path = dir.path().join("device-key");
    let first = load_or_create_device_key(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("passwsync-device-key-v1\n"));
    assert_eq!(text.len(), 24 + 65);
    let again = load_or_create_device_key(&path).unwrap();
    assert_eq!(again.public(), first.public());
    assert_eq!(fs::read_to_string(&path).unwrap(), text, "never rewritten");
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 1,
        "no temp file left"
    );
    let other = TempDir::new("devkey");
    let second = load_or_create_device_key(&other.path().join("device-key")).unwrap();
    assert_ne!(second.public(), first.public(), "fresh random key");
}

#[test]
fn unusable_key_files_are_refused_and_left_untouched() {
    let dir = TempDir::new("devkey");
    let path = dir.path().join("device-key");
    fs::write(&path, KEY).unwrap();
    set_mode(&path, 0o600);
    assert!(load_or_create_device_key(&path).is_ok());
    for bad_mode in [0o644, 0o640, 0o604] {
        set_mode(&path, bad_mode);
        assert!(load_or_create_device_key(&path).is_err(), "{bad_mode:o}");
        assert_eq!(fs::read_to_string(&path).unwrap(), KEY);
    }
    set_mode(&path, 0o600);
    fs::write(&path, "passwsync-device-key-v1\nnot hex\n").unwrap();
    assert!(load_or_create_device_key(&path).is_err());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "passwsync-device-key-v1\nnot hex\n"
    );
    // A symlink to a valid key is refused too.
    let real = dir.path().join("real");
    fs::write(&real, KEY).unwrap();
    set_mode(&real, 0o600);
    let link = dir.path().join("linked-key");
    symlink(&real, &link).unwrap();
    assert!(load_or_create_device_key(&link).is_err());
    // Foreign ownership cannot be produced without root; the owner check is the 002
    // `check_private` helper, covered by tests/paths.rs.
}

fn pin(byte: u8) -> PeerPin {
    PeerPin {
        public: [byte; 32],
        name: DeviceName::parse("Phone").unwrap(),
        paired_at: 1_761_200_000,
        last_seen: Some(1_761_200_100),
        last_addr: Some("192.168.1.7:27472".parse().unwrap()),
    }
}

#[test]
fn peers_file_missing_means_empty_and_saves_atomically_private() {
    let dir = TempDir::new("peers");
    let path = dir.path().join("peers");
    let store = FilePeerStore::new(path.clone(), [0xee; 32], AddressPolicy::lan());
    assert!(store.load().unwrap().is_empty());
    assert!(!path.exists(), "loading does not create the file");
    store.save(&[pin(1), pin(2)]).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(store.load().unwrap(), vec![pin(1), pin(2)]);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .starts_with("passwsync-peers-v1\n")
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "temp renamed");
    store.save(&[]).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "passwsync-peers-v1\n");
}

#[test]
fn unusable_peers_files_are_refused_and_left_untouched() {
    let dir = TempDir::new("peers");
    let path = dir.path().join("peers");
    let store = FilePeerStore::new(path.clone(), [0xee; 32], AddressPolicy::lan());
    store.save(&[pin(1)]).unwrap();
    let good = fs::read_to_string(&path).unwrap();
    set_mode(&path, 0o644);
    assert!(store.load().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), good);
    set_mode(&path, 0o600);
    fs::write(&path, "passwsync-peers-v1\ngarbage\n").unwrap();
    assert!(store.load().is_err());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "passwsync-peers-v1\ngarbage\n"
    );
    let link = dir.path().join("peers-link");
    let real = dir.path().join("real");
    fs::write(&real, &good).unwrap();
    set_mode(&real, 0o600);
    symlink(&real, &link).unwrap();
    let linked = FilePeerStore::new(link, [0xee; 32], AddressPolicy::lan());
    assert!(linked.load().is_err());
}

#[test]
fn service_starts_with_an_unusable_identity_and_never_rewrites_it() {
    let fx = Fixture::new("");
    let path = fx.config_dir.join("device-key");
    fs::write(&path, "broken").unwrap();
    set_mode(&path, 0o600);
    let mut server = TestServer::start_in(fx);
    assert_eq!(server.running().network_status(), "identity_unusable");
    assert_eq!(fs::read(&path).unwrap(), b"broken");
    server.stop();
    assert_eq!(fs::read(&path).unwrap(), b"broken");
}

#[test]
fn service_creates_the_identity_on_first_start_and_keeps_it() {
    let mut server = TestServer::start();
    let path = server.fx.config_dir.join("device-key");
    let first = fs::read_to_string(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(server.running().network_status(), "off");
    let fp = server.running().fingerprint().unwrap();
    let fx = std::mem::replace(&mut server.fx, Fixture::new(""));
    server.stop();
    let again = TestServer::start_in(fx);
    assert_eq!(fs::read_to_string(&path).unwrap(), first);
    assert_eq!(again.running().fingerprint().unwrap(), fp);
}

#[test]
fn unusable_peers_file_keeps_networking_off_without_exit() {
    let fx = Fixture::new("network = on\n");
    let path = fx.config_dir.join("peers");
    fs::write(&path, "nonsense").unwrap();
    set_mode(&path, 0o600);
    let server = TestServer::start_in(fx);
    assert_eq!(server.running().network_status(), "peers_unusable");
    assert_eq!(fs::read(&path).unwrap(), b"nonsense");
}
