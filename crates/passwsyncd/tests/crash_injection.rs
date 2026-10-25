//! 004 T104 (SC-007): every wallet save goes through the two-phase journal; faults at each
//! step keep the wallet openable with the old or the new contents.

mod common;

use std::fs;

use common::server::{Fixture, Session, TestServer, net_config};
use common::sync::PASSWORD;
use passwsyncd::sync_store::WriteStep;
use wallet_sync::record::{decode, sha256};

const WALLET: &str = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;

fn start() -> (TestServer, Session) {
    let server = TestServer::start_in(Fixture::new(&net_config()));
    let s = server.login();
    assert_eq!(
        server.api(&s, "POST", "/api/wallets", Some(WALLET)).status,
        201
    );
    (server, s)
}

fn record_text(server: &TestServer) -> String {
    let sync = server.fx.home.join(".local/share/passwsync/sync");
    let dir = fs::read_dir(sync).unwrap().next().unwrap().unwrap().path();
    fs::read_to_string(dir.join("record")).unwrap()
}

fn wallet_bytes(server: &TestServer) -> Vec<u8> {
    fs::read(server.fx.wallets_dir.join("Personal.pwsw")).unwrap()
}

fn add(server: &TestServer, s: &Session, title: &str) -> u16 {
    let body = format!(r#"{{"title":"{title}","username":"","password":"","url":"","notes":""}}"#);
    server
        .api(s, "POST", "/api/wallets/Personal/entries", Some(&body))
        .status
}

#[test]
fn a_committed_save_leaves_the_record_describing_the_file() {
    let (server, s) = start();
    assert_eq!(add(&server, &s, "one"), 201);
    let record = decode(&record_text(&server)).unwrap();
    assert!(record.prepared.is_none());
    assert_eq!(record.digest, sha256(&wallet_bytes(&server)));
    let _ = PASSWORD;
}

#[test]
fn a_failed_prepare_aborts_the_save_before_the_wallet_file() {
    for step in [WriteStep::TempWrite, WriteStep::Fsync, WriteStep::Rename] {
        let (server, s) = start();
        let before_file = wallet_bytes(&server);
        let before_record = record_text(&server);
        server.running().inject_sync_fault(step);
        let resp = add(&server, &s, "lost");
        assert_eq!(resp, 500, "{step:?}");
        assert_eq!(
            wallet_bytes(&server),
            before_file,
            "{step:?}: wallet untouched"
        );
        assert_eq!(record_text(&server), before_record);
        // The change was rolled back in memory too, and the next save works.
        assert_eq!(add(&server, &s, "kept"), 201);
        let found = server
            .api(
                &s,
                "POST",
                "/api/wallets/Personal/search",
                Some(r#"{"query":""}"#),
            )
            .json();
        assert_eq!(found["entries"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn a_failed_wallet_write_discards_the_prepare() {
    use std::os::unix::fs::PermissionsExt;
    let (server, s) = start();
    let before_record = decode(&record_text(&server)).unwrap();
    let dir = server.fx.wallets_dir.clone();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let resp = add(&server, &s, "lost");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(resp, 500);
    let after = decode(&record_text(&server)).unwrap();
    assert!(after.prepared.is_none(), "prepare discarded");
    assert_eq!(after.digest, before_record.digest);
    assert_eq!(after.digest, sha256(&wallet_bytes(&server)));
}
