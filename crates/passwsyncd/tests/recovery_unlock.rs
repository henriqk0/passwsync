//! 004 T142 (FR-025, FR-036, SC-007): no sync state ever locks the person out.

mod common;

use std::fs;
use std::path::PathBuf;

use common::server::{Fixture, Session, TestServer, net_config};
use common::sync::PASSWORD;
use wallet_sync::record::{Prepared, decode, encode};

const WALLET: &str = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;

fn create() -> (TestServer, Session) {
    let server = TestServer::start_in(Fixture::new(&net_config()));
    let s = server.login();
    assert_eq!(
        server.api(&s, "POST", "/api/wallets", Some(WALLET)).status,
        201
    );
    add(&server, &s, "one");
    (server, s)
}

fn add(server: &TestServer, s: &Session, title: &str) -> u16 {
    let body = format!(r#"{{"title":"{title}","username":"","password":"","url":"","notes":""}}"#);
    server
        .api(s, "POST", "/api/wallets/Personal/entries", Some(&body))
        .status
}

fn restart(server: &mut TestServer) -> (TestServer, Session) {
    let fx = std::mem::replace(&mut server.fx, Fixture::new(""));
    server.stop();
    let server = TestServer::start_in(fx);
    let s = server.login();
    (server, s)
}

fn record_path(server: &TestServer) -> PathBuf {
    let sync = server.fx.home.join(".local/share/passwsync/sync");
    fs::read_dir(sync)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("record")
}

fn unlock(server: &TestServer, s: &Session, password: &str) -> u16 {
    let body = format!(r#"{{"password":"{password}"}}"#);
    server
        .api(s, "POST", "/api/wallets/Personal/unlock", Some(&body))
        .status
}

fn count(server: &TestServer, s: &Session) -> usize {
    server
        .api(
            s,
            "POST",
            "/api/wallets/Personal/search",
            Some(r#"{"query":""}"#),
        )
        .json()["entries"]
        .as_array()
        .unwrap()
        .len()
}

#[test]
fn a_corrupted_or_deleted_record_never_blocks_unlock_or_edits() {
    for delete in [false, true] {
        let (mut server, _) = create();
        let path = record_path(&server);
        if delete {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, "passwsync-sync-record-v1\ngarbage\n").unwrap();
        }
        let (server, s) = restart(&mut server);
        assert_eq!(unlock(&server, &s, PASSWORD), 200);
        assert_eq!(count(&server, &s), 1, "contents intact");
        assert_eq!(add(&server, &s, "two"), 201, "edits still save");
        if !delete {
            assert!(
                fs::read_to_string(&path).unwrap().contains("garbage"),
                "only an explicit reset rebuilds a corrupted record"
            );
        }
    }
}

#[test]
fn a_wallet_flagged_as_possible_rollback_still_unlocks_edits_and_saves() {
    let (mut server, _) = create();
    let path = record_path(&server);
    let mut r = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    r.flags.rollback_state = true;
    fs::write(&path, encode(&r)).unwrap();
    let (server, s) = restart(&mut server);
    assert_eq!(unlock(&server, &s, PASSWORD), 200);
    assert_eq!(add(&server, &s, "two"), 201);
    assert_eq!(count(&server, &s), 2);
}

#[test]
fn a_wrong_password_never_changes_the_record() {
    let (mut server, _) = create();
    let (server, s) = restart(&mut server);
    let before = fs::read(record_path(&server)).unwrap();
    assert_eq!(unlock(&server, &s, "wrong password, wrong"), 422);
    assert_eq!(fs::read(record_path(&server)).unwrap(), before);
}

#[test]
fn an_interrupted_save_never_blocks_the_next_unlock() {
    let (mut server, _) = create();
    let path = record_path(&server);
    let mut r = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    // Crash after step 1: prepared for bytes that never reached the file.
    r.prepared = Some(Prepared {
        digest: [0x77; 32],
        state: r.state.clone(),
        peer_marks: Default::default(),
        consumed: Default::default(),
    });
    fs::write(&path, encode(&r)).unwrap();
    let (server, s) = restart(&mut server);
    assert_eq!(unlock(&server, &s, PASSWORD), 200);
    assert_eq!(count(&server, &s), 1, "the old state stands");
    let after = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    assert!(after.prepared.is_none());
}
