//! 004 T106: start-up step 5c (contracts/host-runtime-sync.md "Start-up").

mod common;

use std::fs;
use std::path::PathBuf;

use common::server::{Fixture, Session, TestServer, net_config};
use common::sync::PASSWORD;
use wallet_sync::ports::PeerId;
use wallet_sync::record::{PendingCopy, PendingStatus, Prepared, decode, encode, sha256};

const WALLET: &str = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;

fn create() -> (TestServer, Session) {
    let server = TestServer::start_in(Fixture::new(&net_config()));
    let s = server.login();
    assert_eq!(
        server.api(&s, "POST", "/api/wallets", Some(WALLET)).status,
        201
    );
    let body = r#"{"title":"one","username":"","password":"","url":"","notes":""}"#;
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Personal/entries", Some(body))
            .status,
        201
    );
    (server, s)
}

fn restart(server: &mut TestServer) -> TestServer {
    let fx = std::mem::replace(&mut server.fx, Fixture::new(""));
    server.stop();
    TestServer::start_in(fx)
}

fn record_dir(server: &TestServer) -> PathBuf {
    let sync = server.fx.home.join(".local/share/passwsync/sync");
    fs::read_dir(sync).unwrap().next().unwrap().unwrap().path()
}

fn wallet_file(server: &TestServer) -> PathBuf {
    server.fx.wallets_dir.join("Personal.pwsw")
}

fn edit_record(server: &TestServer, f: impl FnOnce(&mut wallet_sync::record::SyncRecord)) {
    let path = record_dir(server).join("record");
    let mut r = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    f(&mut r);
    fs::write(&path, encode(&r)).unwrap();
}

fn put(path: &PathBuf, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    common::set_mode(path, 0o600);
}

#[test]
fn partials_orphans_and_an_interrupted_save_are_recovered() {
    let (mut server, _) = create();
    let dir = record_dir(&server);
    let ghost = PeerId([5; 32]);
    let real = PeerId([6; 32]);
    put(
        &dir.join(format!("incoming-{}.part", real.to_hex())),
        b"half",
    );
    put(&dir.join(format!("pending-{}", ghost.to_hex())), b"orphan");
    // A save that reached the wallet file but not the commit: record still has the old digest.
    let file_digest = sha256(&fs::read(wallet_file(&server)).unwrap());
    edit_record(&server, |r| {
        r.prepared = Some(Prepared {
            digest: file_digest,
            state: r.state.clone(),
            peer_marks: Default::default(),
            consumed: Default::default(),
        });
        r.digest = [0xAA; 32];
        r.pending.insert(
            real,
            PendingCopy {
                claimed: r.state.clone(),
                size: 4,
                received_at: 1,
                status: PendingStatus::Waiting,
            },
        );
    });
    let server2 = restart(&mut server);
    assert_eq!(server2.running().network_status(), "on");
    assert!(
        !dir.join(format!("incoming-{}.part", real.to_hex()))
            .exists(),
        "*.part deleted"
    );
    assert!(
        !dir.join(format!("pending-{}", ghost.to_hex())).exists(),
        "orphan file deleted"
    );
    let r = decode(&fs::read_to_string(dir.join("record")).unwrap()).unwrap();
    assert!(r.prepared.is_none());
    assert_eq!(r.digest, file_digest, "the interrupted save was committed");
    assert!(r.pending.is_empty(), "a line without its file is dropped");
    assert!(!r.flags.possible_rollback());
}

#[test]
fn a_replaced_wallet_file_is_flagged_as_possible_rollback() {
    let (mut server, s) = create();
    let old = fs::read(wallet_file(&server)).unwrap();
    let body = r#"{"title":"two","username":"","password":"","url":"","notes":""}"#;
    server.api(&s, "POST", "/api/wallets/Personal/entries", Some(body));
    let path = wallet_file(&server);
    let server_fx_path = path.clone();
    let mut server2 = {
        let fx = std::mem::replace(&mut server.fx, Fixture::new(""));
        server.stop();
        put(&server_fx_path, &old); // an older copy restored while the service was stopped
        TestServer::start_in(fx)
    };
    let r = decode(&fs::read_to_string(record_dir(&server2).join("record")).unwrap()).unwrap();
    assert!(r.flags.rollback_digest);
    assert!(
        server2
            .log_text()
            .contains("sync possible rollback wallet=Personal")
    );
    server2.stop();
}

#[test]
fn a_corrupted_record_disables_sync_for_that_wallet_but_never_stops_the_service() {
    let (mut server, _) = create();
    let path = record_dir(&server).join("record");
    let text = fs::read_to_string(&path).unwrap();
    let corrupted = text.replacen("mark ", "mark x", 1);
    fs::write(&path, &corrupted).unwrap();
    let server2 = restart(&mut server);
    assert_eq!(server2.running().network_status(), "on");
    assert!(
        server2
            .log_text()
            .contains("sync record corrupted wallet=Personal")
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        corrupted,
        "never silently reset"
    );
    // The wallet still unlocks (no lockout, FR-025).
    let s = server2.login();
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    assert_eq!(
        server2
            .api(&s, "POST", "/api/wallets/Personal/unlock", Some(&body))
            .status,
        200
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), corrupted);
}

#[test]
fn two_files_with_the_same_wallet_id_disable_sync_for_both() {
    let (mut server, _) = create();
    let copy = server.fx.wallets_dir.join("Copy.pwsw");
    put(&copy, &fs::read(wallet_file(&server)).unwrap());
    let server2 = restart(&mut server);
    let s = server2.login();
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    for name in ["Personal", "Copy"] {
        assert_eq!(
            server2
                .api(
                    &s,
                    "POST",
                    &format!("/api/wallets/{name}/unlock"),
                    Some(&body)
                )
                .status,
            200
        );
    }
    let r = decode(&fs::read_to_string(record_dir(&server2).join("record")).unwrap()).unwrap();
    assert!(r.flags.duplicate_wallet_id);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.kind == wallet_sync::record::WarningKind::DuplicateWalletId)
    );
}
