//! 004 T108: warnings and recovery actions (FR-021, FR-036, contracts/http-api-sync.md).

mod common;

use std::fs;
use std::path::PathBuf;

use common::server::{Fixture, Session, TestServer, net_config};
use common::sync::PASSWORD;
use wallet_sync::ports::PeerId;
use wallet_sync::record::{WarningKind, decode, encode};

const WALLET: &str = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;

fn setup() -> (TestServer, Session) {
    let server = TestServer::start_in(Fixture::new(&net_config()));
    let s = server.login();
    assert_eq!(
        server.api(&s, "POST", "/api/wallets", Some(WALLET)).status,
        201
    );
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

fn edit_record(server: &TestServer, f: impl FnOnce(&mut wallet_sync::record::SyncRecord)) {
    let path = record_path(server);
    let mut r = decode(&fs::read_to_string(&path).unwrap()).unwrap();
    f(&mut r);
    fs::write(&path, encode(&r)).unwrap();
}

fn record(server: &TestServer) -> wallet_sync::record::SyncRecord {
    decode(&fs::read_to_string(record_path(server)).unwrap()).unwrap()
}

#[test]
fn warnings_are_listed_and_dismissal_changes_nothing_else() {
    let (server, s) = setup();
    let peer = PeerId([3; 32]);
    edit_record(&server, |r| {
        r.warn(
            41,
            WarningKind::OlderStateOffered,
            Some(peer),
            1_761_200_000,
        );
        r.warn(42, WarningKind::PossibleRollback, None, 1_761_200_001);
        r.flags.rollback_state = true;
        r.raise_peer_mark(peer, &r.state.clone());
    });
    let sync = server.api(&s, "GET", "/api/sync", None);
    assert_eq!(sync.status, 200);
    let warnings = sync.json()["warnings"].clone();
    assert_eq!(warnings.as_array().unwrap().len(), 2);
    assert_eq!(warnings[0]["id"], 41);
    assert_eq!(warnings[0]["kind"], "older_state_offered");
    assert_eq!(warnings[0]["wallet"], "Personal");
    assert_eq!(warnings[0]["peer"], peer.to_hex());
    assert_eq!(warnings[1]["peer"], serde_json::Value::Null);
    let before = record(&server);
    let resp = server.api(
        &s,
        "POST",
        "/api/sync/warnings/dismiss",
        Some(r#"{"ids":[41]}"#),
    );
    assert_eq!(resp.status, 200);
    let after = record(&server);
    assert_eq!(after.warnings.len(), 1);
    assert_eq!(
        after.mark, before.mark,
        "dismissal never changes marks (FR-036)"
    );
    assert_eq!(after.flags, before.flags);
    assert_eq!(after.peers, before.peers);
    assert_eq!(
        server
            .api(
                &s,
                "POST",
                "/api/sync/warnings/dismiss",
                Some(r#"{"ids":"x"}"#)
            )
            .status,
        400
    );
}

#[test]
fn accept_older_needs_confirmation_and_an_unlocked_wallet() {
    let (server, s) = setup();
    let peer = PeerId([3; 32]);
    edit_record(&server, |r| {
        r.mark = wallet_sync::record::parse_sv("61:99").unwrap();
        r.flags.rollback_state = true;
        r.raise_peer_mark(peer, &wallet_sync::record::parse_sv("61:50").unwrap());
    });
    let path = "/api/wallets/Personal/sync/accept-older";
    assert_eq!(
        server
            .api(&s, "POST", path, Some(r#"{"confirm":false}"#))
            .status,
        400
    );
    assert_eq!(server.api(&s, "POST", path, Some("{}")).status, 400);
    server.api(&s, "POST", "/api/wallets/Personal/lock", None);
    assert_eq!(
        server
            .api(&s, "POST", path, Some(r#"{"confirm":true}"#))
            .status,
        423
    );
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Personal/unlock", Some(&body))
            .status,
        200
    );
    assert_eq!(
        server
            .api(&s, "POST", path, Some(r#"{"confirm":true}"#))
            .status,
        200
    );
    let r = record(&server);
    assert_eq!(r.mark, r.state, "the mark is reset to the current state");
    assert!(!r.flags.possible_rollback());
    assert_eq!(r.peers.get(&peer).and_then(|p| p.peer_mark.clone()), None);
    assert!(
        server
            .log_text()
            .contains("sync accepted older state wallet=Personal")
    );
}

#[test]
fn reset_rebuilds_a_corrupted_record_from_the_authenticated_file() {
    let (server, s) = setup();
    fs::write(record_path(&server), "corrupted").unwrap();
    let path = "/api/wallets/Personal/sync/reset";
    assert_eq!(
        server
            .api(&s, "POST", path, Some(r#"{"confirm":"yes"}"#))
            .status,
        400
    );
    let resp = server.api(&s, "POST", path, Some(r#"{"confirm":true}"#));
    assert_eq!(resp.status, 200, "{}", resp.text());
    let r = record(&server);
    assert_eq!(r.mark, r.state);
    assert!(r.peers.is_empty());
    assert_eq!(
        r.digest,
        wallet_sync::record::sha256(
            &fs::read(server.fx.wallets_dir.join("Personal.pwsw")).unwrap()
        )
    );
    assert!(
        server
            .log_text()
            .contains("sync state reset wallet=Personal")
    );
    server.api(&s, "POST", "/api/wallets/Personal/lock", None);
    assert_eq!(
        server
            .api(&s, "POST", path, Some(r#"{"confirm":true}"#))
            .status,
        423
    );
}

#[test]
fn recovery_routes_keep_the_protections() {
    let (server, s) = setup();
    let cookie = format!("pws_session={}", s.cookie);
    for path in [
        "/api/sync/warnings/dismiss",
        "/api/wallets/Personal/sync/accept-older",
        "/api/wallets/Personal/sync/reset",
    ] {
        assert_eq!(server.send("POST", path, &[], b"{}").status, 401);
        assert_eq!(
            server
                .send(
                    "POST",
                    path,
                    &[("Cookie", &cookie), ("X-CSRF-Token", &s.csrf)],
                    b"{}"
                )
                .status,
            403
        );
        assert_eq!(server.api(&s, "GET", path, None).status, 405);
    }
}
