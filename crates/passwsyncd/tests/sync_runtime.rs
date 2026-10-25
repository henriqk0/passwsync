//! 004 T059: sync runtime wiring (contracts/host-runtime-sync.md "Start-up", "Shutdown").
//! One test per file: thread names are checked for the whole test process.

mod common;

use std::fs;
use std::time::Duration;

use common::server::{TestServer, net_config, wait_for};

fn thread_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(tasks) = fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            if let Ok(name) = fs::read_to_string(task.path().join("comm")) {
                names.push(name.trim().to_string());
            }
        }
    }
    names
}

fn sync_threads() -> usize {
    thread_names()
        .iter()
        .filter(|n| n.starts_with("sync-"))
        .count()
}

const WALLET: &str = r#"{"name":"Personal","password":"correct horse battery","password_confirm":"correct horse battery"}"#;

#[test]
fn sync_runs_only_with_networking_on_and_stops_before_the_network() {
    // Networking off: no sync thread, no sync directory, no sync file activity.
    let mut off = TestServer::start();
    let s = off.login();
    assert_eq!(
        off.api(&s, "POST", "/api/wallets", Some(WALLET)).status,
        201
    );
    let entry = r#"{"title":"GitHub","username":"u","password":"p","url":"","notes":""}"#;
    assert_eq!(
        off.api(&s, "POST", "/api/wallets/Personal/entries", Some(entry))
            .status,
        201
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(sync_threads(), 0, "{:?}", thread_names());
    let sync_dir = off.fx.home.join(".local/share/passwsync/sync");
    assert!(
        !sync_dir.exists(),
        "no sync file activity with networking off"
    );
    off.stop();

    // Networking on: the sync threads run and the sync directory is owner-only.
    let mut on = TestServer::start_with(&net_config());
    assert_eq!(on.running().network_status(), "on");
    assert!(
        wait_for(Duration::from_secs(2), || sync_threads() >= 2),
        "{:?}",
        thread_names()
    );
    let sync_dir = on.fx.home.join(".local/share/passwsync/sync");
    assert!(sync_dir.is_dir());
    assert_eq!(common::mode(&sync_dir), 0o700);
    let s = on.login();
    assert_eq!(on.api(&s, "POST", "/api/wallets", Some(WALLET)).status, 201);
    // A record now describes the new wallet (written by the journaled save).
    assert!(
        fs::read_dir(&sync_dir).unwrap().count() == 1,
        "one record directory"
    );
    // A stale partial copy is removed at shutdown (rounds aborted).
    let record_dir = fs::read_dir(&sync_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let part = record_dir.join(format!("incoming-{}.part", "ab".repeat(32)));
    fs::write(&part, b"half").unwrap();
    common::set_mode(&part, 0o600);
    on.stop();
    assert_eq!(
        sync_threads(),
        0,
        "sync threads stopped: {:?}",
        thread_names()
    );
    assert!(!part.exists(), "partial copies deleted at shutdown");
    let log = String::from_utf8(on.log.lock().unwrap().clone()).unwrap();
    assert!(log.contains("network off"));
}
