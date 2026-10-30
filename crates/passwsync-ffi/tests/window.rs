//! 007 T112 (US5; FR-011, FR-045): a background sync window is bounded, ends early when the
//! rounds are idle, refuses when off, without peers, without a local network or while busy,
//! closes every socket at the end, ends when the last eligible interface disappears, never
//! unlocks a wallet or needs a password, and logs counts only.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use passwsync_ffi::records::WindowEnd;

const WALLET: &str = "Shared";

#[test]
fn a_window_refuses_when_off_without_peers_without_network_or_in_the_foreground() {
    let _guard = serial();
    let before = socket_fds();
    // Networking off.
    let dir = TempDir::new("win-off");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let report = core.run_sync_window();
    assert!(!report.ran);
    assert_eq!(report.reason, WindowEnd::Off);
    drop(core);
    // On, but no paired device.
    let mut node = Node::new("win-nopeer", "Phone", Vec::new());
    let core = node.start();
    let report = core.run_sync_window();
    assert_eq!((report.ran, report.reason), (false, WindowEnd::NoPeers));
    assert_eq!(socket_fds(), before, "a refused window opens nothing");
    // In the foreground the node already runs: busy.
    core.on_foreground();
    assert_eq!(core.run_sync_window().reason, WindowEnd::Busy);
    core.shutdown();
    drop(core);
    node.core = None;
    // No eligible interface.
    let mut node = Node::new("win-nonet", "Phone", Vec::new());
    node.fakes.eligible = Vec::new();
    let core = node.start();
    let report = core.run_sync_window();
    assert_eq!((report.ran, report.reason), (false, WindowEnd::NoNetwork));
    core.shutdown();
}

#[test]
fn a_window_syncs_ends_early_when_idle_and_closes_every_socket() {
    let _guard = serial();
    let (a, b) = synced_pair("win-run", WALLET);
    background(&a);
    a.core()
        .add_credential(
            WALLET.into(),
            input("Window Entry", "u", Some("window-secret")),
        )
        .unwrap();
    a.core().lock_all();
    let started = Instant::now();
    let report = a.core().run_sync_window();
    assert!(report.ran, "{report:?}");
    assert_eq!(report.reason, WindowEnd::Finished);
    assert!(report.peers_reached >= 1);
    assert!(report.rounds >= 1);
    assert!(started.elapsed() < Duration::from_secs(60), "early stop");
    assert!(!a.core().multicast_wanted(), "node paused at the end");
    assert!(wait_for(Duration::from_secs(10), || titles(
        b.core(),
        WALLET
    ) == [
        "First",
        "Window Entry"
    ]));
    // Never unlocks a wallet.
    assert!(a.core().list_wallets().unwrap().iter().all(|w| !w.unlocked));
    let log = a.fakes.log.lines().join("\n");
    assert!(log.contains("sync window started"), "{log}");
    assert!(log.contains("sync window ended"), "{log}");
    for marker in ["window-secret", "Window Entry", PASSWORD] {
        assert!(!log.contains(marker));
    }
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_window_is_bounded_by_its_time_limit() {
    let _guard = serial();
    let (mut a, b) = synced_pair("win-limit", WALLET);
    // b goes away: a's rounds back off and never finish.
    b.core().shutdown();
    a.core().shutdown();
    let pins = a.dir.path().join("peers.sealed");
    assert!(pins.exists());
    drop(a.core.take());
    a.fakes.window_limit = Duration::from_millis(1500);
    let core = a.start();
    let started = Instant::now();
    let report = core.run_sync_window();
    assert!(report.ran);
    assert_eq!(report.reason, WindowEnd::TimeLimit);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(report.duration_ms >= 1500 && report.duration_ms < 5000);
    assert!(!core.multicast_wanted());
    core.shutdown();
}

#[test]
fn a_window_ends_when_the_last_eligible_interface_disappears() {
    let _guard = serial();
    let (mut a, b) = synced_pair("win-lost", WALLET);
    b.core().shutdown();
    a.core().shutdown();
    drop(a.core.take());
    a.fakes.window_limit = Duration::from_secs(30);
    let core = a.start();
    let runner = Arc::clone(&core);
    let handle = std::thread::spawn(move || runner.run_sync_window());
    assert!(wait_for(Duration::from_secs(5), || core.multicast_wanted()));
    core.set_eligible_interfaces(Vec::new());
    let report = handle.join().unwrap();
    assert!(report.ran);
    assert_eq!(report.reason, WindowEnd::NoNetwork);
    assert!(!core.multicast_wanted());
    core.shutdown();
}
