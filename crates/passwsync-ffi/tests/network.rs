//! 007 T102 (US4; FR-038 to FR-043, FR-051): networking off opens no socket; the node stays
//! paused until the foreground; the switch needs a confirmation and applies at the next start;
//! the eligible-interface set filters the scan; `multicast_wanted` follows the node; leaving
//! the foreground closes the sockets after the linger; foreground-only calls are refused in the
//! background; a non-private address is never used; no name resolution exists in the crate.
//! Socket counts come from `/proc/self/fd`, so the tests of this file run one at a time.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use device_link::name::InterfaceName;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::{FakeInterfaces, Interface};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::lifecycle::linger_should_pause;
use passwsync_ffi::records::NetStateView;

#[test]
fn networking_off_by_default_opens_no_socket() {
    let _guard = serial();
    let before = socket_fds();
    let dir = TempDir::new("net-off");
    let mut fakes = Fakes::new();
    fakes.net = loopback_net(Vec::new());
    fakes.eligible = vec!["lo".into()];
    let core = fakes.start(dir.path()).unwrap();
    core.on_foreground();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(socket_fds(), before, "networking off opens nothing");
    let view = core.network();
    assert_eq!(view.state, NetStateView::Off);
    assert!(!core.multicast_wanted());
    assert!(!core.settings().networking);
    drop(core);
}

#[test]
fn the_node_is_paused_after_start_until_the_foreground() {
    let _guard = serial();
    let before = socket_fds();
    let mut node = Node::new("net-paused", "Phone", Vec::new());
    let core = node.start();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(socket_fds(), before, "paused at start");
    assert_eq!(core.network().state, NetStateView::Paused);
    assert!(!core.multicast_wanted());
    core.on_foreground();
    assert!(wait_for(Duration::from_secs(2), || core.network().state
        == NetStateView::On));
    assert!(socket_fds() > before);
    assert!(core.multicast_wanted(), "true exactly while the node runs");
    core.shutdown();
    assert!(!core.multicast_wanted());
    drop(core);
    node.core = None;
    assert!(wait_for(Duration::from_secs(2), || socket_fds() == before));
}

#[test]
fn switching_networking_on_needs_a_confirmation_and_a_restart() {
    let _guard = serial();
    let dir = TempDir::new("net-switch");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    assert_eq!(
        core.set_networking(true, false).err(),
        Some(CoreError::InvalidInput)
    );
    assert!(!core.settings().networking);
    assert!(!core.settings().restart_required);
    core.set_networking(true, true).unwrap();
    let view = core.settings();
    assert!(view.networking && view.restart_required);
    // Not in force before a restart.
    assert_eq!(core.network().state, NetStateView::Off);
    let text = std::fs::read_to_string(dir.path().join("settings")).unwrap();
    assert!(text.contains("network = on"), "{text}");
    core.set_networking(false, false).unwrap();
    assert!(!core.settings().networking);
}

#[test]
fn the_eligible_interface_set_filters_the_scan_and_empty_is_no_local_network() {
    let _guard = serial();
    let mut node = Node::new("net-eligible", "Phone", Vec::new());
    node.fakes.eligible = Vec::new();
    let core = node.start();
    core.on_foreground();
    assert_eq!(core.network().state, NetStateView::NoLocalNetwork);
    assert!(!core.multicast_wanted());
    core.set_eligible_interfaces(vec!["lo".into()]);
    assert!(wait_for(Duration::from_secs(3), || core.network().state
        == NetStateView::On));
    assert!(core.multicast_wanted());
    core.set_eligible_interfaces(Vec::new());
    assert!(wait_for(Duration::from_secs(3), || core.network().state
        == NetStateView::NoLocalNetwork));
    assert!(!core.multicast_wanted());
    core.shutdown();
}

#[test]
fn leaving_the_foreground_closes_every_socket_after_the_linger() {
    let _guard = serial();
    let before = socket_fds();
    let mut node = Node::new("net-linger", "Phone", Vec::new());
    let core = node.start();
    core.on_foreground();
    assert!(wait_for(Duration::from_secs(2), || core.multicast_wanted()));
    let plan = core.on_background();
    assert_eq!(
        plan.keep_network_ms, 10_000,
        "the plan names the 10 s linger"
    );
    // The linger of this test is 300 ms (production 10 s).
    assert!(
        wait_for(Duration::from_secs(5), || socket_fds() == before),
        "sockets still open"
    );
    assert!(!core.multicast_wanted());
    assert_eq!(core.network().state, NetStateView::Paused);
    // Back in the foreground the node runs again.
    core.on_foreground();
    assert!(wait_for(Duration::from_secs(2), || core.multicast_wanted()));
    core.shutdown();
}

#[test]
fn a_running_transfer_extends_the_linger_to_at_most_120_seconds() {
    let linger = Duration::from_secs(10);
    let cap = Duration::from_secs(120);
    assert!(!linger_should_pause(
        Duration::from_secs(5),
        false,
        linger,
        cap
    ));
    assert!(linger_should_pause(
        Duration::from_secs(10),
        false,
        linger,
        cap
    ));
    assert!(!linger_should_pause(
        Duration::from_secs(60),
        true,
        linger,
        cap
    ));
    assert!(linger_should_pause(
        Duration::from_secs(120),
        true,
        linger,
        cap
    ));
    assert!(linger_should_pause(
        Duration::from_secs(300),
        true,
        linger,
        cap
    ));
}

#[test]
fn foreground_only_calls_are_refused_in_the_background() {
    let _guard = serial();
    let mut node = Node::new("net-fg", "Phone", Vec::new());
    let core = node.start();
    let fg = Some(CoreError::NotForeground);
    assert_eq!(core.start_pairing().err(), fg);
    assert_eq!(
        core.join_pairing("00".repeat(32), bytes("12345678")).err(),
        fg
    );
    assert_eq!(core.accept_pairing("00".repeat(32)).err(), fg);
    assert_eq!(core.revoke_device("00".repeat(32)).err(), fg);
    assert_eq!(core.reset_identity().err(), fg);
    core.on_foreground();
    core.on_background();
    assert_eq!(core.start_pairing().err(), fg);
    core.shutdown();
}

#[test]
fn a_non_private_address_is_never_used() {
    let _guard = serial();
    let before = socket_fds();
    let mut node = Node::new("net-public", "Phone", Vec::new());
    // Production policy (private and link-local only) over a public IPv4 interface.
    let public = Interface {
        name: InterfaceName::parse("wlan0").unwrap(),
        addr: Ipv4Addr::new(8, 8, 8, 8),
        prefix: 24,
        broadcast: Ipv4Addr::new(8, 8, 8, 255),
    };
    node.fakes.net.policy = AddressPolicy::lan();
    node.fakes.net.interfaces = Some(Arc::new(FakeInterfaces::new(vec![public])));
    node.fakes.eligible = vec!["wlan0".into()];
    let core = node.start();
    core.on_foreground();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(core.network().state, NetStateView::NoLocalNetwork);
    assert_eq!(socket_fds(), before, "nothing bound to a public address");
    assert!(!core.multicast_wanted());
    core.shutdown();
}

#[test]
fn the_crate_never_resolves_names() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in [
            "ToSocketAddrs",
            "to_socket_addrs",
            "lookup_host",
            "getaddrinfo",
        ] {
            assert!(!text.contains(needle), "{} uses {needle}", path.display());
        }
    }
}
