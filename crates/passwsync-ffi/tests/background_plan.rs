//! 007 T113 (US5; FR-044, FR-046, FR-048): the background plan schedules the periodic window
//! only with networking on, a paired device and a usable identity; the extra window only with
//! unsent changes; nothing at all with networking off or no peer; the plan is available at app
//! start (jobs are not persisted across reboot).

mod common;

use std::time::Duration;

use common::*;

const WALLET: &str = "Shared";

#[test]
fn networking_off_or_no_peer_schedules_no_window() {
    let _guard = serial();
    let dir = TempDir::new("plan-off");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    for plan in [
        core.background_plan(),
        core.on_background(),
        core.on_deadline(),
    ] {
        assert_eq!(plan.periodic_window_minutes, None);
        assert!(!plan.extra_window);
        assert_eq!(plan.deadline_in_ms, None, "nothing at all to do");
    }
    drop(core);
    let mut node = Node::new("plan-nopeer", "Phone", Vec::new());
    let core = node.start();
    core.on_foreground();
    let plan = core.on_background();
    assert_eq!(plan.periodic_window_minutes, None);
    assert!(!plan.extra_window);
    assert_eq!(plan.keep_network_ms, 10_000);
    core.shutdown();
}

#[test]
fn a_paired_device_schedules_the_periodic_window_and_unsent_changes_the_extra_one() {
    let _guard = serial();
    let (mut a, b) = synced_pair("plan-paired", WALLET);
    // A peer mark rises when a copy arrives from that peer (004): b edits, a merges it and
    // then holds nothing b has not acknowledged. Periodic window at the sync interval
    // (default 60 min), no extra window.
    b.core()
        .add_credential(WALLET.into(), input("From B", "u", Some("p")))
        .unwrap();
    assert!(wait_for(Duration::from_secs(20), || titles(
        a.core(),
        WALLET
    )
    .len()
        == 2));
    assert!(wait_for(Duration::from_secs(20), || !a
        .core()
        .background_plan()
        .extra_window));
    let plan = a.core().background_plan();
    assert_eq!(plan.periodic_window_minutes, Some(60));
    background(&a);
    a.core()
        .add_credential(WALLET.into(), input("Unsent", "u", Some("p")))
        .unwrap();
    let plan = a.core().on_background();
    assert_eq!(plan.periodic_window_minutes, Some(60));
    assert!(plan.extra_window, "an edit no peer has acknowledged");
    // At app start (node paused, pins sealed) the plan is the same.
    a.core().shutdown();
    drop(a.core.take());
    let core = a.start();
    let plan = core.background_plan();
    assert_eq!(plan.periodic_window_minutes, Some(60));
    assert!(plan.extra_window);
    core.shutdown();
    b.core().shutdown();
}

#[test]
fn an_unusable_identity_schedules_no_window() {
    let _guard = serial();
    let (mut a, b) = synced_pair("plan-unusable", WALLET);
    a.core().shutdown();
    drop(a.core.take());
    a.fakes
        .sealer
        .set_mode(passwsync_ffi::testkit::SealerMode::Invalidated);
    let core = a.start();
    let plan = core.background_plan();
    assert_eq!(plan.periodic_window_minutes, None);
    assert!(!plan.extra_window);
    core.shutdown();
    b.core().shutdown();
}
