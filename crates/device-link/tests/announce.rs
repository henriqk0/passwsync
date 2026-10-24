//! Announce gating (FR-013, FR-013a): never without a pin or an active code; immediately on
//! start, network change and code shown; then every 30 s.

use std::time::Duration;

use device_link::identity::DeviceId;
use device_link::link::{Link, Timing};

const S: fn(u64) -> Duration = Duration::from_secs;

fn link() -> Link {
    Link::new(DeviceId::from_bytes([1; 32]), Timing::default())
}

#[test]
fn nothing_is_ever_sent_without_a_pin_or_an_active_code() {
    let mut link = link();
    for t in 0..200 {
        assert!(!link.should_announce(S(t), false, false), "at {t}");
    }
    link.announce_soon();
    assert!(!link.should_announce(S(201), false, false));
}

#[test]
fn first_announce_is_immediate_then_every_30_seconds() {
    let mut link = link();
    assert!(link.should_announce(S(0), true, false), "on start");
    assert!(!link.should_announce(S(1), true, false));
    assert!(!link.should_announce(S(29), true, false));
    assert!(link.should_announce(S(30), true, false));
    assert!(!link.should_announce(S(31), true, false));
    assert!(link.should_announce(S(60), true, false));
}

#[test]
fn showing_a_code_or_a_network_change_announces_at_once() {
    let mut link = link();
    // No pins: silent until a code is shown.
    assert!(!link.should_announce(S(0), false, false));
    link.announce_soon(); // code shown
    assert!(link.should_announce(S(5), false, true));
    assert!(!link.should_announce(S(6), false, true));
    link.announce_soon(); // network change
    assert!(link.should_announce(S(7), false, true));
    assert!(link.should_announce(S(37), false, true), "then every 30 s");
}

#[test]
fn announcements_stop_when_the_last_pin_goes_or_the_code_ends() {
    let mut link = link();
    assert!(link.should_announce(S(0), true, false));
    // The last pin was revoked and no code is shown.
    assert!(!link.should_announce(S(30), false, false));
    assert!(!link.should_announce(S(90), false, false));
    // A code shown then expired.
    link.announce_soon();
    assert!(link.should_announce(S(100), false, true));
    assert!(!link.should_announce(S(130), false, false));
}
