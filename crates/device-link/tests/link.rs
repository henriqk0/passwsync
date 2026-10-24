//! `Link` decisions with a fake clock (research R10): backoff, keepalive, idle close,
//! duplicate resolution, name updates, statuses.

mod support;

use std::time::Duration;

use device_link::link::{Link, PeerStatus, Timing, keep_existing};
use device_link::name::DeviceName;
use device_link::ports::MonoClock;
use device_link::testkit::FakeMonoClock;
use support::Device;
use support::channel::key;

const S: fn(u64) -> Duration = Duration::from_secs;

#[test]
fn default_timing_matches_the_plan() {
    let t = Timing::default();
    assert_eq!(t.announce, S(30));
    assert_eq!(t.nearby_expiry, S(90));
    assert_eq!(t.step_timeout, S(10));
    assert_eq!(t.keepalive, S(60));
    assert_eq!(t.idle_close, S(150));
    assert_eq!(t.dial_backoff_min, S(30));
    assert_eq!(t.dial_backoff_max, S(300));
    assert_eq!(t.rescan, S(30));
}

#[test]
fn dial_backoff_doubles_from_30_to_300_and_resets_on_success() {
    let clock = FakeMonoClock::new();
    let peer = key(2).id();
    let mut link = Link::new(key(1).id(), Timing::default());
    assert!(link.may_dial(&peer, clock.now()), "first attempt at once");
    let mut waits = Vec::new();
    for _ in 0..6 {
        link.dial_failed(&peer, clock.now());
        let mut waited = 0;
        while !link.may_dial(&peer, clock.now()) {
            clock.advance(S(1));
            waited += 1;
        }
        waits.push(waited);
    }
    assert_eq!(waits, [30, 60, 120, 240, 300, 300]);
    link.connected(&peer, key(1).id());
    assert_eq!(link.status(&peer), PeerStatus::Connected);
    assert!(
        !link.may_dial(&peer, clock.now()),
        "never dial a connected peer"
    );
    link.disconnected(&peer, clock.now());
    assert_eq!(link.status(&peer), PeerStatus::Offline);
    link.dial_failed(&peer, clock.now());
    assert!(!link.may_dial(&peer, clock.now() + S(29)));
    assert!(link.may_dial(&peer, clock.now() + S(30)), "reset to 30 s");
}

#[test]
fn an_announcement_resets_the_backoff() {
    let peer = key(2).id();
    let mut link = Link::new(key(1).id(), Timing::default());
    for _ in 0..4 {
        link.dial_failed(&peer, S(0));
    }
    assert!(!link.may_dial(&peer, S(100)));
    link.on_announce(&peer, S(100));
    assert!(link.may_dial(&peer, S(100)));
}

#[test]
fn keepalive_after_60_s_quiet_and_close_after_150_s_silence() {
    let link = Link::new(key(1).id(), Timing::default());
    assert!(!link.keepalive_due(S(0), S(59)));
    assert!(link.keepalive_due(S(0), S(60)));
    assert!(!link.idle_expired(S(0), S(149)));
    assert!(link.idle_expired(S(0), S(150)));
    // The channel thread sleeps until the earlier of the two deadlines.
    assert_eq!(link.next_wake(S(10), S(0), S(20)), S(50));
    assert_eq!(link.next_wake(S(100), S(0), S(120)), S(30));
    assert_eq!(link.next_wake(S(0), S(0), S(200)), Duration::ZERO);
}

#[test]
fn duplicate_channels_keep_the_one_whose_dialer_has_the_smaller_id() {
    let (x, y) = (key(1).id(), key(2).id());
    let (low, high) = if x < y { (x, y) } else { (y, x) };
    // Both orders and both sides reach the same answer.
    assert!(keep_existing(low, high));
    assert!(!keep_existing(high, low));
    assert!(keep_existing(low, low), "same dialer: keep the first");
}

#[test]
fn name_updates_change_the_pin_name_only() {
    let mut a = Device::new(1, "Laptop");
    let b = Device::new(2, "Phone");
    let pin = a.pin_of(&b);
    a.reg.pin(pin).unwrap();
    let mut link = Link::new(a.id(), Timing::default());
    link.on_name_update(&mut a.reg, &b.id(), DeviceName::parse("Phone 2").unwrap())
        .unwrap();
    let pin = a.reg.get(&b.id()).unwrap();
    assert_eq!(pin.name.as_str(), "Phone 2");
    assert_eq!(pin.public, *b.key.public());
    assert_eq!(a.store.pins()[0].name.as_str(), "Phone 2", "saved");
    // Unknown peers are ignored.
    assert!(
        link.on_name_update(&mut a.reg, &key(9).id(), DeviceName::parse("X").unwrap())
            .is_err()
    );
}

#[test]
fn statuses_connected_offline_and_refused_by_peer() {
    let peer = key(2).id();
    let mut link = Link::new(key(1).id(), Timing::default());
    assert_eq!(link.status(&peer), PeerStatus::Offline);
    link.connected(&peer, peer);
    assert_eq!(link.status(&peer), PeerStatus::Connected);
    assert_eq!(link.channel_dialer(&peer), Some(peer));
    link.disconnected(&peer, S(0));
    assert_eq!(link.status(&peer), PeerStatus::Offline);
    assert_eq!(link.channel_dialer(&peer), None);
    link.refused_by_peer(&peer, S(0));
    assert_eq!(link.status(&peer), PeerStatus::RefusedByPeer);
    link.disconnected(&peer, S(1));
    assert_eq!(
        link.status(&peer),
        PeerStatus::RefusedByPeer,
        "stays until a channel succeeds"
    );
    link.connected(&peer, peer);
    assert_eq!(link.status(&peer), PeerStatus::Connected);
    link.forget(&peer);
    assert_eq!(link.status(&peer), PeerStatus::Offline);
}
