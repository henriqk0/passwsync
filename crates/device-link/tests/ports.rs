use std::time::Duration;

use device_link::name::DeviceName;
use device_link::ports::{MonoClock, PeerStore, WallClock};
use device_link::registry::PeerPin;
use device_link::testkit::{FakeMonoClock, FakeWallClock, MemoryPeerStore};

fn pin(byte: u8) -> PeerPin {
    PeerPin {
        public: [byte; 32],
        name: DeviceName::parse("Phone").unwrap(),
        paired_at: 1_761_200_000,
        last_seen: None,
        last_addr: None,
    }
}

#[test]
fn fake_clocks_are_settable_and_advance() {
    let mono = FakeMonoClock::new();
    assert_eq!(mono.now(), Duration::ZERO);
    mono.advance(Duration::from_secs(5));
    assert_eq!(mono.now(), Duration::from_secs(5));
    mono.set(Duration::from_secs(100));
    assert_eq!(mono.now(), Duration::from_secs(100));
    let wall = FakeWallClock::new(1_761_200_000);
    assert_eq!(wall.unix_now(), 1_761_200_000);
    wall.set(1_761_200_300);
    assert_eq!(wall.unix_now(), 1_761_200_300);
}

#[test]
fn memory_store_round_trips_and_fails_on_demand() {
    let store = MemoryPeerStore::new();
    assert!(store.load().unwrap().is_empty());
    store.save(&[pin(1), pin(2)]).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[1].public, [2; 32]);
    store.fail_saves(true);
    assert!(store.save(&[pin(3)]).is_err());
    assert_eq!(
        store.load().unwrap().len(),
        2,
        "failed save leaves contents"
    );
    store.fail_saves(false);
    store.save(&[]).unwrap();
    assert!(store.load().unwrap().is_empty());
    assert_eq!(store.save_count(), 2);
}
