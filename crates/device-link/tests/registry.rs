use std::sync::Arc;

use device_link::error::Error;
use device_link::identity::DeviceId;
use device_link::name::DeviceName;
use device_link::registry::{MAX_PINS, PeerPin, PeerRegistry};
use device_link::testkit::MemoryPeerStore;

const OWN: [u8; 32] = [0xee; 32];

fn pin(byte: u8) -> PeerPin {
    PeerPin {
        public: [byte; 32],
        name: DeviceName::parse("Phone").unwrap(),
        paired_at: 1_761_200_000,
        last_seen: None,
        last_addr: None,
    }
}

fn registry() -> (PeerRegistry, Arc<MemoryPeerStore>) {
    let store = Arc::new(MemoryPeerStore::new());
    (PeerRegistry::load(OWN, store.clone()).unwrap(), store)
}

#[test]
fn pin_saves_before_reporting_success() {
    let (mut reg, store) = registry();
    reg.pin(pin(1)).unwrap();
    assert_eq!(store.pins(), vec![pin(1)]);
    assert!(reg.contains(&DeviceId::from_public(&[1; 32])));
    assert_eq!(reg.get(&pin(1).id()).unwrap().public, [1; 32]);
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.list().len(), 1);
}

#[test]
fn pin_refuses_self_duplicates_and_the_33rd() {
    let (mut reg, store) = registry();
    assert_eq!(reg.pin(pin(0xee)), Err(Error::SelfPair));
    reg.pin(pin(1)).unwrap();
    let mut renamed = pin(1);
    renamed.name = DeviceName::parse("Other").unwrap();
    assert_eq!(reg.pin(renamed), Err(Error::AlreadyPaired));
    assert_eq!(reg.get(&pin(1).id()).unwrap().name.as_str(), "Phone");
    for byte in 2..=MAX_PINS as u8 {
        reg.pin(pin(byte)).unwrap();
    }
    assert_eq!(reg.len(), 32);
    assert!(reg.is_full());
    assert_eq!(reg.pin(pin(200)), Err(Error::Limit));
    assert_eq!(store.pins().len(), 32);
}

#[test]
fn failed_save_leaves_registry_unchanged() {
    let (mut reg, store) = registry();
    reg.pin(pin(1)).unwrap();
    store.fail_saves(true);
    assert_eq!(reg.pin(pin(2)), Err(Error::Storage));
    assert!(!reg.contains(&pin(2).id()));
    assert_eq!(reg.revoke(&pin(1).id()), Err(Error::Storage));
    assert!(reg.contains(&pin(1).id()), "revoke failure keeps the pin");
    store.fail_saves(false);
    assert_eq!(store.pins(), vec![pin(1)]);
}

#[test]
fn revoke_removes_and_saves() {
    let (mut reg, store) = registry();
    reg.pin(pin(1)).unwrap();
    reg.pin(pin(2)).unwrap();
    let removed = reg.revoke(&pin(1).id()).unwrap();
    assert_eq!(removed.public, [1; 32]);
    assert_eq!(store.pins(), vec![pin(2)]);
    assert_eq!(reg.revoke(&pin(1).id()), Err(Error::NotFound));
}

#[test]
fn key_is_never_replaced_and_lookup_is_by_key() {
    let (mut reg, _) = registry();
    reg.pin(pin(1)).unwrap();
    assert!(reg.is_pinned_key(&[1; 32]));
    assert!(!reg.is_pinned_key(&[2; 32]));
    // There is no API that changes a pinned key; a name update keeps it.
    reg.update_name(&pin(1).id(), DeviceName::parse("New").unwrap())
        .unwrap();
    assert_eq!(reg.get(&pin(1).id()).unwrap().public, [1; 32]);
    assert_eq!(reg.get(&pin(1).id()).unwrap().name.as_str(), "New");
}

#[test]
fn last_seen_is_kept_in_memory_until_persisted() {
    let (mut reg, store) = registry();
    reg.pin(pin(1)).unwrap();
    let addr = "192.168.1.7:27472".parse().unwrap();
    reg.touch(&pin(1).id(), 1_761_200_500, Some(addr));
    assert_eq!(store.pins()[0].last_seen, None, "not saved on every touch");
    assert_eq!(
        reg.get(&pin(1).id()).unwrap().last_seen,
        Some(1_761_200_500)
    );
    assert_eq!(reg.find_by_addr(addr).unwrap().public, [1; 32]);
    reg.persist().unwrap();
    assert_eq!(store.pins()[0].last_seen, Some(1_761_200_500));
    assert_eq!(store.pins()[0].last_addr, Some(addr));
}

#[test]
fn load_reads_the_store() {
    let store = Arc::new(MemoryPeerStore::with(vec![pin(1), pin(2)]));
    let reg = PeerRegistry::load(OWN, store).unwrap();
    assert_eq!(reg.len(), 2);
}
