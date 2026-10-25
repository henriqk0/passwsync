//! 005 T010: `Node::ensure_channel` (specs/005-wallet-sharing/contracts/core-api-share.md,
//! research R11): reuse, dial of a hint under the 003 address policy, pin and identity rules,
//! share payloads only on v3 channels, bounded blocking.

mod support;

use std::net::{SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use device_link::identity::{DeviceId, DeviceKey};
use device_link::name::DeviceName;
use device_link::registry::{PeerPin, PeerRegistry};
use device_link::testkit::MemoryPeerStore;
use device_link::wire::{HelloVersion, Payload};
use device_link_net::interfaces::FakeInterfaces;
use device_link_net::{
    EnsureError, Node, NodeConfig, RecordingSink, SendError, StdMonoClock, SystemWallClock,
};
use support::old_peer::{OldPeer, old_peer};
use support::{Options, fast_timing, free_port, pair, start, wait_for};

fn pin(public: [u8; 32], addr: Option<SocketAddrV4>) -> PeerPin {
    PeerPin {
        public,
        name: DeviceName::parse("Peer").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: addr,
    }
}

/// A node with the given pins whose auto-dial never finds the peers (no address known).
fn node(seed: u8, pins: Vec<PeerPin>) -> (Node, Arc<FakeInterfaces>) {
    let key = DeviceKey::from_private([seed; 32]);
    let store = Arc::new(MemoryPeerStore::with(pins));
    let registry = PeerRegistry::load(*key.public(), store).unwrap();
    let interfaces = Arc::new(FakeInterfaces::loopback());
    let node = Node::start(
        NodeConfig {
            key,
            name: DeviceName::parse("Laptop").unwrap(),
            peer_port: free_port(),
            discovery_port: free_port(),
            announce_ports: vec![free_port()],
            policy: device_link::policy::AddressPolicy::testkit(),
            interfaces: interfaces.clone(),
            timing: fast_timing(),
        },
        registry,
        Arc::new(StdMonoClock::new()),
        Arc::new(SystemWallClock),
        Arc::new(RecordingSink::default()),
    )
    .unwrap();
    (node, interfaces)
}

fn peer(seed: u8, own_seed: u8, max: HelloVersion) -> OldPeer {
    old_peer(seed, *DeviceKey::from_private([own_seed; 32]).public(), max)
}

#[test]
fn an_existing_channel_is_returned() {
    let a = start(41, "Laptop", Options::default());
    let b = start(42, "Phone", Options::default());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || b.node.channel_count() == 1));
    let (id, conn) = b.node.ensure_channel(Some(a.id), None).unwrap();
    assert_eq!(id, a.id);
    assert_eq!(b.node.sync_channels(), vec![(a.id, conn)]);
    assert_eq!(b.node.channel_count(), 1, "no second connection");
    a.node.stop();
    b.node.stop();
}

#[test]
fn a_hint_is_dialed_for_the_expected_pinned_peer() {
    let p = peer(43, 44, HelloVersion::V3);
    let (n, _) = node(44, vec![pin(*p.key.public(), None)]);
    let (id, conn) = n.ensure_channel(Some(p.key.id()), Some(p.addr)).unwrap();
    assert_eq!(id, p.key.id());
    assert_eq!(n.channel_version(&id), Some(HelloVersion::V3));
    assert!(n.sync_channels().contains(&(id, conn)));
    // Share payloads go through on a v3 channel.
    n.send_sync(&id, conn, &Payload::ShareMsg { body: vec![1; 5] })
        .unwrap();
    n.stop();
}

#[test]
fn the_known_address_is_used_without_a_hint() {
    let p = peer(45, 46, HelloVersion::V3);
    let (n, _) = node(46, vec![pin(*p.key.public(), Some(p.addr))]);
    // The auto-dialer may get there first; either way one channel results.
    let (id, _) = n.ensure_channel(Some(p.key.id()), None).unwrap();
    assert_eq!(id, p.key.id());
    n.stop();
}

#[test]
fn with_only_an_address_the_responder_must_be_pinned() {
    let p = peer(47, 48, HelloVersion::V3);
    let (n, _) = node(48, vec![pin(*p.key.public(), None)]);
    let (id, _) = n.ensure_channel(None, Some(p.addr)).unwrap();
    assert_eq!(id, p.key.id(), "the answering pinned device is the sender");
    n.stop();

    let stranger = peer(49, 50, HelloVersion::V3);
    let (n, _) = node(50, vec![pin(*p.key.public(), None)]);
    assert_eq!(
        n.ensure_channel(None, Some(stranger.addr)),
        Err(EnsureError::NotPaired)
    );
    assert_eq!(
        stranger.channels.load(Ordering::SeqCst),
        0,
        "never paired up"
    );
    assert_eq!(n.channel_count(), 0);
    n.stop();
}

#[test]
fn an_unpinned_expected_device_is_not_paired() {
    let p = peer(51, 52, HelloVersion::V3);
    let (n, _) = node(52, vec![]);
    assert_eq!(
        n.ensure_channel(Some(p.key.id()), Some(p.addr)),
        Err(EnsureError::NotPaired)
    );
    assert_eq!(p.hellos[3].load(Ordering::SeqCst), 0, "nothing dialed");
    n.stop();
}

#[test]
fn a_different_identity_at_the_address_is_an_id_mismatch() {
    let wanted = DeviceKey::from_private([53; 32]);
    let other = peer(54, 55, HelloVersion::V3);
    let (n, _) = node(
        55,
        vec![pin(*wanted.public(), None), pin(*other.key.public(), None)],
    );
    assert_eq!(
        n.ensure_channel(Some(wanted.id()), Some(other.addr)),
        Err(EnsureError::IdMismatch)
    );
    assert_eq!(other.channels.load(Ordering::SeqCst), 0);
    n.stop();
}

#[test]
fn unreachable_self_and_network_off() {
    let p = DeviceKey::from_private([56; 32]);
    let (n, interfaces) = node(57, vec![pin(*p.public(), None)]);
    // No address known and no hint.
    assert_eq!(
        n.ensure_channel(Some(p.id()), None),
        Err(EnsureError::Unreachable)
    );
    // A closed port.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let addr = SocketAddrV4::new([127, 0, 0, 1].into(), closed);
    assert_eq!(
        n.ensure_channel(Some(p.id()), Some(addr)),
        Err(EnsureError::Unreachable)
    );
    assert_eq!(
        n.ensure_channel(None, Some(addr)),
        Err(EnsureError::Unreachable)
    );
    // A public address is outside the 003 policy: never dialed.
    let public = SocketAddrV4::new([8, 8, 8, 8].into(), 27472);
    assert_eq!(
        n.ensure_channel(Some(p.id()), Some(public)),
        Err(EnsureError::Unreachable)
    );
    // Self.
    let own: DeviceId = n.own_id();
    assert_eq!(
        n.ensure_channel(Some(own), Some(addr)),
        Err(EnsureError::SelfDevice)
    );
    // Network off: no usable interface.
    interfaces.set(Vec::new());
    assert!(wait_for(Duration::from_secs(3), || n
        .ensure_channel(Some(p.id()), Some(addr))
        == Err(EnsureError::NetworkOff)));
    n.stop();
}

#[test]
fn share_payloads_need_a_v3_channel() {
    let p = peer(58, 59, HelloVersion::V2);
    let (n, _) = node(59, vec![pin(*p.key.public(), None)]);
    let (id, conn) = n.ensure_channel(Some(p.key.id()), Some(p.addr)).unwrap();
    assert_eq!(n.channel_version(&id), Some(HelloVersion::V2));
    assert_eq!(
        n.send_sync(&id, conn, &Payload::ShareMsg { body: vec![1] }),
        Err(SendError::NotShareEnabled)
    );
    assert_eq!(
        n.send_sync(&id, conn, &Payload::ShareData { bytes: vec![1] }),
        Err(SendError::NotShareEnabled)
    );
    n.stop();
}

#[test]
fn blocking_is_bounded_by_the_step_timeouts() {
    // Accepts the TCP connection but never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = match silent.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    let p = DeviceKey::from_private([60; 32]);
    let (n, _) = node(61, vec![pin(*p.public(), None)]);
    let started = Instant::now();
    assert_eq!(
        n.ensure_channel(Some(p.id()), Some(addr)),
        Err(EnsureError::Unreachable)
    );
    let step = fast_timing().step_timeout;
    assert!(started.elapsed() < step * 4, "took {:?}", started.elapsed());
    drop(silent);
    n.stop();
}

#[test]
fn with_an_address_the_identity_there_must_match_even_when_a_channel_exists() {
    // `a` and `b` are paired with a channel; another device answers at another address.
    // Asking `b` for `a` at that address is an id mismatch (FR-012), decided before `b`
    // reveals its key there.
    let a = start(62, "Laptop", Options::default());
    let b = start(63, "Phone", Options::default());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || b.node.channel_count() == 1));
    let other = peer(64, 63, HelloVersion::V3);
    assert_eq!(
        b.node.ensure_channel(Some(a.id), Some(other.addr)),
        Err(EnsureError::IdMismatch)
    );
    assert_eq!(other.channels.load(Ordering::SeqCst), 0);
    // The right address reuses the existing channel.
    let (id, _) = b.node.ensure_channel(Some(a.id), Some(a.addr())).unwrap();
    assert_eq!(id, a.id);
    assert_eq!(b.node.channel_count(), 1);
    a.node.stop();
    b.node.stop();
}
