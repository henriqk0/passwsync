//! UDP discovery over loopback (US3): announcements, gating, untrusted input, bounds.

mod support;

use std::net::{SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use device_link::discovery::{decode_announce, encode_announce};
use device_link::error::DropReason;
use device_link::identity::DeviceId;
use device_link::name::InterfaceName;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::Interface;
use support::{Options, free_port, start, wait_for};

fn listener() -> (UdpSocket, u16) {
    let port = free_port();
    let socket = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    (socket, port)
}

/// Waits up to `limit` for an announcement; returns (sender id, peer port).
fn next_announce(socket: &UdpSocket, limit: Duration) -> Option<(DeviceId, u16)> {
    let start = Instant::now();
    let mut buf = [0u8; 64];
    while start.elapsed() < limit {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            if let Ok(found) = decode_announce(&buf[..n], &DeviceId::from_bytes([0; 32])) {
                return Some(found);
            }
        }
    }
    None
}

#[test]
fn a_node_with_nothing_to_offer_stays_silent_and_a_code_starts_announcing() {
    let (socket, port) = listener();
    let a = start(
        1,
        "A",
        Options {
            announce_ports: vec![port],
            ..Options::default()
        },
    );
    assert_eq!(
        next_announce(&socket, Duration::from_millis(1000)),
        None,
        "no pins, no code: silence (FR-013a)"
    );
    let shown = Instant::now();
    a.node.start_pairing().unwrap();
    let (id, peer_port) = next_announce(&socket, Duration::from_secs(2)).expect("announced");
    assert!(shown.elapsed() < Duration::from_millis(300), "immediately");
    assert_eq!((id, peer_port), (a.id, a.peer_port));
    a.node.cancel_pairing();
    // Drain, then expect silence again.
    std::thread::sleep(Duration::from_millis(400));
    while next_announce(&socket, Duration::from_millis(50)).is_some() {}
    assert_eq!(next_announce(&socket, Duration::from_millis(1000)), None);
    a.node.stop();
}

#[test]
fn a_node_discovers_another_showing_a_code() {
    let b = start(2, "B", Options::default());
    let a = start(
        1,
        "A",
        Options {
            announce_ports: vec![b.discovery_port],
            ..Options::default()
        },
    );
    a.node.start_pairing().unwrap();
    assert!(wait_for(Duration::from_secs(3), || b
        .node
        .snapshot()
        .nearby
        .iter()
        .any(|n| n.id == a.id
            && n.addr.port() == a.peer_port
            && !n.paired)));
    a.node.stop();
    b.node.stop();
}

#[test]
fn datagrams_from_addresses_failing_the_policy_are_dropped() {
    let b = start(
        2,
        "B",
        Options {
            policy: AddressPolicy::lan(),
            ..Options::default()
        },
    );
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let packet = encode_announce(&DeviceId::from_bytes([9; 32]), 27472);
    sender
        .send_to(&packet, ("127.0.0.1", b.discovery_port))
        .unwrap();
    assert!(wait_for(Duration::from_secs(2), || b
        .node
        .counters()
        .get(DropReason::Public)
        >= 1));
    assert!(b.node.snapshot().nearby.is_empty());
    b.node.stop();
}

#[test]
fn malformed_datagrams_are_counted() {
    let b = start(2, "B", Options::default());
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"PWSD\x01short", ("127.0.0.1", b.discovery_port))
        .unwrap();
    assert!(wait_for(Duration::from_secs(2), || b
        .node
        .counters()
        .get(DropReason::Malformed)
        >= 1));
    b.node.stop();
}

#[test]
fn an_interface_change_announces_at_once() {
    let (socket, port) = listener();
    let mut options = Options {
        announce_ports: vec![port],
        ..Options::default()
    };
    options.timing.announce = Duration::from_secs(60);
    let a = start(1, "A", options);
    a.node.start_pairing().unwrap();
    assert!(next_announce(&socket, Duration::from_secs(2)).is_some());
    assert_eq!(
        next_announce(&socket, Duration::from_millis(500)),
        None,
        "next one only in 60 s"
    );
    a.interfaces.set(vec![Interface {
        name: InterfaceName::parse("lo").unwrap(),
        addr: [127, 0, 0, 2].into(),
        prefix: 8,
        broadcast: [127, 255, 255, 255].into(),
    }]);
    assert!(
        next_announce(&socket, Duration::from_secs(2)).is_some(),
        "announced on the new subnet without waiting for the interval"
    );
    a.node.stop();
}

#[test]
fn a_flood_keeps_the_nearby_list_bounded() {
    let b = start(2, "B", Options::default());
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = SocketAddrV4::new([127, 0, 0, 1].into(), b.discovery_port);
    for i in 0..10_000u32 {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&i.to_be_bytes());
        let _ = sender.send_to(&encode_announce(&DeviceId::from_bytes(raw), 27472), target);
    }
    assert!(wait_for(Duration::from_secs(3), || b
        .node
        .counters()
        .get(DropReason::Overflow)
        > 0));
    assert!(b.node.snapshot().nearby.len() <= 64);
    // The node still answers promptly.
    let start = Instant::now();
    let _ = b.node.snapshot();
    assert!(start.elapsed() < Duration::from_secs(1));
    b.node.stop();
}

#[test]
fn stopping_closes_the_discovery_socket() {
    let a = start(1, "A", Options::default());
    let port = a.discovery_port;
    assert!(
        UdpSocket::bind(("0.0.0.0", port)).is_err(),
        "in use while running"
    );
    a.node.stop();
    assert!(
        UdpSocket::bind(("0.0.0.0", port)).is_ok(),
        "released on stop"
    );
}

#[test]
fn an_unauthenticated_announcement_never_moves_a_pin_or_raises_a_warning() {
    // B pins A at a known address where nothing listens.
    let a_key = device_link::identity::DeviceKey::from_private([1; 32]);
    let known = SocketAddrV4::new([127, 0, 0, 1].into(), free_port());
    let store = std::sync::Arc::new(device_link::testkit::MemoryPeerStore::with(vec![
        device_link::registry::PeerPin {
            public: *a_key.public(),
            name: device_link::name::DeviceName::parse("Laptop").unwrap(),
            paired_at: 1,
            last_seen: None,
            last_addr: Some(known),
        },
    ]));
    let b = start(
        2,
        "Phone",
        Options {
            store: Some(store.clone()),
            ..Options::default()
        },
    );
    // An attacker C listens elsewhere and announces A's ID with C's port.
    let c = start(3, "Stranger", Options::default());
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let forged = encode_announce(&a_key.id(), c.peer_port);
    for _ in 0..5 {
        sender
            .send_to(&forged, ("127.0.0.1", b.discovery_port))
            .unwrap();
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        b.node.snapshot().warnings.is_empty(),
        "a hint redirected the warning: {:?}",
        b.node.snapshot().warnings
    );
    b.node.stop();
    c.node.stop();
    assert_eq!(
        store.pins()[0].last_addr,
        Some(known),
        "an announcement moved the pin"
    );
}
