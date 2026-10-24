//! Channels between paired nodes over loopback TCP (US4).

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use device_link::link::PeerStatus;
use device_link_net::interfaces::{FakeInterfaces, InterfaceSource};
use device_link_net::{NetEvent, Refusal};
use support::{Options, TestNode, pair, start, wait_for};

fn status(node: &TestNode, peer: &TestNode) -> Option<PeerStatus> {
    status_of(node, peer.id)
}

fn status_of(node: &TestNode, peer: device_link::identity::DeviceId) -> Option<PeerStatus> {
    node.node
        .snapshot()
        .paired
        .iter()
        .find(|p| p.id == peer)
        .map(|p| p.status)
}

fn connected(a: &TestNode, b: &TestNode) -> bool {
    status(a, b) == Some(PeerStatus::Connected) && status(b, a) == Some(PeerStatus::Connected)
}

#[test]
fn paired_nodes_connect_and_keep_one_channel() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    assert!(
        wait_for(Duration::from_secs(5), || connected(&a, &b)),
        "channel up"
    );
    assert_eq!(a.node.channel_count(), 1);
    assert_eq!(b.node.channel_count(), 1);
    assert!(a.has_event(&NetEvent::PeerConnected(b.id)));
    // Keepalives keep it up well past the idle timeout (1.5 s in tests).
    std::thread::sleep(Duration::from_millis(2500));
    assert!(connected(&a, &b));
    assert_eq!(a.node.channel_count(), 1, "at most one channel per peer");
    a.node.stop();
    b.node.stop();
}

#[test]
fn reconnects_after_a_restart_without_re_pairing() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || connected(&a, &b)));
    let (a_port, a_disc, a_store, a_id) = (a.peer_port, a.discovery_port, a.store.clone(), a.id);
    a.node.stop();
    assert!(
        wait_for(Duration::from_secs(5), || status_of(&b, a_id)
            == Some(PeerStatus::Offline)),
        "B sees A offline"
    );
    let a2 = start(
        1,
        "Laptop",
        Options {
            peer_port: Some(a_port),
            discovery_port: Some(a_disc),
            store: Some(a_store),
            ..Options::default()
        },
    );
    assert!(
        wait_for(Duration::from_secs(8), || connected(&a2, &b)),
        "reconnected"
    );
    assert_eq!(a2.store.pins().len(), 1, "no re-pairing");
    a2.node.stop();
    b.node.stop();
}

#[test]
fn an_interface_change_triggers_reconnection() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || connected(&a, &b)));
    // B loses its network, then gets it back.
    b.interfaces.set(Vec::new());
    assert!(wait_for(Duration::from_secs(5), || b
        .events
        .events()
        .iter()
        .any(
            |e| matches!(e, NetEvent::InterfacesChanged(names) if names.is_empty())
        )));
    b.interfaces.set(FakeInterfaces::loopback().scan());
    assert!(wait_for(Duration::from_secs(8), || connected(&a, &b)));
    a.node.stop();
    b.node.stop();
}

#[test]
fn an_unpaired_node_is_refused_and_sees_refused_by_peer() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    // C pins A on its side only (A never paired C).
    let c_store = std::sync::Arc::new(device_link::testkit::MemoryPeerStore::with(vec![
        device_link::registry::PeerPin {
            public: *device_link::identity::DeviceKey::from_private([1; 32]).public(),
            name: device_link::name::DeviceName::parse("Laptop").unwrap(),
            paired_at: 1,
            last_seen: None,
            last_addr: Some(a.addr()),
        },
    ]));
    let c = start(
        3,
        "Stranger",
        Options {
            store: Some(c_store),
            ..Options::default()
        },
    );
    assert!(
        wait_for(Duration::from_secs(8), || status(&c, &a)
            == Some(PeerStatus::RefusedByPeer)),
        "{:?}",
        status(&c, &a)
    );
    assert!(c.has_event(&NetEvent::RefusedByPeer(a.id)));
    assert!(wait_for(Duration::from_secs(2), || a
        .has_event(&NetEvent::PeerRefused(c.id, Refusal::Unpaired))));
    assert_eq!(a.store.pins().len(), 1, "A's pins unchanged");
    a.node.stop();
    b.node.stop();
    c.node.stop();
}

#[test]
fn a_silent_channel_handshake_is_closed_after_the_step_timeout() {
    let a = start(1, "Laptop", Options::default());
    let mut stream = TcpStream::connect(a.addr()).unwrap();
    stream.write_all(b"\x00\x06PWSC\x01\x01").unwrap();
    let start = Instant::now();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "closed without answer");
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(1200) && waited < Duration::from_secs(4));
    a.node.stop();
}

/// SC-008: a flood of connection attempts from one address keeps memory bounded and the
/// legitimate peer still connects. Slow; run with `--ignored`.
#[test]
#[ignore]
fn connection_flood_stays_bounded() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    pair(&a, &b);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut attempts = 0u32;
    while Instant::now() < deadline && attempts < 10_000 {
        if let Ok(mut s) = TcpStream::connect(a.addr()) {
            let _ = s.write_all(b"\x00\x06PWSC\x01\x01");
        }
        attempts += 1;
        if attempts % 100 == 0 {
            assert!(a.node.unauthenticated() <= 16);
        }
    }
    assert!(wait_for(Duration::from_secs(10), || connected(&a, &b)));
    a.node.stop();
    b.node.stop();
}

/// Runs the channel handshake as B over a raw socket to `a`; returns the channel or the error.
fn raw_dial(
    a: &TestNode,
    b_key: &device_link::identity::DeviceKey,
) -> (
    TcpStream,
    Result<device_link::channel::Channel, device_link::channel::ChannelError>,
) {
    use device_link::channel::{ChannelDialer, ChannelError};
    use device_link_net::framed::{read_frame, write_frame};
    let stream = TcpStream::connect(a.addr()).unwrap();
    let a_public = *device_link::identity::DeviceKey::from_private([1; 32]).public();
    let name = device_link::name::DeviceName::parse("Phone").unwrap();
    let mut dialer = ChannelDialer::start(b_key, a_public, name).unwrap();
    for _ in 0..2 {
        for frame in dialer.outgoing() {
            write_frame(&stream, &frame).unwrap();
        }
        let Ok(body) = read_frame(&stream, Duration::from_secs(2)) else {
            return (stream, Err(ChannelError::Protocol));
        };
        match dialer.on_frame(&body) {
            Ok(Some(channel)) => return (stream, Ok(channel)),
            Ok(None) => {}
            Err(error) => return (stream, Err(error)),
        }
    }
    (stream, Err(ChannelError::Protocol))
}

#[test]
fn revoking_sends_nothing_to_the_peer_and_only_its_next_hello_is_refused() {
    let b_key = device_link::identity::DeviceKey::from_private([2; 32]);
    let store = std::sync::Arc::new(device_link::testkit::MemoryPeerStore::with(vec![
        device_link::registry::PeerPin {
            public: *b_key.public(),
            name: device_link::name::DeviceName::parse("Phone").unwrap(),
            paired_at: 1,
            last_seen: None,
            last_addr: None,
        },
    ]));
    let mut options = Options {
        store: Some(store),
        ..Options::default()
    };
    // No keepalive or idle close during the test: any byte after the revoke is the revoke's.
    options.timing.keepalive = Duration::from_secs(30);
    options.timing.idle_close = Duration::from_secs(60);
    let a = start(1, "Laptop", options);
    let (mut stream, channel) = raw_dial(&a, &b_key);
    assert!(channel.is_ok(), "{:?}", channel.err());
    assert!(wait_for(Duration::from_secs(2), || a.node.channel_count() == 1));
    a.node.revoke(&b_key.id()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    let ended = loop {
        match stream.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break true,
            Err(_) => break false,
        }
    };
    assert!(ended, "the channel was not closed within 2 s");
    assert!(
        received.is_empty(),
        "revoke sent {} bytes to the revoked peer",
        received.len()
    );
    // The next Hello is answered with Refused.
    let (_, again) = raw_dial(&a, &b_key);
    assert_eq!(
        again.err(),
        Some(device_link::channel::ChannelError::Refused)
    );
    a.node.stop();
}
