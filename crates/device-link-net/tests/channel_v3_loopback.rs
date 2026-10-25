//! 005 T009: channel v3 over loopback (specs/005-wallet-sharing/contracts/share-protocol.md
//! "Negotiation"): the dialer starts at v3 and falls back v3 -> v2 -> v1 per peer, retries the
//! higher version after 24 h, reports `PeerNoShare`, calls `channel_version` before
//! `channel_up`, and delivers share frames through the `SyncFrameSink`.

mod support;

use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use device_link::channel::ChannelDialer;
use device_link::identity::{DeviceId, DeviceKey};
use device_link::name::DeviceName;
use device_link::registry::{PeerPin, PeerRegistry};
use device_link::testkit::{FakeMonoClock, MemoryPeerStore};
use device_link::wire::{HelloVersion, Payload};
use device_link_net::framed::{read_frame, write_frame};
use device_link_net::interfaces::FakeInterfaces;
use device_link_net::{
    NetEvent, Node, NodeConfig, RecordingSink, SendError, SyncFrameSink, SystemWallClock,
};
use support::old_peer::{OldPeer, old_peer};
use support::{Options, fast_timing, free_port, pair, start, wait_for};

#[derive(Clone, Debug, PartialEq, Eq)]
enum SinkEvent {
    Version(DeviceId, u64, HelloVersion),
    Up(DeviceId, u64),
    Frame(DeviceId, u64, Payload),
    Down(DeviceId, u64),
}

#[derive(Default)]
struct Sink(Mutex<Vec<SinkEvent>>);

impl Sink {
    fn events(&self) -> Vec<SinkEvent> {
        self.0.lock().unwrap().clone()
    }
    fn up(&self) -> Option<(DeviceId, u64)> {
        self.events().into_iter().find_map(|e| match e {
            SinkEvent::Up(p, c) => Some((p, c)),
            _ => None,
        })
    }
    fn frames(&self) -> Vec<Payload> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                SinkEvent::Frame(_, _, p) => Some(p),
                _ => None,
            })
            .collect()
    }
}

impl SyncFrameSink for Sink {
    fn channel_up(&self, peer: DeviceId, conn: u64, _session: [u8; 32], _dialer: bool) {
        self.0.lock().unwrap().push(SinkEvent::Up(peer, conn));
    }
    fn frame(&self, peer: DeviceId, conn: u64, payload: Payload) {
        self.0
            .lock()
            .unwrap()
            .push(SinkEvent::Frame(peer, conn, payload));
    }
    fn channel_down(&self, peer: DeviceId, conn: u64) {
        self.0.lock().unwrap().push(SinkEvent::Down(peer, conn));
    }
    fn channel_version(&self, peer: DeviceId, conn: u64, version: HelloVersion) {
        self.0
            .lock()
            .unwrap()
            .push(SinkEvent::Version(peer, conn, version));
    }
}

#[test]
fn two_005_nodes_open_a_v3_channel_and_exchange_share_frames() {
    let a = start(31, "Laptop", Options::default());
    let b = start(32, "Phone", Options::default());
    let (sa, sb) = (Arc::new(Sink::default()), Arc::new(Sink::default()));
    a.node.set_sync_sink(sa.clone());
    b.node.set_sync_sink(sb.clone());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || sa.up().is_some()
        && sb.up().is_some()));
    let (_, conn_a) = sa.up().unwrap();
    // channel_version comes first, with V3.
    let events = sa.events();
    let version_at = events
        .iter()
        .position(|e| matches!(e, SinkEvent::Version(_, _, HelloVersion::V3)))
        .expect("channel_version reported");
    let up_at = events
        .iter()
        .position(|e| matches!(e, SinkEvent::Up(..)))
        .unwrap();
    assert!(version_at < up_at, "{events:?}");
    assert_eq!(a.node.channel_version(&b.id), Some(HelloVersion::V3));
    assert_eq!(a.node.max_version(&b.id), HelloVersion::V3);

    let msg = Payload::ShareMsg {
        body: vec![0x01; 37],
    };
    let data = Payload::ShareData {
        bytes: vec![7; 1000],
    };
    a.node.send_sync(&b.id, conn_a, &msg).unwrap();
    a.node.send_sync(&b.id, conn_a, &data).unwrap();
    a.node
        .send_sync(
            &b.id,
            conn_a,
            &Payload::SyncCtl {
                more: false,
                fragment: vec![1],
            },
        )
        .unwrap();
    assert!(wait_for(Duration::from_secs(3), || sb.frames().len() == 3));
    assert_eq!(sb.frames()[0], msg);
    assert_eq!(sb.frames()[1], data);
    a.node.stop();
    b.node.stop();
}

fn node_with_pin(seed: u8, pin: PeerPin, mono: Arc<FakeMonoClock>) -> (Node, Arc<RecordingSink>) {
    let key = DeviceKey::from_private([seed; 32]);
    let store = Arc::new(MemoryPeerStore::with(vec![pin]));
    let registry = PeerRegistry::load(*key.public(), store).unwrap();
    let events = Arc::new(RecordingSink::default());
    let node = Node::start(
        NodeConfig {
            key,
            name: DeviceName::parse("Laptop").unwrap(),
            peer_port: free_port(),
            discovery_port: free_port(),
            announce_ports: Vec::new(),
            policy: device_link::policy::AddressPolicy::testkit(),
            interfaces: Arc::new(FakeInterfaces::loopback()),
            timing: fast_timing(),
        },
        registry,
        mono,
        Arc::new(SystemWallClock),
        events.clone(),
    )
    .unwrap();
    (node, events)
}

fn pin_of(peer: &OldPeer) -> PeerPin {
    PeerPin {
        public: *peer.key.public(),
        name: DeviceName::parse("Old").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: Some(peer.addr),
    }
}

#[test]
fn a_v2_only_peer_lowers_the_maximum_to_v2_and_is_retried_at_v3_after_24_hours() {
    let own = DeviceKey::from_private([33; 32]);
    let old = old_peer(34, *own.public(), HelloVersion::V2);
    let mono = Arc::new(FakeMonoClock::new());
    let (node, events) = node_with_pin(33, pin_of(&old), mono.clone());
    let sink = Arc::new(Sink::default());
    node.set_sync_sink(sink.clone());
    let id = old.key.id();

    assert!(
        wait_for(Duration::from_secs(5), || old
            .channels
            .load(Ordering::SeqCst)
            == 1),
        "redialed with v2 at once"
    );
    assert_eq!(old.hellos[3].load(Ordering::SeqCst), 1);
    assert_eq!(old.hellos[2].load(Ordering::SeqCst), 1);
    assert_eq!(old.hellos[1].load(Ordering::SeqCst), 0);
    assert!(events.events().contains(&NetEvent::PeerNoShare(id)));
    assert!(
        !events.events().contains(&NetEvent::PeerLegacy(id)),
        "PeerLegacy keeps meaning no sync"
    );
    assert!(!node.is_legacy(&id));
    assert_eq!(node.max_version(&id), HelloVersion::V2);
    assert!(wait_for(Duration::from_secs(2), || sink.up().is_some()));
    let (_, conn) = sink.up().unwrap();
    assert!(
        sink.events()
            .contains(&SinkEvent::Version(id, conn, HelloVersion::V2))
    );
    assert_eq!(node.channel_version(&id), Some(HelloVersion::V2));
    // Sync works, share does not.
    node.send_sync(
        &id,
        conn,
        &Payload::SyncCtl {
            more: false,
            fragment: vec![1],
        },
    )
    .unwrap();
    assert_eq!(
        node.send_sync(&id, conn, &Payload::ShareMsg { body: vec![1] }),
        Err(SendError::NotShareEnabled)
    );

    // Before 24 h the next dial goes straight to v2.
    old.close_now.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(5), || {
        mono.advance(Duration::from_millis(400));
        old.channels.load(Ordering::SeqCst) == 2
    }));
    assert_eq!(old.hellos[3].load(Ordering::SeqCst), 1);

    // After 24 h v3 is tried again (and falls back again).
    mono.advance(Duration::from_secs(24 * 3600 + 1));
    assert_eq!(node.max_version(&id), HelloVersion::V3);
    old.close_now.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(5), || {
        mono.advance(Duration::from_millis(400));
        old.channels.load(Ordering::SeqCst) == 3
    }));
    assert_eq!(old.hellos[3].load(Ordering::SeqCst), 2);
    node.stop();
}

#[test]
fn a_v1_only_peer_falls_back_v3_v2_v1() {
    let own = DeviceKey::from_private([35; 32]);
    let old = old_peer(36, *own.public(), HelloVersion::V1);
    let mono = Arc::new(FakeMonoClock::new());
    let (node, events) = node_with_pin(35, pin_of(&old), mono);
    let id = old.key.id();
    assert!(wait_for(Duration::from_secs(5), || old
        .channels
        .load(Ordering::SeqCst)
        == 1));
    for v in 1..=3 {
        assert_eq!(old.hellos[v].load(Ordering::SeqCst), 1, "v{v}");
    }
    assert!(events.events().contains(&NetEvent::PeerNoShare(id)));
    assert!(events.events().contains(&NetEvent::PeerLegacy(id)));
    assert!(node.is_legacy(&id));
    assert_eq!(node.max_version(&id), HelloVersion::V1);
    node.stop();
}

#[test]
fn a_restart_forgets_the_lowered_maximum() {
    let own = DeviceKey::from_private([37; 32]);
    let old = old_peer(38, *own.public(), HelloVersion::V2);
    let (node, _) = node_with_pin(37, pin_of(&old), Arc::new(FakeMonoClock::new()));
    assert!(wait_for(Duration::from_secs(5), || old
        .channels
        .load(Ordering::SeqCst)
        == 1));
    node.stop();
    let (node, _) = node_with_pin(37, pin_of(&old), Arc::new(FakeMonoClock::new()));
    assert_eq!(node.max_version(&old.key.id()), HelloVersion::V3);
    assert!(wait_for(Duration::from_secs(5), || old
        .channels
        .load(Ordering::SeqCst)
        == 2));
    assert_eq!(old.hellos[3].load(Ordering::SeqCst), 2, "v3 tried again");
    node.stop();
}

#[test]
fn a_005_responder_accepts_v1_v2_and_v3_hellos() {
    let b = start(39, "Phone", Options::default());
    let old = DeviceKey::from_private([40; 32]);
    let mut pins = b.store.pins();
    pins.push(PeerPin {
        public: *old.public(),
        name: DeviceName::parse("Old").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    });
    b.node.stop();
    let b = start(
        39,
        "Phone",
        Options {
            store: Some(Arc::new(MemoryPeerStore::with(pins))),
            ..Options::default()
        },
    );
    let sink = Arc::new(Sink::default());
    b.node.set_sync_sink(sink.clone());
    let b_public = *DeviceKey::from_private([39; 32]).public();
    for version in [HelloVersion::V1, HelloVersion::V2, HelloVersion::V3] {
        let stream = TcpStream::connect(b.addr()).unwrap();
        let mut dialer = ChannelDialer::start_version(
            &old,
            b_public,
            DeviceName::parse("Old").unwrap(),
            version,
        )
        .unwrap();
        let mut opened = None;
        for _ in 0..2 {
            for frame in dialer.outgoing() {
                write_frame(&stream, &frame).unwrap();
            }
            let body = read_frame(&stream, Duration::from_secs(2)).unwrap();
            if let Some(channel) = dialer.on_frame(&body).unwrap() {
                opened = Some(channel);
            }
        }
        let channel = opened.expect("accepted");
        assert_eq!(channel.version(), version);
        assert!(wait_for(Duration::from_secs(2), || b
            .node
            .channel_version(&old.id())
            == Some(version)));
        drop(stream);
        assert!(wait_for(Duration::from_secs(3), || b.node.channel_count() == 0));
    }
    assert!(
        sink.events()
            .iter()
            .any(|e| matches!(e, SinkEvent::Version(_, _, HelloVersion::V1))),
        "channel_version also reports v1 channels"
    );
    b.node.stop();
}
