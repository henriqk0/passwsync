//! 004 T032: channel v2 over loopback: sync frame delivery, `send_sync`, and the dialer's
//! v2 -> v1 fallback for peers that only speak channel v1 (contracts/sync-protocol.md).

mod support;

use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use device_link::channel::{ChannelDialer, ChannelResponder};
use device_link::identity::{DeviceId, DeviceKey};
use device_link::name::DeviceName;
use device_link::registry::{PeerPin, PeerRegistry};
use device_link::testkit::{FakeMonoClock, MemoryPeerStore};
use device_link::wire::{HelloKind, HelloVersion, Payload, parse_hello_versioned};
use device_link_net::framed::{FrameError, read_frame, write_frame};
use device_link_net::interfaces::FakeInterfaces;
use device_link_net::{
    NetEvent, Node, NodeConfig, RecordingSink, SendError, SyncFrameSink, SystemWallClock,
};
use support::{Options, fast_timing, free_port, pair, start, wait_for};

#[derive(Clone, Debug, PartialEq, Eq)]
enum SinkEvent {
    Up(DeviceId, u64, [u8; 32], bool),
    Frame(DeviceId, u64, Payload),
    Down(DeviceId, u64),
}

#[derive(Default)]
struct RecordingSyncSink(Mutex<Vec<SinkEvent>>);

impl RecordingSyncSink {
    fn events(&self) -> Vec<SinkEvent> {
        self.0.lock().unwrap().clone()
    }

    fn up(&self) -> Option<(DeviceId, u64, [u8; 32], bool)> {
        self.events().into_iter().find_map(|e| match e {
            SinkEvent::Up(p, c, s, d) => Some((p, c, s, d)),
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

impl SyncFrameSink for RecordingSyncSink {
    fn channel_up(&self, peer: DeviceId, conn: u64, session: [u8; 32], dialer: bool) {
        self.0
            .lock()
            .unwrap()
            .push(SinkEvent::Up(peer, conn, session, dialer));
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
}

fn ctl(byte: u8, more: bool) -> Payload {
    Payload::SyncCtl {
        more,
        fragment: vec![byte; 10],
    }
}

#[test]
fn paired_nodes_open_a_sync_channel_and_deliver_frames() {
    let a = start(1, "Laptop", Options::default());
    let b = start(2, "Phone", Options::default());
    let (sa, sb) = (
        Arc::new(RecordingSyncSink::default()),
        Arc::new(RecordingSyncSink::default()),
    );
    a.node.set_sync_sink(sa.clone());
    b.node.set_sync_sink(sb.clone());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || sa.up().is_some()
        && sb.up().is_some()));
    let (peer_b, conn_a, session_a, dialer_a) = sa.up().unwrap();
    let (peer_a, conn_b, session_b, dialer_b) = sb.up().unwrap();
    assert_eq!((peer_b, peer_a), (b.id, a.id));
    assert_eq!(session_a, session_b, "same Noise handshake hash");
    assert_ne!(dialer_a, dialer_b, "exactly one side dialed");

    a.node.send_sync(&b.id, conn_a, &ctl(1, true)).unwrap();
    a.node
        .send_sync(
            &b.id,
            conn_a,
            &Payload::CopyData {
                bytes: vec![2; 1000],
            },
        )
        .unwrap();
    assert!(wait_for(Duration::from_secs(3), || sb.frames().len() == 2));
    assert_eq!(sb.frames()[0], ctl(1, true));
    // A wrong connection number or a non-sync payload is refused.
    assert_eq!(
        a.node.send_sync(&b.id, conn_a + 100, &ctl(1, false)),
        Err(SendError::NotConnected)
    );
    assert_eq!(
        a.node.send_sync(&b.id, conn_a, &Payload::Keepalive),
        Err(SendError::Protocol)
    );
    // Both stop: each side reports the channel down.
    b.node.stop();
    assert!(wait_for(Duration::from_secs(5), || sa
        .events()
        .contains(&SinkEvent::Down(b.id, conn_a))));
    a.node.stop();
    assert!(
        sb.events().contains(&SinkEvent::Down(a.id, conn_b)),
        "{:?}",
        sb.events()
    );
}

#[test]
fn concurrent_senders_keep_nonce_order_equal_to_write_order() {
    let a = start(3, "Laptop", Options::default());
    let b = start(4, "Phone", Options::default());
    let (sa, sb) = (
        Arc::new(RecordingSyncSink::default()),
        Arc::new(RecordingSyncSink::default()),
    );
    a.node.set_sync_sink(sa.clone());
    b.node.set_sync_sink(sb.clone());
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(5), || sa.up().is_some()));
    let (_, conn, _, _) = sa.up().unwrap();
    let node = Arc::new(a.node);
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let node = Arc::clone(&node);
            let peer = b.id;
            thread::spawn(move || {
                for _ in 0..100 {
                    node.send_sync(&peer, conn, &ctl(t, false)).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(
        wait_for(Duration::from_secs(5), || sb.frames().len() == 400),
        "all frames arrived on one intact channel: {}",
        sb.frames().len()
    );
    assert_eq!(b.node.channel_count(), 1);
    b.node.stop();
}

/// A device on the 003 build: closes on Hello v2, completes a v1 channel handshake.
struct LegacyPeer {
    key: DeviceKey,
    addr: SocketAddrV4,
    v2_attempts: Arc<AtomicUsize>,
    v1_channels: Arc<AtomicUsize>,
    close_now: Arc<AtomicBool>,
}

fn legacy_peer(seed: u8, pinned: [u8; 32]) -> LegacyPeer {
    let key = DeviceKey::from_private([seed; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let v2_attempts = Arc::new(AtomicUsize::new(0));
    let v1_channels = Arc::new(AtomicUsize::new(0));
    let close_now = Arc::new(AtomicBool::new(false));
    let (v2, v1, close) = (
        Arc::clone(&v2_attempts),
        Arc::clone(&v1_channels),
        Arc::clone(&close_now),
    );
    let responder_key = key.duplicate();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve_legacy(&responder_key, stream, pinned, &v2, &v1, &close);
        }
    });
    LegacyPeer {
        key,
        addr: SocketAddrV4::new([127, 0, 0, 1].into(), port),
        v2_attempts,
        v1_channels,
        close_now,
    }
}

fn serve_legacy(
    key: &DeviceKey,
    stream: TcpStream,
    pinned: [u8; 32],
    v2: &AtomicUsize,
    v1: &AtomicUsize,
    close: &AtomicBool,
) {
    let step = Duration::from_secs(2);
    let Ok(hello) = read_frame(&stream, step) else {
        return;
    };
    match parse_hello_versioned(&hello) {
        Ok((HelloKind::Channel, HelloVersion::V1)) => {}
        _ => {
            // 003 parse_hello rejects anything but version 1: close at once.
            v2.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }
    let mut responder = ChannelResponder::new(key, DeviceName::parse("Old").unwrap(), &hello);
    let is_pinned = move |k: &[u8; 32]| *k == pinned;
    for _ in 0..2 {
        let Ok(body) = read_frame(&stream, step) else {
            return;
        };
        let result = responder.on_frame(&body, &is_pinned);
        for frame in responder.outgoing() {
            let _ = write_frame(&stream, &frame);
        }
        if let Ok(Some(_channel)) = result {
            v1.fetch_add(1, Ordering::SeqCst);
            close.store(false, Ordering::SeqCst);
            loop {
                if close.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                match read_frame(&stream, Duration::from_millis(50)) {
                    Ok(_) | Err(FrameError::Timeout) => {}
                    Err(_) => return,
                }
            }
        }
    }
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

#[test]
fn a_v1_only_peer_is_marked_legacy_and_redialed_with_v1_then_v2_after_24_hours() {
    let own = DeviceKey::from_private([7; 32]);
    let legacy = legacy_peer(8, *own.public());
    let mono = Arc::new(FakeMonoClock::new());
    let pin = PeerPin {
        public: *legacy.key.public(),
        name: DeviceName::parse("Old").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: Some(legacy.addr),
    };
    let (node, events) = node_with_pin(7, pin, mono.clone());
    let sink = Arc::new(RecordingSyncSink::default());
    node.set_sync_sink(sink.clone());
    let legacy_id = legacy.key.id();

    assert!(
        wait_for(Duration::from_secs(5), || legacy
            .v1_channels
            .load(Ordering::SeqCst)
            == 1),
        "redialed with v1 at once"
    );
    // 005: the dialer starts at v3, so the refused non-v1 Hellos are v3 then v2.
    assert_eq!(legacy.v2_attempts.load(Ordering::SeqCst), 2);
    assert!(events.events().contains(&NetEvent::PeerLegacy(legacy_id)));
    assert!(node.is_legacy(&legacy_id));
    assert!(wait_for(Duration::from_secs(2), || node.channel_count() == 1));
    assert!(sink.up().is_none(), "no sync on a v1 channel");
    let conn = 1;
    assert_eq!(
        node.send_sync(&legacy_id, conn, &ctl(1, false)),
        Err(SendError::NotSyncEnabled)
    );

    // Before 24 h the next dial goes straight to v1. (The node's timers run on the fake
    // clock, so it is moved forward a little while waiting.)
    legacy.close_now.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(5), || {
        mono.advance(Duration::from_millis(400));
        legacy.v1_channels.load(Ordering::SeqCst) == 2
    }));
    assert_eq!(legacy.v2_attempts.load(Ordering::SeqCst), 2);

    // After 24 h v2 is tried again (and falls back again).
    mono.advance(Duration::from_secs(24 * 3600 + 1));
    legacy.close_now.store(true, Ordering::SeqCst);
    assert!(wait_for(Duration::from_secs(5), || {
        mono.advance(Duration::from_millis(400));
        legacy.v1_channels.load(Ordering::SeqCst) == 3
    }));
    assert_eq!(legacy.v2_attempts.load(Ordering::SeqCst), 4);
    node.stop();
}

#[test]
fn a_v2_node_accepts_a_v1_dialer_without_sync() {
    let b = start(9, "Phone", Options::default());
    let sink = Arc::new(RecordingSyncSink::default());
    b.node.set_sync_sink(sink.clone());
    // Pin an old device's key on B.
    let old = DeviceKey::from_private([10; 32]);
    let mut pins = b.store.pins();
    pins.push(PeerPin {
        public: *old.public(),
        name: DeviceName::parse("Old").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    });
    b.node.stop();
    let store = Arc::new(MemoryPeerStore::with(pins));
    let b = start(
        9,
        "Phone",
        Options {
            store: Some(store),
            ..Options::default()
        },
    );
    b.node.set_sync_sink(sink.clone());
    let stream = TcpStream::connect(b.addr()).unwrap();
    let mut dialer = ChannelDialer::start(
        &old,
        *DeviceKey::from_private([9; 32]).public(),
        DeviceName::parse("Old").unwrap(),
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
    let channel = opened.expect("v1 channel accepted by a v2 node");
    assert!(!channel.sync_enabled());
    assert!(wait_for(Duration::from_secs(2), || b.node.channel_count() == 1));
    assert!(sink.up().is_none());
    b.node.stop();
}
