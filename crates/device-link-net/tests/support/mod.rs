//! Loopback nodes for the adapter tests (testkit address policy, fake loopback interface).
#![allow(dead_code)]

use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use device_link::identity::{DeviceId, DeviceKey};
use device_link::link::Timing;
use device_link::name::DeviceName;
use device_link::policy::AddressPolicy;
use device_link::registry::PeerRegistry;
use device_link::testkit::MemoryPeerStore;
use device_link_net::interfaces::FakeInterfaces;
use device_link_net::{NetEvent, Node, NodeConfig, RecordingSink, StdMonoClock, SystemWallClock};

/// A port free for both TCP and UDP and not handed out before in this process, taken from
/// below the kernel's ephemeral range so outgoing connections never grab it.
pub fn free_port() -> u16 {
    static NEXT: Mutex<u16> = Mutex::new(0);
    let mut next = NEXT.lock().unwrap();
    if *next == 0 {
        *next = 15_000 + (std::process::id() % 1_700) as u16 * 10;
    }
    loop {
        let port = *next;
        *next = if *next >= 32_000 { 15_000 } else { *next + 1 };
        if TcpListener::bind(("0.0.0.0", port)).is_ok()
            && UdpSocket::bind(("0.0.0.0", port)).is_ok()
        {
            return port;
        }
    }
}

pub fn fast_timing() -> Timing {
    Timing {
        announce: Duration::from_millis(300),
        nearby_expiry: Duration::from_millis(900),
        step_timeout: Duration::from_millis(1500),
        keepalive: Duration::from_millis(600),
        idle_close: Duration::from_millis(1500),
        dial_backoff_min: Duration::from_millis(200),
        dial_backoff_max: Duration::from_millis(800),
        rescan: Duration::from_millis(300),
    }
}

pub struct TestNode {
    pub node: Node,
    pub id: DeviceId,
    pub peer_port: u16,
    pub discovery_port: u16,
    pub store: Arc<MemoryPeerStore>,
    pub events: Arc<RecordingSink>,
    pub interfaces: Arc<FakeInterfaces>,
}

pub struct Options {
    pub policy: AddressPolicy,
    pub timing: Timing,
    pub announce_ports: Vec<u16>,
    pub store: Option<Arc<MemoryPeerStore>>,
    pub peer_port: Option<u16>,
    pub discovery_port: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: AddressPolicy::testkit(),
            timing: fast_timing(),
            announce_ports: Vec::new(),
            store: None,
            peer_port: None,
            discovery_port: None,
        }
    }
}

pub fn start(seed: u8, name: &str, options: Options) -> TestNode {
    let key = DeviceKey::from_private([seed; 32]);
    let id = key.id();
    let store = options
        .store
        .unwrap_or_else(|| Arc::new(MemoryPeerStore::new()));
    let registry = PeerRegistry::load(*key.public(), store.clone()).unwrap();
    let peer_port = options.peer_port.unwrap_or_else(free_port);
    let discovery_port = options.discovery_port.unwrap_or_else(free_port);
    let events = Arc::new(RecordingSink::default());
    let interfaces = Arc::new(FakeInterfaces::loopback());
    let node = Node::start(
        NodeConfig {
            key,
            name: DeviceName::parse(name).unwrap(),
            peer_port,
            discovery_port,
            announce_ports: options.announce_ports,
            policy: options.policy,
            interfaces: interfaces.clone(),
            timing: options.timing,
        },
        registry,
        Arc::new(StdMonoClock::new()),
        Arc::new(SystemWallClock),
        events.clone(),
    )
    .unwrap();
    TestNode {
        node,
        id,
        peer_port,
        discovery_port,
        store,
        events,
        interfaces,
    }
}

impl TestNode {
    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new([127, 0, 0, 1].into(), self.peer_port)
    }

    pub fn has_event(&self, wanted: &NetEvent) -> bool {
        self.events.events().contains(wanted)
    }
}

/// Polls `check` every 20 ms for up to `limit`.
pub fn wait_for(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    check()
}

/// Pairs `a` (shows the code) and `b` (joins) over loopback and waits for both pins.
pub fn pair(a: &TestNode, b: &TestNode) {
    a.node.start_pairing().unwrap();
    let code = a.node.snapshot().pairing.unwrap().code.unwrap();
    b.node.join(a.addr(), &code, Some(a.id)).unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || a
            .node
            .snapshot()
            .pairing
            .is_some_and(|p| p.state == "awaiting_acceptance")),
        "A never awaited acceptance: {:?}",
        a.node.snapshot().pairing.map(|p| (p.state, p.reason))
    );
    a.node.accept(&b.id).unwrap();
    assert!(wait_for(Duration::from_secs(5), || b
        .node
        .snapshot()
        .join
        .is_some_and(|j| j.state == "paired")));
    assert!(a.node.snapshot().paired.iter().any(|p| p.id == b.id));
    assert!(b.node.snapshot().paired.iter().any(|p| p.id == a.id));
}
