//! Shared helpers of the host-runtime integration tests.
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use device_link::identity::DeviceKey;
use device_link::link::Timing;
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::testkit::MemoryPeerStore;
use device_link_net::interfaces::FakeInterfaces;
use host_runtime::config::NetworkSettings;
use host_runtime::net_runtime::{IdentityError, IdentityStore, NetDeps};

/// A temporary directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use rand_core::RngCore;
        let mut bytes = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("host-runtime-{tag}-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o700);
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A port no other test in this process has been given (below the ephemeral range).
pub fn free_port() -> u16 {
    static NEXT: Mutex<u16> = Mutex::new(0);
    let mut next = NEXT.lock().unwrap();
    if *next == 0 {
        *next = 15_000 + (std::process::id() % 1_700) as u16 * 10;
    }
    loop {
        let port = *next;
        *next = if *next >= 32_000 { 15_000 } else { *next + 1 };
        if TcpListener::bind(("127.0.0.1", port)).is_ok()
            && TcpListener::bind(("0.0.0.0", port)).is_ok()
            && std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
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

pub fn fast_sync_timing() -> wallet_sync::sched::SyncTiming {
    wallet_sync::sched::SyncTiming {
        quiet: Duration::from_millis(150),
        safety: Duration::from_secs(3600),
        backoff_min: Duration::from_millis(300),
        backoff_max: Duration::from_secs(2),
        round_timeout: Duration::from_secs(3),
    }
}

pub fn loopback_deps() -> NetDeps {
    NetDeps {
        policy: AddressPolicy::testkit(),
        interfaces: Some(Arc::new(FakeInterfaces::loopback())),
        timing: fast_timing(),
        announce_ports: Vec::new(),
        sync: fast_sync_timing(),
    }
}

pub fn net_on() -> NetworkSettings {
    NetworkSettings {
        enabled: true,
        peer_port: free_port(),
        discovery_port: free_port(),
        ..NetworkSettings::default()
    }
}

/// In-memory identity: a fixed key and a shared memory peer store.
pub struct MemoryIdentity {
    pub key: Option<[u8; 32]>,
    pub peers_ok: bool,
    pub store: Arc<MemoryPeerStore>,
}

impl MemoryIdentity {
    pub fn new(seed: u8) -> Self {
        Self {
            key: Some([seed; 32]),
            peers_ok: true,
            store: Arc::new(MemoryPeerStore::new()),
        }
    }
}

impl IdentityStore for MemoryIdentity {
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError> {
        self.key
            .map(DeviceKey::from_private)
            .ok_or(IdentityError::Unusable)
    }

    fn peer_store(&self, _own_public: [u8; 32], _policy: AddressPolicy) -> Arc<dyn PeerStore> {
        if self.peers_ok {
            Arc::clone(&self.store) as Arc<dyn PeerStore>
        } else {
            Arc::new(BrokenStore)
        }
    }
}

struct BrokenStore;

impl PeerStore for BrokenStore {
    fn load(&self) -> Result<Vec<device_link::registry::PeerPin>, device_link::error::Error> {
        Err(device_link::error::Error::Storage)
    }
    fn save(&self, _: &[device_link::registry::PeerPin]) -> Result<(), device_link::error::Error> {
        Err(device_link::error::Error::Storage)
    }
}

pub fn wait_for(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    check()
}

/// Number of socket descriptors of this process (Linux `/proc/self/fd`).
pub fn socket_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|t| t.to_string_lossy().starts_with("socket:"))
        .count()
}
