#![allow(dead_code)]
//! Shared helpers of the passwsync-ffi integration tests.

use std::path::{Path, PathBuf};

/// A private (0700) temporary directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use rand_core::RngCore;
        let mut bytes = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("passwsync-ffi-{tag}-{name}"));
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

pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// --- 007 US1/US2: a core over fakes ---------------------------------------------------------

use std::sync::Arc;
use std::time::Duration;

use host_runtime::net_runtime::NetDeps;
use passwsync_ffi::api::{Deps, Instance, PasswsyncCore};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CoreConfig, CredentialInput};
use passwsync_ffi::testkit::{
    FakeClipboard, FakeProcess, FakeSealer, RecordingLog, RecordingNotifier,
};
use vault_core::KdfConfig;
use wallet_service::testkit::FakeElapsedClock;

pub const PASSWORD: &str = "correct horse battery staple";
pub const OTHER_PASSWORD: &str = "another long master password";

/// Every fake a core is started with; shared across restarts over the same directory.
pub struct Fakes {
    pub sealer: Arc<FakeSealer>,
    pub clipboard: Arc<FakeClipboard>,
    pub log: Arc<RecordingLog>,
    pub notifier: Arc<RecordingNotifier>,
    pub clock: Arc<FakeElapsedClock>,
    pub process: Arc<FakeProcess>,
    pub instance: Arc<Instance>,
    pub sweep_period: Duration,
    pub net: NetDeps,
    pub eligible: Vec<String>,
    pub linger: Duration,
    pub window_limit: Duration,
}

impl Fakes {
    pub fn new() -> Self {
        Self::with_process(FakeProcess::new())
    }

    pub fn with_process(process: FakeProcess) -> Self {
        Self {
            sealer: Arc::new(FakeSealer::new()),
            clipboard: Arc::new(FakeClipboard::new()),
            log: Arc::new(RecordingLog::new()),
            notifier: Arc::new(RecordingNotifier::new()),
            clock: Arc::new(FakeElapsedClock::new()),
            process: Arc::new(process),
            instance: Arc::new(Instance::new()),
            // Long enough that only the explicit calls of a test sweep, unless it asks.
            sweep_period: Duration::from_secs(3600),
            net: NetDeps::production(),
            eligible: Vec::new(),
            linger: Duration::from_secs(10),
            window_limit: Duration::from_secs(120),
        }
    }

    pub fn deps(&self) -> Deps {
        Deps {
            process: self.process.clone(),
            elapsed: self.clock.clone(),
            wallet_kdf: KdfConfig::MINIMUM,
            net: self.net.clone(),
            instance: Arc::clone(&self.instance),
            sweep_period: self.sweep_period,
            linger: self.linger,
            window_limit: self.window_limit,
            ..Deps::production()
        }
    }

    pub fn start(&self, dir: &Path) -> Result<Arc<PasswsyncCore>, CoreError> {
        PasswsyncCore::start_with(
            CoreConfig {
                data_dir: dir.to_string_lossy().into_owned(),
                eligible_interfaces: self.eligible.clone(),
            },
            self.sealer.clone(),
            self.clipboard.clone(),
            self.log.clone(),
            self.notifier.clone(),
            self.deps(),
        )
    }
}

pub fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

/// A started core with one unlocked wallet `name`.
pub fn core_with_wallet(dir: &Path, fakes: &Fakes, name: &str) -> Arc<PasswsyncCore> {
    let core = fakes.start(dir).unwrap();
    core.create_wallet(name.into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    core
}

pub fn input(title: &str, username: &str, password: Option<&str>) -> CredentialInput {
    CredentialInput {
        title: title.into(),
        username: username.into(),
        url: format!("https://{}.example", title.to_lowercase().replace(' ', "-")),
        notes: format!("notes of {title}"),
        password: password.map(bytes),
    }
}

/// Every file and directory under `root` with its mode, relative and sorted.
pub fn tree(root: &Path) -> Vec<(String, bool, u32)> {
    let mut out = Vec::new();
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, bool, u32)>) {
        let Ok(items) = std::fs::read_dir(at) else {
            return;
        };
        for item in items.flatten() {
            let path = item.path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            out.push((rel, meta.is_dir(), mode(&path)));
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}

// --- 007 US4-US6: networked cores over loopback ---------------------------------------------

use device_link::link::Timing;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::FakeInterfaces;

/// A port no other test in this process has been given (below the ephemeral range).
pub fn free_port() -> u16 {
    use std::net::{TcpListener, UdpSocket};
    use std::sync::Mutex;
    static NEXT: Mutex<u16> = Mutex::new(0);
    let mut next = NEXT.lock().unwrap();
    if *next == 0 {
        *next = 33_000 + (std::process::id() % 1_500) as u16 * 10;
    }
    loop {
        let port = *next;
        *next = if *next >= 49_000 { 33_000 } else { *next + 1 };
        if TcpListener::bind(("127.0.0.1", port)).is_ok()
            && TcpListener::bind(("0.0.0.0", port)).is_ok()
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

pub fn fast_sync_timing() -> wallet_sync::sched::SyncTiming {
    wallet_sync::sched::SyncTiming {
        quiet: Duration::from_millis(150),
        safety: Duration::from_secs(3600),
        backoff_min: Duration::from_millis(300),
        backoff_max: Duration::from_secs(2),
        round_timeout: Duration::from_secs(3),
    }
}

/// Loopback networking (`AddressPolicy::testkit`), announcing to `announce` discovery ports.
pub fn loopback_net(announce: Vec<u16>) -> NetDeps {
    NetDeps {
        policy: AddressPolicy::testkit(),
        interfaces: Some(Arc::new(FakeInterfaces::loopback())),
        timing: fast_timing(),
        announce_ports: announce,
        sync: fast_sync_timing(),
    }
}

/// Writes a settings file with networking `on` and the given ports (0600).
pub fn write_network_settings(dir: &Path, name: &str, peer: u16, discovery: u16) {
    let path = dir.join("settings");
    std::fs::write(
        &path,
        format!(
            "network = on\npeer_port = {peer}\ndiscovery_port = {discovery}\ndevice_name = \"{name}\"\n"
        ),
    )
    .unwrap();
    set_mode(&path, 0o600);
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

/// Serializes the tests of one binary that count sockets.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One networked core: its directory, fakes and ports.
pub struct Node {
    pub dir: TempDir,
    pub fakes: Fakes,
    pub peer_port: u16,
    pub discovery_port: u16,
    pub core: Option<Arc<PasswsyncCore>>,
}

impl Node {
    /// Networking on over loopback, announcing to `announce`; not started yet.
    pub fn new(tag: &str, name: &str, announce: Vec<u16>) -> Self {
        let dir = TempDir::new(tag);
        let mut fakes = Fakes::new();
        fakes.net = loopback_net(announce);
        fakes.eligible = vec!["lo".into()];
        fakes.linger = Duration::from_millis(300);
        let (peer_port, discovery_port) = (free_port(), free_port());
        write_network_settings(dir.path(), name, peer_port, discovery_port);
        Self {
            dir,
            fakes,
            peer_port,
            discovery_port,
            core: None,
        }
    }

    pub fn start(&mut self) -> Arc<PasswsyncCore> {
        let core = self.fakes.start(self.dir.path()).unwrap();
        self.core = Some(Arc::clone(&core));
        core
    }

    pub fn core(&self) -> &Arc<PasswsyncCore> {
        self.core.as_ref().expect("started")
    }

    pub fn id(&self) -> String {
        self.core().network().this_device.unwrap().id
    }
}

/// Two started, foreground cores announcing to each other.
pub fn two_nodes(tag: &str) -> (Node, Node) {
    let (pa, pb) = (free_port(), free_port());
    let mut a = Node::new(&format!("{tag}-a"), "Phone-A", vec![pb]);
    a.discovery_port = pa;
    write_network_settings(a.dir.path(), "Phone-A", a.peer_port, pa);
    let mut b = Node::new(&format!("{tag}-b"), "Phone-B", vec![pa]);
    b.discovery_port = pb;
    write_network_settings(b.dir.path(), "Phone-B", b.peer_port, pb);
    a.start().on_foreground();
    b.start().on_foreground();
    (a, b)
}

/// `a` shows a code, `b` joins with it, `a` accepts; waits until both see the other paired.
pub fn pair(a: &Node, b: &Node) {
    let a_id = a.id();
    let b_id = b.id();
    // 003: a device announces itself only while it shows a code.
    let view = a.core().start_pairing().unwrap();
    let code = view.code.expect("initiator shows the code");
    assert!(
        wait_for(Duration::from_secs(10), || b
            .core()
            .network()
            .nearby
            .iter()
            .any(|n| n.device.id == a_id)),
        "b hears a"
    );
    b.core().join_pairing(a_id.clone(), bytes(&code)).unwrap();
    assert!(
        wait_for(Duration::from_secs(10), || a.core().pairing().state
            == passwsync_ffi::records::PairingState::Confirming),
        "a awaits acceptance: {:?}",
        a.core().pairing()
    );
    a.core().accept_pairing(b_id.clone()).unwrap();
    assert!(
        wait_for(Duration::from_secs(10), || {
            a.core()
                .network()
                .paired
                .iter()
                .any(|p| p.device.id == b_id)
                && b.core()
                    .network()
                    .paired
                    .iter()
                    .any(|p| p.device.id == a_id)
        }),
        "both pinned"
    );
}

/// Both see the other connected.
pub fn connected(a: &Node, b: &Node) -> bool {
    let (a_id, b_id) = (a.id(), b.id());
    a.core()
        .network()
        .paired
        .iter()
        .any(|p| p.device.id == b_id && p.status == "connected")
        && b.core()
            .network()
            .paired
            .iter()
            .any(|p| p.device.id == a_id && p.status == "connected")
}

// --- a plain desktop HostCore, wired as passwsyncd wires it ---------------------------------

use device_link::identity::DeviceKey;
use device_link::ports::PeerStore;
use device_link::testkit::MemoryPeerStore;
use host_runtime::config::Settings;
use host_runtime::log::Log;
use host_runtime::net_runtime::{IdentityError, IdentityStore};
use host_runtime::wiring::{HostCore, HostDirs};
use wallet_service::ServiceConfig;

/// In-memory desktop identity: a fixed key and a memory pin store.
pub struct MemoryIdentity {
    pub key: [u8; 32],
    pub store: Arc<MemoryPeerStore>,
}

impl IdentityStore for MemoryIdentity {
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError> {
        Ok(DeviceKey::from_private(self.key))
    }

    fn peer_store(&self, _own: [u8; 32], _policy: AddressPolicy) -> Arc<dyn PeerStore> {
        Arc::clone(&self.store) as Arc<dyn PeerStore>
    }
}

/// A desktop host (passwsyncd steps 5a-5e through `HostCore::assemble`).
pub struct Desktop {
    pub dir: TempDir,
    pub host: HostCore,
    pub log: Log,
    pub buffer: Arc<std::sync::Mutex<Vec<u8>>>,
    pub peer_port: u16,
    pub discovery_port: u16,
}

impl Desktop {
    pub fn start(tag: &str, seed: u8, discovery_port: u16, announce: Vec<u16>) -> Self {
        let dir = TempDir::new(tag);
        for sub in ["wallets", "sync", "received"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
            set_mode(&dir.path().join(sub), 0o700);
        }
        let mut settings = Settings::default();
        settings.network.enabled = true;
        settings.network.peer_port = free_port();
        settings.network.discovery_port = discovery_port;
        let (log, buffer) = Log::to_buffer();
        let identity = MemoryIdentity {
            key: [seed; 32],
            store: Arc::new(MemoryPeerStore::new()),
        };
        let host = HostCore::assemble(
            &HostDirs {
                wallets: dir.path().join("wallets"),
                sync: dir.path().join("sync"),
                received: dir.path().join("received"),
            },
            &settings,
            &identity,
            loopback_net(announce),
            ServiceConfig {
                device: host_runtime::files::load_or_create_device_id(
                    &dir.path().join("device-id"),
                )
                .unwrap(),
                wallet_kdf: KdfConfig::MINIMUM,
                auto_lock: Duration::from_secs(600),
            },
            Arc::new(FakeElapsedClock::new()),
            &log,
        );
        Self {
            dir,
            host,
            log,
            buffer,
            peer_port: settings.network.peer_port,
            discovery_port,
        }
    }

    pub fn id(&self) -> String {
        self.host.net.this_device.as_ref().unwrap().id.to_hex()
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        self.host.sync.stop();
        self.host.share.shutdown();
        self.host.net.stop();
    }
}

// --- US5/US6: wallets on two nodes ------------------------------------------------------------

/// Titles of every credential of `wallet` (sorted).
pub fn titles(core: &PasswsyncCore, wallet: &str) -> Vec<String> {
    let mut out: Vec<String> = core
        .search(wallet.into(), String::new())
        .map(|found| found.into_iter().map(|c| c.title).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// Copies `wallet`'s file from `from` to `to` (as a person would by hand, 004 tests).
pub fn copy_wallet(from: &Node, to: &Node, wallet: &str) {
    let name = format!("wallets/{wallet}.pwsw");
    let bytes = std::fs::read(from.dir.path().join(&name)).unwrap();
    let dest = to.dir.path().join(&name);
    std::fs::write(&dest, bytes).unwrap();
    set_mode(&dest, 0o600);
}

/// Two paired, connected foreground nodes sharing one unlocked wallet `wallet`.
pub fn synced_pair(tag: &str, wallet: &str) -> (Node, Node) {
    let (a, b) = two_nodes(tag);
    pair(&a, &b);
    assert!(
        wait_for(Duration::from_secs(8), || connected(&a, &b)),
        "channel up"
    );
    a.core()
        .create_wallet(wallet.into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    a.core()
        .add_credential(wallet.into(), input("First", "user-1", Some("pw-1")))
        .unwrap();
    copy_wallet(&a, &b, wallet);
    b.core()
        .unlock_wallet(wallet.into(), bytes(PASSWORD))
        .unwrap();
    assert_eq!(titles(b.core(), wallet), ["First"]);
    (a, b)
}

/// Leaves the foreground and waits until the node is paused (linger of the test fakes).
pub fn background(node: &Node) {
    node.core().on_background();
    assert!(
        wait_for(Duration::from_secs(5), || !node.core().multicast_wanted()),
        "node paused"
    );
}
