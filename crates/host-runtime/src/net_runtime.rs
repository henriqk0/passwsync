//! Device networking inside the service (003): identity, status, and (when enabled) the
//! `device-link-net` node. Problems here never stop the service; they set a status shown in
//! the UI (contracts/host-runtime-network.md "Start-up sequence").

use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use device_link::identity::{DeviceId, DeviceKey, Fingerprint};
use device_link::link::Timing;
use device_link::name::{DeviceName, InterfaceName};
use device_link::pairing::{AcceptError, PeerInfo};
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::registry::PeerRegistry;
use device_link::wire::{HelloVersion, Payload};
use device_link_net::interfaces::{Interface, InterfaceSource, OsInterfaces};
use device_link_net::{
    ChannelOpener, Disconnect, EventSink, JoinError, NetEvent, Node, NodeConfig, PairStartError,
    Refusal, RevokeError, SendError, Snapshot, StartError, StdMonoClock, SyncFrameSink,
    SystemWallClock,
};
use wallet_sync::sched::SyncTiming;

use crate::config::NetworkSettings;
use crate::log::{DisconnectReason, DropLog, Log, LogEvent, NetUnavailable, RefuseReason};

/// Where the device identity and the pins live (desktop: plain owner-only files; Android:
/// Keystore-sealed blobs). Contract shared-runtime-extraction.md section 3.1.
pub trait IdentityStore: Send + Sync {
    /// The device key, created on first use. An existing unusable identity is never replaced.
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError>;
    /// The pin store for this device's public key.
    fn peer_store(&self, own_public: [u8; 32], policy: AddressPolicy) -> Arc<dyn PeerStore>;
}

/// The identity cannot be read or created; networking stays off with a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    Unusable,
}

/// Adapters the network side needs; tests replace them.
#[derive(Clone)]
pub struct NetDeps {
    pub policy: AddressPolicy,
    /// `None`: the OS interfaces (restricted by `network_interface`).
    pub interfaces: Option<Arc<dyn InterfaceSource>>,
    pub timing: Timing,
    /// Announcement destination ports; empty means `discovery_port`.
    pub announce_ports: Vec<u16>,
    /// 004: sync scheduler timings (the safety interval comes from the configuration).
    pub sync: SyncTiming,
}

impl NetDeps {
    pub fn production() -> Self {
        Self {
            policy: AddressPolicy::lan(),
            interfaces: None,
            timing: Timing::default(),
            announce_ports: Vec::new(),
            sync: SyncTiming::default(),
        }
    }
}

/// `status.state` of `GET /api/network`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetState {
    Off,
    IdentityUnusable,
    PeersUnusable,
    PortInUse(u16),
    NoLocalNetwork,
    On,
}

impl NetState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::IdentityUnusable => "identity_unusable",
            Self::PeersUnusable => "peers_unusable",
            Self::PortInUse(_) => "port_in_use",
            Self::NoLocalNetwork => "no_local_network",
            Self::On => "on",
        }
    }
}

/// Public facts about this installation.
#[derive(Clone, Debug)]
pub struct ThisDevice {
    pub id: DeviceId,
    pub fingerprint: Fingerprint,
    pub name: DeviceName,
}

/// Maps node events to the closed log set.
struct LogSink(Log);

impl EventSink for LogSink {
    fn emit(&self, event: NetEvent) {
        let log = &self.0;
        match event {
            NetEvent::PairingSucceeded(id) => log.emit(&LogEvent::PairingSucceeded {
                fingerprint: &id.fingerprint(),
            }),
            NetEvent::PairingFailed(reason) => log.emit(&LogEvent::PairingFailed(reason)),
            NetEvent::PeerConnected(id) => log.emit(&LogEvent::PeerConnected {
                fingerprint: &id.fingerprint(),
            }),
            NetEvent::PeerDisconnected(id, why) => log.emit(&LogEvent::PeerDisconnected {
                fingerprint: &id.fingerprint(),
                why: match why {
                    Disconnect::Timeout => DisconnectReason::Timeout,
                    Disconnect::Closed => DisconnectReason::Closed,
                    Disconnect::Error => DisconnectReason::Error,
                    Disconnect::Duplicate => DisconnectReason::Duplicate,
                },
            }),
            NetEvent::PeerRefused(id, why) => log.emit(&LogEvent::PeerRefused {
                fingerprint: &id.fingerprint(),
                why: match why {
                    Refusal::Unpaired => RefuseReason::Unpaired,
                    Refusal::Revoked => RefuseReason::Revoked,
                    Refusal::KeyMismatch => RefuseReason::KeyMismatch,
                },
            }),
            NetEvent::RefusedByPeer(id) => log.emit(&LogEvent::RefusedByPeer {
                fingerprint: &id.fingerprint(),
            }),
            NetEvent::InterfacesChanged(names) => {
                log.emit(&LogEvent::InterfacesChanged { interfaces: &names })
            }
            NetEvent::PeerLegacy(id) => log.emit(&LogEvent::SyncPeerLegacy {
                fingerprint: &id.fingerprint(),
            }),
            NetEvent::PeerNoShare(id) => log.emit(&LogEvent::SharePeerUnsupported {
                fingerprint: &id.fingerprint(),
            }),
        }
    }
}

/// Inputs kept to (re)start the node, e.g. once a local network appears.
struct Pending {
    key: DeviceKey,
    store: Arc<dyn PeerStore>,
}

pub struct NetRuntime {
    pub settings: NetworkSettings,
    pub this_device: Option<ThisDevice>,
    deps: NetDeps,
    log: Log,
    state: Mutex<NetState>,
    node: Mutex<Option<Node>>,
    /// Held only while networking is on but no local network exists yet (FR-007).
    pending: Mutex<Option<Pending>>,
    drop_log: DropLog,
    /// 004: where sync frames go; attached to every node this runtime starts.
    sync_sink: Mutex<Option<Arc<dyn SyncFrameSink>>>,
    /// 007: the start inputs of the running (or paused) node, so `resume` can restart it;
    /// wiped by `stop`.
    held: Mutex<Option<Pending>>,
    /// 007: `pause` was called and `resume` not yet.
    paused: Mutex<bool>,
    /// 007: interface source set by `set_interfaces` (Android eligible interfaces).
    interfaces: Mutex<Option<Arc<dyn InterfaceSource>>>,
}

impl NetRuntime {
    /// Start-up steps 5a and 5b.
    pub fn start(
        settings: NetworkSettings,
        identity: &dyn IdentityStore,
        deps: NetDeps,
        log: &Log,
    ) -> Self {
        let mut runtime = Self {
            settings,
            this_device: None,
            deps,
            log: log.clone(),
            state: Mutex::new(NetState::Off),
            node: Mutex::new(None),
            pending: Mutex::new(None),
            drop_log: DropLog::default(),
            sync_sink: Mutex::new(None),
            held: Mutex::new(None),
            paused: Mutex::new(false),
            interfaces: Mutex::new(None),
        };
        let Ok(key) = identity.load_or_create_key() else {
            runtime.set_state(NetState::IdentityUnusable);
            log.emit(&LogEvent::NetworkUnavailable(
                NetUnavailable::IdentityUnusable,
            ));
            return runtime;
        };
        let id = key.id();
        let fingerprint = id.fingerprint();
        let name = runtime
            .settings
            .device_name
            .clone()
            .unwrap_or_else(|| DeviceName::default_for(&fingerprint));
        runtime.this_device = Some(ThisDevice {
            id,
            fingerprint,
            name,
        });
        if !runtime.settings.enabled {
            // Networking off: the key is dropped (wiped) right here.
            drop(key);
            log.emit(&LogEvent::NetworkOff);
            return runtime;
        }
        let store = identity.peer_store(*key.public(), runtime.deps.policy);
        if PeerRegistry::load(*key.public(), store.clone()).is_err() {
            drop(key);
            runtime.set_state(NetState::PeersUnusable);
            log.emit(&LogEvent::NetworkUnavailable(NetUnavailable::PeersUnusable));
            return runtime;
        }
        *runtime
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Pending { key, store });
        runtime.try_start_node();
        runtime
    }

    /// Starts the node from the pending inputs; on `no_local_network` keeps them for a
    /// later attempt, on `port_in_use` gives up until restart.
    fn try_start_node(&self) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(inputs) = pending.as_ref() else {
            return;
        };
        let Ok(registry) = PeerRegistry::load(*inputs.key.public(), inputs.store.clone()) else {
            *pending = None;
            self.set_state(NetState::PeersUnusable);
            self.log
                .emit(&LogEvent::NetworkUnavailable(NetUnavailable::PeersUnusable));
            return;
        };
        let chosen = self
            .interfaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let interfaces: Arc<dyn InterfaceSource> =
            match chosen.as_ref().or(self.deps.interfaces.as_ref()) {
                Some(source) => Arc::clone(source),
                None => Arc::new(OsInterfaces::new(
                    self.deps.policy,
                    self.settings.interface.clone(),
                )),
            };
        let name = self
            .this_device
            .as_ref()
            .map(|d| d.name.clone())
            .unwrap_or_else(|| DeviceName::default_for(&inputs.key.id().fingerprint()));
        let config = NodeConfig {
            key: inputs.key.duplicate(),
            name,
            peer_port: self.settings.peer_port,
            discovery_port: self.settings.discovery_port,
            announce_ports: self.deps.announce_ports.clone(),
            policy: self.deps.policy,
            interfaces,
            timing: self.deps.timing,
        };
        let started = Node::start(
            config,
            registry,
            Arc::new(StdMonoClock::new()),
            Arc::new(SystemWallClock),
            Arc::new(LogSink(self.log.clone())),
        );
        match started {
            Ok(node) => {
                *self.held.lock().unwrap_or_else(PoisonError::into_inner) = pending.take();
                if let Some(sink) = self
                    .sync_sink
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
                {
                    node.set_sync_sink(sink);
                }
                let names: Vec<InterfaceName> = node
                    .snapshot()
                    .interfaces
                    .into_iter()
                    .map(|i| i.name)
                    .collect();
                self.log.emit(&LogEvent::NetworkOn {
                    peer: self.settings.peer_port,
                    discovery: self.settings.discovery_port,
                    interfaces: &names,
                });
                *self.node() = Some(node);
                self.set_state(NetState::On);
            }
            Err(StartError::PortInUse(port)) => {
                *pending = None;
                self.set_state(NetState::PortInUse(port));
                self.log
                    .emit(&LogEvent::NetworkUnavailable(NetUnavailable::PortInUse(
                        port,
                    )));
            }
            Err(StartError::NoLocalNetwork) => {
                if self.state() != NetState::NoLocalNetwork {
                    self.set_state(NetState::NoLocalNetwork);
                    self.log.emit(&LogEvent::NetworkUnavailable(
                        NetUnavailable::NoLocalNetwork,
                    ));
                }
            }
        }
    }

    /// Background tick (every sweep): retry when no local network existed, and log
    /// aggregated drop counts.
    pub fn tick(&self, now: Duration) {
        if self.state() == NetState::NoLocalNetwork {
            self.try_start_node();
        }
        let node = self.node();
        if let Some(node) = node.as_ref() {
            if let Some(line) = self.drop_log.flush(node.counters(), now) {
                self.log.emit(&line);
            }
        }
    }

    pub fn node(&self) -> MutexGuard<'_, Option<Node>> {
        self.node.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn state(&self) -> NetState {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_state(&self, state: NetState) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }

    pub fn policy(&self) -> AddressPolicy {
        self.deps.policy
    }

    /// Whether the private key is in memory (node running or waiting for a network).
    pub fn key_held(&self) -> bool {
        self.node().is_some()
            || self
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some()
            || self
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some()
    }

    /// 007 (FR-042, FR-045): closes every socket and drops the node, keeping the identity and
    /// pins in memory; `tick` does not restart it. Does nothing when no node runs or waits.
    pub fn pause(&self) {
        let mut paused = self.paused.lock().unwrap_or_else(PoisonError::into_inner);
        let node = self.node().take();
        let waiting = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(inputs) = waiting {
            *self.held.lock().unwrap_or_else(PoisonError::into_inner) = Some(inputs);
        }
        if let Some(node) = node {
            node.stop();
        }
        if self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
        {
            *paused = true;
        }
    }

    /// 007: restarts a paused node with the same identity and pins (a missing local network
    /// gives `NoLocalNetwork` and the usual retry on `tick`).
    pub fn resume(&self) {
        let mut paused = self.paused.lock().unwrap_or_else(PoisonError::into_inner);
        if !*paused {
            return;
        }
        *paused = false;
        let inputs = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = inputs;
        drop(paused);
        self.try_start_node();
    }

    /// 007: whether `pause` was called without a later `resume`.
    pub fn is_paused(&self) -> bool {
        *self.paused.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 007 (FR-044): the number of pinned devices while the node runs, is paused or waits for
    /// a local network (read from the pin store when no node runs); 0 otherwise.
    pub fn pin_count(&self) -> usize {
        if let Some(snapshot) = self.snapshot() {
            return snapshot.paired.len();
        }
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        held.as_ref()
            .or(pending.as_ref())
            .and_then(|inputs| PeerRegistry::load(*inputs.key.public(), inputs.store.clone()).ok())
            .map_or(0, |registry| registry.len())
    }

    /// 007 (FR-039): the interface source for every later node start (`resume`, retries).
    pub fn set_interfaces(&self, source: Arc<dyn InterfaceSource>) {
        *self
            .interfaces
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(source);
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.node().as_ref().map(Node::snapshot)
    }

    /// The first in-use address with the peer port (for the QR text).
    pub fn local_peer_addr(&self, interfaces: &[Interface]) -> Option<SocketAddrV4> {
        interfaces
            .first()
            .map(|i| SocketAddrV4::new(i.addr, self.settings.peer_port))
    }

    pub fn start_pairing(&self) -> Result<Result<(), PairStartError>, NetOff> {
        let node = self.node();
        let node = node.as_ref().ok_or(NetOff)?;
        let result = node.start_pairing();
        if result.is_ok() {
            self.log.emit(&LogEvent::PairingStarted);
        }
        Ok(result)
    }

    pub fn cancel_pairing(&self) {
        if let Some(node) = self.node().as_ref() {
            node.cancel_pairing();
        }
    }

    pub fn accept(&self, id: &DeviceId) -> Result<PeerInfo, AcceptError> {
        match self.node().as_ref() {
            Some(node) => node.accept(id),
            None => Err(AcceptError::NothingPending),
        }
    }

    pub fn reject(&self) {
        if let Some(node) = self.node().as_ref() {
            node.reject();
        }
    }

    pub fn join(
        &self,
        addr: SocketAddrV4,
        code: &str,
        expected: Option<DeviceId>,
    ) -> Result<Result<(), JoinError>, NetOff> {
        let node = self.node();
        let node = node.as_ref().ok_or(NetOff)?;
        Ok(node.join(addr, code, expected))
    }

    pub fn revoke(&self, id: &DeviceId) -> Result<(), RevokeError> {
        let node = self.node();
        let node = node.as_ref().ok_or(RevokeError::NotFound)?;
        node.revoke(id)?;
        self.log.emit(&LogEvent::DeviceRevoked {
            fingerprint: &id.fingerprint(),
        });
        Ok(())
    }

    pub fn clear_warnings(&self) {
        if let Some(node) = self.node().as_ref() {
            node.clear_warnings();
        }
    }

    /// 004: the sync timings this runtime was started with.
    pub fn sync_timing(&self) -> SyncTiming {
        self.deps.sync
    }

    /// 004: routes channel-v2 sync frames to `sink` (now and for any node started later).
    pub fn set_sync_sink(&self, sink: Arc<dyn SyncFrameSink>) {
        *self
            .sync_sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&sink));
        if let Some(node) = self.node().as_ref() {
            node.set_sync_sink(sink);
        }
    }

    /// 004: sends one sync payload on a channel.
    pub fn send_sync(
        &self,
        peer: &DeviceId,
        conn: u64,
        payload: &Payload,
    ) -> Result<(), SendError> {
        match self.node().as_ref() {
            Some(node) => node.send_sync(peer, conn, payload),
            None => Err(SendError::NotConnected),
        }
    }

    /// 004: closes one channel after a sync protocol error.
    pub fn close_channel(&self, peer: &DeviceId, conn: u64) {
        if let Some(node) = self.node().as_ref() {
            node.close_channel(peer, conn);
        }
    }

    /// 004: number of paired (pinned) devices; 0 while networking is not running.
    pub fn paired_count(&self) -> usize {
        self.snapshot().map_or(0, |s| s.paired.len())
    }

    /// 004: whether `peer` is currently treated as v1-only ("sync unsupported by peer").
    pub fn is_legacy(&self, peer: &DeviceId) -> bool {
        self.node().as_ref().is_some_and(|n| n.is_legacy(peer))
    }

    /// 005: the Hello version of the current channel to `peer`.
    pub fn channel_version(&self, peer: &DeviceId) -> Option<HelloVersion> {
        self.node().as_ref().and_then(|n| n.channel_version(peer))
    }

    /// 005: the highest channel version currently dialed to `peer` (`None`: no node).
    pub fn max_version(&self, peer: &DeviceId) -> Option<HelloVersion> {
        self.node().as_ref().map(|n| n.max_version(peer))
    }

    /// 005: a handle that opens channels from a worker thread.
    pub fn opener(&self) -> Option<ChannelOpener> {
        self.node().as_ref().map(Node::opener)
    }

    /// Shutdown: close the network (Close(shutdown) on channels, sockets closed, last seen
    /// saved), then wipe the private key and any code.
    pub fn stop(&self) {
        let node = self.node().take();
        if let Some(node) = node {
            node.stop();
            self.set_state(NetState::Off);
            self.log.emit(&LogEvent::NetworkOff);
        }
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        *self.paused.lock().unwrap_or_else(PoisonError::into_inner) = false;
    }
}

/// Networking is not running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetOff;
