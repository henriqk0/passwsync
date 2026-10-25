//! `std::net` adapter for `device-link` (research R1, R10): one TCP listener, one UDP
//! discovery socket, outbound dials, and one blocking thread per connection with read
//! timeouts (no busy polling, FR-039). Trust decisions stay in `device-link`.
#![forbid(unsafe_code)]

pub mod conn;
pub mod dialer;
pub mod discovery;
pub mod framed;
pub mod interfaces;
pub mod listener;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use device_link::channel::Channel;
use device_link::code::{CodeRateLimiter, PairingCode, normalize_code};
use device_link::discovery::NearbyList;
use device_link::error::{DropCounters, FailReason};
use device_link::identity::{DeviceId, DeviceKey};
use device_link::link::{Link, PeerStatus, Timing, Warning};
use device_link::name::{DeviceName, InterfaceName};
use device_link::pairing::{
    AcceptError, InitiatorState, JoinerState, PairingInitiator, PairingJoiner, PairingSlot,
    PeerInfo, Role,
};
use device_link::policy::AddressPolicy;
use device_link::ports::{MonoClock, WallClock};
use device_link::registry::PeerRegistry;
use device_link::wire::{CloseReason, HelloVersion, Payload};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::interfaces::{Interface, InterfaceSource};

/// At most this many connections may be unauthenticated at once (FR-030).
pub const MAX_UNAUTHENTICATED: usize = 16;
/// Stack size of every network thread (R10).
pub const THREAD_STACK: usize = 128 * 1024;

/// Monotonic clock from `Instant`.
pub struct StdMonoClock(Instant);

impl StdMonoClock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for StdMonoClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonoClock for StdMonoClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn unix_now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disconnect {
    Timeout,
    Closed,
    Error,
    Duplicate,
}

pub use device_link::link::Refusal;

/// Closed set of things worth logging; the host maps them to its log lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    PairingSucceeded(DeviceId),
    PairingFailed(FailReason),
    PeerConnected(DeviceId),
    PeerDisconnected(DeviceId, Disconnect),
    PeerRefused(DeviceId, Refusal),
    RefusedByPeer(DeviceId),
    InterfacesChanged(Vec<InterfaceName>),
    /// 004: the peer closed a channel v2 dial before Noise message 2; it is dialed with v1
    /// (no sync) and retried with v2 after 24 hours or a restart.
    PeerLegacy(DeviceId),
    /// 005: the peer closed a channel v3 dial before Noise message 2; it is dialed with v2
    /// (sync, no sharing) and retried with v3 after 24 hours or a restart.
    PeerNoShare(DeviceId),
}

/// 004: receives the sync side of channel v2 (contracts/vault-core-sync-api.md). Called on
/// network threads; implementations must return quickly.
pub trait SyncFrameSink: Send + Sync {
    /// A sync-enabled channel is up. `session` is the Noise handshake hash; `dialer` tells
    /// whether this device opened the connection.
    fn channel_up(&self, peer: DeviceId, conn: u64, session: [u8; 32], dialer: bool);
    /// A `SyncCtl` or `CopyData` payload arrived on that channel.
    fn frame(&self, peer: DeviceId, conn: u64, payload: Payload);
    /// The channel closed.
    fn channel_down(&self, peer: DeviceId, conn: u64);
    /// 005: the Hello version of a newly authenticated channel (every version), reported
    /// before `channel_up`. `ShareMsg`/`ShareData` payloads arrive through `frame` on v3.
    fn channel_version(&self, _peer: DeviceId, _conn: u64, _version: HelloVersion) {}
}

/// Why [`Node::send_sync`] did not send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// No channel to that peer with that connection number.
    NotConnected,
    /// The channel was negotiated with Hello v1.
    NotSyncEnabled,
    /// 005: a share payload on a channel below v3.
    NotShareEnabled,
    /// Not a `SyncCtl`/`CopyData` payload, or out of bounds.
    Protocol,
    /// The write failed; the channel is being closed.
    Io,
}

/// A v1-only peer is retried with channel v2 after this long (004 R7); 005 uses the same
/// delay to retry a lowered per-peer maximum version.
pub const LEGACY_RETRY: Duration = Duration::from_secs(24 * 3600);

/// Why [`Node::ensure_channel`] found no channel (005 R11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnsureError {
    /// The expected device is not pinned, the answering device is not pinned, or the peer
    /// refused this device.
    NotPaired,
    /// The device at the address proved another identity than the expected one (FR-012).
    IdMismatch,
    /// No address, an address outside the policy, or the dial or handshake failed.
    Unreachable,
    /// Networking is stopping or no usable interface exists.
    NetworkOff,
    /// The expected device is this device.
    SelfDevice,
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: NetEvent);
}

/// Keeps every event (feature `testkit`).
#[cfg(feature = "testkit")]
#[derive(Default)]
pub struct RecordingSink(Mutex<Vec<NetEvent>>);

#[cfg(feature = "testkit")]
impl RecordingSink {
    pub fn events(&self) -> Vec<NetEvent> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(feature = "testkit")]
impl EventSink for RecordingSink {
    fn emit(&self, event: NetEvent) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

pub struct NodeConfig {
    pub key: DeviceKey,
    pub name: DeviceName,
    pub peer_port: u16,
    pub discovery_port: u16,
    /// Destination ports for announcements; empty means `discovery_port`. Tests running
    /// two nodes on one host point each at the other's discovery port.
    pub announce_ports: Vec<u16>,
    pub policy: AddressPolicy,
    pub interfaces: Arc<dyn InterfaceSource>,
    pub timing: Timing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    PortInUse(u16),
    NoLocalNetwork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairStartError {
    Busy,
    Limit,
    TooManyCodes,
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    InvalidAddress,
    InvalidCode,
    Busy,
    AlreadyPaired,
    Limit,
    SelfPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeError {
    NotFound,
    Storage,
}

/// The initiator side as the UI sees it.
#[derive(Clone, Debug)]
pub struct PairingView {
    /// `waiting | exchanging | awaiting_acceptance | paired | failed`.
    pub state: &'static str,
    /// 8 digits, only while the code is valid.
    pub code: Option<Zeroizing<String>>,
    pub expires_in: u64,
    pub peer: Option<PeerInfo>,
    pub reason: Option<FailReason>,
}

#[derive(Clone, Debug)]
pub struct JoinView {
    /// `connecting | exchanging | awaiting_acceptance | paired | failed`.
    pub state: &'static str,
    pub peer: Option<DeviceId>,
    pub peer_name: Option<DeviceName>,
    pub seconds_left: Option<u16>,
    pub reason: Option<FailReason>,
}

#[derive(Clone, Debug)]
pub struct PairedView {
    pub id: DeviceId,
    pub name: DeviceName,
    pub paired_at: u64,
    pub last_seen: Option<u64>,
    pub status: PeerStatus,
}

#[derive(Clone, Debug)]
pub struct NearbyView {
    pub id: DeviceId,
    pub addr: SocketAddrV4,
    pub paired: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub interfaces: Vec<Interface>,
    pub nearby: Vec<NearbyView>,
    pub paired: Vec<PairedView>,
    pub pairing: Option<PairingView>,
    pub join: Option<JoinView>,
    pub warnings: Vec<Warning>,
}

pub(crate) struct InitSession {
    pub generation: u64,
    pub code: PairingCode,
    pub machine: Option<PairingInitiator>,
    pub stream: Option<TcpStream>,
}

pub(crate) struct JoinSession {
    pub generation: u64,
    pub connecting: bool,
    pub state: JoinerState,
    pub stream: Option<TcpStream>,
}

/// An authenticated channel to a pinned peer.
pub(crate) struct ChannelEntry {
    pub conn: u64,
    pub dialer: DeviceId,
    pub stream: TcpStream,
    pub channel: Arc<Mutex<Channel>>,
    /// Monotonic time of the last frame written (keepalive clock, shared with `send_sync`).
    pub last_sent: Arc<Mutex<Duration>>,
    /// 004: channel v2 or v3 (sync frames allowed).
    pub sync: bool,
    /// 005: the negotiated Hello version (v3 allows share frames).
    pub version: HelloVersion,
}

impl ChannelEntry {
    /// Sends `Close(reason)` (best effort) and shuts the socket down.
    pub fn close(&self, reason: CloseReason) {
        if let Ok(mut channel) = self.channel.lock() {
            if let Ok(frame) = channel.seal(&Payload::Close { reason }) {
                let _ = framed::write_frame(&self.stream, &frame);
            }
        }
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

pub(crate) struct State {
    pub link: Link,
    pub nearby: NearbyList,
    pub channels: HashMap<DeviceId, ChannelEntry>,
    pub dialing: HashSet<DeviceId>,
    pub next_conn: u64,
    pub registry: PeerRegistry,
    pub interfaces: Vec<Interface>,
    pub pairing: Option<InitSession>,
    pub join: Option<JoinSession>,
    pub slot: PairingSlot,
    pub rate: CodeRateLimiter,
    pub next_generation: u64,
    /// 004/005: per-peer lowered maximum channel version and when to try v3 again.
    pub max_version: HashMap<DeviceId, (HelloVersion, Duration)>,
}

pub(crate) struct Shared {
    pub key: DeviceKey,
    pub own_id: DeviceId,
    pub name: DeviceName,
    pub policy: AddressPolicy,
    pub timing: Timing,
    pub peer_port: u16,
    pub announce_ports: Vec<u16>,
    pub interfaces_src: Arc<dyn InterfaceSource>,
    /// The discovery socket (sending side shared with API threads for announcements).
    pub udp: UdpSocket,
    pub mono: Arc<dyn MonoClock>,
    pub wall: Arc<dyn WallClock>,
    pub events: Arc<dyn EventSink>,
    pub counters: DropCounters,
    pub unauth: AtomicUsize,
    /// Loop wake-ups (socket readiness or timer), for the SC-007 budget.
    pub wakes: std::sync::atomic::AtomicU64,
    pub stop: AtomicBool,
    pub state: Mutex<State>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    /// 004: where sync frames go (none until the host sets one).
    pub sync_sink: Mutex<Option<Arc<dyn SyncFrameSink>>>,
}

impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn sync_sink(&self) -> Option<Arc<dyn SyncFrameSink>> {
        self.sync_sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Spawns a tracked network thread; finished ones are reaped on the way.
    pub fn spawn(self: &Arc<Self>, name: &str, work: impl FnOnce() + Send + 'static) -> bool {
        let mut threads = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        threads.retain(|t| !t.is_finished());
        match thread::Builder::new()
            .name(name.into())
            .stack_size(THREAD_STACK)
            .spawn(work)
        {
            Ok(handle) => {
                threads.push(handle);
                true
            }
            Err(_) => false,
        }
    }
}

/// Decrements the unauthenticated-connection count when dropped.
pub(crate) struct UnauthSlot<'a>(Option<&'a AtomicUsize>);

impl<'a> UnauthSlot<'a> {
    pub fn new(counter: &'a AtomicUsize) -> Self {
        Self(Some(counter))
    }

    /// The connection authenticated: it no longer counts.
    pub fn release(&mut self) {
        if let Some(counter) = self.0.take() {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for UnauthSlot<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// A running network node.
pub struct Node {
    shared: Arc<Shared>,
    /// A handle on the listening socket, shut down to wake the blocking accept (no
    /// self-connection, FR-011).
    accept_handle: TcpListener,
    listener: Option<JoinHandle<()>>,
    discovery: Option<JoinHandle<()>>,
}

impl Node {
    /// Scans interfaces, binds TCP then UDP (closing TCP again if UDP fails), and starts
    /// the listener thread.
    pub fn start(
        config: NodeConfig,
        registry: PeerRegistry,
        mono: Arc<dyn MonoClock>,
        wall: Arc<dyn WallClock>,
        events: Arc<dyn EventSink>,
    ) -> Result<Self, StartError> {
        let interfaces = config.interfaces.scan();
        if interfaces.is_empty() {
            return Err(StartError::NoLocalNetwork);
        }
        let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, config.peer_port))
            .map_err(|_| StartError::PortInUse(config.peer_port))?;
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, config.discovery_port))
            .map_err(|_| StartError::PortInUse(config.discovery_port))?;
        udp.set_broadcast(true)
            .map_err(|_| StartError::PortInUse(config.discovery_port))?;
        let udp_recv = udp
            .try_clone()
            .map_err(|_| StartError::PortInUse(config.discovery_port))?;
        let accept_handle = tcp
            .try_clone()
            .map_err(|_| StartError::PortInUse(config.peer_port))?;
        let own_id = config.key.id();
        let announce_ports = if config.announce_ports.is_empty() {
            vec![config.discovery_port]
        } else {
            config.announce_ports
        };
        let shared = Arc::new(Shared {
            own_id,
            key: config.key,
            name: config.name,
            policy: config.policy,
            timing: config.timing,
            peer_port: config.peer_port,
            announce_ports,
            interfaces_src: config.interfaces,
            udp,
            mono,
            wall,
            events,
            counters: DropCounters::default(),
            unauth: AtomicUsize::new(0),
            wakes: std::sync::atomic::AtomicU64::new(0),
            stop: AtomicBool::new(false),
            state: Mutex::new(State {
                link: Link::new(own_id, config.timing),
                nearby: NearbyList::new(config.timing.nearby_expiry, config.policy),
                channels: HashMap::new(),
                dialing: HashSet::new(),
                next_conn: 1,
                registry,
                interfaces,
                pairing: None,
                join: None,
                slot: PairingSlot::default(),
                rate: CodeRateLimiter::default(),
                next_generation: 1,
                max_version: HashMap::new(),
            }),
            threads: Mutex::new(Vec::new()),
            sync_sink: Mutex::new(None),
        });
        let accept_shared = Arc::clone(&shared);
        let listener = thread::Builder::new()
            .name("net-accept".into())
            .stack_size(THREAD_STACK)
            .spawn(move || listener::run(&accept_shared, tcp))
            .map_err(|_| StartError::PortInUse(config.peer_port))?;
        let discovery_shared = Arc::clone(&shared);
        let discovery = thread::Builder::new()
            .name("net-discovery".into())
            .stack_size(THREAD_STACK)
            .spawn(move || discovery::run(&discovery_shared, udp_recv))
            .map_err(|_| StartError::PortInUse(config.discovery_port))?;
        Ok(Self {
            shared,
            accept_handle,
            listener: Some(listener),
            discovery: Some(discovery),
        })
    }

    /// Authenticated channels currently open.
    pub fn channel_count(&self) -> usize {
        self.shared.lock().channels.len()
    }

    pub fn own_id(&self) -> DeviceId {
        self.shared.own_id
    }

    pub fn counters(&self) -> &DropCounters {
        &self.shared.counters
    }

    /// Wake-ups of the discovery and channel loops so far (SC-007).
    pub fn wakes(&self) -> u64 {
        self.shared.wakes.load(Ordering::Relaxed)
    }

    pub fn unauthenticated(&self) -> usize {
        self.shared.unauth.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> Snapshot {
        let now = self.shared.mono.now();
        let state = self.shared.lock();
        let paired = state
            .registry
            .list()
            .iter()
            .map(|pin| PairedView {
                id: pin.id(),
                name: pin.name.clone(),
                paired_at: pin.paired_at,
                last_seen: pin.last_seen,
                status: state.link.status(&pin.id()),
            })
            .collect();
        let pairing = state.pairing.as_ref().map(|s| pairing_view(s, now));
        let join = state.join.as_ref().map(join_view);
        Snapshot {
            interfaces: state.interfaces.clone(),
            nearby: discovery::nearby_view(&state, now),
            paired,
            pairing,
            join,
            warnings: state.link.warnings(),
        }
    }

    /// Shows a new code, replacing any previous one (FR-017).
    pub fn start_pairing(&self) -> Result<(), PairStartError> {
        let now = self.shared.mono.now();
        let mut state = self.shared.lock();
        let joining = state
            .join
            .as_ref()
            .is_some_and(|j| !matches!(j.state, JoinerState::Paired(_) | JoinerState::Failed(_)));
        if joining {
            return Err(PairStartError::Busy);
        }
        if state.registry.is_full() {
            return Err(PairStartError::Limit);
        }
        if !state.rate.try_create(now) {
            return Err(PairStartError::TooManyCodes);
        }
        let code = PairingCode::generate(&mut OsRng, now).map_err(|_| PairStartError::Random)?;
        if let Some(mut old) = state.pairing.take() {
            old.code.replace();
            if let Some(stream) = old.stream.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        let generation = state.next_generation;
        state.next_generation += 1;
        state.pairing = Some(InitSession {
            generation,
            code,
            machine: None,
            stream: None,
        });
        // Announce at once while the code is shown (FR-013).
        state.link.announce_soon();
        drop(state);
        discovery::announce_if_due(&self.shared, now);
        Ok(())
    }

    /// Withdraws the code (idempotent).
    pub fn cancel_pairing(&self) {
        let mut state = self.shared.lock();
        if let Some(mut old) = state.pairing.take() {
            old.code.cancel();
            if let Some(stream) = old.stream.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    pub fn accept(&self, device_id: &DeviceId) -> Result<PeerInfo, AcceptError> {
        let now = self.shared.mono.now();
        let now_unix = self.shared.wall.unix_now();
        let mut guard = self.shared.lock();
        let State {
            registry, pairing, ..
        } = &mut *guard;
        let Some(session) = pairing.as_mut() else {
            return Err(AcceptError::NothingPending);
        };
        let Some(machine) = session.machine.as_mut() else {
            return Err(AcceptError::NothingPending);
        };
        let result = machine.accept(device_id, registry, Some(&mut session.code), now, now_unix);
        let frames = machine.outgoing();
        if let Some(stream) = session.stream.as_ref() {
            for frame in &frames {
                if framed::write_frame(stream, frame).is_err() {
                    break;
                }
            }
        }
        if let Ok(peer) = &result {
            self.shared.events.emit(NetEvent::PairingSucceeded(peer.id));
        }
        result
    }

    pub fn reject(&self) {
        let mut state = self.shared.lock();
        let Some(session) = state.pairing.as_mut() else {
            return;
        };
        let Some(machine) = session.machine.as_mut() else {
            return;
        };
        machine.reject(Some(&mut session.code));
        let frames = machine.outgoing();
        if let Some(stream) = session.stream.as_ref() {
            for frame in &frames {
                let _ = framed::write_frame(stream, frame);
            }
        }
    }

    /// Removes the pin and saves; a failed save keeps it (FR-033).
    pub fn revoke(&self, id: &DeviceId) -> Result<(), RevokeError> {
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        match state.link.revoke(&mut state.registry, id) {
            Ok(_) => {}
            Err(device_link::error::Error::NotFound) => return Err(RevokeError::NotFound),
            Err(_) => return Err(RevokeError::Storage),
        }
        // Nothing is sent to the revoked peer (FR-034): the socket is just shut down.
        if let Some(entry) = state.channels.remove(id) {
            let _ = entry.stream.shutdown(Shutdown::Both);
        }
        Ok(())
    }

    pub fn clear_warnings(&self) {
        self.shared.lock().link.clear_warnings();
    }

    /// 004: routes sync frames of channel v2 to `sink`; channels already up are reported
    /// with `channel_up` at once.
    pub fn set_sync_sink(&self, sink: Arc<dyn SyncFrameSink>) {
        *self
            .shared
            .sync_sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&sink));
        let up: Vec<(DeviceId, u64, HelloVersion, bool, [u8; 32], bool)> = {
            let state = self.shared.lock();
            state
                .channels
                .iter()
                .filter_map(|(id, e)| {
                    let channel = e.channel.lock().ok()?;
                    Some((
                        *id,
                        e.conn,
                        e.version,
                        e.sync,
                        channel.session_hash(),
                        channel.is_dialer(),
                    ))
                })
                .collect()
        };
        for (peer, conn, version, sync, session, dialer) in up {
            sink.channel_version(peer, conn, version);
            if sync {
                sink.channel_up(peer, conn, session, dialer);
            }
        }
    }

    /// 004: seals and writes one sync payload on the channel `conn` to `peer`. The channel
    /// mutex is held across seal and write, so nonce order equals write order; the write
    /// counts for the keepalive clock.
    pub fn send_sync(
        &self,
        peer: &DeviceId,
        conn: u64,
        payload: &Payload,
    ) -> Result<(), SendError> {
        let (stream, channel, last_sent, sync, version) = {
            let state = self.shared.lock();
            let entry = state
                .channels
                .get(peer)
                .filter(|e| e.conn == conn)
                .ok_or(SendError::NotConnected)?;
            let stream = entry.stream.try_clone().map_err(|_| SendError::Io)?;
            (
                stream,
                Arc::clone(&entry.channel),
                Arc::clone(&entry.last_sent),
                entry.sync,
                entry.version,
            )
        };
        if !sync {
            return Err(SendError::NotSyncEnabled);
        }
        if matches!(
            payload,
            Payload::ShareMsg { .. } | Payload::ShareData { .. }
        ) && version != HelloVersion::V3
        {
            return Err(SendError::NotShareEnabled);
        }
        let mut guard = channel.lock().map_err(|_| SendError::Io)?;
        let frame = guard.seal_sync(payload).map_err(|_| SendError::Protocol)?;
        if framed::write_frame(&stream, &frame).is_err() {
            drop(guard);
            let _ = stream.shutdown(Shutdown::Both);
            return Err(SendError::Io);
        }
        *last_sent.lock().unwrap_or_else(PoisonError::into_inner) = self.shared.mono.now();
        Ok(())
    }

    /// 004: closes the channel `conn` to `peer` (a sync protocol error).
    pub fn close_channel(&self, peer: &DeviceId, conn: u64) {
        let state = self.shared.lock();
        if let Some(entry) = state.channels.get(peer).filter(|e| e.conn == conn) {
            let _ = entry.stream.shutdown(Shutdown::Both);
        }
    }

    /// 004: whether `peer` is currently treated as v1-only.
    pub fn is_legacy(&self, peer: &DeviceId) -> bool {
        self.max_version(peer) == HelloVersion::V1
    }

    /// 005: the highest channel version dialed to `peer` now (v3 unless lowered within the
    /// last 24 hours of this run).
    pub fn max_version(&self, peer: &DeviceId) -> HelloVersion {
        let now = self.shared.mono.now();
        dialer::max_version(&self.shared.lock(), peer, now)
    }

    /// 005: the Hello version of the current channel to `peer`, if one is open.
    pub fn channel_version(&self, peer: &DeviceId) -> Option<HelloVersion> {
        self.shared.lock().channels.get(peer).map(|e| e.version)
    }

    /// 005: returns the open channel to `expected`, or dials `hint` (else the pin's last
    /// known address) under the address policy. With `expected = None` the responder's static
    /// key must be pinned and that device is the result. Blocks for at most the step
    /// timeouts of the dial attempts; call it from a short-lived worker (R11).
    pub fn ensure_channel(
        &self,
        expected: Option<DeviceId>,
        hint: Option<SocketAddrV4>,
    ) -> Result<(DeviceId, u64), EnsureError> {
        ensure_channel(&self.shared, expected, hint)
    }

    /// 005: a cloneable handle for [`Node::ensure_channel`] that a worker thread can use
    /// without holding the node (it reports `NetworkOff` once the node stopped).
    pub fn opener(&self) -> ChannelOpener {
        ChannelOpener(Arc::clone(&self.shared))
    }

    /// 004: open sync-enabled channels as `(peer, conn)`.
    pub fn sync_channels(&self) -> Vec<(DeviceId, u64)> {
        self.shared
            .lock()
            .channels
            .iter()
            .filter(|(_, e)| e.sync)
            .map(|(id, e)| (*id, e.conn))
            .collect()
    }

    /// Starts joining the device at `addr` with the typed code (FR-019).
    pub fn join(
        &self,
        addr: SocketAddrV4,
        typed: &str,
        expected: Option<DeviceId>,
    ) -> Result<(), JoinError> {
        let digits = normalize_code(typed).map_err(|_| JoinError::InvalidCode)?;
        if addr.port() == 0 || !self.shared.policy.allows_v4(*addr.ip()) {
            return Err(JoinError::InvalidAddress);
        }
        let mut state = self.shared.lock();
        if expected == Some(self.shared.own_id) {
            return Err(JoinError::SelfPair);
        }
        if expected.is_some_and(|id| state.registry.contains(&id)) {
            return Err(JoinError::AlreadyPaired);
        }
        if state.registry.is_full() {
            return Err(JoinError::Limit);
        }
        if !state.slot.try_acquire(Role::Joiner) {
            return Err(JoinError::Busy);
        }
        let machine = PairingJoiner::start(
            &self.shared.key,
            self.shared.name.clone(),
            &digits,
            expected,
            &mut OsRng,
        )
        .map_err(|_| JoinError::InvalidCode);
        let machine = match machine {
            Ok(machine) => machine,
            Err(error) => {
                state.slot.release();
                return Err(error);
            }
        };
        let generation = state.next_generation;
        state.next_generation += 1;
        state.join = Some(JoinSession {
            generation,
            connecting: true,
            state: JoinerState::Exchanging,
            stream: None,
        });
        drop(state);
        let shared = Arc::clone(&self.shared);
        if !self.shared.spawn("net-join", move || {
            dialer::run_join(&shared, generation, addr, machine)
        }) {
            let mut state = self.shared.lock();
            state.slot.release();
            if let Some(join) = state.join.as_mut() {
                join.state = JoinerState::Failed(FailReason::Protocol);
            }
        }
        Ok(())
    }

    /// Stops every thread, closes every socket and wipes the code. The private key is
    /// wiped when the node is dropped.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.shared.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        {
            let mut state = self.shared.lock();
            if let Some(mut session) = state.pairing.take() {
                session.code.cancel();
                if let Some(stream) = session.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
            if let Some(join) = state.join.as_mut() {
                if let Some(stream) = join.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
            for (_, entry) in state.channels.drain() {
                entry.close(CloseReason::Shutdown);
            }
        }
        // Wake the blocked receive and accept by shutting their sockets down for reading;
        // nothing is sent anywhere (FR-011). On an unbound-peer UDP socket the call reports
        // "not connected" but still wakes the receiver.
        let _ = rustix::net::shutdown(&self.shared.udp, rustix::net::Shutdown::Read);
        if let Some(discovery) = self.discovery.take() {
            let _ = discovery.join();
        }
        let _ = rustix::net::shutdown(&self.accept_handle, rustix::net::Shutdown::Read);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        let threads: Vec<JoinHandle<()>> = std::mem::take(
            &mut *self
                .shared
                .threads
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for handle in threads {
            let _ = handle.join();
        }
        let _ = self.shared.lock().registry.persist();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pairing_view(session: &InitSession, now: Duration) -> PairingView {
    let active = session.code.is_active(now);
    let (state, peer, reason) = match session.machine.as_ref().map(PairingInitiator::state) {
        None if active => ("waiting", None, None),
        None => ("failed", None, Some(FailReason::Expired)),
        Some(InitiatorState::Exchanging) => ("exchanging", None, None),
        Some(InitiatorState::AwaitingAcceptance(peer)) => ("awaiting_acceptance", Some(peer), None),
        Some(InitiatorState::Paired(peer)) => ("paired", Some(peer), None),
        Some(InitiatorState::Failed(reason)) => ("failed", None, Some(reason)),
    };
    PairingView {
        state,
        code: active.then(|| Zeroizing::new(session.code.digits().to_owned())),
        expires_in: if active {
            session.code.seconds_left(now)
        } else {
            0
        },
        peer,
        reason,
    }
}

fn join_view(session: &JoinSession) -> JoinView {
    let mut view = JoinView {
        state: "exchanging",
        peer: None,
        peer_name: None,
        seconds_left: None,
        reason: None,
    };
    match &session.state {
        JoinerState::Exchanging if session.connecting => view.state = "connecting",
        JoinerState::Exchanging => {}
        JoinerState::AwaitingAcceptance { peer, seconds_left } => {
            view.state = "awaiting_acceptance";
            view.peer = Some(*peer);
            view.seconds_left = Some(*seconds_left);
        }
        JoinerState::Paired(peer) => {
            view.state = "paired";
            view.peer = Some(peer.id);
            view.peer_name = Some(peer.name.clone());
        }
        JoinerState::Failed(reason) => {
            view.state = "failed";
            view.reason = Some(*reason);
        }
    }
    view
}

/// 005: opens channels for a redemption from a worker thread (see [`Node::opener`]).
#[derive(Clone)]
pub struct ChannelOpener(Arc<Shared>);

impl ChannelOpener {
    pub fn ensure_channel(
        &self,
        expected: Option<DeviceId>,
        hint: Option<SocketAddrV4>,
    ) -> Result<(DeviceId, u64), EnsureError> {
        ensure_channel(&self.0, expected, hint)
    }
}

fn ensure_channel(
    shared: &Arc<Shared>,
    expected: Option<DeviceId>,
    hint: Option<SocketAddrV4>,
) -> Result<(DeviceId, u64), EnsureError> {
    if expected == Some(shared.own_id) {
        return Err(EnsureError::SelfDevice);
    }
    let (known, addr) = {
        let state = shared.lock();
        if shared.stopping() || state.interfaces.is_empty() {
            return Err(EnsureError::NetworkOff);
        }
        match expected {
            Some(id) => {
                let Some(pin) = state.registry.get(&id) else {
                    return Err(EnsureError::NotPaired);
                };
                // Without an address the existing channel is the answer; with one, the
                // identity at that address is checked first (FR-012).
                if let (None, Some(entry)) = (hint, state.channels.get(&id)) {
                    return Ok((id, entry.conn));
                }
                (Some(pin.public), hint.or(pin.last_addr))
            }
            None => (None, hint),
        }
    };
    let addr = addr.ok_or(EnsureError::Unreachable)?;
    if addr.port() == 0 || !shared.policy.allows_v4(*addr.ip()) {
        return Err(EnsureError::Unreachable);
    }
    let public = match known {
        Some(public) if hint.is_some() => {
            // An address was given with the expected identity: probe the identity there
            // (without revealing ours) and reuse an existing channel only if it matches.
            let id = DeviceId::from_public(&public);
            match dialer::probe_identity(shared, addr) {
                Ok(presented) if presented == id => {}
                Ok(_) => return Err(EnsureError::IdMismatch),
                Err(error) => return Err(error),
            }
            if let Some(entry) = shared.lock().channels.get(&id) {
                return Ok((id, entry.conn));
            }
            public
        }
        Some(public) => public,
        None => {
            let id = dialer::probe_identity(shared, addr)?;
            if id == shared.own_id {
                return Err(EnsureError::SelfDevice);
            }
            let state = shared.lock();
            let Some(pin) = state.registry.get(&id) else {
                return Err(EnsureError::NotPaired);
            };
            if let Some(entry) = state.channels.get(&id) {
                return Ok((id, entry.conn));
            }
            pin.public
        }
    };
    dialer::dial_now(shared, DeviceId::from_public(&public), public, addr)
}
