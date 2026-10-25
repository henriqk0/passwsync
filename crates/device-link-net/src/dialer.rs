//! Outbound connections: the pairing joiner (B side).

use std::net::{Shutdown, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use device_link::channel::{ChannelDialer, ChannelError};
use device_link::error::FailReason;
use device_link::identity::DeviceId;
use device_link::link::Refusal;
use device_link::pairing::{JoinerState, PairingJoiner};
use device_link::wire::HelloVersion;

use crate::framed::{FrameError, read_frame, write_frame};
use crate::{EnsureError, NetEvent, Shared};

/// Policy-checked connect with the step timeout.
pub(crate) fn connect(shared: &Shared, addr: SocketAddrV4) -> Option<TcpStream> {
    if !shared.policy.allows_v4(*addr.ip()) {
        return None;
    }
    let stream = TcpStream::connect_timeout(&addr.into(), shared.timing.step_timeout).ok()?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(shared.timing.step_timeout));
    Some(stream)
}

fn set_state(shared: &Shared, generation: u64, update: impl FnOnce(&mut crate::JoinSession)) {
    let mut state = shared.lock();
    if let Some(join) = state.join.as_mut().filter(|j| j.generation == generation) {
        update(join);
    }
}

pub(crate) fn run_join(
    shared: &Arc<Shared>,
    generation: u64,
    addr: SocketAddrV4,
    mut machine: PairingJoiner,
) {
    let final_state = match connect(shared, addr) {
        None => JoinerState::Failed(FailReason::Unreachable),
        Some(stream) => {
            let clone = stream.try_clone().ok();
            set_state(shared, generation, |join| {
                join.connecting = false;
                join.stream = clone;
            });
            let result = drive_joiner(shared, generation, &stream, &mut machine);
            let _ = stream.shutdown(Shutdown::Both);
            result
        }
    };
    let mut state = shared.lock();
    state.slot.release();
    if let Some(join) = state.join.as_mut().filter(|j| j.generation == generation) {
        join.state = final_state.clone();
        join.connecting = false;
        join.stream = None;
    }
    drop(state);
    match final_state {
        JoinerState::Paired(peer) => {
            shared.events.emit(NetEvent::PairingSucceeded(peer.id));
            // Remember where A listens and open the channel at once.
            {
                let mut state = shared.lock();
                state.registry.note_addr(&peer.id, addr);
                state.link.paired(peer.id);
                let now = shared.mono.now();
                state.link.on_announce(&peer.id, now);
            }
            dial_peer(shared, peer.id, None);
        }
        JoinerState::Failed(reason) => shared.events.emit(NetEvent::PairingFailed(reason)),
        _ => {}
    }
}

fn drive_joiner(
    shared: &Arc<Shared>,
    generation: u64,
    stream: &TcpStream,
    machine: &mut PairingJoiner,
) -> JoinerState {
    loop {
        for frame in machine.outgoing() {
            if write_frame(stream, &frame).is_err() {
                machine.on_closed();
            }
        }
        if machine.is_done() || shared.stopping() {
            machine.on_closed();
            return machine.state();
        }
        let timeout = match machine.state() {
            JoinerState::AwaitingAcceptance { .. } => machine.read_timeout(),
            _ => shared.timing.step_timeout,
        };
        let read = read_frame(stream, timeout);
        let now_unix = shared.wall.unix_now();
        let mut state = shared.lock();
        match read {
            Ok(body) => machine.on_frame(&body, &mut state.registry, now_unix),
            Err(FrameError::Timeout) => machine.on_timeout(),
            Err(_) => machine.on_closed(),
        }
        if let Some(join) = state.join.as_mut().filter(|j| j.generation == generation) {
            join.state = machine.state();
        }
    }
}

/// Starts a channel dial to a pinned peer at `hint` (an announced address, used for this
/// attempt only) or else its last known address, unless it is connected, already being
/// dialed, or its backoff has not elapsed.
pub(crate) fn dial_peer(shared: &Arc<Shared>, id: DeviceId, hint: Option<SocketAddrV4>) {
    let now = shared.mono.now();
    let target = {
        let mut state = shared.lock();
        if shared.stopping()
            || state.interfaces.is_empty()
            || state.channels.contains_key(&id)
            || state.dialing.contains(&id)
            || !state.link.may_dial(&id, now)
        {
            return;
        }
        let Some((public, addr)) = state
            .registry
            .get(&id)
            .and_then(|p| Some((p.public, hint.or(p.last_addr)?)))
        else {
            return;
        };
        state.dialing.insert(id);
        (public, addr)
    };
    let worker = Arc::clone(shared);
    if !shared.spawn("net-dial", move || {
        run_dial(&worker, id, target.0, target.1)
    }) {
        shared.lock().dialing.remove(&id);
    }
}

/// 005: the highest channel version to dial `id` with at `now` (v3 unless lowered within
/// the retry period).
pub(crate) fn max_version(state: &crate::State, id: &DeviceId, now: Duration) -> HelloVersion {
    match state.max_version.get(id) {
        Some((version, until)) if now < *until => *version,
        _ => HelloVersion::V3,
    }
}

/// Dials with the peer's current maximum version; a close before Noise message 2 lowers the
/// maximum by one (v3 -> v2 emits `PeerNoShare`, v2 -> v1 emits `PeerLegacy`, as in 004) and
/// redials at once (005 contracts/share-protocol.md "Negotiation").
fn dial_negotiated(
    shared: &Arc<Shared>,
    id: DeviceId,
    public: [u8; 32],
    addr: SocketAddrV4,
) -> Result<Option<Opened>, DialFail> {
    let mut version = max_version(&shared.lock(), &id, shared.mono.now());
    loop {
        match dial_channel(shared, id, public, addr, version) {
            Err(DialFail::ClosedBeforeMsg2) if version != HelloVersion::V1 => {
                let (lower, event) = if version == HelloVersion::V3 {
                    (HelloVersion::V2, NetEvent::PeerNoShare(id))
                } else {
                    (HelloVersion::V1, NetEvent::PeerLegacy(id))
                };
                let until = shared.mono.now() + crate::LEGACY_RETRY;
                shared.lock().max_version.insert(id, (lower, until));
                shared.events.emit(event);
                version = lower;
            }
            other => return other,
        }
    }
}

/// 005: learns the static key of the device at `addr` without revealing this device's key:
/// the dialer stops at Noise message 2 when the presented key differs from the expected one
/// (here this device's own key, which no other device can present).
pub(crate) fn probe_identity(
    shared: &Arc<Shared>,
    addr: SocketAddrV4,
) -> Result<DeviceId, EnsureError> {
    let own = *shared.key.public();
    for version in [HelloVersion::V3, HelloVersion::V2, HelloVersion::V1] {
        let stream = connect(shared, addr).ok_or(EnsureError::Unreachable)?;
        let mut dialer =
            ChannelDialer::start_version(&shared.key, own, shared.name.clone(), version)
                .map_err(|_| EnsureError::Unreachable)?;
        let mut closed_early = false;
        for frame in dialer.outgoing() {
            if write_frame(&stream, &frame).is_err() {
                closed_early = true;
                break;
            }
        }
        let body = if closed_early {
            Err(FrameError::Closed)
        } else {
            read_frame(&stream, shared.timing.step_timeout)
        };
        let _ = stream.shutdown(Shutdown::Both);
        match body {
            Ok(body) => {
                return match dialer.on_frame(&body) {
                    Err(ChannelError::KeyMismatch { presented }) => Ok(presented),
                    _ => Err(EnsureError::Unreachable),
                };
            }
            Err(FrameError::Closed) => continue,
            Err(_) => return Err(EnsureError::Unreachable),
        }
    }
    Err(EnsureError::Unreachable)
}

/// 005: dials `id` at `addr` now (person action: no backoff) and runs the channel on its
/// own thread; returns the connection number.
pub(crate) fn dial_now(
    shared: &Arc<Shared>,
    id: DeviceId,
    public: [u8; 32],
    addr: SocketAddrV4,
) -> Result<(DeviceId, u64), EnsureError> {
    let mine = shared.lock().dialing.insert(id);
    let outcome = dial_negotiated(shared, id, public, addr);
    if mine {
        shared.lock().dialing.remove(&id);
    }
    match outcome {
        Ok(Some((stream, registered))) => {
            let conn = registered.conn;
            let closer = stream.try_clone().ok();
            let worker = Arc::clone(shared);
            if shared.spawn("net-chan", move || {
                crate::conn::run_channel(&worker, stream, registered)
            }) {
                Ok((id, conn))
            } else {
                if let Some(closer) = closer {
                    let _ = closer.shutdown(Shutdown::Both);
                }
                let mut state = shared.lock();
                if state.channels.get(&id).is_some_and(|e| e.conn == conn) {
                    state.channels.remove(&id);
                }
                Err(EnsureError::Unreachable)
            }
        }
        // A duplicate was resolved in favour of the other connection.
        Ok(None) => shared
            .lock()
            .channels
            .get(&id)
            .map(|e| (id, e.conn))
            .ok_or(EnsureError::Unreachable),
        Err(DialFail::Channel(ChannelError::KeyMismatch { .. })) => Err(EnsureError::IdMismatch),
        Err(DialFail::Channel(ChannelError::Refused)) => Err(EnsureError::NotPaired),
        Err(_) => Err(EnsureError::Unreachable),
    }
}

fn run_dial(shared: &Arc<Shared>, id: DeviceId, public: [u8; 32], addr: SocketAddrV4) {
    let outcome = dial_negotiated(shared, id, public, addr).map_err(|fail| match fail {
        DialFail::Channel(error) => error,
        DialFail::ClosedBeforeMsg2 => ChannelError::Protocol,
    });
    let now = shared.mono.now();
    let mut state = shared.lock();
    state.dialing.remove(&id);
    match outcome {
        Ok(Some(stream_and_conn)) => {
            drop(state);
            let (stream, conn) = stream_and_conn;
            crate::conn::run_channel(shared, stream, conn);
        }
        Ok(None) => {}
        Err(ChannelError::Refused) => {
            state.link.refused_by_peer(&id, now);
            drop(state);
            shared.events.emit(NetEvent::RefusedByPeer(id));
        }
        Err(ChannelError::KeyMismatch { presented }) => {
            // Warn only when the pin's own last known address answered with another key; an
            // announced hint never produces a warning (FR-028).
            if state.registry.get(&id).and_then(|p| p.last_addr) == Some(addr) {
                state.link.warn_unpaired_key(addr, presented, id);
            }
            state.link.dial_failed(&id, now);
            drop(state);
            shared
                .events
                .emit(NetEvent::PeerRefused(presented, Refusal::KeyMismatch));
        }
        Err(_) => state.link.dial_failed(&id, now),
    }
}

type Opened = (TcpStream, crate::conn::Registered);

enum DialFail {
    Channel(ChannelError),
    /// The peer closed the connection before Noise message 2 (a v1-only peer on Hello v2).
    ClosedBeforeMsg2,
}

impl From<ChannelError> for DialFail {
    fn from(error: ChannelError) -> Self {
        Self::Channel(error)
    }
}

/// Runs the dialer handshake with Hello `version`. `Ok(None)`: a duplicate was kept instead.
fn dial_channel(
    shared: &Arc<Shared>,
    id: DeviceId,
    public: [u8; 32],
    addr: SocketAddrV4,
    version: HelloVersion,
) -> Result<Option<Opened>, DialFail> {
    let protocol = || DialFail::Channel(ChannelError::Protocol);
    let stream = connect(shared, addr).ok_or_else(protocol)?;
    let mut dialer =
        ChannelDialer::start_version(&shared.key, public, shared.name.clone(), version)
            .map_err(|_| protocol())?;
    for step in 0..2 {
        for frame in dialer.outgoing() {
            if write_frame(&stream, &frame).is_err() {
                return Err(if step == 0 {
                    DialFail::ClosedBeforeMsg2
                } else {
                    protocol()
                });
            }
        }
        let body = match read_frame(&stream, shared.timing.step_timeout) {
            Ok(body) => body,
            Err(FrameError::Closed) if step == 0 => return Err(DialFail::ClosedBeforeMsg2),
            Err(_) => return Err(protocol()),
        };
        if let Some(channel) = dialer.on_frame(&body)? {
            if channel.peer_id() != id {
                return Err(protocol());
            }
            return Ok(crate::conn::register(shared, &stream, channel, Some(addr))
                .map(|registered| (stream, registered)));
        }
    }
    Err(protocol())
}
