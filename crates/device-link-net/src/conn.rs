//! One accepted connection: Hello dispatch, then the pairing initiator driver (A side).

use std::net::{IpAddr, Shutdown, SocketAddrV4, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use device_link::channel::{Channel, ChannelError, ChannelResponder};
use device_link::error::DropReason;
use device_link::identity::DeviceId;
use device_link::link::keep_existing;
use device_link::pairing::{InitiatorState, PairingInitiator, Role};
use device_link::wire::{CloseReason, HelloKind, Payload, parse_hello_versioned};

use crate::framed::{FrameError, read_frame, write_frame};
use crate::{ChannelEntry, Disconnect, NetEvent, Shared, UnauthSlot};

pub(crate) fn count_frame_error(shared: &Shared, error: FrameError) {
    match error {
        FrameError::Timeout => shared.counters.count(DropReason::Timeout),
        FrameError::Oversized => shared.counters.count(DropReason::Oversized),
        FrameError::Malformed => shared.counters.count(DropReason::Malformed),
        FrameError::Closed | FrameError::Io => {}
    }
}

pub(crate) fn serve(shared: &Arc<Shared>, stream: TcpStream) {
    let mut unauth = UnauthSlot::new(&shared.unauth);
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(shared.timing.step_timeout));
    let hello = match read_frame(&stream, shared.timing.step_timeout) {
        Ok(hello) => hello,
        Err(error) => return count_frame_error(shared, error),
    };
    // 004: channel Hello v1 and v2 are accepted; pairing stays v1 (contracts/sync-protocol.md).
    match parse_hello_versioned(&hello) {
        Ok((HelloKind::Pairing, _)) => serve_pairing(shared, &stream, &hello),
        Ok((HelloKind::Channel, _)) => serve_channel(shared, stream, &hello, &mut unauth),
        Err(_) => shared.counters.count(DropReason::Malformed),
    }
}

/// Drives `PairingInitiator` for the session that shows the code. Refuses at once when no
/// code is shown or an exchange is already running (FR-025).
fn serve_pairing(shared: &Arc<Shared>, stream: &TcpStream, hello: &[u8]) {
    let generation = {
        let mut state = shared.lock();
        let now = shared.mono.now();
        let ready = state
            .pairing
            .as_ref()
            .is_some_and(|s| s.machine.is_none() && s.code.is_active(now));
        if !ready || !state.slot.try_acquire(Role::Initiator) {
            return;
        }
        let session = state.pairing.as_mut().unwrap_or_else(|| unreachable!());
        session.machine = Some(PairingInitiator::new(
            &shared.key,
            shared.name.clone(),
            hello,
        ));
        session.stream = stream.try_clone().ok();
        session.generation
    };
    let outcome = drive_initiator(shared, stream, generation);
    let mut state = shared.lock();
    state.slot.release();
    if let Some(session) = state
        .pairing
        .as_mut()
        .filter(|s| s.generation == generation)
    {
        session.stream = None;
    }
    drop(state);
    if let Some(InitiatorState::Failed(reason)) = outcome {
        shared.events.emit(NetEvent::PairingFailed(reason));
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn drive_initiator(
    shared: &Arc<Shared>,
    stream: &TcpStream,
    generation: u64,
) -> Option<InitiatorState> {
    loop {
        // While the person decides, wake at the code's expiry; otherwise the step timeout.
        let timeout = {
            let state = shared.lock();
            let session = state
                .pairing
                .as_ref()
                .filter(|s| s.generation == generation)?;
            let machine = session.machine.as_ref()?;
            if machine.awaiting_acceptance() || machine.awaiting_ack() {
                session
                    .code
                    .expires_at()
                    .saturating_sub(shared.mono.now())
                    .max(
                        shared
                            .timing
                            .step_timeout
                            .min(std::time::Duration::from_millis(100)),
                    )
                    .min(std::time::Duration::from_secs(310))
            } else {
                shared.timing.step_timeout
            }
        };
        let read = read_frame(stream, timeout);
        let now = shared.mono.now();
        let mut guard = shared.lock();
        let state = &mut *guard;
        let session = state
            .pairing
            .as_mut()
            .filter(|s| s.generation == generation)?;
        let machine = session.machine.as_mut()?;
        match read {
            Ok(body) => machine.on_frame(&body, Some(&mut session.code), &state.registry, now),
            Err(FrameError::Timeout) if machine.awaiting_acceptance() => {
                machine.tick(Some(&mut session.code), now)
            }
            Err(FrameError::Timeout) => machine.on_timeout(Some(&mut session.code)),
            Err(_) => machine.on_closed(Some(&mut session.code)),
        }
        for frame in machine.outgoing() {
            if write_frame(stream, &frame).is_err() {
                break;
            }
        }
        let current = machine.state();
        if machine.is_done() {
            return Some(current);
        }
        if shared.stopping() {
            machine.on_closed(Some(&mut session.code));
            return Some(machine.state());
        }
    }
}

/// Responder side of a channel (contracts/peer-protocol.md "Channel").
fn serve_channel(
    shared: &Arc<Shared>,
    stream: TcpStream,
    hello: &[u8],
    unauth: &mut UnauthSlot<'_>,
) {
    let peer_ip = match stream.peer_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(ip)) => ip,
        _ => return,
    };
    let mut responder = ChannelResponder::new(&shared.key, shared.name.clone(), hello);
    let is_pinned = |key: &[u8; 32]| shared.lock().registry.is_pinned_key(key);
    let mut channel = None;
    for _ in 0..2 {
        let body = match read_frame(&stream, shared.timing.step_timeout) {
            Ok(body) => body,
            Err(error) => return count_frame_error(shared, error),
        };
        let result = responder.on_frame(&body, &is_pinned);
        for frame in responder.outgoing() {
            if write_frame(&stream, &frame).is_err() {
                return;
            }
        }
        match result {
            Ok(None) => {}
            Ok(Some(open)) => {
                channel = Some(open);
                break;
            }
            Err(ChannelError::Unpaired { presented }) => {
                let mut state = shared.lock();
                let reason = state.link.refusal_reason(&presented);
                // An unknown key from a paired device's last address: warn (FR-028).
                let claimed = state
                    .registry
                    .list()
                    .iter()
                    .find(|p| p.last_addr.is_some_and(|a| *a.ip() == peer_ip))
                    .map(|p| (p.id(), p.last_addr));
                if let Some((claimed, Some(addr))) = claimed {
                    state.link.warn_unpaired_key(addr, presented, claimed);
                }
                drop(state);
                shared.events.emit(NetEvent::PeerRefused(presented, reason));
                return;
            }
            Err(_) => return,
        }
    }
    let Some(channel) = channel else { return };
    unauth.release();
    if let Some(conn) = register(shared, &stream, channel, None) {
        run_channel(shared, stream, conn);
    }
}

/// Records an authenticated channel, resolving duplicates (FR-029). Returns the entry's
/// connection number, or `None` if this channel was closed in favour of another.
pub(crate) fn register(
    shared: &Arc<Shared>,
    stream: &TcpStream,
    channel: Channel,
    dialed: Option<SocketAddrV4>,
) -> Option<Registered> {
    let id = channel.peer_id();
    let dialer = channel.dialer_id();
    let peer_name = channel.peer_name().clone();
    let sync = channel.sync_enabled();
    let (session, is_dialer) = (channel.session_hash(), channel.is_dialer());
    let channel = Arc::new(Mutex::new(channel));
    let last_sent = Arc::new(Mutex::new(shared.mono.now()));
    let entry = ChannelEntry {
        conn: 0,
        dialer,
        stream: stream.try_clone().ok()?,
        channel: Arc::clone(&channel),
        last_sent: Arc::clone(&last_sent),
        sync,
    };
    let now_unix = shared.wall.unix_now();
    let mut state = shared.lock();
    if shared.stopping() || !state.registry.contains(&id) {
        drop(state);
        entry.close(CloseReason::Shutdown);
        return None;
    }
    if let Some(existing) = state.channels.get(&id) {
        if keep_existing(existing.dialer, dialer) {
            drop(state);
            entry.close(CloseReason::Duplicate);
            return None;
        }
        if let Some(old) = state.channels.remove(&id) {
            old.close(CloseReason::Duplicate);
        }
    }
    let conn = state.next_conn;
    state.next_conn += 1;
    state.channels.insert(id, ChannelEntry { conn, ..entry });
    state.link.connected(&id, dialer);
    state.registry.touch(&id, now_unix, dialed);
    let State { link, registry, .. } = &mut *state;
    let _ = link.on_name_update(registry, &id, peer_name);
    drop(state);
    shared.events.emit(NetEvent::PeerConnected(id));
    if sync {
        if let Some(sink) = shared.sync_sink() {
            sink.channel_up(id, conn, session, is_dialer);
        }
    }
    Some(Registered {
        conn,
        id,
        channel,
        last_sent,
        sync,
    })
}

/// An authenticated channel as registered (connection number and shared parts).
pub(crate) struct Registered {
    pub conn: u64,
    pub id: DeviceId,
    pub channel: Arc<Mutex<Channel>>,
    pub last_sent: Arc<Mutex<std::time::Duration>>,
    pub sync: bool,
}

use crate::State;

/// The channel's life: keepalives, idle close, name updates, close (R10). Blocking reads
/// with a timeout until the next deadline; no polling (FR-039).
pub(crate) fn run_channel(shared: &Arc<Shared>, stream: TcpStream, registered: Registered) {
    let Registered {
        conn,
        id,
        channel,
        last_sent: sent_clock,
        sync,
    } = registered;
    let timing = shared.timing;
    let last_sent = || {
        *sent_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let mut last_received = shared.mono.now();
    let why = loop {
        if shared.stopping() {
            break Disconnect::Closed;
        }
        let now = shared.mono.now();
        let keepalive = (last_sent() + timing.keepalive).saturating_sub(now);
        let idle = (last_received + timing.idle_close).saturating_sub(now);
        let wait = keepalive.min(idle).max(Duration::from_millis(5));
        let read = read_frame(&stream, wait);
        shared
            .wakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match read {
            Ok(frame) => {
                let opened = channel
                    .lock()
                    .map_err(|_| ChannelError::Protocol)
                    .and_then(|mut c| c.open(&frame));
                last_received = shared.mono.now();
                match opened {
                    Ok(Payload::Keepalive) => {}
                    Ok(Payload::NameUpdate { name }) => {
                        let mut state = shared.lock();
                        let State { link, registry, .. } = &mut *state;
                        let _ = link.on_name_update(registry, &id, name);
                    }
                    Ok(Payload::Close { reason }) => {
                        break match reason {
                            CloseReason::Duplicate => Disconnect::Duplicate,
                            CloseReason::Shutdown => Disconnect::Closed,
                        };
                    }
                    // 004: sync frames (accepted by `open` only on channel v2).
                    Ok(payload @ (Payload::SyncCtl { .. } | Payload::CopyData { .. })) => {
                        if let Some(sink) = shared.sync_sink() {
                            sink.frame(id, conn, payload);
                        }
                    }
                    Ok(_) | Err(_) => break Disconnect::Error,
                }
                let now_unix = shared.wall.unix_now();
                shared.lock().registry.touch(&id, now_unix, None);
            }
            Err(FrameError::Timeout) => {
                let now = shared.mono.now();
                if now.saturating_sub(last_received) >= timing.idle_close {
                    break Disconnect::Timeout;
                }
                if now.saturating_sub(last_sent()) >= timing.keepalive {
                    // Seal and write under the channel mutex (as `send_sync` does).
                    let sent = channel.lock().ok().and_then(|mut c| {
                        let frame = c.seal(&Payload::Keepalive).ok()?;
                        write_frame(&stream, &frame).ok()
                    });
                    match sent {
                        Some(()) => {
                            *sent_clock
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = now;
                        }
                        None => break Disconnect::Error,
                    }
                }
            }
            Err(FrameError::Oversized | FrameError::Malformed) => break Disconnect::Error,
            Err(_) => break Disconnect::Closed,
        }
    };
    let _ = stream.shutdown(Shutdown::Both);
    let now = shared.mono.now();
    let mut state = shared.lock();
    let current = state.channels.get(&id).is_some_and(|e| e.conn == conn);
    if current {
        state.channels.remove(&id);
        state.link.disconnected(&id, now);
        // last_seen is saved when a channel closes, not on every message (R11).
        let _ = state.registry.persist();
    }
    let still_paired = state.registry.contains(&id);
    drop(state);
    if sync {
        if let Some(sink) = shared.sync_sink() {
            sink.channel_down(id, conn);
        }
    }
    if current && still_paired && !shared.stopping() {
        shared.events.emit(NetEvent::PeerDisconnected(id, why));
    }
}
