//! The discovery thread (R6, R8, R10): one blocking `recv_from` with a timeout up to the
//! next timer tick. Each tick re-scans interfaces, expires nearby entries, announces when
//! allowed (FR-013a) and schedules dials to offline pins. Datagrams are untrusted hints.

use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use device_link::discovery::{decode_announce, encode_announce};
use device_link::error::DropReason;
use device_link::identity::DeviceId;

use crate::{NearbyView, NetEvent, Shared, State, dialer};

pub(crate) fn nearby_view(state: &State, now: Duration) -> Vec<NearbyView> {
    state
        .nearby
        .views(now, |id| state.registry.contains(id))
        .into_iter()
        .map(|n| NearbyView {
            id: n.id,
            addr: n.addr,
            paired: n.paired,
        })
        .collect()
}

pub(crate) fn run(shared: &Arc<Shared>, udp: UdpSocket) {
    let timing = shared.timing;
    let mut next_tick = shared.mono.now();
    let mut buf = [0u8; 64];
    loop {
        if shared.stopping() {
            return;
        }
        let now = shared.mono.now();
        if now >= next_tick {
            tick(shared, now);
            next_tick = now + timing.rescan.min(timing.announce);
        }
        let wait = next_tick
            .saturating_sub(shared.mono.now())
            .max(Duration::from_millis(5));
        let _ = udp.set_read_timeout(Some(wait));
        let received = udp.recv_from(&mut buf);
        shared
            .wakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok((n, source)) = received {
            if shared.stopping() {
                return;
            }
            on_datagram(shared, &buf[..n], source);
        }
    }
}

fn on_datagram(shared: &Arc<Shared>, bytes: &[u8], source: SocketAddr) {
    let SocketAddr::V4(source) = source else {
        return shared.counters.count(DropReason::Public);
    };
    let now = shared.mono.now();
    let mut state = shared.lock();
    let in_subnet = state
        .interfaces
        .iter()
        .any(|i| i.contains(*source.ip()) && !i.is_network_or_broadcast(*source.ip()));
    if !shared.policy.allows_v4(*source.ip()) || !in_subnet {
        drop(state);
        return shared.counters.count(DropReason::Public);
    }
    let (id, port) = match decode_announce(bytes, &shared.own_id) {
        Ok(found) => found,
        Err(reason) => {
            drop(state);
            return shared.counters.count(reason);
        }
    };
    let paired = state.registry.contains(&id);
    match state.nearby.observe(id, source, port, now, paired) {
        Ok(addr) if paired => {
            // An unauthenticated hint: dial it for this attempt only; the pin's address
            // changes solely once a channel authenticates there (FR-014, FR-028).
            state.link.on_announce(&id, now);
            let connected = state.channels.contains_key(&id);
            drop(state);
            if !connected {
                dialer::dial_peer(shared, id, Some(addr));
            }
        }
        Ok(_) => {}
        Err(reason) => {
            drop(state);
            shared.counters.count(reason);
        }
    }
}

/// Sends an announcement to every in-use interface's directed broadcast when the link
/// decides one is due (never without a pin or an active code).
pub(crate) fn announce_if_due(shared: &Arc<Shared>, now: Duration) {
    let targets: Vec<Ipv4Addr> = {
        let mut state = shared.lock();
        let has_pins = !state.registry.is_empty();
        let code_active = state
            .pairing
            .as_ref()
            .is_some_and(|p| p.code.is_active(now));
        if !state.link.should_announce(now, has_pins, code_active) {
            return;
        }
        state.interfaces.iter().map(|i| i.broadcast).collect()
    };
    let packet = encode_announce(&shared.own_id, shared.peer_port);
    for broadcast in targets {
        if !shared.policy.allows_v4(broadcast) {
            continue;
        }
        for port in &shared.announce_ports {
            let _ = shared
                .udp
                .send_to(&packet, SocketAddrV4::new(broadcast, *port));
        }
    }
}

fn tick(shared: &Arc<Shared>, now: Duration) {
    let scanned = shared.interfaces_src.scan();
    let mut state = shared.lock();
    state.nearby.expire(now);
    if scanned != state.interfaces {
        state.interfaces = scanned.clone();
        state.link.reset_backoffs(now);
        state.link.announce_soon();
        if scanned.is_empty() {
            // No local network: close every channel.
            let closed: Vec<_> = state.channels.drain().collect();
            for (id, entry) in closed {
                let _ = entry.stream.shutdown(Shutdown::Both);
                state.link.disconnected(&id, now);
            }
        }
        let names = scanned.iter().map(|i| i.name.clone()).collect();
        drop(state);
        shared.events.emit(NetEvent::InterfacesChanged(names));
        state = shared.lock();
    }
    let offline: Vec<DeviceId> = state
        .registry
        .list()
        .iter()
        .map(|p| p.id())
        .filter(|id| !state.channels.contains_key(id))
        .collect();
    drop(state);
    announce_if_due(shared, now);
    for id in offline {
        dialer::dial_peer(shared, id, None);
    }
}
