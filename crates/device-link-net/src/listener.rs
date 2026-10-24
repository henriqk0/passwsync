//! The bounded accept loop (FR-030, R8): peer address policy, local address on an in-use
//! interface, at most 16 unauthenticated connections; excess closed at once and counted.

use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use device_link::error::DropReason;

use crate::{MAX_UNAUTHENTICATED, Shared, conn};

pub(crate) fn run(shared: &Arc<Shared>, listener: TcpListener) {
    for stream in listener.incoming() {
        if shared.stopping() {
            break;
        }
        let Ok(stream) = stream else { continue };
        let (Ok(peer), Ok(local)) = (stream.peer_addr(), stream.local_addr()) else {
            continue;
        };
        let peer_ok = match peer.ip() {
            IpAddr::V4(ip) => shared.policy.allows_v4(ip),
            IpAddr::V6(_) => false,
        };
        let local_ok = match local.ip() {
            IpAddr::V4(ip) => shared.lock().interfaces.iter().any(|i| i.addr == ip),
            IpAddr::V6(_) => false,
        };
        if !peer_ok || !local_ok {
            shared.counters.count(DropReason::Public);
            continue;
        }
        if shared.unauth.fetch_add(1, Ordering::SeqCst) >= MAX_UNAUTHENTICATED {
            shared.unauth.fetch_sub(1, Ordering::SeqCst);
            shared.counters.count(DropReason::Overflow);
            continue;
        }
        let worker = Arc::clone(shared);
        if !shared.spawn("net-conn", move || conn::serve(&worker, stream)) {
            shared.unauth.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
