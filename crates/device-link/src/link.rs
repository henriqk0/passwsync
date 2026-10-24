//! Networking decisions without I/O (research R10): timing, dial backoff, keepalive and idle
//! close, duplicate-channel resolution, peer statuses, warnings and announce gating.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddrV4;
use std::time::Duration;

use crate::error::Error;
use crate::identity::DeviceId;
use crate::name::DeviceName;
use crate::registry::{PeerPin, PeerRegistry};

/// Protocol timers; 007 may lengthen them within the spec bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub announce: Duration,
    pub nearby_expiry: Duration,
    pub step_timeout: Duration,
    pub keepalive: Duration,
    pub idle_close: Duration,
    pub dial_backoff_min: Duration,
    pub dial_backoff_max: Duration,
    pub rescan: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            announce: Duration::from_secs(30),
            nearby_expiry: Duration::from_secs(90),
            step_timeout: Duration::from_secs(10),
            keepalive: Duration::from_secs(60),
            idle_close: Duration::from_secs(150),
            dial_backoff_min: Duration::from_secs(30),
            dial_backoff_max: Duration::from_secs(300),
            rescan: Duration::from_secs(30),
        }
    }
}

/// Runtime status of a pinned peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Connected,
    Offline,
    /// The last attempt got `Refused` (the peer revoked us or never paired).
    RefusedByPeer,
}

impl PeerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Offline => "offline",
            Self::RefusedByPeer => "refused_by_peer",
        }
    }
}

/// Shown in the UI; the [`MAX_WARNINGS`] most recent are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// A key other than the pinned one was presented at a paired device's address.
    UnpairedKeyAtAddress {
        addr: SocketAddrV4,
        presented: DeviceId,
        claimed: DeviceId,
    },
}

pub const MAX_WARNINGS: usize = 8;

/// Why a peer was refused (for the log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unpaired,
    Revoked,
    KeyMismatch,
}

/// FR-029: of two channels to the same peer, both sides keep the one whose dialer has the
/// smaller device ID. `true`: keep the existing channel and close the new one.
pub fn keep_existing(existing_dialer: DeviceId, new_dialer: DeviceId) -> bool {
    existing_dialer <= new_dialer
}

#[derive(Clone, Debug)]
struct PeerRuntime {
    status: PeerStatus,
    channel_dialer: Option<DeviceId>,
    backoff: Duration,
    next_dial: Duration,
}

pub struct Link {
    timing: Timing,
    own_id: DeviceId,
    peers: BTreeMap<DeviceId, PeerRuntime>,
    warnings: VecDeque<Warning>,
    revoked: BTreeSet<DeviceId>,
    last_announce: Option<Duration>,
    announce_now: bool,
}

impl Link {
    pub fn new(own_id: DeviceId, timing: Timing) -> Self {
        Self {
            timing,
            own_id,
            peers: BTreeMap::new(),
            warnings: VecDeque::new(),
            revoked: BTreeSet::new(),
            last_announce: None,
            announce_now: true,
        }
    }

    pub fn timing(&self) -> &Timing {
        &self.timing
    }

    pub fn own_id(&self) -> DeviceId {
        self.own_id
    }

    fn peer(&mut self, id: &DeviceId) -> &mut PeerRuntime {
        self.peers.entry(*id).or_insert(PeerRuntime {
            status: PeerStatus::Offline,
            channel_dialer: None,
            backoff: Duration::ZERO,
            next_dial: Duration::ZERO,
        })
    }

    pub fn status(&self, id: &DeviceId) -> PeerStatus {
        self.peers.get(id).map_or(PeerStatus::Offline, |p| p.status)
    }

    pub fn channel_dialer(&self, id: &DeviceId) -> Option<DeviceId> {
        self.peers.get(id).and_then(|p| p.channel_dialer)
    }

    // --- dialing ---

    /// Not connected and the backoff has elapsed.
    pub fn may_dial(&mut self, id: &DeviceId, now: Duration) -> bool {
        let peer = self.peer(id);
        peer.channel_dialer.is_none() && now >= peer.next_dial
    }

    /// 30 s, doubling up to 300 s.
    pub fn dial_failed(&mut self, id: &DeviceId, now: Duration) {
        let (min, max) = (self.timing.dial_backoff_min, self.timing.dial_backoff_max);
        let peer = self.peer(id);
        peer.backoff = if peer.backoff.is_zero() {
            min
        } else {
            (peer.backoff * 2).min(max)
        };
        peer.next_dial = now + peer.backoff;
    }

    /// An announcement from the peer: try again at once.
    pub fn on_announce(&mut self, id: &DeviceId, now: Duration) {
        let peer = self.peer(id);
        peer.backoff = Duration::ZERO;
        peer.next_dial = now;
    }

    /// Network change: retry every offline peer at once.
    pub fn reset_backoffs(&mut self, now: Duration) {
        for peer in self.peers.values_mut() {
            peer.backoff = Duration::ZERO;
            peer.next_dial = now;
        }
    }

    pub fn connected(&mut self, id: &DeviceId, dialer: DeviceId) {
        let peer = self.peer(id);
        peer.status = PeerStatus::Connected;
        peer.channel_dialer = Some(dialer);
        peer.backoff = Duration::ZERO;
    }

    pub fn disconnected(&mut self, id: &DeviceId, now: Duration) {
        let peer = self.peer(id);
        if peer.status == PeerStatus::Connected {
            peer.status = PeerStatus::Offline;
        }
        peer.channel_dialer = None;
        peer.next_dial = peer.next_dial.max(now);
    }

    pub fn refused_by_peer(&mut self, id: &DeviceId, now: Duration) {
        self.dial_failed(id, now);
        self.peer(id).status = PeerStatus::RefusedByPeer;
    }

    /// Drops all runtime state of a peer (revoked).
    pub fn forget(&mut self, id: &DeviceId) {
        self.peers.remove(id);
    }

    // --- channel timers ---

    pub fn keepalive_due(&self, last_sent: Duration, now: Duration) -> bool {
        now.saturating_sub(last_sent) >= self.timing.keepalive
    }

    pub fn idle_expired(&self, last_received: Duration, now: Duration) -> bool {
        now.saturating_sub(last_received) >= self.timing.idle_close
    }

    /// Time until the next keepalive or idle deadline.
    pub fn next_wake(
        &self,
        last_sent: Duration,
        last_received: Duration,
        now: Duration,
    ) -> Duration {
        let keepalive = (last_sent + self.timing.keepalive).saturating_sub(now);
        let idle = (last_received + self.timing.idle_close).saturating_sub(now);
        keepalive.min(idle)
    }

    // --- names ---

    /// Only called for messages from an authenticated channel.
    pub fn on_name_update(
        &mut self,
        registry: &mut PeerRegistry,
        id: &DeviceId,
        name: DeviceName,
    ) -> Result<(), Error> {
        if registry.get(id).is_some_and(|p| p.name == name) {
            return Ok(());
        }
        registry.update_name(id, name)
    }

    // --- trust ---

    /// Revocation (FR-033): the pin is removed and saved first; only after a successful save
    /// is the peer marked revoked and its channel forgotten. A failed save changes nothing.
    pub fn revoke(&mut self, registry: &mut PeerRegistry, id: &DeviceId) -> Result<PeerPin, Error> {
        let removed = registry.revoke(id)?;
        self.revoked(*id);
        Ok(removed)
    }

    pub fn revoked(&mut self, id: DeviceId) {
        self.revoked.insert(id);
        self.forget(&id);
    }

    pub fn paired(&mut self, id: DeviceId) {
        self.revoked.remove(&id);
    }

    pub fn refusal_reason(&self, id: &DeviceId) -> Refusal {
        if self.revoked.contains(id) {
            Refusal::Revoked
        } else {
            Refusal::Unpaired
        }
    }

    pub fn warn_unpaired_key(
        &mut self,
        addr: SocketAddrV4,
        presented: DeviceId,
        claimed: DeviceId,
    ) {
        let warning = Warning::UnpairedKeyAtAddress {
            addr,
            presented,
            claimed,
        };
        if self.warnings.contains(&warning) {
            return;
        }
        if self.warnings.len() == MAX_WARNINGS {
            self.warnings.pop_front();
        }
        self.warnings.push_back(warning);
    }

    pub fn warnings(&self) -> Vec<Warning> {
        self.warnings.iter().cloned().collect()
    }

    pub fn clear_warnings(&mut self) {
        self.warnings.clear();
    }

    // --- announcements (FR-013, FR-013a) ---

    /// Requests an immediate announcement (start, network change, code shown).
    pub fn announce_soon(&mut self) {
        self.announce_now = true;
    }

    /// Whether to send an announcement now. Never without a pin or an active code.
    pub fn should_announce(&mut self, now: Duration, has_pins: bool, code_active: bool) -> bool {
        if !has_pins && !code_active {
            return false;
        }
        let due = self.announce_now
            || self
                .last_announce
                .is_none_or(|at| now.saturating_sub(at) >= self.timing.announce);
        if due {
            self.announce_now = false;
            self.last_announce = Some(now);
        }
        due
    }
}
