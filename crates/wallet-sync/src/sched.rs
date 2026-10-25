//! Scheduling of sync rounds (research R14, FR-027, FR-028).

use std::time::Duration;

/// Timings of the sync scheduler (production defaults; tests shorten them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncTiming {
    /// Quiet period after a local save before rounds start (coalesces bursts of edits).
    pub quiet: Duration,
    /// Safety interval between rounds with one peer (`sync_interval_minutes`).
    pub safety: Duration,
    /// First retry delay after a failed round; doubles up to `backoff_max`.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// No progress for this long fails a round.
    pub round_timeout: Duration,
}

impl Default for SyncTiming {
    fn default() -> Self {
        Self {
            quiet: Duration::from_secs(5),
            safety: Duration::from_secs(60 * 60),
            backoff_min: Duration::from_secs(30),
            backoff_max: Duration::from_secs(60 * 60),
            round_timeout: Duration::from_secs(30),
        }
    }
}

use std::collections::BTreeMap;

use rand_core::RngCore;

use crate::ports::PeerId;
use crate::round::RoundClass;

#[derive(Default)]
struct PeerSched {
    legacy: bool,
    connected: bool,
    /// A round is wanted from this time on (channel up, unlock, sync now, retry).
    due_at: Option<Duration>,
    /// "Sync now": ignore the backoff once.
    bypass: bool,
    backoff_until: Option<Duration>,
    failures: u32,
    next_safety: Option<Duration>,
}

/// When to start rounds with which peer (FR-027 a-e, FR-028). Sans-IO: the host asks
/// [`Scheduler::due`] at [`Scheduler::next_deadline`] and reports finished rounds.
pub struct Scheduler {
    timing: SyncTiming,
    rng: Box<dyn RngCore + Send>,
    peers: BTreeMap<PeerId, PeerSched>,
    dirty_since: Option<Duration>,
}

impl Scheduler {
    pub fn new(timing: SyncTiming, rng: Box<dyn RngCore + Send>) -> Self {
        Self {
            timing,
            rng,
            peers: BTreeMap::new(),
            dirty_since: None,
        }
    }

    pub fn timing(&self) -> &SyncTiming {
        &self.timing
    }

    /// `d` scaled by a random factor in [0.8, 1.2].
    fn jitter(&mut self, d: Duration) -> Duration {
        let permille = 800 + self.rng.next_u64() % 401;
        d * permille as u32 / 1000
    }

    fn eligible(p: &PeerSched) -> bool {
        p.connected && !p.legacy
    }

    /// (a) A sync-enabled channel came up.
    pub fn channel_up(&mut self, peer: PeerId, now: Duration) {
        let safety = self.jitter(self.timing.safety);
        let p = self.peers.entry(peer).or_default();
        p.connected = true;
        p.due_at = Some(now);
        p.next_safety = Some(now + safety);
    }

    pub fn channel_down(&mut self, peer: PeerId) {
        if let Some(p) = self.peers.get_mut(&peer) {
            p.connected = false;
            p.due_at = None;
            p.bypass = false;
        }
    }

    /// A v1-only peer is never scheduled.
    pub fn set_legacy(&mut self, peer: PeerId, legacy: bool) {
        self.peers.entry(peer).or_default().legacy = legacy;
    }

    /// (b) A wallet was saved locally: after the quiet period, rounds with every peer.
    pub fn wallet_saved(&mut self, now: Duration) {
        self.dirty_since.get_or_insert(now);
    }

    /// (c) A wallet was unlocked with pending copies.
    pub fn unlocked_with_pending(&mut self, now: Duration) {
        for p in self.peers.values_mut().filter(|p| Self::eligible(p)) {
            p.due_at.get_or_insert(now);
        }
    }

    /// (d) "Sync now": every connected peer not already in a round, bypassing the backoff
    /// once. Presses during a running round do nothing.
    pub fn sync_now(&mut self, now: Duration, running: &dyn Fn(PeerId) -> bool) {
        for (peer, p) in self.peers.iter_mut() {
            if Self::eligible(p) && !running(*peer) {
                p.due_at = Some(now);
                p.bypass = true;
            }
        }
    }

    /// A round ended: success resets the backoff; a failure backs off exponentially (30 s
    /// doubling to 1 h, jittered); `Busy` backs off without counting as a failure.
    pub fn round_finished(&mut self, peer: PeerId, class: RoundClass, now: Duration) {
        let safety = self.jitter(self.timing.safety);
        let failures = self.peers.get(&peer).map_or(0, |p| p.failures);
        let delay = match class {
            RoundClass::Ok => None,
            RoundClass::Busy => Some(self.timing.backoff_min),
            _ => {
                let exp = failures.min(16);
                Some(
                    self.timing
                        .backoff_min
                        .saturating_mul(1u32 << exp)
                        .min(self.timing.backoff_max),
                )
            }
        };
        let delay = delay.map(|d| self.jitter(d));
        let p = self.peers.entry(peer).or_default();
        p.next_safety = Some(now + safety);
        match (class, delay) {
            (RoundClass::Ok, _) | (_, None) => {
                p.failures = 0;
                p.backoff_until = None;
            }
            (RoundClass::Busy, Some(d)) => {
                p.backoff_until = Some(now + d);
                p.due_at = Some(now);
            }
            (_, Some(d)) => {
                p.failures = p.failures.saturating_add(1);
                p.backoff_until = Some(now + d);
                p.due_at = Some(now);
            }
        }
    }

    /// Peers whose round should start now (not `running`).
    pub fn due(&mut self, now: Duration, running: &dyn Fn(PeerId) -> bool) -> Vec<PeerId> {
        if self
            .dirty_since
            .is_some_and(|since| now >= since + self.timing.quiet)
        {
            self.dirty_since = None;
            for p in self.peers.values_mut().filter(|p| Self::eligible(p)) {
                p.due_at.get_or_insert(now);
            }
        }
        let mut out = Vec::new();
        for (peer, p) in self.peers.iter_mut() {
            if !Self::eligible(p) || running(*peer) {
                continue;
            }
            if p.next_safety.is_some_and(|t| now >= t) {
                p.due_at.get_or_insert(now);
            }
            let Some(at) = p.due_at else { continue };
            let backoff_over = p.bypass || p.backoff_until.is_none_or(|u| now >= u);
            if now >= at && backoff_over {
                p.due_at = None;
                p.bypass = false;
                out.push(*peer);
            }
        }
        out
    }

    /// The earliest time something may become due; `None` when nothing can (no timers).
    pub fn next_deadline(&self) -> Option<Duration> {
        let eligible: Vec<&PeerSched> = self.peers.values().filter(|p| Self::eligible(p)).collect();
        if eligible.is_empty() {
            return None;
        }
        let mut best = self.dirty_since.map(|s| s + self.timing.quiet);
        let mut consider = |t: Duration| best = Some(best.map_or(t, |b| b.min(t)));
        for p in eligible {
            if let Some(at) = p.due_at {
                let gate = if p.bypass { None } else { p.backoff_until };
                consider(gate.map_or(at, |g| g.max(at)));
            }
            if let Some(t) = p.next_safety {
                let gate = p.backoff_until.unwrap_or(t);
                consider(t.max(gate));
            }
        }
        best
    }
}
