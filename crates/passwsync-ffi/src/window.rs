#![forbid(unsafe_code)]
//! The background sync window and the background plan (US5; contracts/ffi-api.md section 5,
//! FR-011, FR-044 to FR-048). A window resumes the node, lets the 004 rounds run with every
//! reachable paired device, stops early once they are idle or at the time limit, pauses the
//! node again and runs the received-wallet expiry sweep. It never unlocks a wallet and never
//! needs a password: locked wallets keep received data as ciphertext (004).

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use host_runtime::log::LogEvent;
use host_runtime::net_runtime::NetState;

use crate::api::{Inner, KEEP_NETWORK_MS, PasswsyncCore, TRANSFER_CAP_MS};
use crate::records::{BackgroundPlan, CoreEvent, WindowEnd, WindowReport};

/// How often a running window looks at the rounds.
const POLL: Duration = Duration::from_millis(50);
/// Consecutive idle polls before a window ends early.
const IDLE_POLLS: u32 = 4;

fn refused(reason: WindowEnd) -> WindowReport {
    WindowReport {
        ran: false,
        reason,
        peers_reached: 0,
        rounds: 0,
        duration_ms: 0,
    }
}

/// Clears the running flag however the window ends.
struct Running<'a>(&'a Inner);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.window_running.store(false, Ordering::SeqCst);
    }
}

impl Inner {
    /// Networking is on with a usable identity and pins.
    fn sync_possible(&self) -> bool {
        self.running.network.enabled
            && self.host.net.this_device.is_some()
            && !matches!(
                self.host.net.state(),
                NetState::IdentityUnusable | NetState::PeersUnusable | NetState::PortInUse(_)
            )
    }

    /// The full plan: deadline, periodic window, extra window and linger (FR-044, FR-046).
    pub(crate) fn plan(&self) -> BackgroundPlan {
        let mut plan = self.plan_deadline_only();
        if self.sync_possible() && self.host.net.pin_count() > 0 {
            let minutes = self.running.sync_interval.as_secs() / 60;
            plan.periodic_window_minutes = Some(u32::try_from(minutes).unwrap_or(u32::MAX));
            plan.extra_window = self.host.sync.has_unsent_changes();
        }
        plan.keep_network_ms = if self.transfer_running() {
            TRANSFER_CAP_MS
        } else {
            KEEP_NETWORK_MS
        };
        plan
    }

    fn window(&self) -> WindowReport {
        if self.lifecycle().is_foreground() {
            return refused(WindowEnd::Busy);
        }
        if !self.sync_possible() {
            return refused(WindowEnd::Off);
        }
        if self.eligible.is_empty() {
            return refused(WindowEnd::NoNetwork);
        }
        if self.host.net.pin_count() == 0 {
            return refused(WindowEnd::NoPeers);
        }
        if self.window_running.swap(true, Ordering::SeqCst) {
            return refused(WindowEnd::Busy);
        }
        let _running = Running(self);
        self.log.emit(&LogEvent::WindowStarted);
        self.lifecycle().end_linger();
        let started = Instant::now();
        self.host.net.resume();
        self.notify(CoreEvent::NetworkChanged);
        let mut reached = BTreeSet::new();
        let mut rounds = 0u32;
        let mut busy = false;
        let mut asked = false;
        let mut idle = 0u32;
        let reason = loop {
            std::thread::sleep(POLL);
            if self.lifecycle().is_foreground() {
                break WindowEnd::Finished;
            }
            if self.eligible.is_empty() {
                break WindowEnd::NoNetwork;
            }
            if started.elapsed() >= self.window_limit {
                break WindowEnd::TimeLimit;
            }
            for peer in self.snapshot().paired {
                if peer.status.as_str() == "connected" {
                    reached.insert(peer.id);
                }
            }
            if !reached.is_empty() && !asked {
                asked = self.host.sync.sync_now();
            }
            let now_busy = !self.host.sync.rounds_idle();
            if now_busy && !busy {
                rounds += 1;
            }
            busy = now_busy;
            if asked && !now_busy {
                idle += 1;
                if idle >= IDLE_POLLS {
                    break WindowEnd::Finished;
                }
            } else {
                idle = 0;
            }
        };
        if !self.lifecycle().is_foreground() {
            self.host.net.pause();
        }
        // 005: received wallets unopened for 24 h are deleted at each window.
        self.sweep_received();
        let duration = started.elapsed();
        self.log.emit(&LogEvent::WindowEnded {
            rounds,
            seconds: duration.as_secs(),
        });
        self.notify(CoreEvent::NetworkChanged);
        self.notify(CoreEvent::SyncChanged);
        WindowReport {
            ran: true,
            reason,
            peers_reached: u32::try_from(reached.len()).unwrap_or(u32::MAX),
            rounds,
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

#[uniffi::export]
impl PasswsyncCore {
    /// One background sync window (job 2 or 3): at most the window limit (120 s).
    pub fn run_sync_window(&self) -> WindowReport {
        self.inner.window()
    }

    /// The plan at app start (jobs are not persisted across reboot).
    pub fn background_plan(&self) -> BackgroundPlan {
        let core = &self.inner;
        core.housekeep();
        core.plan()
    }
}
