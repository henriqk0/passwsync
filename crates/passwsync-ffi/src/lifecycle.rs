#![forbid(unsafe_code)]
//! Foreground/background state and the core sweeper (data-model.md section 6; contracts
//! ffi-api.md section 7). The sweeper runs every period while the app is in the foreground and
//! parks in the background; deadlines in the background come from `on_deadline`.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::api::Inner;

/// Whether the node lingering after the foreground should pause now (FR-042): after `linger`
/// without a running transfer, and in any case after `cap`.
pub fn linger_should_pause(
    elapsed: Duration,
    transfer_running: bool,
    linger: Duration,
    cap: Duration,
) -> bool {
    elapsed >= cap || (!transfer_running && elapsed >= linger)
}

#[derive(Debug, Default)]
struct State {
    foreground: bool,
    stop: bool,
    /// Left the foreground at this time with the node still running.
    linger_since: Option<Instant>,
}

/// What the sweeper thread does next.
enum Wake {
    Sweep,
    Linger(Duration),
    Stop,
}

/// Shared by the core and its sweeper thread.
#[derive(Debug, Default)]
pub struct Lifecycle {
    state: Mutex<State>,
    wake: Condvar,
}

impl Lifecycle {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn is_foreground(&self) -> bool {
        self.state().foreground
    }

    /// Enters the foreground and wakes the sweeper; any linger ends.
    pub fn enter_foreground(&self) {
        let mut state = self.state();
        state.foreground = true;
        state.linger_since = None;
        drop(state);
        self.wake.notify_all();
    }

    /// Enters the background; the sweeper parks after its current pass, after pausing the
    /// node at the end of the linger when `node_running`.
    pub fn enter_background(&self, node_running: bool) {
        let mut state = self.state();
        state.foreground = false;
        state.linger_since = node_running.then(Instant::now);
        drop(state);
        self.wake.notify_all();
    }

    /// The linger is over (node paused) or taken over by a sync window.
    pub fn end_linger(&self) {
        self.state().linger_since = None;
    }

    /// Stops the sweeper for good.
    pub fn stop(&self) {
        self.state().stop = true;
        self.wake.notify_all();
    }

    /// Waits until the next sweep or linger check is due.
    fn next(&self, period: Duration) -> Wake {
        const LINGER_POLL: Duration = Duration::from_millis(100);
        let mut state = self.state();
        loop {
            if state.stop {
                return Wake::Stop;
            }
            if state.foreground {
                let (next, _) = self
                    .wake
                    .wait_timeout(state, period)
                    .unwrap_or_else(PoisonError::into_inner);
                state = next;
                if state.stop {
                    return Wake::Stop;
                }
                if state.foreground {
                    return Wake::Sweep;
                }
                continue;
            }
            if let Some(since) = state.linger_since {
                let (next, _) = self
                    .wake
                    .wait_timeout(state, LINGER_POLL)
                    .unwrap_or_else(PoisonError::into_inner);
                state = next;
                if state.stop {
                    return Wake::Stop;
                }
                if !state.foreground && state.linger_since == Some(since) {
                    return Wake::Linger(since.elapsed());
                }
                continue;
            }
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// The sweeper thread. Holds only a weak reference: dropping the core ends it.
pub fn spawn_sweeper(inner: Weak<Inner>, period: Duration) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("passwsync-sweeper".into())
        .spawn(move || {
            loop {
                let Some(core) = inner.upgrade() else { break };
                let lifecycle = core.lifecycle();
                drop(core);
                let wake = lifecycle.next(period);
                let Some(core) = inner.upgrade() else { break };
                match wake {
                    Wake::Stop => break,
                    Wake::Sweep => core.sweep(),
                    Wake::Linger(elapsed) => core.linger_check(elapsed),
                }
            }
        })
}
