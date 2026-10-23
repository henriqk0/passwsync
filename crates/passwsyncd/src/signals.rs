//! SIGTERM, SIGINT and SIGHUP trigger an orderly stop (FR-030). `signal-hook` keeps the
//! async-signal-safe part out of our code, which forbids `unsafe`.

use std::io;
use std::thread::{self, JoinHandle};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::{Handle, Signals};

use crate::app::Stopper;

pub struct SignalThread {
    handle: Handle,
    thread: JoinHandle<()>,
}

/// Registers the handlers and starts the thread that turns the first signal into a stop.
pub fn spawn(stopper: Stopper) -> io::Result<SignalThread> {
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP])?;
    let handle = signals.handle();
    let thread = thread::Builder::new()
        .name("signals".into())
        .stack_size(128 * 1024)
        .spawn(move || {
            if signals.forever().next().is_some() {
                stopper.stop();
            }
        })?;
    Ok(SignalThread { handle, thread })
}

impl SignalThread {
    pub fn close(self) {
        self.handle.close();
        let _ = self.thread.join();
    }
}
