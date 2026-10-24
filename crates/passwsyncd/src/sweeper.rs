//! Background auto-lock: every 15 s, lock wallets after a suspend or after the idle timeout,
//! and log the aggregated rejection counts (FR-019, FR-020a, SC-004). Waits on a condition
//! variable between ticks, so it never busy-polls (SC-008).

use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wallet_service::{ElapsedClock, Service};

use crate::app::Stopper;
use crate::log::{LockReason, Log, LogEvent, Rejections};

pub const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Locks everything if a suspend is detected, logging it. Also runs before every request.
pub fn lock_if_suspended(service: &Service, log: &Log) {
    if let Some(locked) = service.check_suspend() {
        log.emit(&LogEvent::SuspendDetected);
        for wallet in &locked {
            log.emit(&LogEvent::Locked {
                wallet,
                reason: LockReason::Suspend,
            });
        }
    }
}

/// One sweep: suspend check, idle locks, rejection summary.
pub fn tick(service: &Service, rejections: &Rejections, log: &Log, clock: &dyn ElapsedClock) {
    lock_if_suspended(service, log);
    for wallet in &service.sweep() {
        log.emit(&LogEvent::Locked {
            wallet,
            reason: LockReason::Idle,
        });
    }
    if let Some(line) = rejections.flush(clock.monotonic()) {
        log.emit(&line);
    }
}

pub fn spawn(
    service: Arc<Service>,
    rejections: Arc<Rejections>,
    log: Log,
    clock: Arc<dyn ElapsedClock>,
    stopper: Stopper,
    extra: Box<dyn Fn(Duration) + Send>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("sweeper".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            while !stopper.wait_timeout(SWEEP_INTERVAL) {
                tick(&service, &rejections, &log, clock.as_ref());
                extra(clock.monotonic());
            }
        })
}
