//! OS clocks for idle auto-lock (monotonic, stops in suspend) and suspend detection
//! (boot time, keeps counting in suspend).

use std::time::Duration;

use rustix::time::{ClockId, clock_gettime};
use wallet_service::ElapsedClock;

#[derive(Clone, Copy, Debug, Default)]
pub struct OsElapsedClock;

fn read(id: ClockId) -> Duration {
    let time = clock_gettime(id);
    Duration::new(
        u64::try_from(time.tv_sec).unwrap_or(0),
        u32::try_from(time.tv_nsec).unwrap_or(0),
    )
}

impl ElapsedClock for OsElapsedClock {
    fn monotonic(&self) -> Duration {
        read(ClockId::Monotonic)
    }

    fn boottime(&self) -> Duration {
        read(ClockId::Boottime)
    }
}
