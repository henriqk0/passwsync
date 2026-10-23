use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Timestamp;

/// Source of "now" so timestamps are deterministic in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as Timestamp)
    }
}

/// Test clock that only moves when told to.
pub struct FixedClock(AtomicI64);

impl FixedClock {
    pub fn new(now: Timestamp) -> Self {
        Self(AtomicI64::new(now))
    }

    pub fn set(&self, now: Timestamp) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_returns_set_time() {
        let clock = FixedClock::new(100);
        assert_eq!(clock.now(), 100);
        clock.set(500);
        assert_eq!(clock.now(), 500);
        clock.advance(7);
        assert_eq!(clock.now(), 507);
    }

    #[test]
    fn system_clock_is_close_to_system_time() {
        let expected = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((SystemClock.now() - expected).abs() <= 5);
    }
}
