//! Ports of the core (hexagonal boundary): pin storage and the two clocks.

use std::time::Duration;

use crate::error::Error;
use crate::registry::PeerPin;

/// Persists the pinned peers. `save` must be atomic: either the whole list is stored or the
/// previous one stays.
pub trait PeerStore: Send + Sync {
    fn load(&self) -> Result<Vec<PeerPin>, Error>;
    fn save(&self, pins: &[PeerPin]) -> Result<(), Error>;
}

/// Monotonic time since an arbitrary origin.
pub trait MonoClock: Send + Sync {
    fn now(&self) -> Duration;
}

/// Unix seconds, for dates shown to the person only.
pub trait WallClock: Send + Sync {
    fn unix_now(&self) -> u64;
}
