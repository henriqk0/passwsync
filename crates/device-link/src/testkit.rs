//! In-memory fakes of the ports and a scripted RNG (feature `testkit`).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use rand_core::{CryptoRng, RngCore};

use crate::error::Error;
use crate::ports::{MonoClock, PeerStore, WallClock};
use crate::registry::PeerPin;

#[derive(Default)]
pub struct FakeMonoClock(Mutex<Duration>);

impl FakeMonoClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, now: Duration) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = now;
    }

    pub fn advance(&self, by: Duration) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) += by;
    }
}

impl MonoClock for FakeMonoClock {
    fn now(&self) -> Duration {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub struct FakeWallClock(Mutex<u64>);

impl FakeWallClock {
    pub fn new(now: u64) -> Self {
        Self(Mutex::new(now))
    }

    pub fn set(&self, now: u64) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = now;
    }
}

impl WallClock for FakeWallClock {
    fn unix_now(&self) -> u64 {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct StoreState {
    pins: Vec<PeerPin>,
    fail: bool,
    saves: usize,
}

/// Pins kept in memory; saves can be made to fail on demand.
#[derive(Default)]
pub struct MemoryPeerStore(Mutex<StoreState>);

impl MemoryPeerStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(pins: Vec<PeerPin>) -> Self {
        Self(Mutex::new(StoreState {
            pins,
            ..StoreState::default()
        }))
    }

    pub fn fail_saves(&self, fail: bool) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).fail = fail;
    }

    /// Successful saves so far.
    pub fn save_count(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).saves
    }

    pub fn pins(&self) -> Vec<PeerPin> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pins
            .clone()
    }
}

impl PeerStore for MemoryPeerStore {
    fn load(&self) -> Result<Vec<PeerPin>, Error> {
        Ok(self.pins())
    }

    fn save(&self, pins: &[PeerPin]) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.fail {
            return Err(Error::Storage);
        }
        state.pins = pins.to_vec();
        state.saves += 1;
        Ok(())
    }
}

/// Yields the scripted `u32` values (big-endian bytes for `fill_bytes`), then a fixed
/// counter-based sequence. Deterministic; for tests only.
pub struct ScriptedRng {
    script: VecDeque<u32>,
    counter: u64,
}

impl ScriptedRng {
    pub fn new(script: &[u32]) -> Self {
        Self {
            script: script.iter().copied().collect(),
            counter: 0,
        }
    }

    pub fn seeded(seed: u64) -> Self {
        Self {
            script: VecDeque::new(),
            counter: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15),
        }
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        if let Some(next) = self.script.pop_front() {
            return next;
        }
        // splitmix64: deterministic filler, not a security RNG.
        self.counter = self.counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.counter;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) as u32
    }

    fn next_u64(&mut self) -> u64 {
        (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let bytes = self.next_u32().to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ScriptedRng {}
