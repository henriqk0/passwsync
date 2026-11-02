//! Test-only hardening tools for passwsync (feature 008): a deterministic, seeded, std-only
//! mutation fuzz engine with panic, time, allocation and value oracles. No dependencies, no
//! `unsafe`, never linked into a release build (only integration tests use it).
#![forbid(unsafe_code)]

pub mod mutate;
pub mod oracle;
pub mod report;
pub mod rng;
pub mod runner;

/// Seed used when `PASSWSYNC_FUZZ_SEED` is unset ("PWSYNC" + feature 008).
pub const DEFAULT_SEED: u64 = 0x5057_5359_4E43_0008;
