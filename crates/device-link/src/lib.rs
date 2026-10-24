//! Device identity, pairing and secure channel for passwsync (sans-IO core).
//!
//! No sockets, files or threads here: those are adapters (`device-link-net`, `passwsyncd`)
//! behind the ports in [`ports`].
#![forbid(unsafe_code)]

pub mod channel;
pub mod code;
pub mod discovery;
pub mod error;
pub mod files;
pub mod identity;
pub mod link;
pub mod name;
mod noise;
pub mod pairing;
pub mod policy;
pub mod ports;
pub mod registry;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod wire;
