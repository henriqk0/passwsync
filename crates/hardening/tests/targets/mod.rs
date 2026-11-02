//! Shared fuzz target modules (contracts/fuzz-harness.md). Every target module exposes
//!
//! - `pub fn target() -> Target`: seeds from the project's own encoders, the per-input `one`
//!   function with the target's oracles, and its limits;
//! - `pub fn one_bytes(data: &[u8])`: the same oracles on raw bytes, panicking on a violation
//!   (the optional cargo-fuzz entry in `fuzz/`, which includes this file with `#[path]`).
//!
//! Each `tests/fuzz_<target>.rs` binary declares `mod targets;` and runs one target, so every
//! target has its own process (allocation oracle, hang watchdog). Shared helpers are reached
//! as `super::<module>`, which resolves the same way in both builds.
#![allow(dead_code)]

pub mod common;
pub mod handshake;

pub mod channel_dialer;
pub mod channel_payload;
pub mod channel_responder;
pub mod discovery;
pub mod ffi_args;
pub mod frame;
pub mod hello;
pub mod http_request;
pub mod pairing_initiator;
pub mod pairing_joiner;
pub mod share_msg;
pub mod sync_copy;
pub mod sync_ctl;
pub mod sync_reassembly;
pub mod wallet_header;
pub mod wallet_payload;
pub mod wallet_unlock;
