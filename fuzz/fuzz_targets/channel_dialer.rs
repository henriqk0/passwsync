//! cargo-fuzz entry for the in-tree target `channel_dialer` (008 FR-009). Unbuilt and unverified; see
//! fuzz/README.md. Runs the same oracles as `crates/hardening/tests/fuzz_channel_dialer.rs`.
#![no_main]

#[path = "../../crates/hardening/tests/targets/mod.rs"]
mod targets;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    targets::channel_dialer::one_bytes(data);
});
