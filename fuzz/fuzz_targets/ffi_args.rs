//! cargo-fuzz entry for the in-tree target `ffi_args` (008 FR-009). Unbuilt and unverified; see
//! fuzz/README.md. Runs the same oracles as `crates/hardening/tests/fuzz_ffi_args.rs`.
#![no_main]

#[path = "../../crates/hardening/tests/targets/mod.rs"]
mod targets;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    targets::ffi_args::one_bytes(data);
});
