//! 008 fuzz target `ffi_args` (contracts/fuzz-harness.md, "Targets", #17).
mod targets;

#[test]
fn fuzz_ffi_args() {
    hardening::runner::run(targets::ffi_args::target());
}
