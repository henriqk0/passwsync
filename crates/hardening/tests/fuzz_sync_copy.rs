//! 008 fuzz target `sync_copy` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_sync_copy() {
    hardening::runner::run(targets::sync_copy::target());
}
