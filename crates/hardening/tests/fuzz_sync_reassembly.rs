//! 008 fuzz target `sync_reassembly` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_sync_reassembly() {
    hardening::runner::run(targets::sync_reassembly::target());
}
