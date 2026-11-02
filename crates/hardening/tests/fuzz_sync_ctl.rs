//! 008 fuzz target `sync_ctl` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_sync_ctl() {
    hardening::runner::run(targets::sync_ctl::target());
}
