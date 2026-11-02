//! 008 fuzz target `discovery` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_discovery() {
    hardening::runner::run(targets::discovery::target());
}
