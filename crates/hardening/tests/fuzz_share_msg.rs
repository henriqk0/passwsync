//! 008 fuzz target `share_msg` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_share_msg() {
    hardening::runner::run(targets::share_msg::target());
}
