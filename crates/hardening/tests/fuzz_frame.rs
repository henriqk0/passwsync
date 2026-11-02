//! 008 fuzz target `frame` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_frame() {
    hardening::runner::run(targets::frame::target());
}
