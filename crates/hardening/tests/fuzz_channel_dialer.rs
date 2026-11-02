//! 008 fuzz target `channel_dialer` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_channel_dialer() {
    hardening::runner::run(targets::channel_dialer::target());
}
