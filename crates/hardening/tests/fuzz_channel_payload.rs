//! 008 fuzz target `channel_payload` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_channel_payload() {
    hardening::runner::run(targets::channel_payload::target());
}
