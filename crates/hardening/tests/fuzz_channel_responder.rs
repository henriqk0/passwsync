//! 008 fuzz target `channel_responder` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_channel_responder() {
    hardening::runner::run(targets::channel_responder::target());
}
