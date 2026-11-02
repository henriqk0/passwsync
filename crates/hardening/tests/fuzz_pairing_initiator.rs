//! 008 fuzz target `pairing_initiator` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_pairing_initiator() {
    hardening::runner::run(targets::pairing_initiator::target());
}
