//! 008 fuzz target `pairing_joiner` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_pairing_joiner() {
    hardening::runner::run(targets::pairing_joiner::target());
}
