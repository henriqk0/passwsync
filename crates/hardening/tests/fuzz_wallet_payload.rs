//! 008 fuzz target `wallet_payload` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_wallet_payload() {
    hardening::runner::run(targets::wallet_payload::target());
}
