//! 008 fuzz target `wallet_unlock` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_wallet_unlock() {
    hardening::runner::run(targets::wallet_unlock::target());
}
