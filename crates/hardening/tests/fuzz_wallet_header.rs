//! 008 fuzz target `wallet_header` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_wallet_header() {
    hardening::runner::run(targets::wallet_header::target());
}
