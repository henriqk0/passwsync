//! 008 fuzz target `hello` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_hello() {
    hardening::runner::run(targets::hello::target());
}
