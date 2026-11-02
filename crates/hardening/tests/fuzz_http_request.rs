//! 008 fuzz target `http_request` (contracts/fuzz-harness.md, "Targets").
mod targets;

#[test]
fn fuzz_http_request() {
    hardening::runner::run(targets::http_request::target());
}
