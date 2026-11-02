# Optional cargo-fuzz targets (unbuilt, unverified)

Coverage-guided companions of the 17 deterministic in-tree fuzz targets of feature 008
(`crates/hardening/tests/fuzz_*.rs`). Each `fuzz_targets/<target>.rs` includes the shared
target code with `#[path]` and calls the target's `one_bytes`, which runs the same oracles
and panics on any violation.

Status: **never built by any gate and unverified.**

- It needs nightly Rust and `cargo-fuzz`, and `libfuzzer-sys` (version `=0.4.10` recorded in
  `Cargo.toml`), none of which is available on the development host (no network). The version
  is therefore not verified.
- It is its own Cargo workspace (`[workspace]` in `Cargo.toml`); the root `Cargo.toml` lists
  `fuzz` in `exclude`, so the product workspace, its `Cargo.lock`, `cargo deny` and
  `cargo audit` do not see it. No lock file is committed here.
- Before first use, a maintainer must generate its lock on a trusted networked machine, run
  `cargo deny check` and `cargo audit` on it (same policy as the root `deny.toml`), and review
  `libfuzzer-sys` and its dependencies.
- The unsafe-scope scan (`crates/passwsync-ffi/tests/unsafe_scope.rs`) covers these sources:
  they must not contain `unsafe`.

Use (after the steps above): `cargo +nightly fuzz run <target>` from this directory. The
`ffi_args` target is part of the 17; `wallet_unlock` derives keys and is slow by design.
