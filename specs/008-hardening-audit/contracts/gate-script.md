# Contract: Gate Script

**Covers**: FR-030, FR-034, FR-036, FR-037, FR-038, SC-009, SC-012 | Research R17-R19

## CLI

```text
scripts/gate.sh            run every step offline (default)
scripts/gate.sh --fetch    networked, one time: cargo fetch --locked (root + tools/uniffi-bindgen),
                           refresh cargo-audit and cargo-deny advisory DBs; then exit 0/1
scripts/gate.sh --list     print the step names and exit 0
exit: 0 all PASS; 1 any FAIL; 2 any MISSING (tool or advisory DB absent) and no FAIL; 64 usage
env:  PASSWSYNC_FUZZ_SEED / PASSWSYNC_FUZZ_ITERS passed through to the fuzz step
      PASSWSYNC_GATE_SELFTEST=fail|missing   runs only one synthetic step ending FAIL/MISSING
                                             (self-test); the real steps are skipped, so the
                                             self-test cannot re-run the `policy` step that calls it
```

Bash, `set -u -o pipefail`, `LC_ALL=C`, runs from the repository root, writes logs under a
`mktemp -d` directory removed on exit (path printed on failure), never writes outside it and
`target/`. Cargo flags for every offline step: `--frozen --offline`. Same conventions as
`packaging/verify.sh` and `android/verify.sh`.

## Steps (fixed order; each prints exactly one result line)

| # | Step | Command (summary) | FAIL when |
|---|------|-------------------|-----------|
| 1 | `toolchain` | print `rustc -V`, `cargo -V`, `cargo deny --version`, `cargo audit --version`, `python3 -V`; advisory DB dates (cargo-audit DB `git log -1 --format=%cs`, cargo-deny DB likewise) | MISSING if any tool or DB absent |
| 2 | `fmt` | `cargo fmt --all --check` | diff |
| 3 | `clippy` | `cargo clippy --frozen --offline --workspace --all-targets --all-features -- -D warnings` | any warning |
| 4 | `test` | `cargo test --frozen --offline --workspace --all-features --exclude hardening` | any failure |
| 5 | `budgets` | `cargo test --frozen --offline --release -p hardening --lib --test budgets --test leakage` | any failure |
| 6 | `fuzz` | `cargo test --frozen --offline --release -p hardening --test 'fuzz_*' -- --nocapture`; verify one `FUZZ ... result=PASS` line per file `crates/hardening/tests/fuzz_*.rs`; wall time < 300 s | any failure, a missing target line, or ≥ 300 s |
| 7 | `release-isolation` | `cargo tree --frozen --offline -e features,normal,build --target all -p passwsyncd` and `-p passwsync-ffi`: no `testkit` feature, no `hardening`; `cargo build --frozen --offline --release -p passwsyncd --bin passwsyncd` and `-p passwsync-ffi`; `nm -C` shows no `testkit::` or `hardening` symbol | any match |
| 8 | `unsafe-scope` | `cargo test --frozen --offline -p passwsync-ffi --test unsafe_scope` (scan extended to `crates/*/{src,tests,benches}` and `fuzz/`) | any `unsafe` outside `memprotect.rs` |
| 9 | `audit` | ignore ids read from `deny.toml` (and `tools/uniffi-bindgen/deny.toml` for its lock); `cargo audit --no-fetch --deny warnings --ignore <each>` on `Cargo.lock` and `tools/uniffi-bindgen/Cargo.lock`; prints DB date | any advisory of any kind (vulnerability, unsound, unmaintained, yanked) not ignored |
| 10 | `deny` | `cargo deny --offline check` (root and `--manifest-path tools/uniffi-bindgen/Cargo.toml`); prints `duplicates=<n>` from `cargo tree --duplicates --depth 0` (warning only) | advisories, bans, licenses or sources error |
| 11 | `policy` | `python3 scripts/check_workflow.py`; `python3 scripts/check_threat_model.py`; `python3 -m unittest discover -s scripts/tests`; deny fixture checks (R19): `cargo audit --file scripts/tests/fixtures/advisory.lock` must FAIL, `cargo deny --offline check bans licenses` on the fixture workspace must FAIL, `deny.toml` keeps `unknown-registry = "deny"`, `unknown-git = "deny"`, `yanked = "deny"`; `bash -n` on every `scripts/*.sh` | any |

Step names are the contract; tasks may split a step internally but keep one result line.

## Output

```text
[gate] toolchain          PASS  rustc 1.99.1; cargo-deny 0.20.2; cargo-audit 0.22.2; advisory-db 2026-10-24
[gate] fmt                PASS
...
[gate] fuzz               PASS  17 targets, 170,064 inputs, 112 s
[gate] policy             PASS  workflow: 2 pins PENDING [CI]
[gate] result             PASS  (11 PASS, 0 FAIL, 0 MISSING)
```

On FAIL the line names the step and the log file; the last 40 lines of that log are printed.

## Invariants

- Same script on host and CI; CI only adds `--fetch` before it.
- No network access in default mode (cargo `--offline`, audit `--no-fetch`, deny `--offline`).
- Writes nothing tracked by git; no commit, push, tag or upload.
- Does not run `android/verify.sh` or `packaging/verify.sh` (CI runs them as separate jobs; the
  quickstart runs all three on the host).
