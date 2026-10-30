# Contract: `android/verify.sh` (offline host verification entry point)

Implements FR-058, FR-059, SC-001, SC-002, SC-004 (research R15). Bash, `set -euo pipefail`,
no network access, no Android SDK/NDK. Every Cargo invocation uses `--frozen --offline`
(`CARGO_NET_OFFLINE=true`); every Python invocation is `python3 -I`.

## CLI

```text
android/verify.sh [--quick] [--keep-work] [--only STEP[,STEP…]] [--help]
```

| Option | Effect |
|--------|--------|
| `--quick` | runs `cargo test` only for `host-runtime`, `passwsync-ffi`, `passwsyncd` instead of `--workspace`; final status at best 2 (incomplete) |
| `--keep-work` | keep `target/android-verify/` (default: kept anyway; cleaned at start) |
| `--only` | run the named steps; final status at best 2 |
| `--help` | usage, exit 0 |

Unknown option: usage on stderr, exit 64.

## Work layout

`target/android-verify/` (recreated at start): `kotlin/` (generated bindings), `mut/` (mutation
copies, one per mutation, deleted after each), `logs/<step>.log`, `summary.txt`.

## Steps (in order; each prints `PASS|FAIL|SKIPPED|MISSING <step> <detail>`)

| # | Step | Command / check | Fail when |
|---|------|-----------------|-----------|
| 1 | `tools` | `cargo`, `python3`, `xmllint` on PATH; `cargo-deny` and `cargo-audit` looked up on PATH, then in `${CARGO_HOME:-$HOME/.cargo}/bin` (verify.sh prepends that directory to PATH and prints the path used); `ktlint` optional | a required tool is missing ⇒ `MISSING`, overall ≥ 2 |
| 2 | `passwsyncd-tests-unchanged` | `git diff --quiet main -- crates/passwsyncd/tests` and no untracked file there | any change (X1) |
| 3 | `fmt-clippy` | `cargo fmt --all --check`; `cargo clippy --frozen --offline --workspace --all-targets --features …testkit -- -D warnings` | any diagnostic |
| 4 | `workspace-tests` | `cargo test --frozen --offline --workspace` (all features needed for testkit via dev-deps) | any failure (covers SC-003, SC-004, host-runtime + ffi suites) |
| 5 | `unsafe-scope` | part of 4 (`passwsync-ffi/tests/unsafe_scope.rs`); repeated here as a grep summary for the log | — |
| 6 | `host-cdylib` | `cargo build --frozen --offline -p passwsync-ffi` produces `target/debug/libpasswsync_ffi.so`; `nm -D` lists `uniffi_passwsync_ffi_*` symbols and no `JNI_OnLoad` | missing file/symbols |
| 7 | `bindgen` | `cargo run --frozen --offline --manifest-path tools/uniffi-bindgen/Cargo.toml -- generate --library target/debug/libpasswsync_ffi.so --language kotlin --no-format --out-dir target/android-verify/kotlin` | non-zero exit or no `.kt` file |
| 8 | `uniffi-pin` | the `uniffi` version in `Cargo.lock` equals the one in `tools/uniffi-bindgen/Cargo.lock` (both `=0.32.2`) | mismatch |
| 9 | `bindings` | `check_bindings.py target/android-verify/kotlin` (B1–B6) | any rule |
| 10 | `xml-wellformed` | `xmllint --noout --nonet` on the manifest and every `res/**/*.xml` | any error (X1) |
| 11 | `manifest-policy` | `check_manifest.py android` (M*, X*, G*) | any rule |
| 12 | `source-policy` | `check_sources.py android` (S*) | any rule |
| 13 | `policy-unit` | `python3 -I -m unittest discover -s android/policy/tests` | any failure |
| 14 | `mutations` | for each mutation in `mutations.py`: copy, mutate, run the owning checker, expect exit 1 with a line starting with the rule id; also assert every rule id in the three checkers has ≥ 1 mutation | a mutation not detected, detected under another id, or a rule without mutation (FR-059, SC-002) |
| 15 | `deny` | `cargo deny --offline check` (root) and `cargo deny --offline --manifest-path tools/uniffi-bindgen/Cargo.toml check` | any error (warnings allowed: duplicates) |
| 16 | `audit` | `cargo audit --no-fetch --deny warnings --ignore RUSTSEC-2023-0089` (root; same ignore and reason as `deny.toml` — measured: without the ignore `--deny warnings` exits 1 today), `cargo audit --no-fetch --deny warnings --ignore RUSTSEC-2026-0374 --file tools/uniffi-bindgen/Cargo.lock` | any vulnerability or unignored warning |
| 17 | `lock-diff` | packages in `Cargo.lock` not in `main`'s lock are exactly the reviewed set in `android/policy/reviewed-crates.txt` | an unreviewed crate |
| 18 | `ktlint` | `ktlint 'android/app/src/**/*.kt'` when installed | lint errors; absent ⇒ `SKIPPED ktlint (not installed)` (does **not** lower the status) |

The advisory database is the local one (`~/.cargo/advisory-db`); its date is printed so a stale
database is visible.

## Root `deny.toml` additions (FR-040)

```toml
[bans]
multiple-versions = "warn"
deny = [
  { name = "reqwest" }, { name = "hyper" }, { name = "ureq" }, { name = "curl" },
  { name = "isahc" }, { name = "attohttpc" }, { name = "surf" }, { name = "h2" },
  { name = "trust-dns-resolver" }, { name = "hickory-resolver" }, { name = "native-tls" },
  { name = "openssl" }, { name = "openssl-sys" }, { name = "rustls" }, { name = "tokio" },
  { name = "sentry" }, { name = "opentelemetry" },
]
[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | every step PASS (ktlint may be SKIPPED) |
| 1 | at least one FAIL |
| 2 | no FAIL, but a required tool MISSING, or `--quick`/`--only` used |
| 64 | usage error |

`summary.txt` lists each step with its status and the elapsed time; the last line is
`RESULT <code>`.

## Self-tests

`android/policy/tests/test_verify_cli.sh`-style checks are done inside `policy-unit` with Python
`unittest` + `subprocess`: unknown option ⇒ 64; `--only xml-wellformed` on a tree with a broken XML
⇒ 1; `--only` ⇒ never 0; missing `xmllint` on a stripped `PATH` ⇒ `MISSING` and 2.
