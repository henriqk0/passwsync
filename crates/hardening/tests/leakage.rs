//! 008 T051 (FR-038, research R9): fuzz output never carries secret-looking content.
//!
//! 1. A scratch target whose seed holds a planted marker fails (panicking with the input in
//!    its message): no `FUZZ`, `FUZZ-TIME` or `FUZZ-FAIL` line and no recorded panic detail
//!    contains the marker.
//! 2. The real targets' seeds contain none of the leak markers the 001-007 leakage scans look
//!    for, so printing a failing input (hex or escaped text, FR-007) prints nothing those scans
//!    treat as secret.
mod targets;

use hardening::mutate::Seed;
use hardening::oracle::Verdict;
use hardening::report::{FuzzConfig, Render};
use hardening::runner::{Target, execute};

const PLANTED: &str = "PLANTED-LEAK-MARKER-7f3a";

fn config() -> FuzzConfig {
    FuzzConfig {
        seed: 1,
        iters: None,
        only: None,
        trace: false,
    }
}

fn scratch(render: Render) -> Target {
    Target::new(
        "scratch_leak",
        || {
            let mut bytes = b"prefix ".to_vec();
            bytes.extend_from_slice(PLANTED.as_bytes());
            vec![Seed::new("planted", bytes)]
        },
        |input| {
            let text = String::from_utf8_lossy(&input.bytes).into_owned();
            if input.mutated && text.contains("LEAK") {
                panic!("unexpected input {text}");
            }
            if input.mutated {
                Verdict::Rejected("Protocol")
            } else {
                Verdict::Accepted
            }
        },
    )
    .min_inputs(2000)
    .alloc_bound(u64::MAX / 4)
    .render(render)
    .error_kinds(&["Protocol"])
}

#[test]
fn a_failing_input_with_a_planted_marker_is_printed_without_it() {
    let failure = execute(&scratch(Render::Hex), &config()).expect_err("scratch target fails");
    let line = failure.line();
    assert!(line.starts_with("FUZZ-FAIL target=scratch_leak"));
    assert!(!line.contains(PLANTED), "{line}");
    assert!(!failure.detail.contains(PLANTED));
    assert!(!failure.detail.contains("LEAK"));
}

#[test]
fn passing_report_lines_carry_only_labels_and_counts() {
    let target = Target::new(
        "scratch_pass",
        || vec![Seed::new("planted", PLANTED.as_bytes().to_vec())],
        |input| {
            if input.mutated {
                Verdict::Rejected("Protocol")
            } else {
                Verdict::Accepted
            }
        },
    )
    .min_inputs(500)
    .alloc_bound(u64::MAX / 4)
    .error_kinds(&["Protocol"]);
    let report = execute(&target, &config()).unwrap();
    for line in [report.fuzz_line(), report.time_line()] {
        assert!(!line.contains(PLANTED), "{line}");
    }
}

/// Every quoted string containing `MARKER` in the existing leakage scans.
fn leak_markers() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut markers = Vec::new();
    for file in [
        "crates/vault-core/tests/leakage.rs",
        "crates/passwsync-ffi/tests/leakage.rs",
        "crates/passwsyncd/tests/share_leakage.rs",
    ] {
        let text = std::fs::read_to_string(root.join(file)).expect("leakage scan source");
        for piece in text.split('"').skip(1).step_by(2) {
            if piece.contains("MARKER") && !piece.contains('{') {
                markers.push(piece.to_owned());
            }
        }
    }
    assert!(markers.len() >= 10, "marker lists not found");
    markers
}

#[test]
fn real_seeds_contain_no_leak_marker() {
    let markers = leak_markers();
    let all: Vec<(&str, Vec<Seed>)> = vec![
        ("wallet_header", targets::wallet_header::seeds()),
        ("wallet_payload", targets::wallet_payload::seeds()),
        ("wallet_unlock", targets::wallet_unlock::seeds()),
        ("frame", targets::frame::seeds()),
        ("hello", targets::hello::seeds()),
        ("channel_payload", targets::channel_payload::seeds()),
        ("discovery", targets::discovery::seeds()),
        ("pairing_initiator", targets::pairing_initiator::seeds()),
        ("pairing_joiner", targets::pairing_joiner::seeds()),
        ("channel_responder", targets::channel_responder::seeds()),
        ("channel_dialer", targets::channel_dialer::seeds()),
        ("sync_ctl", targets::sync_ctl::seeds()),
        ("sync_reassembly", targets::sync_reassembly::seeds()),
        ("sync_copy", targets::sync_copy::seeds()),
        ("share_msg", targets::share_msg::seeds()),
        ("http_request", targets::http_request::seeds()),
        ("ffi_args", targets::ffi_args::seeds()),
    ];
    for (target, seeds) in &all {
        for seed in seeds {
            let text = String::from_utf8_lossy(&seed.bytes);
            for marker in &markers {
                assert!(
                    !text.contains(marker.as_str()),
                    "{target} seed holds a leak marker"
                );
            }
            assert!(
                !text.contains("MARKER"),
                "{target} seed holds a marker-like string"
            );
        }
    }
    // The synthetic password itself is not a marker either.
    let password = targets::wallet_unlock::PASSWORD;
    assert!(markers.iter().all(|m| !password.contains(m.as_str())));
}
