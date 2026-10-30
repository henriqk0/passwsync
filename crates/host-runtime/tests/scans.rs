//! X3 (contracts/shared-runtime-extraction.md section 5): the moved runtimes keep the rules of
//! `crates/passwsyncd/tests/scans.rs` (004 T-scans, 005 T087), applied here to the code that now
//! lives in `crates/host-runtime/src`. passwsyncd's own scans read its facades after the move;
//! this file is the guard for the moved code.

use std::fs;
use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn all_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(src()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(!out.is_empty());
    out
}

/// `(derive line, struct body)` for every struct in `text` (same parser as passwsyncd's scans).
fn structs(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (pos, _) in text.match_indices("struct ") {
        let before = &text[..pos];
        let derive = before
            .rfind("#[derive(")
            .filter(|d| !before[*d..].contains('}'))
            .map(|d| before[d..].lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        let rest = &text[pos..];
        let end = rest.find("\n}").unwrap_or(rest.len());
        out.push((derive, rest[..end].to_string()));
    }
    out
}

#[test]
fn moved_modules_print_nothing_and_have_no_unsafe_code() {
    for (file, text) in all_sources() {
        for needle in ["unsafe ", "println!", "eprintln!", "dbg!", "print!("] {
            assert!(!text.contains(needle), "{needle} in {file}");
        }
        assert!(!text.contains("allow(unsafe_code)"), "{file}");
        // Logging goes only through the closed `LogEvent` set.
        assert!(!text.contains("log.fatal("), "{file}");
    }
}

#[test]
fn lib_forbids_unsafe_code() {
    let lib = fs::read_to_string(src().join("lib.rs")).unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn no_moved_type_derives_debug_while_holding_a_secret() {
    for (file, text) in all_sources() {
        for (derive, body) in structs(&text) {
            let secret = ["code:", "password:", "proof:", "rid:"]
                .iter()
                .any(|f| body.contains(f));
            assert!(
                !(secret && derive.contains("Debug")),
                "{file}: Debug derived for a secret-holding type: {}",
                body.lines().next().unwrap_or("")
            );
        }
    }
}

#[test]
fn moved_modules_never_reach_back_into_the_desktop_host() {
    for (file, text) in all_sources() {
        for module in [
            "app", "http", "peer", "qr", "signals", "sweeper", "assets", "paths",
        ] {
            assert!(
                !text.contains(&format!("crate::{module}")),
                "crate::{module} in {file}"
            );
        }
        assert!(!text.contains("passwsyncd::"), "passwsyncd:: in {file}");
    }
}

#[test]
fn sharing_events_carry_only_typed_non_secret_fields() {
    // Moved guard of passwsyncd `tests/share_log.rs` (005): it now reads the real enum here.
    let source = fs::read_to_string(src().join("log.rs")).unwrap();
    let start = source.find("// --- 005 sharing events").expect("marker");
    let end = source[start..].find("\n}\n").unwrap() + start;
    let block = &source[start..end];
    for forbidden in [
        "WalletName",
        "&'a str",
        "String",
        "[u8",
        "Vec<",
        "WalletId",
        "code",
        "proof",
        "rid",
        "password",
    ] {
        assert!(!block.contains(forbidden), "{forbidden} in the 005 events");
    }
}

#[test]
fn the_invite_code_reuses_the_reviewed_pairing_code_generator() {
    // Moved guard of passwsyncd `tests/share_qr.rs` (005).
    let source = fs::read_to_string(src().join("share_runtime.rs")).unwrap();
    assert!(source.contains("PairingCode::generate"));
}

fn assert_moved(file: &str) {
    assert!(
        src().join(file).is_file(),
        "{file} is not in host-runtime/src"
    );
}

#[test]
fn inventory_log() {
    assert_moved("log.rs");
}
#[test]
fn inventory_hex() {
    assert_moved("hex.rs");
}
#[test]
fn inventory_files() {
    assert_moved("files.rs");
}
#[test]
fn inventory_clock() {
    assert_moved("clock.rs");
}
#[test]
fn inventory_config() {
    assert_moved("config.rs");
}
#[test]
fn inventory_hardening() {
    assert_moved("hardening.rs");
}
#[test]
fn inventory_fs_dir() {
    assert_moved("fs_dir.rs");
}
#[test]
fn inventory_net_store() {
    assert_moved("net_store.rs");
}
#[test]
fn inventory_net_runtime() {
    assert_moved("net_runtime.rs");
}
#[test]
fn inventory_sync_store() {
    assert_moved("sync_store.rs");
}
#[test]
fn inventory_sync_runtime() {
    assert_moved("sync_runtime.rs");
}
#[test]
fn inventory_share_store() {
    assert_moved("share_store.rs");
}
#[test]
fn inventory_share_runtime() {
    assert_moved("share_runtime.rs");
}
#[test]
fn inventory_wiring() {
    assert_moved("wiring.rs");
}
