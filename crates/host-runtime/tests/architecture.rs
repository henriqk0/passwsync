//! X4 (contracts/shared-runtime-extraction.md section 1): dependency directions of the shared
//! runtime crate, read from the manifests with plain text parsing.

use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Names declared in the `[section]` table of a manifest (`name = ...` or `name.workspace`).
fn section_deps(manifest: &str, section: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name.trim().split('.').next().unwrap_or("").trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn manifest(krate: &str) -> String {
    fs::read_to_string(crates_dir().join(krate).join("Cargo.toml")).unwrap()
}

#[test]
fn host_runtime_depends_on_exactly_the_core_crates_and_basics() {
    let mut deps = section_deps(&manifest("host-runtime"), "dependencies");
    deps.sort();
    let mut want: Vec<String> = [
        "device-link",
        "device-link-net",
        "rand_core",
        "rustix",
        "sha2",
        "vault-core",
        "vault-storage-file",
        "wallet-service",
        "wallet-sync",
        "zeroize",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    want.sort();
    assert_eq!(deps, want);
}

#[test]
fn host_runtime_never_depends_on_a_host_or_boundary_crate() {
    let text = manifest("host-runtime");
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        for dep in section_deps(&text, section) {
            for banned in [
                "passwsyncd",
                "passwsync-ffi",
                "httparse",
                "signal-hook",
                "qrcodegen",
                "serde_json",
            ] {
                assert_ne!(dep, banned, "host-runtime [{section}] has {banned}");
            }
            assert!(
                !dep.starts_with("uniffi"),
                "host-runtime [{section}] has {dep}"
            );
        }
    }
}

#[test]
fn passwsyncd_depends_on_host_runtime() {
    let deps = section_deps(&manifest("passwsyncd"), "dependencies");
    assert!(deps.iter().any(|d| d == "host-runtime"), "{deps:?}");
}

/// Text of a Rust file with `//` comments removed (block comments are not used in core crates).
fn code_of(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn core_crates_never_mention_the_mobile_platform() {
    let mut files = Vec::new();
    for krate in [
        "vault-core",
        "vault-storage-file",
        "wallet-service",
        "device-link",
        "device-link-net",
        "wallet-sync",
    ] {
        rust_files(&crates_dir().join(krate).join("src"), &mut files);
    }
    assert!(files.len() > 10, "core sources found: {}", files.len());
    for file in files {
        let code = code_of(&fs::read_to_string(&file).unwrap()).to_lowercase();
        for word in ["android", "uniffi", "jni"] {
            assert!(!code.contains(word), "{word} in {}", file.display());
        }
    }
}
