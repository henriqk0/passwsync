//! FR-005: the single unsafe module. Every `*.rs` under `crates/*/{src,tests,benches}/` and the
//! optional `fuzz/` workspace (008 FR-037) is scanned after stripping comments and string/char
//! literals; `unsafe` or `allow(unsafe_code)` may appear only in
//! `crates/passwsync-ffi/src/memprotect.rs`.

use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Rust source with comments, string literals (plain, byte, raw) and char literals replaced
/// by spaces. Lifetimes (`'a`) are kept.
fn strip(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // Raw strings: r"..", r#".."#, br#".."#.
        let raw_start = if c == b'r' {
            Some(i + 1)
        } else if c == b'b' && b.get(i + 1) == Some(&b'r') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_start {
            let ident_before = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if !ident_before && b.get(j) == Some(&b'"') {
                j += 1;
                loop {
                    if j >= b.len() {
                        break;
                    }
                    if b[j] == b'"'
                        && b[j + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|x| **x == b'#')
                            .count()
                            == hashes
                    {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                i = j;
                out.push(' ');
                continue;
            }
        }
        if c == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            out.push(' ');
            continue;
        }
        if c == b'\'' {
            // Char literal ('x', '\n', '\u{..}') vs lifetime ('a).
            let close = if b.get(i + 1) == Some(&b'\\') {
                b[i + 2..]
                    .iter()
                    .position(|x| *x == b'\'')
                    .map(|p| i + 2 + p)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                // Multi-byte char literal.
                let s = &src[i + 1..];
                s.chars()
                    .next()
                    .filter(|ch| s[ch.len_utf8()..].starts_with('\''))
                    .map(|ch| i + 1 + ch.len_utf8())
            };
            if let Some(end) = close {
                i = end + 1;
                out.push(' ');
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

fn has_word(code: &str, word: &str) -> bool {
    code.match_indices(word).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + word.len()..].chars().next();
        let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        boundary(before) && boundary(after)
    })
}

#[test]
fn the_stripper_removes_comments_and_literals() {
    let code =
        strip("let a = \"unsafe \"; // unsafe\n/* unsafe */ let b = r#\"unsafe\"#; fn f<'a>() {}");
    assert!(!code.contains("unsafe"), "{code}");
    assert!(code.contains("fn f<'a>()"));
    assert!(has_word(&strip("unsafe { x }"), "unsafe"));
    assert!(!has_word("unsafe_code", "unsafe"));
}

/// `crates/*/{src,tests,benches}` and `fuzz/` under `workspace` (sorted).
fn scan_roots(workspace: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(entries) = fs::read_dir(workspace.join("crates")) {
        for entry in entries {
            let dir = entry.unwrap().path();
            for sub in ["src", "tests", "benches"] {
                roots.push(dir.join(sub));
            }
        }
    }
    roots.push(workspace.join("fuzz"));
    roots.sort();
    roots
}

/// Files under the scan roots of `workspace` that contain `unsafe` or `allow(unsafe_code)`
/// in code (comments and literals stripped), except `allowed`.
fn offenders(workspace: &Path, allowed: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in scan_roots(workspace) {
        rust_files(&root, &mut files);
    }
    files
        .into_iter()
        .filter(|file| file != allowed)
        .filter(|file| {
            let code = strip(&fs::read_to_string(file).unwrap());
            has_word(&code, "unsafe") || code.replace(' ', "").contains("allow(unsafe_code)")
        })
        .collect()
}

#[test]
fn unsafe_appears_only_in_memprotect() {
    let workspace = crates_dir().parent().unwrap().to_path_buf();
    let allowed = crates_dir().join("passwsync-ffi/src/memprotect.rs");
    let mut files = Vec::new();
    for root in scan_roots(&workspace) {
        rust_files(&root, &mut files);
    }
    assert!(files.len() > 200, "sources found: {}", files.len());
    assert!(allowed.is_file(), "memprotect.rs must exist");
    let found = offenders(&workspace, &allowed);
    assert!(found.is_empty(), "unsafe outside memprotect.rs: {found:?}");
}

#[test]
fn every_other_ffi_module_forbids_unsafe_code() {
    let mut files = Vec::new();
    rust_files(&crates_dir().join("passwsync-ffi/src"), &mut files);
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&file).unwrap();
        match name.as_str() {
            "lib.rs" => assert!(text.contains("#![deny(unsafe_code)]")),
            "memprotect.rs" => {
                assert!(text.contains("#![allow(unsafe_code)]"));
            }
            _ => {
                let first = strip(&text)
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("")
                    .to_string();
                assert_eq!(first, "#![forbid(unsafe_code)]", "{name}");
            }
        }
    }
}

#[test]
fn every_other_member_uses_the_workspace_lints() {
    for entry in fs::read_dir(crates_dir()).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = fs::read_to_string(&manifest).unwrap();
        if dir.ends_with("passwsync-ffi") {
            assert!(
                text.contains("[lints.rust]\nunsafe_code = \"deny\""),
                "ffi lints"
            );
            assert!(!text.contains("[lints]\nworkspace = true"));
        } else {
            assert!(
                text.contains("[lints]\nworkspace = true"),
                "{} must use the workspace lints",
                manifest.display()
            );
        }
    }
    let root = fs::read_to_string(crates_dir().parent().unwrap().join("Cargo.toml")).unwrap();
    assert!(root.contains("[workspace.lints.rust]\nunsafe_code = \"forbid\""));
}

// --- 008 T064: the scan covers tests, benches and the optional fuzz workspace too ----------

#[test]
fn the_widened_scan_reports_unsafe_in_tests_benches_and_fuzz() {
    let root = std::env::temp_dir().join(format!("passwsync-unsafe-scan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let token = ["un", "safe"].concat();
    for rel in [
        "crates/x/src/lib.rs",
        "crates/x/tests/a.rs",
        "crates/x/benches/b.rs",
        "fuzz/fuzz_targets/c.rs",
    ] {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let body = if rel.ends_with("lib.rs") {
            "pub fn f() {}\n".to_owned()
        } else {
            format!("fn f() {{ {token} {{ }} }}\n")
        };
        fs::write(&path, body).unwrap();
    }
    let found = offenders(&root, &root.join("crates/x/src/none.rs"));
    let _ = fs::remove_dir_all(&root);
    let mut names: Vec<String> = found
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["a.rs", "b.rs", "c.rs"]);
}

#[test]
fn the_real_scan_roots_include_the_hardening_crate_and_fuzz() {
    let workspace = crates_dir().parent().unwrap().to_path_buf();
    let roots = scan_roots(&workspace);
    for want in ["crates/hardening/src", "crates/hardening/tests", "fuzz"] {
        assert!(
            roots.contains(&workspace.join(want)),
            "scan roots miss {want}: {roots:?}"
        );
    }
}
