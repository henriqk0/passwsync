//! FR-002 (B4 twin): the exported API equals `api_inventory.txt` (one `Type::method` per
//! line, from contracts/ffi-api.md sections 3 and 5). Each story's test task extends the
//! inventory, so the equality holds after every story.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root().join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    out
}

/// The `{ ... }` block starting at the first `{` at or after `from`.
fn block(text: &str, from: usize) -> &str {
    let open = from + text[from..].find('{').unwrap();
    let mut depth = 0;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open..=open + i];
                }
            }
            _ => {}
        }
    }
    &text[open..]
}

fn word_after<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let at = text.find(keyword)? + keyword.len();
    let rest = text[at..].trim_start();
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// `(Type::method, signature line)` for every export.
fn exports() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (_, text) in sources() {
        for (at, attr) in text.match_indices("#[uniffi::export") {
            let after = &text[at + attr.len()..];
            let foreign = after.starts_with("(with_foreign)");
            let item_at = at + text[at..].find(']').unwrap() + 1;
            let head_end = item_at + text[item_at..].find('{').unwrap();
            let head = &text[item_at..head_end];
            let body = block(&text, item_at);
            if foreign {
                let Some(name) = word_after(head, "trait ") else {
                    continue;
                };
                for line in body.lines() {
                    let l = line.trim();
                    if let Some(m) = word_after(l, "fn ").filter(|_| l.starts_with("fn ")) {
                        out.push((format!("{name}::{m}"), l.to_string()));
                    }
                }
            } else if let Some(name) = word_after(head, "impl ") {
                for line in body.lines() {
                    let l = line.trim();
                    if l.starts_with("pub fn ") || l.starts_with("pub async fn ") {
                        let m = word_after(l, "fn ").unwrap();
                        out.push((format!("{name}::{m}"), l.to_string()));
                    }
                }
            } else if let Some(m) = word_after(head, "fn ") {
                out.push((format!("fn::{m}"), head.trim().to_string()));
            }
        }
    }
    out
}

#[test]
fn the_exported_api_equals_the_inventory() {
    let found: BTreeSet<String> = exports().into_iter().map(|(n, _)| n).collect();
    let listed: BTreeSet<String> = fs::read_to_string(root().join("tests/api_inventory.txt"))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let extra: Vec<_> = found.difference(&listed).collect();
    let missing: Vec<_> = listed.difference(&found).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "undocumented exports {extra:?}; inventory entries without export {missing:?}"
    );
}

#[test]
fn no_export_is_async_or_takes_a_secret_as_text() {
    let secret = ["password", "secret", "code", "plaintext", "key"];
    for (name, signature) in exports() {
        assert!(!signature.contains("async fn"), "{name} is async");
        // `name: String` pairs of the parameter list and the return type.
        let params = signature.split('(').nth(1).unwrap_or("");
        for param in params.split(',') {
            if let Some((pname, ty)) = param.split_once(':') {
                let pname = pname.trim().to_lowercase();
                if ty.contains("String") && secret.iter().any(|s| pname.contains(s)) {
                    panic!("{name}: secret parameter {pname} is a String");
                }
            }
        }
        let lower = name.to_lowercase();
        if signature.contains("-> String") || signature.contains("Option<String>") {
            assert!(
                !secret.iter().any(|s| lower.contains(s)),
                "{name} returns a secret as String"
            );
        }
    }
}

#[test]
fn records_hold_no_secret_text_except_the_displayed_codes() {
    for (file, text) in sources() {
        for line in text.lines() {
            let l = line.trim().trim_start_matches("pub ");
            // Function signatures (e.g. `fn reveal_password(&self, name: String, ...)`) are
            // checked parameter by parameter by `no_export_is_async_or_takes_a_secret_as_text`.
            if l.starts_with("fn ") || l.starts_with("pub(crate) fn ") {
                continue;
            }
            if let Some((field, ty)) = l.split_once(':') {
                let field = field.trim();
                let secretish = ["password", "secret", "plaintext"]
                    .iter()
                    .any(|s| field.contains(s));
                if secretish && ty.contains("String") {
                    panic!("{file}: field {field} holds a secret as String");
                }
            }
        }
    }
}

#[test]
fn the_crate_prints_nothing() {
    for (file, text) in sources() {
        for needle in ["println!", "eprintln!", "dbg!", "print!("] {
            assert!(!text.contains(needle), "{needle} in {file}");
        }
    }
}
