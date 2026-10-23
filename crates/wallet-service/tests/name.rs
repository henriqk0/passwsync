use wallet_service::{InvalidName, WalletName};

fn ok(name: &str) {
    assert_eq!(WalletName::parse(name).unwrap().as_str(), name, "{name:?}");
}

fn bad(name: &str) {
    assert_eq!(WalletName::parse(name), Err(InvalidName), "{name:?}");
}

#[test]
fn accepts_the_safe_character_set() {
    ok("Personal");
    ok("a");
    ok("Work 2024_v1.backup-x");
    ok("x.");
    ok(&"a".repeat(64));
}

#[test]
fn rejects_empty_and_too_long() {
    bad("");
    bad(&"a".repeat(65));
}

#[test]
fn rejects_path_traversal_and_separators() {
    bad("../x");
    bad("..");
    bad(".");
    bad("a/b");
    bad("/");
    bad("a\\b");
    bad("a\0b");
}

#[test]
fn rejects_leading_dot_and_trailing_space() {
    bad(".hidden");
    bad("name ");
}

#[test]
fn rejects_characters_outside_the_set() {
    for name in ["a:b", "tab\t", "new\nline", "café", "a*b", "a%2e", "a?b"] {
        bad(name);
    }
}

#[test]
fn ordering_is_byte_order() {
    let mut names: Vec<WalletName> = ["b", "B", "a", "A", "_"]
        .into_iter()
        .map(|n| WalletName::parse(n).unwrap())
        .collect();
    names.sort();
    let sorted: Vec<&str> = names.iter().map(WalletName::as_str).collect();
    assert_eq!(sorted, ["A", "B", "_", "a", "b"]);
}

#[test]
fn display_is_the_name() {
    assert_eq!(
        WalletName::parse("Personal").unwrap().to_string(),
        "Personal"
    );
}
