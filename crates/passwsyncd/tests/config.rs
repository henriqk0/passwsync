mod common;

use std::fs;
use std::time::Duration;

use common::{TempDir, set_mode};
use passwsyncd::config::{Settings, load, parse};

fn err(text: &str) -> String {
    parse(text).unwrap_err().to_string()
}

#[test]
fn empty_file_gives_defaults() {
    let settings = parse("").unwrap();
    assert_eq!(settings, Settings::default());
    assert_eq!(settings.port, 27471);
    assert_eq!(settings.auto_lock, Duration::from_secs(15 * 60));
    assert_eq!(settings.clipboard_clear, Duration::from_secs(30));
}

#[test]
fn parses_keys_comments_and_blank_lines() {
    let text = "# passwsync settings\n\nport = 28000   # comment\nauto_lock_minutes=1\n  clipboard_clear_seconds = 300\n";
    let settings = parse(text).unwrap();
    assert_eq!(settings.port, 28000);
    assert_eq!(settings.auto_lock, Duration::from_secs(60));
    assert_eq!(settings.clipboard_clear, Duration::from_secs(300));
}

#[test]
fn unknown_key_is_rejected_naming_the_key() {
    assert_eq!(err("colour = 3"), "config: colour: unknown key");
}

#[test]
fn duplicate_key_is_rejected() {
    assert_eq!(
        err("port = 2000\nport = 3000"),
        "config: port: duplicate key"
    );
}

#[test]
fn bad_syntax_is_rejected_naming_the_line() {
    assert_eq!(
        err("\nport 2000"),
        "config: line 2: expected `key = integer`"
    );
    assert_eq!(err("port = "), "config: port: not a decimal integer");
    assert_eq!(err("port = 0x10"), "config: port: not a decimal integer");
    assert_eq!(err("port = -5"), "config: port: not a decimal integer");
    assert_eq!(err("port = \"1\""), "config: port: not a decimal integer");
}

#[test]
fn out_of_range_values_are_rejected() {
    assert_eq!(err("port = 1023"), "config: port: must be 1024..=65535");
    assert_eq!(err("port = 65536"), "config: port: must be 1024..=65535");
    assert_eq!(
        err("auto_lock_minutes = 0"),
        "config: auto_lock_minutes: must be 1..=240"
    );
    assert_eq!(
        err("auto_lock_minutes = 241"),
        "config: auto_lock_minutes: must be 1..=240"
    );
    assert_eq!(
        err("clipboard_clear_seconds = 4"),
        "config: clipboard_clear_seconds: must be 5..=300"
    );
    assert_eq!(
        err("clipboard_clear_seconds = 301"),
        "config: clipboard_clear_seconds: must be 5..=300"
    );
    assert_eq!(
        err("port = 99999999999999999999999"),
        "config: port: must be 1024..=65535"
    );
}

#[test]
fn missing_file_gives_defaults() {
    let dir = TempDir::new("config");
    assert_eq!(
        load(&dir.path().join("config")).unwrap(),
        Settings::default()
    );
}

#[test]
fn file_with_group_or_other_bits_is_rejected() {
    let dir = TempDir::new("config");
    let path = dir.path().join("config");
    fs::write(&path, "port = 28000\n").unwrap();
    set_mode(&path, 0o600);
    assert_eq!(load(&path).unwrap().port, 28000);
    for mode in [0o640, 0o604, 0o660] {
        set_mode(&path, mode);
        let message = load(&path).unwrap_err().to_string();
        assert!(message.starts_with("config: "), "{message}");
        assert!(message.contains(&*path.to_string_lossy()), "{message}");
    }
    set_mode(&path, 0o400);
    assert!(load(&path).is_ok(), "stricter than 0600 is fine");
}
