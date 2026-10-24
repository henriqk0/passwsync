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

// --- 003: networking keys and the extended grammar (contracts/host-runtime-network.md) ---

#[test]
fn network_defaults_are_off_with_default_ports() {
    let net = parse("").unwrap().network;
    assert!(!net.enabled);
    assert_eq!(net.peer_port, 27472);
    assert_eq!(net.discovery_port, 27473);
    assert_eq!(net.device_name, None);
    assert_eq!(net.interface, None);
}

#[test]
fn network_keys_parse_on_off_and_quoted_strings() {
    let text = "network = on\npeer_port = 30000\ndiscovery_port = 30001\ndevice_name = \"Laptop #1 é\"  # comment\nnetwork_interface = \"wlan0\"\n";
    let net = parse(text).unwrap().network;
    assert!(net.enabled);
    assert_eq!(net.peer_port, 30000);
    assert_eq!(net.discovery_port, 30001);
    assert_eq!(net.device_name.unwrap().as_str(), "Laptop #1 é");
    assert_eq!(net.interface.as_deref(), Some("wlan0"));
    assert!(!parse("network = off").unwrap().network.enabled);
    assert_eq!(
        parse("network_interface = \"br-lan.10_x\"")
            .unwrap()
            .network
            .interface
            .as_deref(),
        Some("br-lan.10_x")
    );
}

#[test]
fn network_switch_rejects_other_words() {
    assert_eq!(err("network = yes"), "config: network: must be on or off");
    assert_eq!(err("network = 1"), "config: network: must be on or off");
    assert_eq!(
        err("network = \"on\""),
        "config: network: must be on or off"
    );
    assert_eq!(err("network = ON"), "config: network: must be on or off");
}

#[test]
fn network_ports_are_checked_and_distinct() {
    assert_eq!(
        err("peer_port = 1023"),
        "config: peer_port: must be 1024..=65535"
    );
    assert_eq!(
        err("discovery_port = 65536"),
        "config: discovery_port: must be 1024..=65535"
    );
    assert_eq!(
        err("peer_port = on"),
        "config: peer_port: not a decimal integer"
    );
    assert_eq!(
        err("peer_port = 27471"),
        "config: peer_port: must differ from port and discovery_port"
    );
    assert_eq!(
        err("port = 30000\npeer_port = 30000"),
        "config: peer_port: must differ from port and discovery_port"
    );
    assert_eq!(
        err("discovery_port = 27472"),
        "config: discovery_port: must differ from port and peer_port"
    );
    assert_eq!(
        err("discovery_port = 27471"),
        "config: discovery_port: must differ from port and peer_port"
    );
    assert!(parse("port = 27472\npeer_port = 27500").is_ok());
}

#[test]
fn device_name_must_be_a_valid_quoted_name() {
    let problem =
        "config: device_name: must be 1..64 characters without control characters or quotes";
    assert_eq!(err("device_name = \"\""), problem);
    assert_eq!(
        err(&format!("device_name = \"{}\"", "x".repeat(65))),
        problem
    );
    assert_eq!(err("device_name = \"tab\there\""), problem);
    assert_eq!(
        err("device_name = Laptop"),
        "config: device_name: not a quoted string"
    );
    assert_eq!(
        err("device_name = \"a\"b\""),
        "config: device_name: not a quoted string"
    );
    assert_eq!(
        err("device_name = \"open"),
        "config: device_name: not a quoted string"
    );
    assert_eq!(
        err("device_name = \"a\\\"b\""),
        "config: device_name: not a quoted string"
    );
    assert!(parse(&format!("device_name = \"{}\"", "é".repeat(64))).is_ok());
}

#[test]
fn network_interface_is_restricted() {
    let problem = "config: network_interface: must be 1..15 of [A-Za-z0-9._-]";
    assert_eq!(err("network_interface = \"\""), problem);
    assert_eq!(err("network_interface = \"abcdefghijklmnop\""), problem);
    assert_eq!(err("network_interface = \"wlan 0\""), problem);
    assert_eq!(err("network_interface = \"wl/an\""), problem);
    assert_eq!(err("network_interface = \"wlané\""), problem);
    assert_eq!(
        err("network_interface = wlan0"),
        "config: network_interface: not a quoted string"
    );
    assert!(parse("network_interface = \"abcdefghijklmno\"").is_ok());
}

#[test]
fn new_keys_reject_duplicates_and_strings_where_integers_go() {
    assert_eq!(
        err("network = on\nnetwork = off"),
        "config: network: duplicate key"
    );
    assert_eq!(
        err("device_name = \"a\"\ndevice_name = \"b\""),
        "config: device_name: duplicate key"
    );
    assert_eq!(
        err("auto_lock_minutes = on"),
        "config: auto_lock_minutes: not a decimal integer"
    );
    assert_eq!(err("networking = on"), "config: networking: unknown key");
}

#[test]
fn bad_network_config_exits_with_code_two() {
    let error = passwsyncd::app::StartError::Config(parse("network = maybe").unwrap_err());
    assert_eq!(error.exit_code(), 2);
}
