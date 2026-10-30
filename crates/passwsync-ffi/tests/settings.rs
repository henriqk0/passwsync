//! FR-033, FR-036 (part 1): settings load with fallback, the default device name and the data
//! directory layout.

mod common;

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::{TempDir, mode, set_mode};
use device_link::identity::{DeviceKey, Fingerprint};
use host_runtime::config::Settings;
use host_runtime::log::Log;
use passwsync_ffi::dirs::DataDirs;
use passwsync_ffi::settings::{self, LoadedSettings, SETTINGS_FILE};

fn fingerprint() -> Fingerprint {
    DeviceKey::from_private([3; 32]).id().fingerprint()
}

fn lines(buffer: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    String::from_utf8(buffer.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_settings(dir: &Path, text: &str) {
    let path = dir.join(SETTINGS_FILE);
    fs::write(&path, text).unwrap();
    set_mode(&path, 0o600);
}

fn load(dir: &Path) -> (LoadedSettings, Vec<String>) {
    let (log, buffer) = Log::to_buffer();
    let loaded = settings::load(dir, &log);
    (loaded, lines(&buffer))
}

#[test]
fn a_missing_file_gives_the_defaults_without_notice() {
    let dir = TempDir::new("settings-missing");
    let (loaded, log) = load(dir.path());
    assert_eq!(loaded.settings, Settings::default());
    assert!(
        !loaded.settings.network.enabled,
        "networking off by default"
    );
    assert!(!loaded.reset_notice);
    assert!(log.is_empty(), "{log:?}");
    assert!(
        !dir.path().join(SETTINGS_FILE).exists(),
        "nothing written at load"
    );
}

#[test]
fn the_default_device_name_comes_from_the_fingerprint() {
    let dir = TempDir::new("settings-name");
    let (loaded, _) = load(dir.path());
    let fp = fingerprint();
    let view = settings::view(&loaded, Some(&fp), false);
    assert_eq!(
        view.device_name,
        format!("passwsync device {}", fp.prefix4())
    );
    assert_eq!(view.auto_lock_minutes, 15);
    assert_eq!(view.clipboard_clear_seconds, 30);
    assert_eq!(view.sync_interval_minutes, 60);
    assert!(!view.networking);
    assert_eq!(view.network_interface, None);
    assert!(!view.reset_notice);
    assert!(!view.restart_required);
    // Without an identity there is still no OS-provided name.
    let none = settings::view(&loaded, None, false);
    assert!(none.device_name.starts_with("passwsync device"));
}

#[test]
fn a_valid_file_is_used() {
    let dir = TempDir::new("settings-valid");
    write_settings(
        dir.path(),
        "auto_lock_minutes = 5\nclipboard_clear_seconds = 10\nnetwork = on\n\
         device_name = \"Pixel\"\nsync_interval_minutes = 30\nnetwork_interface = \"wlan0\"\n",
    );
    let (loaded, log) = load(dir.path());
    assert!(!loaded.reset_notice);
    assert!(log.is_empty());
    let view = settings::view(&loaded, Some(&fingerprint()), true);
    assert_eq!(view.auto_lock_minutes, 5);
    assert_eq!(view.clipboard_clear_seconds, 10);
    assert!(view.networking);
    assert_eq!(view.device_name, "Pixel");
    assert_eq!(view.sync_interval_minutes, 30);
    assert_eq!(view.network_interface.as_deref(), Some("wlan0"));
    assert!(view.restart_required);
}

#[test]
fn an_invalid_file_gives_defaults_networking_off_a_notice_and_one_log_line() {
    for text in [
        "network = on\nauto_lock_minutes = 0\n",
        "network = on\nno such key = 1\n",
        "network = on\nnetwork = on\n",
        "\u{0}garbage",
    ] {
        let dir = TempDir::new("settings-invalid");
        write_settings(dir.path(), text);
        let (loaded, log) = load(dir.path());
        assert_eq!(loaded.settings, Settings::default(), "{text:?}");
        assert!(!loaded.settings.network.enabled);
        assert!(loaded.reset_notice);
        assert_eq!(
            log,
            vec!["passwsyncd: settings reset to defaults".to_string()]
        );
        assert!(settings::view(&loaded, None, false).reset_notice);
    }
}

#[test]
fn a_file_open_to_others_is_invalid() {
    let dir = TempDir::new("settings-mode");
    write_settings(dir.path(), "network = on\n");
    set_mode(&dir.path().join(SETTINGS_FILE), 0o644);
    let (loaded, log) = load(dir.path());
    assert!(loaded.reset_notice);
    assert!(!loaded.settings.network.enabled);
    assert_eq!(log.len(), 1);
}

#[test]
fn the_desktop_port_key_is_ignored() {
    let dir = TempDir::new("settings-port");
    // 27472 would clash with peer_port on the desktop; here the key is not read at all.
    write_settings(dir.path(), "port = 27472\nnetwork = on\n");
    let (loaded, log) = load(dir.path());
    assert!(!loaded.reset_notice, "{log:?}");
    assert!(loaded.settings.network.enabled);
    assert_eq!(loaded.settings.port, Settings::default().port);
}

#[test]
fn data_dirs_are_created_private() {
    let dir = TempDir::new("dirs");
    let root = dir.path().join("files");
    let dirs = DataDirs::prepare(&root).unwrap();
    for path in [&dirs.root, &dirs.wallets, &dirs.sync, &dirs.received] {
        assert!(path.is_dir(), "{path:?}");
        assert_eq!(mode(path), 0o700, "{path:?}");
    }
    assert_eq!(dirs.wallets, root.join("wallets"));
    assert_eq!(dirs.sync, root.join("sync"));
    assert_eq!(dirs.received, root.join("received"));
    assert_eq!(dirs.settings_file(), root.join(SETTINGS_FILE));
    // An existing directory open to others is refused, not silently fixed.
    set_mode(&dirs.sync, 0o755);
    assert!(DataDirs::prepare(&root).is_err());
}

// --- part 2 (T082, FR-033): editing through the core -------------------------------------

use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::SettingsInput;

fn edit(auto: u32, clip: u32, sync: u32) -> SettingsInput {
    SettingsInput {
        auto_lock_minutes: auto,
        clipboard_clear_seconds: clip,
        device_name: None,
        sync_interval_minutes: sync,
        network_interface: None,
    }
}

#[test]
fn update_settings_validates_every_range() {
    let dir = TempDir::new("settings-ranges");
    let fakes = common::Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    for bad in [
        edit(0, 30, 60),
        edit(241, 30, 60),
        edit(15, 4, 60),
        edit(15, 301, 60),
        edit(15, 30, 14),
        edit(15, 30, 1441),
    ] {
        assert_eq!(core.update_settings(bad), Err(CoreError::InvalidInput));
    }
    for name in ["", "with \"quote\"", "line\nbreak", &"x".repeat(65)] {
        let mut input = edit(15, 30, 60);
        input.device_name = Some(name.to_string());
        assert_eq!(
            core.update_settings(input),
            Err(CoreError::InvalidInput),
            "{name:?}"
        );
    }
    let mut input = edit(15, 30, 60);
    input.network_interface = Some("not an interface!".into());
    assert_eq!(core.update_settings(input), Err(CoreError::InvalidInput));
    assert!(!dir.path().join(SETTINGS_FILE).exists(), "nothing saved");
    assert!(!core.settings().restart_required);
    for good in [edit(1, 5, 15), edit(240, 300, 1440)] {
        core.update_settings(good).unwrap();
    }
}

#[test]
fn a_saved_edit_is_encoded_atomically_and_needs_a_restart() {
    let dir = TempDir::new("settings-save");
    let fakes = common::Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let before = core.settings();
    assert!(!before.restart_required);
    let mut input = edit(5, 10, 30);
    input.device_name = Some("My phone".into());
    input.network_interface = Some("wlan0".into());
    core.update_settings(input).unwrap();
    let path = dir.path().join(SETTINGS_FILE);
    assert_eq!(mode(&path), 0o600);
    let text = fs::read_to_string(&path).unwrap();
    let parsed = host_runtime::config::parse(&text).unwrap();
    assert_eq!(parsed.auto_lock.as_secs(), 5 * 60);
    assert_eq!(parsed.clipboard_clear.as_secs(), 10);
    assert_eq!(parsed.sync_interval.as_secs(), 30 * 60);
    assert_eq!(
        parsed.network.device_name.as_ref().map(|n| n.as_str()),
        Some("My phone")
    );
    assert!(
        !text.contains("port = 27471"),
        "the desktop port is never written"
    );
    assert!(
        !parsed.network.enabled,
        "networking is not changed by settings edits"
    );
    let view = core.settings();
    assert!(view.restart_required);
    assert_eq!(view.auto_lock_minutes, 5);
    assert_eq!(view.device_name, "My phone");
    assert_eq!(view.network_interface.as_deref(), Some("wlan0"));
    // After a restart the new values are in force and no restart is pending.
    drop(core);
    let core = fakes.start(dir.path()).unwrap();
    let view = core.settings();
    assert!(!view.restart_required);
    assert_eq!(view.clipboard_clear_seconds, 10);
    assert!(!view.reset_notice);
}

#[test]
fn the_default_device_name_is_kept_when_none_is_given() {
    let dir = TempDir::new("settings-defname");
    let fakes = common::Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let name = core.settings().device_name;
    assert!(name.starts_with("passwsync device "), "{name}");
    core.update_settings(edit(15, 30, 60)).unwrap();
    let text = fs::read_to_string(dir.path().join(SETTINGS_FILE)).unwrap();
    assert!(!text.contains("device_name"), "{text}");
    assert_eq!(core.settings().device_name, name);
}

#[test]
fn an_invalid_file_shows_the_notice_through_the_core() {
    let dir = TempDir::new("settings-core-invalid");
    write_settings(dir.path(), "network = on\nauto_lock_minutes = 0\n");
    let fakes = common::Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let view = core.settings();
    assert!(view.reset_notice);
    assert!(!view.networking);
    let resets = fakes
        .log
        .lines()
        .iter()
        .filter(|l| l.contains("settings reset to defaults"))
        .count();
    assert_eq!(resets, 1);
}

#[test]
fn shutdown_locks_everything_and_stops() {
    let dir = TempDir::new("settings-shutdown");
    let fakes = common::Fakes::new();
    let core = common::core_with_wallet(dir.path(), &fakes, "Personal");
    core.shutdown();
    assert!(core.list_wallets().unwrap().iter().all(|w| !w.unlocked));
    // Idempotent.
    core.shutdown();
}
