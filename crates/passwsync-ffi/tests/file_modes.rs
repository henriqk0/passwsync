//! FR-030, FR-031: everything the core writes lives under `data_dir`, directories 0700 and
//! files 0600; writes are atomic (temp file then rename) and a leftover temp file is ignored.

mod common;

use std::fs;

use common::{Fakes, OTHER_PASSWORD, PASSWORD, TempDir, bytes, core_with_wallet, input, tree};
use passwsync_ffi::records::{CopyField, SettingsInput};

#[test]
fn every_created_directory_is_0700_and_every_file_0600() {
    let parent = TempDir::new("modes");
    let data = parent.path().join("data");
    let fakes = Fakes::new();
    let core = core_with_wallet(&data, &fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    core.update_settings(SettingsInput {
        auto_lock_minutes: 5,
        clipboard_clear_seconds: 20,
        device_name: None,
        sync_interval_minutes: 60,
        network_interface: None,
    })
    .unwrap();
    let entries = tree(&data);
    assert!(
        entries.iter().any(|(p, _, _)| p == "wallets/Personal.pwsw"),
        "{entries:?}"
    );
    assert!(entries.iter().any(|(p, _, _)| p == "settings"));
    assert!(entries.iter().any(|(p, _, _)| p == "clipboard-pending"));
    assert!(entries.iter().any(|(p, _, _)| p == "device-id"));
    assert_eq!(common::mode(&data), 0o700);
    for (path, dir, mode) in entries {
        let want = if dir { 0o700 } else { 0o600 };
        assert_eq!(mode, want, "{path} has mode {mode:o}");
    }
}

#[test]
fn nothing_is_written_outside_the_data_dir() {
    let parent = TempDir::new("outside");
    let data = parent.path().join("data");
    fs::create_dir(parent.path().join("sibling")).unwrap();
    fs::write(parent.path().join("sibling/keep"), b"x").unwrap();
    let before: Vec<_> = tree(parent.path())
        .into_iter()
        .filter(|(p, _, _)| !p.starts_with("data"))
        .collect();
    let fakes = Fakes::new();
    let core = core_with_wallet(&data, &fakes, "Personal");
    core.change_password(
        "Personal".into(),
        bytes(PASSWORD),
        bytes(OTHER_PASSWORD),
        bytes(OTHER_PASSWORD),
    )
    .unwrap();
    core.add_credential("Personal".into(), input("Bank", "me", Some("pw")))
        .unwrap();
    core.shutdown();
    let after: Vec<_> = tree(parent.path())
        .into_iter()
        .filter(|(p, _, _)| !p.starts_with("data"))
        .collect();
    assert_eq!(before, after);
    // The temp directory of the OS gets nothing named after the app either.
    let tmp_hits = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".pwsw"))
        .count();
    assert_eq!(tmp_hits, 0);
}

#[test]
fn a_leftover_temp_file_is_ignored_at_the_next_start() {
    let parent = TempDir::new("leftover");
    let data = parent.path().join("data");
    let fakes = Fakes::new();
    let core = core_with_wallet(&data, &fakes, "Personal");
    drop(core);
    // A crash between write and rename leaves `.<name>.tmp` files behind.
    fs::write(data.join("wallets/.Personal.pwsw.tmp"), b"partial").unwrap();
    fs::write(data.join(".settings.tmp"), b"auto_lock_minutes = 1\n").unwrap();
    common::set_mode(&data.join("wallets/.Personal.pwsw.tmp"), 0o600);
    common::set_mode(&data.join(".settings.tmp"), 0o600);
    let core = fakes.start(&data).unwrap();
    let names: Vec<_> = core
        .list_wallets()
        .unwrap()
        .into_iter()
        .map(|w| w.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert_eq!(
        core.settings().auto_lock_minutes,
        15,
        "temp settings unused"
    );
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
}

#[test]
fn a_settings_save_is_atomic() {
    let parent = TempDir::new("atomic");
    let data = parent.path().join("data");
    let fakes = Fakes::new();
    let core = fakes.start(&data).unwrap();
    let input = SettingsInput {
        auto_lock_minutes: 7,
        clipboard_clear_seconds: 30,
        device_name: Some("Phone".into()),
        sync_interval_minutes: 60,
        network_interface: None,
    };
    core.update_settings(input).unwrap();
    let text = fs::read_to_string(data.join("settings")).unwrap();
    assert!(text.contains("auto_lock_minutes = 7"), "{text}");
    assert!(!data.join(".settings.tmp").exists(), "temp renamed away");
}
