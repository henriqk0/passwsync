//! FR-013, FR-014, FR-015, FR-019, FR-020: wallet create, list, unlock, lock and change
//! password through the exported API; one message for a wrong password and a corrupted file;
//! the 128 MiB KDF cap; atomic saves; one core per process.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::{Fakes, OTHER_PASSWORD, PASSWORD, TempDir, bytes, core_with_wallet, input, set_mode};
use passwsync_ffi::api::Deps;
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::CoreEvent;
use vault_core::KdfConfig;

fn names_and_state(core: &passwsync_ffi::api::PasswsyncCore) -> Vec<(String, bool)> {
    core.list_wallets()
        .unwrap()
        .into_iter()
        .map(|w| (w.name, w.unlocked))
        .collect()
}

#[test]
fn production_wallets_use_the_default_kdf() {
    assert_eq!(Deps::production().wallet_kdf, KdfConfig::DEFAULT);
}

#[test]
fn create_asks_for_the_password_twice_and_twelve_characters() {
    let dir = TempDir::new("w-create");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    assert_eq!(
        core.create_wallet("Personal".into(), bytes("short pw"), bytes("short pw")),
        Err(CoreError::PasswordTooShort)
    );
    assert_eq!(
        core.create_wallet("Personal".into(), bytes(PASSWORD), bytes(OTHER_PASSWORD)),
        Err(CoreError::PasswordMismatch)
    );
    assert_eq!(
        core.create_wallet("bad/name".into(), bytes(PASSWORD), bytes(PASSWORD)),
        Err(CoreError::InvalidName)
    );
    assert_eq!(
        core.create_wallet("Personal".into(), vec![0xff, 0xfe], vec![0xff, 0xfe]),
        Err(CoreError::InvalidInput)
    );
    assert!(core.list_wallets().unwrap().is_empty(), "nothing written");
    core.create_wallet("Personal".into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    assert_eq!(
        core.create_wallet("Personal".into(), bytes(PASSWORD), bytes(PASSWORD)),
        Err(CoreError::WalletExists)
    );
    assert_eq!(names_and_state(&core), [("Personal".to_string(), true)]);
    assert!(dir.path().join("wallets/Personal.pwsw").is_file());
    assert!(fakes.notifier.events().contains(&CoreEvent::WalletsChanged));
}

#[test]
fn list_reports_locked_and_unlocked() {
    let dir = TempDir::new("w-list");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.create_wallet("Work".into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    core.lock_wallet("Work".into()).unwrap();
    assert_eq!(
        names_and_state(&core),
        [("Personal".to_string(), true), ("Work".to_string(), false)]
    );
    let info = &core.list_wallets().unwrap()[0];
    assert_eq!(info.conflicts, 0);
    assert!(!info.pending_copy);
}

#[test]
fn wrong_password_and_corrupted_file_give_the_same_error() {
    let dir = TempDir::new("w-generic");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.create_wallet("Broken".into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    core.lock_all();
    let wrong = core
        .unlock_wallet("Personal".into(), bytes(OTHER_PASSWORD))
        .unwrap_err();
    // Flip one ciphertext byte at the end of the file.
    let path = dir.path().join("wallets/Broken.pwsw");
    let mut data = fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0x01;
    fs::write(&path, &data).unwrap();
    let corrupt = core
        .unlock_wallet("Broken".into(), bytes(PASSWORD))
        .unwrap_err();
    assert_eq!(wrong, CoreError::InvalidPasswordOrCorrupted);
    assert_eq!(wrong, corrupt);
    assert_eq!(wrong.code(), corrupt.code());
    assert_eq!(wrong.to_string(), corrupt.to_string());
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
    assert_eq!(
        names_and_state(&core),
        [
            ("Broken".to_string(), false),
            ("Personal".to_string(), true)
        ]
    );
}

#[test]
fn kdf_memory_above_128_mib_is_refused_before_any_derivation() {
    let dir = TempDir::new("w-cap");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Big");
    core.lock_all();
    let path = dir.path().join("wallets/Big.pwsw");
    let mut data = fs::read(&path).unwrap();
    // Header: magic and version, then memory_kib (u32 LE) at offset 7.
    data[7..11].copy_from_slice(&(128 * 1024 + 1u32).to_le_bytes());
    fs::write(&path, &data).unwrap();
    let started = Instant::now();
    let error = core
        .unlock_wallet("Big".into(), bytes(PASSWORD))
        .unwrap_err();
    assert_eq!(error, CoreError::KdfParamsOutOfRange);
    assert_eq!(error.code(), "kdf_params_out_of_range");
    assert_ne!(
        error.to_string(),
        CoreError::InvalidPasswordOrCorrupted.to_string()
    );
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[test]
fn change_password_requires_the_current_password() {
    let dir = TempDir::new("w-change");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    assert_eq!(
        core.change_password(
            "Personal".into(),
            bytes(OTHER_PASSWORD),
            bytes("brand new master password"),
            bytes("brand new master password"),
        ),
        Err(CoreError::InvalidPasswordOrCorrupted)
    );
    assert_eq!(
        core.change_password(
            "Personal".into(),
            bytes(PASSWORD),
            bytes("brand new master password"),
            bytes("brand new master pasword"),
        ),
        Err(CoreError::PasswordMismatch)
    );
    assert_eq!(
        core.change_password(
            "Personal".into(),
            bytes(PASSWORD),
            bytes("too short"),
            bytes("too short"),
        ),
        Err(CoreError::PasswordTooShort)
    );
    core.change_password(
        "Personal".into(),
        bytes(PASSWORD),
        bytes(OTHER_PASSWORD),
        bytes(OTHER_PASSWORD),
    )
    .unwrap();
    core.lock_all();
    assert_eq!(
        core.unlock_wallet("Personal".into(), bytes(PASSWORD)),
        Err(CoreError::InvalidPasswordOrCorrupted)
    );
    core.unlock_wallet("Personal".into(), bytes(OTHER_PASSWORD))
        .unwrap();
}

#[test]
fn a_failed_save_leaves_the_previous_file_byte_identical() {
    let dir = TempDir::new("w-atomic");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    let path = dir.path().join("wallets/Personal.pwsw");
    let before = fs::read(&path).unwrap();
    // A read-only wallets directory: the temp file of the atomic save cannot be created.
    set_mode(&dir.path().join("wallets"), 0o500);
    let added = core.add_credential("Personal".into(), input("Bank", "me", Some("pw")));
    let changed = core.change_password(
        "Personal".into(),
        bytes(PASSWORD),
        bytes(OTHER_PASSWORD),
        bytes(OTHER_PASSWORD),
    );
    set_mode(&dir.path().join("wallets"), 0o700);
    assert_eq!(added, Err(CoreError::Storage));
    assert_eq!(changed, Err(CoreError::Storage));
    assert_eq!(fs::read(&path).unwrap(), before);
    // Memory matches the file: the failed credential is not there.
    let titles: Vec<_> = core
        .search("Personal".into(), String::new())
        .unwrap()
        .into_iter()
        .map(|c| c.title)
        .collect();
    assert_eq!(titles, ["Mail"]);
}

#[test]
fn a_second_start_in_the_same_process_is_refused() {
    let dir = TempDir::new("w-single");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let other = TempDir::new("w-single-2");
    assert_eq!(
        fakes.start(other.path()).map(|_| ()),
        Err(CoreError::AlreadyStarted)
    );
    drop(core);
}

#[test]
fn a_new_core_over_the_same_directory_starts_with_every_wallet_locked() {
    let dir = TempDir::new("w-restart");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.create_wallet("Work".into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    assert!(names_and_state(&core).iter().all(|(_, unlocked)| *unlocked));
    drop(core);
    let core = fakes.start(dir.path()).unwrap();
    assert_eq!(
        names_and_state(&core),
        [("Personal".to_string(), false), ("Work".to_string(), false)]
    );
    assert_eq!(
        core.search("Personal".into(), String::new()).map(|_| ()),
        Err(CoreError::WalletLocked)
    );
}

#[test]
fn unknown_wallets_are_not_found() {
    let dir = TempDir::new("w-missing");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    assert_eq!(
        core.unlock_wallet("Nobody".into(), bytes(PASSWORD)),
        Err(CoreError::WalletNotFound)
    );
    assert_eq!(
        core.lock_wallet("Nobody".into()),
        Err(CoreError::WalletNotFound)
    );
}
