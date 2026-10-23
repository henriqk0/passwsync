mod common;

use common::*;
use vault_core::{KdfConfig, peek_kdf_config};
use wallet_service::{ServiceError, WalletStatus};

fn status(wallet: &str, unlocked: bool) -> WalletStatus {
    WalletStatus {
        name: name(wallet),
        unlocked,
    }
}

#[test]
fn create_saves_an_encrypted_wallet_with_the_configured_kdf_and_leaves_it_unlocked() {
    let fx = fx();
    let created = create(&fx, "Personal");
    assert_eq!(created, name("Personal"));
    let bytes = fx.dir.bytes(&created).unwrap();
    assert_eq!(peek_kdf_config(&bytes).unwrap(), KdfConfig::MINIMUM);
    assert!(
        !bytes
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes())
    );
    assert_eq!(fx.service.list().unwrap(), vec![status("Personal", true)]);
    reopen(&fx, &created);
}

#[test]
fn create_validates_in_order_name_mismatch_length_exists() {
    let fx = fx();
    create(&fx, "Taken");
    let svc = &fx.service;
    assert_eq!(
        svc.create("../bad", pw("short"), pw("other")),
        Err(ServiceError::InvalidName)
    );
    assert_eq!(
        svc.create("Taken", pw("short"), pw("other")),
        Err(ServiceError::PasswordMismatch)
    );
    assert_eq!(
        svc.create("Taken", pw("short"), pw("short")),
        Err(ServiceError::PasswordTooShort)
    );
    assert_eq!(
        svc.create("Taken", pw(PASSWORD), pw(PASSWORD)),
        Err(ServiceError::WalletExists)
    );
    assert_eq!(
        svc.create("", pw(PASSWORD), pw(PASSWORD)),
        Err(ServiceError::InvalidName)
    );
    assert_eq!(
        svc.create("New", pw("eleven char"), pw("eleven char")),
        Err(ServiceError::PasswordTooShort)
    );
}

#[test]
fn nothing_is_written_when_creation_fails() {
    let fx = fx();
    let _ = fx.service.create("New", pw("short"), pw("short"));
    let _ = fx
        .service
        .create("New", pw(PASSWORD), pw("different password"));
    assert!(fx.service.list().unwrap().is_empty());
    assert!(fx.dir.bytes(&name("New")).is_none());
}

#[test]
fn failed_first_save_leaves_no_wallet() {
    let fx = fx();
    fx.dir.set_failing(true);
    assert_eq!(
        fx.service.create("New", pw(PASSWORD), pw(PASSWORD)),
        Err(ServiceError::Storage)
    );
    fx.dir.set_failing(false);
    assert!(fx.service.list().unwrap().is_empty());
    create(&fx, "New");
}

#[test]
fn list_is_sorted_and_shows_locked_wallets_found_in_the_directory() {
    let fx = fx();
    create(&fx, "b");
    foreign_wallet(&fx, "A", KdfConfig::MINIMUM, &[]);
    create(&fx, "a");
    assert_eq!(
        fx.service.list().unwrap(),
        vec![status("A", false), status("a", true), status("b", true)]
    );
}

#[test]
fn add_entry_is_saved_to_the_directory() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let stored = reopen(&fx, &wallet);
    let entry = stored.get(id).unwrap();
    assert_eq!(entry.fields().unwrap().title, "GitHub");
    assert_eq!(entry.fields().unwrap().password, "GitHub-secret");
}

#[test]
fn add_entry_errors() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let locked = foreign_wallet(&fx, "Locked", KdfConfig::MINIMUM, &[]);
    assert_eq!(
        fx.service.add_entry(&wallet, fields(" ")),
        Err(ServiceError::EmptyTitle)
    );
    assert_eq!(
        fx.service.add_entry(&locked, fields("x")),
        Err(ServiceError::WalletLocked)
    );
    assert_eq!(
        fx.service.add_entry(&name("Nobody"), fields("x")),
        Err(ServiceError::WalletNotFound)
    );
    let mut big = fields("Big");
    big.notes = "x".repeat(1024 * 1024 + 1);
    assert_eq!(
        fx.service.add_entry(&wallet, big),
        Err(ServiceError::FieldTooLarge)
    );
}

#[test]
fn failed_save_of_an_add_changes_neither_memory_nor_file() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let before = fx.dir.bytes(&wallet).unwrap();
    fx.dir.set_failing(true);
    assert_eq!(
        fx.service.add_entry(&wallet, fields("GitHub")),
        Err(ServiceError::Storage)
    );
    fx.dir.set_failing(false);
    assert_eq!(fx.dir.bytes(&wallet).unwrap(), before);
    fx.service.add_entry(&wallet, fields("GitLab")).unwrap();
    let stored = reopen(&fx, &wallet);
    let titles: Vec<String> = stored
        .list()
        .iter()
        .map(|e| e.fields().unwrap().title.clone())
        .collect();
    assert_eq!(titles, ["GitLab"], "the failed add left nothing in memory");
}
