//! FR-010, FR-020: credential add/get/update/delete/search through the exported API; lists
//! carry no password and no notes; `reveal_password` is the only way a password comes back;
//! every change is saved before `Ok`.

mod common;

use std::fs;

use common::{Fakes, PASSWORD, TempDir, bytes, core_with_wallet, input};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CredentialDetails, CredentialInput, CredentialSummary};

/// Compile-time field lists: adding a field (a password, notes) breaks these patterns.
#[allow(dead_code)]
fn summary_fields(summary: CredentialSummary) {
    let CredentialSummary {
        id: _,
        title: _,
        username: _,
        url: _,
        conflicted: _,
    } = summary;
}

#[allow(dead_code)]
fn details_fields(details: CredentialDetails) {
    let CredentialDetails {
        id: _,
        title: _,
        username: _,
        url: _,
        notes: _,
        created_at: _,
        modified_at: _,
    } = details;
}

fn titles(core: &passwsync_ffi::api::PasswsyncCore, query: &str) -> Vec<String> {
    core.search("Personal".into(), query.into())
        .unwrap()
        .into_iter()
        .map(|c| c.title)
        .collect()
}

fn reveal(core: &passwsync_ffi::api::PasswsyncCore, id: &str) -> Vec<u8> {
    core.reveal_password("Personal".into(), id.into())
        .unwrap()
        .password
}

#[test]
fn add_get_update_delete() {
    let dir = TempDir::new("cred-crud");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential(
            "Personal".into(),
            input("Mail", "me@example", Some("s3cret!")),
        )
        .unwrap();
    assert_eq!(id.len(), 32, "{id}");
    let details = core.get_credential("Personal".into(), id.clone()).unwrap();
    assert_eq!(details.id, id);
    assert_eq!(details.title, "Mail");
    assert_eq!(details.username, "me@example");
    assert_eq!(details.url, "https://mail.example");
    assert_eq!(details.notes, "notes of Mail");
    assert!(details.modified_at >= details.created_at);
    assert_eq!(reveal(&core, &id), b"s3cret!");

    core.update_credential(
        "Personal".into(),
        id.clone(),
        input("Mail box", "you@example", Some("n3w")),
    )
    .unwrap();
    assert_eq!(
        core.get_credential("Personal".into(), id.clone())
            .unwrap()
            .username,
        "you@example"
    );
    assert_eq!(reveal(&core, &id), b"n3w");

    core.delete_credential("Personal".into(), id.clone())
        .unwrap();
    assert_eq!(
        core.get_credential("Personal".into(), id.clone())
            .map(|_| ()),
        Err(CoreError::EntryNotFound)
    );
    assert!(titles(&core, "").is_empty());
}

#[test]
fn update_without_a_password_keeps_it() {
    let dir = TempDir::new("cred-keep");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Bank", "me", Some("keep me")))
        .unwrap();
    core.update_credential("Personal".into(), id.clone(), input("Bank 2", "me", None))
        .unwrap();
    assert_eq!(reveal(&core, &id), b"keep me");
    assert_eq!(titles(&core, ""), ["Bank 2"]);
}

#[test]
fn a_new_credential_needs_a_password_field_value_or_empty() {
    let dir = TempDir::new("cred-new");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    // No password on add: an empty password.
    let id = core
        .add_credential("Personal".into(), input("Note only", "", None))
        .unwrap();
    assert_eq!(reveal(&core, &id), b"");
    assert_eq!(
        core.add_credential("Personal".into(), input("  ", "me", Some("x"))),
        Err(CoreError::EmptyTitle)
    );
    let bad = CredentialInput {
        password: Some(vec![0xff]),
        ..input("Bad", "me", None)
    };
    assert_eq!(
        core.add_credential("Personal".into(), bad),
        Err(CoreError::InvalidInput)
    );
    assert_eq!(
        core.get_credential("Personal".into(), "not-an-id".into())
            .map(|_| ()),
        Err(CoreError::EntryNotFound)
    );
}

#[test]
fn search_is_case_insensitive_over_title_username_url_and_notes() {
    let dir = TempDir::new("cred-search");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.add_credential("Personal".into(), input("Mail", "alice", Some("p1")))
        .unwrap();
    core.add_credential(
        "Personal".into(),
        CredentialInput {
            notes: "Recovery codes in the safe".into(),
            ..input("Bank", "bob", Some("p2"))
        },
    )
    .unwrap();
    assert_eq!(titles(&core, "MAIL"), ["Mail"]);
    assert_eq!(titles(&core, "ALI"), ["Mail"]);
    assert_eq!(titles(&core, "bank.exam"), ["Bank"]);
    assert_eq!(titles(&core, "recovery"), ["Bank"]);
    assert_eq!(titles(&core, ""), ["Bank", "Mail"]);
    assert!(titles(&core, "p1").is_empty(), "passwords are not searched");
    let found = core.search("Personal".into(), "bank".into()).unwrap();
    assert_eq!(found[0].username, "bob");
    assert!(!found[0].conflicted);
}

#[test]
fn every_change_is_saved_before_ok() {
    let dir = TempDir::new("cred-saved");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let path = dir.path().join("wallets/Personal.pwsw");
    let mut last = fs::read(&path).unwrap();
    let mut changed = |what: &str| {
        let now = fs::read(&path).unwrap();
        assert_ne!(now, last, "{what} was not saved");
        last = now;
    };
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    changed("add");
    core.update_credential("Personal".into(), id.clone(), input("Mail", "you", None))
        .unwrap();
    changed("update");
    core.delete_credential("Personal".into(), id).unwrap();
    changed("delete");
    // A new process sees exactly what was saved.
    drop(core);
    let core = fakes.start(dir.path()).unwrap();
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
    assert!(titles(&core, "").is_empty());
}

#[test]
fn a_locked_wallet_refuses_every_credential_call() {
    let dir = TempDir::new("cred-locked");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    core.lock_all();
    let locked = Err(CoreError::WalletLocked);
    assert_eq!(
        core.search("Personal".into(), String::new()).map(|_| ()),
        locked
    );
    assert_eq!(
        core.get_credential("Personal".into(), id.clone())
            .map(|_| ()),
        locked
    );
    assert_eq!(
        core.add_credential("Personal".into(), input("X", "y", None))
            .map(|_| ()),
        locked
    );
    assert_eq!(
        core.update_credential("Personal".into(), id.clone(), input("X", "y", None)),
        locked
    );
    assert_eq!(
        core.delete_credential("Personal".into(), id.clone()),
        locked
    );
    assert_eq!(
        core.reveal_password("Personal".into(), id).map(|_| ()),
        locked
    );
}

#[test]
fn reveal_is_the_only_path_returning_the_password() {
    let dir = TempDir::new("cred-only");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let marker = "MARKER-only-reveal-pw";
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some(marker)))
        .unwrap();
    let listed = format!(
        "{:?}",
        core.search("Personal".into(), String::new()).unwrap()
    );
    let details = format!(
        "{:?}",
        core.get_credential("Personal".into(), id.clone()).unwrap()
    );
    let wallets = format!("{:?}", core.list_wallets().unwrap());
    for text in [listed, details, wallets] {
        assert!(!text.contains(marker), "{text}");
    }
    let ticket = core.reveal_password("Personal".into(), id).unwrap();
    assert_eq!(ticket.password, marker.as_bytes());
    assert_eq!(ticket.hide_in_ms, 30_000);
}
