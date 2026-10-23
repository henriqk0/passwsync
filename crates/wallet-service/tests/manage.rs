mod common;

use common::*;
use vault_core::{EntryId, KdfConfig};
use wallet_service::ServiceError;

fn titles(fx: &Fx, wallet: &wallet_service::WalletName, query: &str) -> Vec<String> {
    fx.service
        .search(wallet, query)
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect()
}

#[test]
fn search_lists_summaries_without_passwords_in_vault_core_order() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    for title in ["GitLab", "bank", "GitHub"] {
        fx.service.add_entry(&wallet, fields(title)).unwrap();
    }
    assert_eq!(titles(&fx, &wallet, ""), ["bank", "GitHub", "GitLab"]);
    assert_eq!(titles(&fx, &wallet, "git"), ["GitHub", "GitLab"]);
    assert_eq!(titles(&fx, &wallet, "BANK-user"), ["bank"]);
    assert!(
        titles(&fx, &wallet, "secret").is_empty(),
        "passwords are not searched"
    );
    let summary = &fx.service.search(&wallet, "GitHub").unwrap()[0];
    assert_eq!(summary.username.as_str(), "GitHub-user");
    assert_eq!(summary.url.as_str(), "https://github.example");
}

#[test]
fn get_entry_returns_details_but_no_password() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let view = fx.service.get_entry(&wallet, id).unwrap();
    assert_eq!(view.id, id);
    assert_eq!(view.title.as_str(), "GitHub");
    assert_eq!(view.username.as_str(), "GitHub-user");
    assert_eq!(view.url.as_str(), "https://github.example");
    assert_eq!(view.notes.as_str(), "GitHub notes");
    assert_eq!(view.created_at, 1_000);
    assert_eq!(view.modified_at, 1_000);
    assert!(!format!("{view:?}").contains("GitHub-secret"));
}

#[test]
fn update_replaces_all_fields_and_is_saved() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    fx.time.advance(30);
    fx.service
        .update_entry(&wallet, id, fields("GitHub2"))
        .unwrap();
    let view = fx.service.get_entry(&wallet, id).unwrap();
    assert_eq!(view.title.as_str(), "GitHub2");
    assert_eq!(view.modified_at, 1_030);
    let stored = reopen(&fx, &wallet);
    assert_eq!(
        stored.get(id).unwrap().fields().unwrap().password,
        "GitHub2-secret"
    );
}

#[test]
fn update_keeping_the_password_merges_the_stored_one_server_side() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let mut change = fields("GitHub2");
    change.password = String::new();
    fx.service
        .update_entry_keeping_password(&wallet, id, change)
        .unwrap();
    let view = fx.service.get_entry(&wallet, id).unwrap();
    assert_eq!(view.title.as_str(), "GitHub2");
    let stored = reopen(&fx, &wallet);
    let f = stored.get(id).unwrap().fields().unwrap();
    assert_eq!(f.password, "GitHub-secret", "stored password kept");
    assert_eq!(f.username, "GitHub2-user");
    let missing = EntryId::from_bytes([7; 16]);
    assert_eq!(
        fx.service
            .update_entry_keeping_password(&wallet, missing, fields("x")),
        Err(ServiceError::EntryNotFound)
    );
}

#[test]
fn delete_removes_the_entry_and_is_saved() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    fx.service.delete_entry(&wallet, id).unwrap();
    assert!(titles(&fx, &wallet, "").is_empty());
    assert_eq!(
        fx.service.get_entry(&wallet, id).unwrap_err(),
        ServiceError::EntryNotFound
    );
    assert!(reopen(&fx, &wallet).get(id).is_none());
}

#[test]
fn unknown_entries_locked_and_missing_wallets() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let missing = EntryId::from_bytes([7; 16]);
    assert_eq!(
        fx.service.get_entry(&wallet, missing).unwrap_err(),
        ServiceError::EntryNotFound
    );
    assert_eq!(
        fx.service.update_entry(&wallet, missing, fields("x")),
        Err(ServiceError::EntryNotFound)
    );
    assert_eq!(
        fx.service.delete_entry(&wallet, missing),
        Err(ServiceError::EntryNotFound)
    );
    let locked = foreign_wallet(&fx, "Locked", KdfConfig::MINIMUM, &["a"]);
    assert_eq!(
        fx.service.search(&locked, "").unwrap_err(),
        ServiceError::WalletLocked
    );
    assert_eq!(
        fx.service.get_entry(&locked, missing).unwrap_err(),
        ServiceError::WalletLocked
    );
    assert_eq!(
        fx.service.update_entry(&locked, missing, fields("x")),
        Err(ServiceError::WalletLocked)
    );
    assert_eq!(
        fx.service.delete_entry(&locked, missing),
        Err(ServiceError::WalletLocked)
    );
    assert_eq!(
        fx.service.search(&name("Nobody"), "").unwrap_err(),
        ServiceError::WalletNotFound
    );
}

#[test]
fn failed_saves_leave_memory_and_file_unchanged() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let file = fx.dir.bytes(&wallet).unwrap();
    let before = fx.service.get_entry(&wallet, id).unwrap();
    fx.time.advance(30);
    fx.dir.set_failing(true);
    assert_eq!(
        fx.service.update_entry(&wallet, id, fields("Changed")),
        Err(ServiceError::Storage)
    );
    assert_eq!(
        fx.service.delete_entry(&wallet, id),
        Err(ServiceError::Storage)
    );
    fx.dir.set_failing(false);
    assert_eq!(fx.dir.bytes(&wallet).unwrap(), file);
    let after = fx.service.get_entry(&wallet, id).unwrap();
    assert_eq!(after.title, before.title);
    assert_eq!(after.modified_at, before.modified_at);
    assert_eq!(titles(&fx, &wallet, ""), ["GitHub"]);
}
