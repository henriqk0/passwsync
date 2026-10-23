mod common;

use common::*;
use vault_core::{EntryId, KdfConfig};
use wallet_service::{Field, ServiceError};

#[test]
fn returns_exactly_one_requested_value() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let password = fx.service.field(&wallet, id, Field::Password).unwrap();
    assert_eq!(password.as_str(), "GitHub-secret");
    let username = fx.service.field(&wallet, id, Field::Username).unwrap();
    assert_eq!(username.as_str(), "GitHub-user");
}

#[test]
fn only_password_and_username_are_valid_field_names() {
    assert_eq!(Field::parse("password"), Some(Field::Password));
    assert_eq!(Field::parse("username"), Some(Field::Username));
    for other in ["notes", "title", "url", "Password", "", "password "] {
        assert_eq!(Field::parse(other), None, "{other:?}");
    }
}

#[test]
fn locked_missing_and_unknown() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let missing = EntryId::from_bytes([3; 16]);
    assert_eq!(
        fx.service
            .field(&wallet, missing, Field::Password)
            .unwrap_err(),
        ServiceError::EntryNotFound
    );
    let locked = foreign_wallet(&fx, "Locked", KdfConfig::MINIMUM, &["a"]);
    assert_eq!(
        fx.service
            .field(&locked, missing, Field::Password)
            .unwrap_err(),
        ServiceError::WalletLocked
    );
}
