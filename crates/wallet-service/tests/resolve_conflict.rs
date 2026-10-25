//! 004 T074: `Service::resolve_conflict` (FR-016).

mod common;

use std::time::Duration;

use common::*;
use vault_core::{DeviceId, EntryId, FixedClock, MasterPassword, Resolution, Vault};
use wallet_service::{CopyVerdict, ServiceError, WalletName};

/// Creates `Personal` with one credential and a concurrent edit merged in: a conflict.
fn conflicted(fx: &Fx) -> (WalletName, EntryId) {
    let w = create(fx, "Personal");
    let id = fx.service.add_entry(&w, fields("Shared")).unwrap();
    let mut other = Vault::unlock(
        &fx.dir.bytes(&w).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("phone").unwrap(),
        Box::new(FixedClock::new(9_000)),
    )
    .unwrap();
    other.update_entry(id, fields("Phone edit")).unwrap();
    let bytes = other.seal().unwrap();
    fx.service
        .update_entry(&w, id, fields("Local edit"))
        .unwrap();
    fx.service
        .merge_copy(&w, &bytes, &|_| CopyVerdict::Accept)
        .unwrap();
    (w, id)
}

#[test]
fn resolving_saves_and_clears_the_conflict() {
    let fx = fx();
    let (w, id) = conflicted(&fx);
    assert!(fx.service.search(&w, "").unwrap()[0].conflicted);
    let created = fx
        .service
        .resolve_conflict(&w, id, Resolution::KeepBoth)
        .unwrap();
    assert_eq!(created.len(), 1);
    let found = fx.service.search(&w, "").unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|e| !e.conflicted));
    assert_eq!(reopen(&fx, &w).all_records().count(), 2, "saved");
}

#[test]
fn errors_and_locked_wallets() {
    let fx = fx();
    let (w, id) = conflicted(&fx);
    assert_eq!(
        fx.service.resolve_conflict(&w, id, Resolution::Keep(5)),
        Err(ServiceError::InvalidVersionIndex)
    );
    fx.dir.set_failing(true);
    assert_eq!(
        fx.service.resolve_conflict(&w, id, Resolution::Keep(0)),
        Err(ServiceError::Storage)
    );
    assert!(
        fx.service.search(&w, "").unwrap()[0].conflicted,
        "rolled back"
    );
    fx.dir.set_failing(false);
    fx.service
        .resolve_conflict(&w, id, Resolution::Keep(0))
        .unwrap();
    assert_eq!(
        fx.service.resolve_conflict(&w, id, Resolution::Keep(0)),
        Err(ServiceError::NotConflicted)
    );
    fx.service.lock(&w).unwrap();
    assert_eq!(
        fx.service.resolve_conflict(&w, id, Resolution::Keep(0)),
        Err(ServiceError::WalletLocked)
    );
}

#[test]
fn a_resolution_is_a_deliberate_action() {
    let fx = fx();
    let (w, id) = conflicted(&fx);
    fx.elapsed.advance(AUTO_LOCK - Duration::from_secs(5));
    fx.service
        .resolve_conflict(&w, id, Resolution::Keep(0))
        .unwrap();
    fx.elapsed.advance(Duration::from_secs(10));
    assert!(fx.service.sweep().is_empty(), "the idle timer was reset");
}

#[test]
fn conflict_details_are_available_while_unlocked() {
    let fx = fx();
    let (w, id) = conflicted(&fx);
    let list = fx.service.conflicts(&w).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].versions, 2);
    let versions = fx.service.conflict_versions(&w, id).unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(
        versions[0].title.as_deref().map(|t| t.as_str()),
        Some("Phone edit")
    );
    assert_eq!(
        fx.service
            .conflict_field(&w, id, 1, wallet_service::Field::Password)
            .unwrap()
            .as_str(),
        "Local edit-secret"
    );
    fx.service.lock(&w).unwrap();
    assert_eq!(
        fx.service.conflicts(&w).err(),
        Some(ServiceError::WalletLocked)
    );
}
