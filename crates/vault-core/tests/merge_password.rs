//! 004 T024: the password-change epoch (FR-022, research R6).

mod support;

use support::PASSWORD;
use vault_core::testkit::{copy_of, fork};
use vault_core::{
    DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, MemoryStorage, MergeError,
    PasswordChoice, Vault, VaultStorage,
};

const NEW_A: &str = "new password chosen on a";
const NEW_B: &str = "new password chosen on b";

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn pw(text: &str) -> MasterPassword {
    MasterPassword::new(text.into())
}

fn base() -> Vault {
    let mut v = Vault::create(
        pw(PASSWORD),
        KdfConfig::MINIMUM,
        d("a"),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    let mut f = EntryFields::default();
    f.title = "x".into();
    v.add_entry(f).unwrap();
    v
}

fn unlock(bytes: &[u8], password: &str) -> bool {
    Vault::unlock(bytes, pw(password), d("z"), Box::new(FixedClock::new(1))).is_ok()
}

#[test]
fn a_newer_epoch_is_adopted_with_its_key() {
    let a0 = base();
    let mut a = fork(&a0, "a", 2);
    a.change_master_password(pw(NEW_A)).unwrap();
    let copy_bytes = a.seal().unwrap();
    let mut b = fork(&a0, "b", 2);
    assert!(b.needs_password(&copy_bytes).unwrap());
    let copy = Vault::open_copy_with_password(&copy_bytes, pw(NEW_A)).unwrap();
    let report = b.merge(copy).unwrap();
    assert!(report.password_adopted);
    assert_eq!(b.password_epoch(), a.password_epoch());
    let mut storage = MemoryStorage::new();
    b.save(&mut storage).unwrap();
    let saved = storage.load().unwrap();
    assert!(unlock(&saved, NEW_A), "saved under the adopted password");
    assert!(!unlock(&saved, PASSWORD));
    // Header (salt) equals the copy's: no password needed for further copies of a.
    assert!(!b.needs_password(&copy_bytes).unwrap());
}

#[test]
fn an_older_epoch_is_ignored() {
    let a0 = base();
    let mut b = fork(&a0, "b", 2);
    b.change_master_password(pw(NEW_B)).unwrap();
    let old = Vault::open_copy_with_password(&a0.seal().unwrap(), pw(PASSWORD)).unwrap();
    let report = b.merge(old).unwrap();
    assert!(!report.password_adopted);
    let mut storage = MemoryStorage::new();
    b.save(&mut storage).unwrap();
    assert!(unlock(&storage.load().unwrap(), NEW_B));
}

#[test]
fn concurrent_epochs_are_a_password_conflict_and_change_nothing() {
    let a0 = base();
    let mut a = fork(&a0, "a", 2);
    let mut b = fork(&a0, "b", 2);
    a.change_master_password(pw(NEW_A)).unwrap();
    b.change_master_password(pw(NEW_B)).unwrap();
    let before = (b.state().clone(), b.password_epoch().clone());
    let copy = Vault::open_copy_with_password(&a.seal().unwrap(), pw(NEW_A)).unwrap();
    assert!(matches!(b.merge(copy), Err(MergeError::PasswordConflict)));
    assert_eq!((b.state().clone(), b.password_epoch().clone()), before);
}

#[test]
fn choosing_a_password_joins_the_epochs_and_counts_as_my_change() {
    let a0 = base();
    let mut a = fork(&a0, "a", 2);
    let mut b = fork(&a0, "b", 2);
    a.change_master_password(pw(NEW_A)).unwrap();
    b.change_master_password(pw(NEW_B)).unwrap();
    let a_bytes = a.seal().unwrap();

    // Keep the copy's password.
    let mut keep_copy = fork(&b, "b", 3);
    let copy = Vault::open_copy_with_password(&a_bytes, pw(NEW_A)).unwrap();
    let report = keep_copy
        .merge_choosing_password(copy, PasswordChoice::Copy)
        .unwrap();
    assert!(report.password_adopted);
    let epoch = keep_copy.password_epoch();
    assert!(epoch.dominates(a.password_epoch()) && epoch.dominates(b.password_epoch()));
    assert_eq!(epoch.get(&d("b")), b.password_epoch().get(&d("b")) + 1);
    let mut storage = MemoryStorage::new();
    keep_copy.save(&mut storage).unwrap();
    assert!(unlock(&storage.load().unwrap(), NEW_A));

    // Keep the local password.
    let mut keep_local = fork(&b, "b", 3);
    let copy = Vault::open_copy_with_password(&a_bytes, pw(NEW_A)).unwrap();
    let report = keep_local
        .merge_choosing_password(copy, PasswordChoice::Local)
        .unwrap();
    assert!(!report.password_adopted);
    let mut storage = MemoryStorage::new();
    keep_local.save(&mut storage).unwrap();
    assert!(unlock(&storage.load().unwrap(), NEW_B));
    assert!(keep_local.state().get(&d("b")) > b.state().get(&d("b")));

    // The chosen result dominates both sides: merging either side again changes nothing.
    let again = keep_local.merge(copy_of(&b)).unwrap();
    assert!(!again.changed);
}

#[test]
fn a_wrong_password_copy_with_another_header_needs_its_password() {
    let a0 = base();
    let mut a = fork(&a0, "a", 2);
    a.change_master_password(pw(NEW_A)).unwrap();
    let bytes = a.seal().unwrap();
    let b = fork(&a0, "b", 2);
    assert!(b.needs_password(&bytes).unwrap());
    assert!(b.open_copy_own_key(&bytes).is_err());
    assert!(Vault::open_copy_with_password(&bytes, pw(PASSWORD)).is_err());
}
