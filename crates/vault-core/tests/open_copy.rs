//! 004 T018: opening a received copy (contracts/vault-core-sync-api.md).

mod support;

use std::time::Instant;

use support::{PASSWORD, contains};
use vault_core::{
    DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, OpenedCopy, Vault, VaultError,
};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn pw(text: &str) -> MasterPassword {
    MasterPassword::new(text.into())
}

fn marker_fields() -> EntryFields {
    EntryFields {
        title: "TITLE-MARKER".into(),
        username: "USER-MARKER".into(),
        password: "PASSWORD-MARKER".into(),
        url: "URL-MARKER".into(),
        notes: "NOTES-MARKER".into(),
    }
}

fn pair(kdf: KdfConfig) -> (Vault, Vault) {
    let mut a = Vault::create(pw(PASSWORD), kdf, d("a"), Box::new(FixedClock::new(1))).unwrap();
    a.add_entry(marker_fields()).unwrap();
    let bytes = a.seal().unwrap();
    let b = Vault::unlock(&bytes, pw(PASSWORD), d("b"), Box::new(FixedClock::new(1))).unwrap();
    (a, b)
}

#[test]
fn own_key_opens_a_copy_without_running_the_kdf() {
    let (mut a, b) = pair(KdfConfig::DEFAULT);
    a.add_entry(marker_fields()).unwrap();
    let copy_bytes = a.seal().unwrap();
    let started = Instant::now();
    let copy = b.open_copy_own_key(&copy_bytes).unwrap();
    assert!(started.elapsed().as_millis() < 100, "no Argon2 run");
    assert_eq!(copy.wallet_id(), b.wallet_id());
    assert_eq!(copy.state(), a.state());
    assert!(!b.needs_password(&copy_bytes).unwrap());
}

#[test]
fn authentication_failure_is_the_generic_error() {
    let (a, b) = pair(KdfConfig::MINIMUM);
    let mut bytes = a.seal().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        b.open_copy_own_key(&bytes),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
    assert!(matches!(
        b.open_copy_own_key(&bytes[..40]),
        Err(VaultError::MalformedFile)
    ));
}

#[test]
fn a_copy_under_another_password_needs_that_password() {
    let (mut a, b) = pair(KdfConfig::MINIMUM);
    a.change_master_password(pw("a brand new master password"))
        .unwrap();
    let bytes = a.seal().unwrap();
    assert!(b.needs_password(&bytes).unwrap());
    assert!(matches!(
        b.open_copy_own_key(&bytes),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
    assert!(matches!(
        Vault::open_copy_with_password(&bytes, pw(PASSWORD)),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
    let copy = Vault::open_copy_with_password(&bytes, pw("a brand new master password")).unwrap();
    assert_eq!(copy.wallet_id(), a.wallet_id());
    assert_eq!(copy.password_epoch(), a.password_epoch());
    assert!(b.needs_password(b"short").is_err());
}

#[test]
fn opened_copy_is_not_clone_or_serialize() {
    // Compiles only if `T` implements neither (ambiguity trick).
    macro_rules! assert_not_impl {
        ($t:ty, $tr:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $tr> AmbiguousIfImpl<u8> for T {}
            let _ = <$t as AmbiguousIfImpl<_>>::check;
        }};
    }
    assert_not_impl!(OpenedCopy, Clone);
    assert_not_impl!(OpenedCopy, serde::Serialize);
    fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes::<OpenedCopy>();
}

#[test]
fn debug_shows_only_wallet_id_and_state() {
    let (a, b) = pair(KdfConfig::MINIMUM);
    let copy = b.open_copy_own_key(&a.seal().unwrap()).unwrap();
    let text = format!("{copy:?}");
    assert!(text.contains("OpenedCopy"));
    for marker in [
        "TITLE-MARKER",
        "USER-MARKER",
        "PASSWORD-MARKER",
        "URL-MARKER",
        "NOTES-MARKER",
        PASSWORD,
    ] {
        assert!(!text.contains(marker), "{marker} in debug output");
    }
    assert!(!contains(text.as_bytes(), b"key"));
}
