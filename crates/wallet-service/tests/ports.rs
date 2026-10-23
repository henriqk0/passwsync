use std::time::Duration;

use vault_core::StorageError;
use wallet_service::testkit::{FakeElapsedClock, MemoryWalletDirectory};
use wallet_service::{ElapsedClock, WalletDirectory, WalletName};

fn name(n: &str) -> WalletName {
    WalletName::parse(n).unwrap()
}

#[test]
fn memory_directory_lists_sorted_and_reports_existence() {
    let dir = MemoryWalletDirectory::new();
    assert!(dir.list().unwrap().is_empty());
    for n in ["b", "a", "C"] {
        dir.storage(&name(n)).store(n.as_bytes()).unwrap();
    }
    assert_eq!(dir.list().unwrap(), vec![name("C"), name("a"), name("b")]);
    assert!(dir.exists(&name("a")).unwrap());
    assert!(!dir.exists(&name("z")).unwrap());
}

#[test]
fn memory_directory_storage_is_shared_between_handles() {
    let dir = MemoryWalletDirectory::new();
    let n = name("Personal");
    assert!(matches!(
        dir.storage(&n).load(),
        Err(StorageError::NotFound)
    ));
    dir.storage(&n).store(b"cipher").unwrap();
    assert_eq!(dir.storage(&n).load().unwrap(), b"cipher");
    assert_eq!(dir.bytes(&n).unwrap(), b"cipher");
}

#[test]
fn memory_directory_can_fail_saves_and_plant_or_remove_files() {
    let dir = MemoryWalletDirectory::new();
    let n = name("Personal");
    dir.insert(&n, b"old");
    dir.set_failing(true);
    assert!(matches!(
        dir.storage(&n).store(b"new"),
        Err(StorageError::Io(_))
    ));
    assert_eq!(dir.bytes(&n).unwrap(), b"old");
    dir.set_failing(false);
    dir.remove(&n);
    assert!(!dir.exists(&n).unwrap());
}

#[test]
fn fake_clock_is_settable_and_models_suspend() {
    let clock = FakeElapsedClock::new();
    assert_eq!(clock.monotonic(), Duration::ZERO);
    assert_eq!(clock.boottime(), Duration::ZERO);
    clock.advance(Duration::from_secs(10));
    assert_eq!(clock.monotonic(), Duration::from_secs(10));
    assert_eq!(clock.boottime(), Duration::from_secs(10));
    clock.suspend(Duration::from_secs(60));
    assert_eq!(clock.monotonic(), Duration::from_secs(10));
    assert_eq!(clock.boottime(), Duration::from_secs(70));
}
