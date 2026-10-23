mod common;

use std::fs;

use common::{TempDir, mode};
use passwsyncd::fs_dir::FsWalletDirectory;
use vault_core::StorageError;
use wallet_service::{WalletDirectory, WalletName};

fn name(n: &str) -> WalletName {
    WalletName::parse(n).unwrap()
}

#[test]
fn lists_only_regular_pwsw_files_with_valid_names_sorted() {
    let dir = TempDir::new("fsdir");
    let root = dir.path();
    for file in [
        "b.pwsw",
        "A.pwsw",
        "Work 1.pwsw",
        "notes.txt",
        ".hidden.pwsw",
        ".b.pwsw.tmp-0011",
        "bad:name.pwsw",
        ".pwsw",
    ] {
        fs::write(root.join(file), b"x").unwrap();
    }
    fs::create_dir(root.join("dir.pwsw")).unwrap();
    std::os::unix::fs::symlink(root.join("b.pwsw"), root.join("link.pwsw")).unwrap();
    let listed = FsWalletDirectory::new(root.to_path_buf()).list().unwrap();
    assert_eq!(listed, vec![name("A"), name("Work 1"), name("b")]);
}

#[test]
fn exists_and_storage_use_name_dot_pwsw() {
    let dir = TempDir::new("fsdir");
    let wallets = FsWalletDirectory::new(dir.path().to_path_buf());
    let n = name("Personal");
    assert!(!wallets.exists(&n).unwrap());
    assert!(matches!(
        wallets.storage(&n).load(),
        Err(StorageError::NotFound)
    ));
    wallets.storage(&n).store(b"cipher").unwrap();
    let path = dir.path().join("Personal.pwsw");
    assert_eq!(fs::read(&path).unwrap(), b"cipher");
    assert_eq!(mode(&path), 0o600);
    assert!(wallets.exists(&n).unwrap());
    assert_eq!(wallets.storage(&n).load().unwrap(), b"cipher");
}

#[test]
fn a_symlink_does_not_count_as_an_existing_wallet_for_listing() {
    let dir = TempDir::new("fsdir");
    let target = dir.path().join("elsewhere");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join("Linked.pwsw")).unwrap();
    let wallets = FsWalletDirectory::new(dir.path().to_path_buf());
    assert!(wallets.list().unwrap().is_empty());
    // A name already taken by anything on disk must not be created over.
    assert!(wallets.exists(&name("Linked")).unwrap());
}

mod service_over_files {
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use super::common::{TempDir, mode};
    use passwsyncd::fs_dir::FsWalletDirectory;
    use vault_core::{DeviceId, EntryFields, KdfConfig, SystemClock};
    use wallet_service::testkit::FakeElapsedClock;
    use wallet_service::{Service, ServiceConfig, ServiceError, WalletName};
    use zeroize::Zeroizing;

    const PW: &str = "correct horse battery";

    fn service(dir: &TempDir) -> Service {
        Service::new(
            Arc::new(FsWalletDirectory::new(dir.path().to_path_buf())),
            Arc::new(SystemClock),
            Arc::new(FakeElapsedClock::new()),
            ServiceConfig {
                device: DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
                wallet_kdf: KdfConfig::MINIMUM,
                auto_lock: Duration::from_secs(900),
            },
        )
    }

    fn titled(title: &str) -> EntryFields {
        let mut fields = EntryFields::default();
        fields.title = title.into();
        fields
    }

    #[test]
    fn file_deleted_while_unlocked_is_rewritten_atomically_on_next_save() {
        let dir = TempDir::new("fsdir-svc");
        let svc = service(&dir);
        let pw = || Zeroizing::new(PW.to_string());
        let wallet = svc.create("Personal", pw(), pw()).unwrap();
        let path = dir.path().join("Personal.pwsw");
        fs::remove_file(&path).unwrap();
        svc.add_entry(&wallet, titled("GitHub")).unwrap();
        assert!(path.is_file());
        assert_eq!(mode(&path), 0o600);
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, ["Personal.pwsw"], "no temp files left");
    }

    #[test]
    fn corrupted_file_on_disk_is_listed_and_reports_its_class() {
        let dir = TempDir::new("fsdir-svc");
        fs::write(dir.path().join("Broken.pwsw"), b"garbage").unwrap();
        let svc = service(&dir);
        let listed = svc.list().unwrap();
        assert_eq!(listed[0].name, WalletName::parse("Broken").unwrap());
        assert_eq!(
            svc.unlock(&listed[0].name, Zeroizing::new(PW.to_string())),
            Err(ServiceError::MalformedFile)
        );
    }
}
