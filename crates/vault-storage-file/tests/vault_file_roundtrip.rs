mod common;

use common::TestDir;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
use vault_storage_file::FileStorage;

const PASSWORD: &str = "correct horse battery";

fn pw() -> MasterPassword {
    MasterPassword::new(PASSWORD.to_string())
}

fn device() -> DeviceId {
    DeviceId::new("laptop").unwrap()
}

#[test]
fn vault_saved_to_a_file_opens_again() {
    let dir = TestDir::new();
    let path = dir.path().join("wallet.pwsv");
    let mut vault = Vault::create(
        pw(),
        KdfConfig::MINIMUM,
        device(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    let mut fields = EntryFields::default();
    fields.title = "GitHub".into();
    fields.username = "octocat".into();
    fields.password = "PASSWORD-MARKER-123".into();
    fields.notes = "NOTES-MARKER-456".into();
    let id = vault.add_entry(fields).unwrap();

    let mut storage = FileStorage::new(&path);
    vault.save(&mut storage).unwrap();

    let opened = Vault::open(&storage, pw(), device(), Box::new(FixedClock::new(2))).unwrap();
    let entry = opened.get(id).unwrap();
    assert_eq!(entry.fields().unwrap().title, "GitHub");
    assert_eq!(entry.fields().unwrap().password, "PASSWORD-MARKER-123");

    let file = std::fs::read(&path).unwrap();
    assert_eq!(file[..7], [0x50, 0x57, 0x53, 0x56, 0x01, 0x00, 0x01]);
    for marker in [
        "PASSWORD-MARKER-123",
        "NOTES-MARKER-456",
        "octocat",
        "GitHub",
        PASSWORD,
    ] {
        assert!(
            !file.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "plaintext leaked into the file"
        );
    }
}
