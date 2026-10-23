//! Manual smoke check: create a wallet in a temp directory, save, reopen, print the title.
//! Inspect the file afterwards with `xxd`; it must start `PWSV 0100 01` and show no plaintext.

use vault_core::{DeviceId, EntryFields, KdfConfig, MasterPassword, SystemClock, Vault};
use vault_storage_file::FileStorage;

fn main() {
    let path = std::env::temp_dir().join("vault-smoke.pwsv");
    let device = || DeviceId::new("smoke").unwrap();
    let password = || MasterPassword::new("correct horse battery".to_string());

    let mut vault = Vault::create(
        password(),
        KdfConfig::DEFAULT,
        device(),
        Box::new(SystemClock),
    )
    .expect("create wallet");
    let mut fields = EntryFields::default();
    fields.title = "GitHub".into();
    fields.password = "not-a-real-password".into();
    let id = vault.add_entry(fields).expect("add entry");

    let mut storage = FileStorage::new(&path);
    vault.save(&mut storage).expect("save wallet");

    let reopened =
        Vault::open(&storage, password(), device(), Box::new(SystemClock)).expect("reopen wallet");
    println!(
        "{}",
        reopened
            .get(id)
            .expect("entry")
            .fields()
            .expect("live")
            .title
    );
    println!("wallet file: {}", path.display());
}
