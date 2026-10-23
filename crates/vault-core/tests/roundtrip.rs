use vault_core::{
    DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, MemoryStorage, StorageError,
    Vault, VaultError, VaultStorage,
};

const PASSWORD: &str = "correct horse battery";

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_string())
}

fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn clock(t: i64) -> Box<FixedClock> {
    Box::new(FixedClock::new(t))
}

fn new_vault() -> Vault {
    Vault::create(
        pw(PASSWORD),
        KdfConfig::MINIMUM,
        device("laptop"),
        clock(1_000),
    )
    .unwrap()
}

fn fields(title: &str, password: &str) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: format!("{title}-user"),
        password: password.into(),
        url: format!("https://{title}.example"),
        notes: format!("{title} notes"),
    }
}

#[test]
fn create_add_save_open_returns_identical_data() {
    let mut vault = new_vault();
    let ids: Vec<_> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|t| vault.add_entry(fields(t, &format!("{t}-secret"))).unwrap())
        .collect();
    let mut storage = MemoryStorage::new();
    vault.save(&mut storage).unwrap();

    let opened = Vault::open(&storage, pw(PASSWORD), device("laptop"), clock(2_000)).unwrap();
    assert_eq!(opened.wallet_id(), vault.wallet_id());
    assert_eq!(opened.created_at(), 1_000);
    assert_eq!(opened.kdf_config(), KdfConfig::MINIMUM);
    for (id, title) in ids.iter().zip(["alpha", "beta", "gamma"]) {
        let original = vault.get(*id).unwrap();
        let reopened = opened.get(*id).unwrap();
        assert_eq!(
            reopened.fields(),
            Some(&fields(title, &format!("{title}-secret")))
        );
        assert_eq!(reopened.fields(), original.fields());
        assert_eq!(reopened.id(), *id);
        assert_eq!(reopened.created_at(), 1_000);
        assert_eq!(reopened.modified_at(), 1_000);
        assert_eq!(reopened.last_modified_by(), &device("laptop"));
        assert_eq!(reopened.version(), original.version());
    }
}

#[test]
fn wrong_password_gives_the_generic_error() {
    let mut storage = MemoryStorage::new();
    new_vault().save(&mut storage).unwrap();
    let result = Vault::open(
        &storage,
        pw("incorrect horse battery"),
        device("laptop"),
        clock(0),
    );
    assert!(matches!(
        result,
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}

#[test]
fn password_length_policy_is_twelve_characters() {
    let short = Vault::create(pw("12345678901"), KdfConfig::MINIMUM, device("d"), clock(0));
    assert!(matches!(short, Err(VaultError::PasswordTooShort)));
    assert!(
        Vault::create(
            pw("123456789012"),
            KdfConfig::MINIMUM,
            device("d"),
            clock(0)
        )
        .is_ok()
    );
}

#[test]
fn nfc_equivalent_password_unlocks() {
    let vault = Vault::create(
        pw("caf\u{e9} au lait!"),
        KdfConfig::MINIMUM,
        device("d"),
        clock(0),
    )
    .unwrap();
    let mut storage = MemoryStorage::new();
    vault.save(&mut storage).unwrap();
    assert!(Vault::open(&storage, pw("cafe\u{301} au lait!"), device("d"), clock(0)).is_ok());
}

#[test]
fn add_entry_validates_the_title() {
    let mut vault = new_vault();
    assert!(matches!(
        vault.add_entry(fields("  ", "x")),
        Err(VaultError::EmptyTitle)
    ));
}

#[test]
fn create_rejects_kdf_outside_bounds() {
    let weak = KdfConfig {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        Vault::create(pw(PASSWORD), weak, device("d"), clock(0)),
        Err(VaultError::KdfParamsOutOfRange)
    ));
}

#[test]
fn short_new_password_is_rejected_and_old_one_still_works() {
    let mut vault = new_vault();
    assert!(matches!(
        vault.change_master_password(pw("short")),
        Err(VaultError::PasswordTooShort)
    ));
    let mut storage = MemoryStorage::new();
    vault.save(&mut storage).unwrap();
    assert!(Vault::open(&storage, pw(PASSWORD), device("laptop"), clock(0)).is_ok());
}

#[test]
fn changing_the_password_replaces_key_and_salt() {
    let mut vault = new_vault();
    vault.add_entry(fields("alpha", "secret")).unwrap();
    let mut before = MemoryStorage::new();
    vault.save(&mut before).unwrap();

    vault
        .change_master_password(pw("a brand new password"))
        .unwrap();
    let mut after = MemoryStorage::new();
    vault.save(&mut after).unwrap();

    let (old_bytes, new_bytes) = (before.load().unwrap(), after.load().unwrap());
    assert_ne!(old_bytes[19..51], new_bytes[19..51], "salt must change");
    assert!(matches!(
        Vault::open(&after, pw(PASSWORD), device("laptop"), clock(0)),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
    let reopened = Vault::open(
        &after,
        pw("a brand new password"),
        device("laptop"),
        clock(0),
    )
    .unwrap();
    assert_eq!(reopened.wallet_id(), vault.wallet_id());
}

#[test]
fn open_on_empty_storage_is_not_found() {
    let result = Vault::open(
        &MemoryStorage::new(),
        pw(PASSWORD),
        device("laptop"),
        clock(0),
    );
    assert!(matches!(
        result,
        Err(VaultError::Storage(StorageError::NotFound))
    ));
}

#[test]
fn lock_consumes_the_vault() {
    let vault = new_vault();
    vault.lock();
    // `vault` is moved; any further use would not compile.
}

#[test]
fn wallet_from_another_device_opens_with_the_password_alone() {
    let mut vault_a =
        Vault::create(pw(PASSWORD), KdfConfig::MINIMUM, device("A"), clock(5)).unwrap();
    let id = vault_a.add_entry(fields("alpha", "secret")).unwrap();
    let bytes = vault_a.seal().unwrap();

    let vault_b = Vault::unlock(&bytes, pw(PASSWORD), device("B"), clock(9)).unwrap();
    assert_eq!(vault_b.wallet_id(), vault_a.wallet_id());
    assert_eq!(
        vault_b.get(id).unwrap().fields(),
        vault_a.get(id).unwrap().fields()
    );
}

#[test]
fn repeated_saves_need_no_password() {
    let mut vault = new_vault();
    let mut storage = MemoryStorage::new();
    let mut ids = Vec::new();
    for n in 0..3 {
        ids.push(
            vault
                .add_entry(fields(&format!("entry{n}"), "secret"))
                .unwrap(),
        );
        vault.save(&mut storage).unwrap();
    }
    let opened = Vault::open(&storage, pw(PASSWORD), device("laptop"), clock(0)).unwrap();
    assert!(ids.iter().all(|id| opened.get(*id).is_some()));
}

#[test]
fn wallet_over_the_file_size_limit_is_refused_at_save_time() {
    // 17 entries x 4 fields x 1 MiB is ~68 MiB, above the 64 MiB limit a reader accepts.
    let mut vault = new_vault();
    let mib = "x".repeat(1024 * 1024);
    for n in 0..17 {
        vault
            .add_entry(EntryFields {
                title: format!("big{n}"),
                username: mib.clone(),
                password: mib.clone(),
                url: mib.clone(),
                notes: mib.clone(),
            })
            .unwrap();
    }
    assert!(matches!(vault.seal(), Err(VaultError::WalletTooLarge)));

    let mut storage = MemoryStorage::new();
    assert!(matches!(
        vault.save(&mut storage),
        Err(VaultError::WalletTooLarge)
    ));
    assert!(
        matches!(storage.load(), Err(StorageError::NotFound)),
        "nothing may be stored"
    );
}
