use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault, VaultError};

const MASTER: &str = "MASTER-MARKER-correct-horse";
const TITLE: &str = "TITLE-MARKER-1a2b";
const USERNAME: &str = "USERNAME-MARKER-3c4d";
const PASSWORD: &str = "PASSWORD-MARKER-5e6f";
const URL: &str = "https://URL-MARKER-7a8b.example";
const NOTES: &str = "NOTES-MARKER-9c0d";

fn device() -> DeviceId {
    DeviceId::new("laptop").unwrap()
}

fn clock() -> Box<FixedClock> {
    Box::new(FixedClock::new(1))
}

fn master() -> MasterPassword {
    MasterPassword::new(MASTER.to_string())
}

fn marker_fields() -> EntryFields {
    EntryFields {
        title: TITLE.into(),
        username: USERNAME.into(),
        password: PASSWORD.into(),
        url: URL.into(),
        notes: NOTES.into(),
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Secrets per FR-024: master password, derived key, entry password and notes.
fn assert_no_secret(text: &str, context: &str) {
    for secret in [MASTER, PASSWORD, NOTES] {
        assert!(!text.contains(secret), "secret marker found in {context}");
    }
}

#[test]
fn sealed_bytes_contain_no_plaintext_at_all() {
    let mut vault = Vault::create(master(), KdfConfig::MINIMUM, device(), clock()).unwrap();
    vault.add_entry(marker_fields()).unwrap();
    let sealed = vault.seal().unwrap();
    for marker in [MASTER, TITLE, USERNAME, PASSWORD, URL, NOTES] {
        assert!(
            !contains(&sealed, marker),
            "plaintext marker found in sealed bytes"
        );
    }
}

#[test]
fn debug_output_never_shows_secrets() {
    let mut vault = Vault::create(master(), KdfConfig::MINIMUM, device(), clock()).unwrap();
    let id = vault.add_entry(marker_fields()).unwrap();
    let entry = vault.get(id).unwrap();

    assert_no_secret(&format!("{vault:?}"), "Vault debug");
    assert_no_secret(&format!("{entry:?}"), "Entry debug");
    assert_no_secret(
        &format!("{:?}", entry.fields().unwrap()),
        "EntryFields debug",
    );
    assert_no_secret(&format!("{:?}", master()), "MasterPassword debug");
    assert_no_secret(
        &format!("{:#?}", vault.all_records().collect::<Vec<_>>()),
        "records debug",
    );
}

#[test]
fn errors_never_show_secrets() {
    let mut vault = Vault::create(master(), KdfConfig::MINIMUM, device(), clock()).unwrap();
    vault.add_entry(marker_fields()).unwrap();
    let sealed = vault.seal().unwrap();

    let mut flipped = sealed.clone();
    flipped[70] ^= 0x01;
    let mut bad_magic = sealed.clone();
    bad_magic[0] = b'X';
    let mut bad_kdf = sealed.clone();
    bad_kdf[7..11].copy_from_slice(&1u32.to_le_bytes());

    let unlock = |bytes: &[u8], password: &str| {
        Vault::unlock(
            bytes,
            MasterPassword::new(password.to_string()),
            device(),
            clock(),
        )
    };
    let mut errors: Vec<VaultError> = vec![
        unlock(&sealed, "WRONG-PASSWORD-MARKER").err().unwrap(),
        unlock(&flipped, MASTER).err().unwrap(),
        unlock(&bad_magic, MASTER).err().unwrap(),
        unlock(&bad_kdf, MASTER).err().unwrap(),
        unlock(&sealed[..40], MASTER).err().unwrap(),
        Vault::create(
            MasterPassword::new("SHORT-MK".into()),
            KdfConfig::MINIMUM,
            device(),
            clock(),
        )
        .err()
        .unwrap(),
    ];
    let mut blank_title = marker_fields();
    blank_title.title = " ".into();
    errors.push(vault.add_entry(blank_title).err().unwrap());

    for error in errors {
        for text in [error.to_string(), format!("{error:?}")] {
            assert_no_secret(&text, "error output");
            assert!(!text.contains("WRONG-PASSWORD-MARKER") && !text.contains("SHORT-MK"));
        }
    }
}
