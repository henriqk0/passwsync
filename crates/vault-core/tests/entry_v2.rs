//! 004 T008: entry versions, content hash and the v2 entry invariants (data-model.md).

use sha2::{Digest, Sha256};
use vault_core::{
    DeviceId, Entry, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, Vault,
    VaultError, Version, VersionVector,
};

fn d(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn fields(title: &str) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: "user".into(),
        password: "pw".into(),
        url: "https://x.example".into(),
        notes: "n".into(),
    }
}

fn vv(pairs: &[(&str, u64)]) -> VersionVector {
    let mut v = VersionVector::empty();
    for (name, count) in pairs {
        for _ in 0..*count {
            v.increment(&d(name));
        }
    }
    v
}

fn live(title: &str, at: i64, by: &str, version: &[(&str, u64)]) -> Version {
    Version::new_live(fields(title), at, d(by), vv(version)).unwrap()
}

fn tomb(at: i64, by: &str, version: &[(&str, u64)]) -> Version {
    Version::new_deleted(at, at, d(by), vv(version))
}

#[derive(serde::Serialize)]
enum RawState {
    Live {
        title: String,
        username: String,
        password: String,
        url: String,
        notes: String,
    },
    #[allow(dead_code)]
    Deleted { deleted_at: i64 },
}

#[derive(serde::Serialize)]
struct RawVersion {
    modified_at: i64,
    last_modified_by: String,
    version: Vec<(String, u64)>,
    state: RawState,
}

#[test]
fn content_hash_is_sha256_of_the_postcard_version() {
    let version = live("GitHub", 77, "laptop", &[("laptop", 2), ("phone", 1)]);
    let raw = RawVersion {
        modified_at: 77,
        last_modified_by: "laptop".into(),
        version: vec![("laptop".into(), 2), ("phone".into(), 1)],
        state: RawState::Live {
            title: "GitHub".into(),
            username: "user".into(),
            password: "pw".into(),
            url: "https://x.example".into(),
            notes: "n".into(),
        },
    };
    let expected: [u8; 32] = Sha256::digest(postcard::to_allocvec(&raw).unwrap()).into();
    assert_eq!(version.content_hash(), expected);
    // Pinned known-answer value: any change of the encoding changes version identity.
    assert_eq!(
        hex(&version.content_hash()),
        "b5b31525c95476011a18afed844d2fbcef74d3f27b7092de70348ed2d23c0207",
        "content hash known answer"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn content_hash_covers_every_field() {
    let base = live("t", 1, "a", &[("a", 1)]);
    for other in [
        live("u", 1, "a", &[("a", 1)]),
        live("t", 2, "a", &[("a", 1)]),
        live("t", 1, "b", &[("a", 1)]),
        live("t", 1, "a", &[("a", 2)]),
        tomb(1, "a", &[("a", 1)]),
    ] {
        assert_ne!(base.content_hash(), other.content_hash());
    }
    assert_eq!(
        base.content_hash(),
        live("t", 1, "a", &[("a", 1)]).content_hash()
    );
}

#[test]
fn version_accessors() {
    let v = live("GitHub", 5, "laptop", &[("laptop", 1)]);
    assert_eq!(v.modified_at(), 5);
    assert_eq!(v.last_modified_by(), &d("laptop"));
    assert_eq!(v.version().get(&d("laptop")), 1);
    assert_eq!(v.fields().unwrap().title, "GitHub");
    assert!(!v.is_deleted());
    assert_eq!(v.deleted_at(), None);
    let t = tomb(9, "phone", &[("phone", 1)]);
    assert!(t.is_deleted());
    assert_eq!(t.deleted_at(), Some(9));
    assert!(t.fields().is_none());
    assert!(Version::new_live(fields(" "), 1, d("a"), vv(&[("a", 1)])).is_err());
}

#[test]
fn a_new_entry_has_one_version_and_no_conflict() {
    let mut vault = Vault::create(
        MasterPassword::new("correct horse battery".into()),
        KdfConfig::MINIMUM,
        d("laptop"),
        Box::new(FixedClock::new(3)),
    )
    .unwrap();
    let id = vault.add_entry(fields("GitHub")).unwrap();
    let entry = vault.get(id).unwrap();
    assert!(!entry.is_conflicted());
    assert!(entry.conflicts().is_empty());
    assert_eq!(entry.versions().len(), 1);
    assert_eq!(entry.current().fields().unwrap().title, "GitHub");
    // 001 accessors read the current version.
    assert_eq!(entry.fields().unwrap().title, "GitHub");
    assert_eq!(entry.modified_at(), 3);
    assert_eq!(entry.version(), entry.current().version());
    assert_eq!(entry.last_modified_by(), &d("laptop"));
}

fn id(n: u8) -> EntryId {
    EntryId::from_bytes([n; 16])
}

#[test]
fn from_versions_orders_canonically_with_current_first() {
    // Concurrent versions: a tombstone (newest) and two live ones.
    let entry = Entry::from_versions(
        id(1),
        0,
        vec![
            tomb(50, "c", &[("c", 1)]),
            live("old", 10, "z", &[("z", 1)]),
            live("new", 20, "a", &[("a", 1)]),
        ],
    )
    .unwrap();
    let titles: Vec<Option<String>> = entry
        .versions()
        .iter()
        .map(|v| v.fields().map(|f| f.title.clone()))
        .collect();
    // Live before tombstone, then newest modification first.
    assert_eq!(
        titles,
        [Some("new".to_string()), Some("old".to_string()), None]
    );
    assert!(entry.is_conflicted());
    assert_eq!(entry.conflicts().len(), 2);
    assert_eq!(entry.fields().unwrap().title, "new");
}

#[test]
fn ties_break_by_device_then_content_hash() {
    let entry = Entry::from_versions(
        id(1),
        0,
        vec![
            live("x", 10, "a", &[("a", 1)]),
            live("y", 10, "b", &[("b", 1)]),
        ],
    )
    .unwrap();
    assert_eq!(
        entry.current().last_modified_by(),
        &d("b"),
        "larger device id"
    );
    let one = live("x", 10, "a", &[("a", 1), ("b", 1)]);
    let two = live("y", 10, "a", &[("a", 1), ("c", 1)]);
    let larger = one.content_hash().max(two.content_hash());
    let entry = Entry::from_versions(id(2), 0, vec![one, two]).unwrap();
    assert_eq!(
        entry.current().content_hash(),
        larger,
        "larger content hash"
    );
}

#[test]
fn from_versions_rejects_broken_invariants() {
    let dup = || live("x", 1, "a", &[("a", 1)]);
    let cases: Vec<Vec<Version>> = vec![
        vec![],
        vec![dup(), dup()], // equal content hash
        vec![
            live("x", 1, "a", &[("a", 1)]),
            live("y", 2, "a", &[("a", 2)]),
        ], // dominated
        (0..17)
            .map(|i| live("x", 1, &format!("d{i:02}"), &[(&format!("d{i:02}"), 1)]))
            .collect(), // 17 versions
    ];
    for versions in cases {
        assert!(matches!(
            Entry::from_versions(id(1), 0, versions),
            Err(VaultError::InvalidPasswordOrCorrupted)
        ));
    }
    let sixteen: Vec<Version> = (0..16)
        .map(|i| live("x", 1, &format!("d{i:02}"), &[(&format!("d{i:02}"), 1)]))
        .collect();
    assert_eq!(
        Entry::from_versions(id(1), 0, sixteen)
            .unwrap()
            .conflicts()
            .len(),
        15
    );
}

#[test]
fn equal_vectors_with_different_content_are_both_kept() {
    let entry = Entry::from_versions(
        id(1),
        0,
        vec![
            live("x", 1, "a", &[("a", 1)]),
            live("y", 1, "a", &[("a", 1)]),
        ],
    )
    .unwrap();
    assert!(entry.is_conflicted());
}
