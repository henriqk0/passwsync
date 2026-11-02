//! 008 T016: the `testkit` payload and header entry points run the production decoder.
#![cfg(feature = "testkit")]

use vault_core::testkit::{
    DecodedPayload, HeaderFields, decode_payload, encode_payload, encode_payload_v1, header_bytes,
    parse_header, payload_of, seal_payload,
};
use vault_core::{
    DeviceId, Entry, EntryFields, EntryId, FixedClock, KdfConfig, MasterPassword, StateVector,
    Vault, VaultError, Version, VersionVector, WalletId,
};

const PASSWORD: &str = "fuzz-only-password";
const MAX_FIELD: usize = 1024 * 1024;

fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn fields(title: &str) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: "fz-user".into(),
        password: "fz-pass".into(),
        url: "https://fz.example".into(),
        notes: "fz".into(),
    }
}

fn vault_with(entries: usize) -> Vault {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        device("fz-a"),
        Box::new(FixedClock::new(1_000)),
    )
    .unwrap();
    for i in 0..entries {
        vault.add_entry(fields(&format!("fz-{i}"))).unwrap();
    }
    vault
}

fn equal(a: &DecodedPayload, b: &DecodedPayload) -> bool {
    encode_payload(a) == encode_payload(b)
}

#[test]
fn v2_payloads_round_trip_for_0_1_and_50_entries() {
    for n in [0, 1, 50] {
        let payload = payload_of(&vault_with(n));
        let bytes = encode_payload(&payload);
        let decoded = decode_payload(2, &bytes).unwrap();
        assert_eq!(decoded.entries.len(), n);
        assert_eq!(decoded.format, 2);
        assert_eq!(encode_payload(&decoded), bytes);
    }
}

#[test]
fn tombstones_updates_and_conflicts_round_trip() {
    let mut vault = vault_with(3);
    let ids: Vec<EntryId> = vault.list().iter().map(|e| e.id()).collect();
    vault.delete_entry(ids[0]).unwrap();
    vault.update_entry(ids[1], fields("fz-renamed")).unwrap();
    let mut payload = payload_of(&vault);
    // A conflicted entry: two concurrent versions by two devices.
    let (a, b) = (device("fz-a"), device("fz-b"));
    let v1 = Version::new_live(fields("fz-x"), 5, a.clone(), VersionVector::new(&a)).unwrap();
    let v2 = Version::new_live(fields("fz-y"), 6, b.clone(), VersionVector::new(&b)).unwrap();
    payload
        .entries
        .push(Entry::from_versions(EntryId::from_bytes([7; 16]), 5, vec![v1, v2]).unwrap());
    payload.state = payload
        .state
        .join(&StateVector::from_pairs(vec![(b, 1)]).unwrap());
    let bytes = encode_payload(&payload);
    let decoded = decode_payload(2, &bytes).unwrap();
    assert!(decoded.entries.iter().any(Entry::is_deleted));
    assert!(decoded.entries.iter().any(Entry::is_conflicted));
    assert_eq!(encode_payload(&decoded), bytes);
}

#[test]
fn v1_payloads_decode_to_the_same_wallet() {
    for n in [0, 1, 50] {
        let mut vault = vault_with(n);
        if n > 0 {
            let id = vault.list()[0].id();
            vault.delete_entry(id).unwrap();
        }
        let payload = payload_of(&vault);
        let v1 = encode_payload_v1(&payload);
        let decoded = decode_payload(1, &v1).unwrap();
        assert_eq!(decoded.format, 1);
        assert_eq!(decoded.entries.len(), n);
        assert_eq!(encode_payload_v1(&decoded), v1);
    }
}

#[test]
fn a_trailing_byte_is_rejected() {
    let mut bytes = encode_payload(&payload_of(&vault_with(1)));
    bytes.push(0);
    assert!(matches!(
        decode_payload(2, &bytes),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}

/// Replaces the 1 MiB length prefix of the notes field with 1 MiB + 1 and adds one byte.
fn over_limit(at_limit: &[u8]) -> Vec<u8> {
    let prefix = [0x80, 0x80, 0x40]; // varint(1 MiB)
    let marker: Vec<u8> = prefix.iter().copied().chain([b'z'; 8]).collect();
    let at = at_limit
        .windows(marker.len())
        .position(|w| w == marker.as_slice())
        .expect("1 MiB field");
    let mut out = at_limit[..at].to_vec();
    out.extend_from_slice(&[0x81, 0x80, 0x40]); // varint(1 MiB + 1)
    out.push(b'z');
    out.extend_from_slice(&at_limit[at + 3..]);
    out
}

#[test]
fn a_text_field_over_1_mib_is_rejected_and_at_1_mib_accepted() {
    let mut vault = vault_with(0);
    let mut big = fields("fz-big");
    big.notes = "z".repeat(MAX_FIELD);
    vault.add_entry(big).unwrap();
    let at_limit = encode_payload(&payload_of(&vault));
    assert!(decode_payload(2, &at_limit).is_ok());
    assert!(matches!(
        decode_payload(2, &over_limit(&at_limit)),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}

#[test]
fn a_duplicate_id_is_rejected() {
    let a = device("fz-a");
    let entry = |title: &str| {
        let v = Version::new_live(fields(title), 1, a.clone(), VersionVector::new(&a)).unwrap();
        Entry::from_versions(EntryId::from_bytes([3; 16]), 1, vec![v]).unwrap()
    };
    let payload = DecodedPayload {
        wallet_id: WalletId::from_bytes([1; 16]),
        created_at: 1,
        state: StateVector::from_pairs(vec![(a.clone(), 1)]).unwrap(),
        password_epoch: VersionVector::empty(),
        entries: vec![entry("fz-1"), entry("fz-2")],
        format: 2,
    };
    assert!(matches!(
        decode_payload(2, &encode_payload(&payload)),
        Err(VaultError::InvalidPasswordOrCorrupted)
    ));
}

#[test]
fn the_header_round_trips_through_63_bytes() {
    let sealed = vault_with(1).seal().unwrap();
    let header = parse_header(&sealed).unwrap();
    assert_eq!(header.version, 2);
    assert_eq!(header.kdf, KdfConfig::MINIMUM);
    let bytes = header_bytes(&header);
    assert_eq!(bytes.len(), 63);
    assert_eq!(&bytes[..], &sealed[..63]);
    let again = HeaderFields {
        version: 1,
        kdf: KdfConfig::DEFAULT,
        salt: [9; 32],
        nonce: [4; 12],
    };
    let mut file = header_bytes(&again).to_vec();
    file.extend_from_slice(&[0; 16]);
    assert_eq!(parse_header(&file).unwrap(), again);
    assert!(matches!(
        parse_header(&file[..78]),
        Err(VaultError::MalformedFile)
    ));
}

fn unlock(bytes: &[u8]) -> Result<Vault, VaultError> {
    Vault::unlock(
        bytes,
        MasterPassword::new(PASSWORD.into()),
        device("fz-b"),
        Box::new(FixedClock::new(1)),
    )
}

#[test]
fn testkit_decoding_and_unlock_accept_and_reject_the_same_plaintexts() {
    let good = encode_payload(&payload_of(&vault_with(2)));
    let mut trailing = good.clone();
    trailing.push(1);
    let mut flipped = good.clone();
    flipped[20] ^= 0x40;
    let v1 = encode_payload_v1(&payload_of(&vault_with(2)));
    let cases: [(u16, &[u8]); 6] = [
        (2, &good),
        (2, &trailing),
        (2, &flipped),
        (2, &good[..good.len() - 1]),
        (1, &v1),
        (1, &good),
    ];
    for (version, plaintext) in cases {
        let sealed = seal_payload(PASSWORD, KdfConfig::MINIMUM, version, plaintext);
        let production = unlock(&sealed);
        let testkit = decode_payload(version, plaintext);
        assert_eq!(production.is_ok(), testkit.is_ok(), "version {version}");
        if let (Err(a), Err(b)) = (&production, &testkit) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
        if let (Ok(vault), Ok(decoded)) = (production, testkit) {
            assert!(equal(&payload_of(&vault), &decoded));
        }
    }
}

#[test]
fn sealing_with_a_fixed_salt_and_nonce_is_deterministic_and_unlocks() {
    let plaintext = encode_payload(&payload_of(&vault_with(1)));
    let a = vault_core::testkit::seal_payload_with(
        PASSWORD,
        KdfConfig::MINIMUM,
        2,
        &plaintext,
        [7; 32],
        [9; 12],
    );
    let b = vault_core::testkit::seal_payload_with(
        PASSWORD,
        KdfConfig::MINIMUM,
        2,
        &plaintext,
        [7; 32],
        [9; 12],
    );
    assert_eq!(a, b);
    let header = parse_header(&a).unwrap();
    assert_eq!((header.salt, header.nonce), ([7; 32], [9; 12]));
    assert!(unlock(&a).is_ok());
}
